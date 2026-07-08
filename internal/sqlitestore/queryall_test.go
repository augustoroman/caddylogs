package sqlitestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// TestQueryAll_SpansEveryPool verifies that backend.TableAll queries the
// UNION ALL of dynamic+static+malicious: an unfiltered overview equals the sum
// of the three pools, and a filtered query (the "all requests from one IP"
// use case) aggregates that IP's rows across whichever pools they landed in.
func TestQueryAll_SpansEveryPool(t *testing.T) {
	cls, err := classify.New(classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cls.Close()
	store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	// 8.8.8.8 gets a doc hit (dynamic) and a .css hit (static) so its rows
	// straddle two pools — the exact case TableAll must stitch together.
	evs := []parser.Event{
		{Timestamp: now, Status: 200, Method: "GET", Host: "h", URI: "/a", RemoteIP: "8.8.8.8"},
		{Timestamp: now.Add(1 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/b.css", RemoteIP: "8.8.8.8"},
		{Timestamp: now.Add(2 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/c", RemoteIP: "1.1.1.1"},
		{Timestamp: now.Add(3 * time.Second), Status: 404, Method: "GET", Host: "h", URI: "/wp-login.php", RemoteIP: "9.9.9.9"},
	}
	if err := store.Ingest(ctx, evs); err != nil {
		t.Fatal(err)
	}

	hits := func(table backend.Table, f backend.Filter) int64 {
		t.Helper()
		r, err := store.Query(ctx, backend.Query{Table: table, Kind: backend.KindOverview, Filter: f})
		if err != nil {
			t.Fatal(err)
		}
		return r.Overview.Hits
	}

	// Unfiltered: All == dynamic + static + malicious, regardless of how the
	// classifier split the rows.
	dyn := hits(backend.TableDynamic, backend.Filter{})
	stat := hits(backend.TableStatic, backend.Filter{})
	mal := hits(backend.TableMalicious, backend.Filter{})
	all := hits(backend.TableAll, backend.Filter{})
	if all != dyn+stat+mal {
		t.Fatalf("TableAll unfiltered: got %d, want %d (dyn=%d static=%d mal=%d)", all, dyn+stat+mal, dyn, stat, mal)
	}
	if all != int64(len(evs)) {
		t.Fatalf("TableAll unfiltered: got %d, want %d total rows", all, len(evs))
	}

	// Filtered to one IP: aggregates its rows across pools (dynamic + static).
	ipFilter := backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {"8.8.8.8"}}}
	if got := hits(backend.TableAll, ipFilter); got != 2 {
		t.Fatalf("TableAll ip=8.8.8.8: got %d, want 2", got)
	}

	// A TopN by host over the union also sums across pools for that IP.
	res, err := store.Query(ctx, backend.Query{
		Table: backend.TableAll, Kind: backend.KindTopN,
		Filter: ipFilter, GroupBy: backend.DimHost, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TopN) != 1 || res.TopN[0].Key != "h" || res.TopN[0].Hits != 2 {
		t.Fatalf("TableAll topn host: got %+v, want one row {h, 2}", res.TopN)
	}

	// COUNT(DISTINCT visitor_hash) must not double-count a visitor that appears
	// in multiple pools: 8.8.8.8 (same UA/day) is one visitor across dyn+static.
	if v := func() int64 {
		r, _ := store.Query(ctx, backend.Query{Table: backend.TableAll, Kind: backend.KindOverview, Filter: ipFilter})
		return r.Overview.Visitors
	}(); v != 1 {
		t.Fatalf("TableAll ip=8.8.8.8 visitors: got %d, want 1", v)
	}
}
