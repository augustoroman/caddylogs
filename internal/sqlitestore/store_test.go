package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/ingest"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

func TestEndToEndWithSampleLog(t *testing.T) {
	paths, _ := filepath.Glob("../../*.access.log")
	gzPaths, _ := filepath.Glob("../../*.access-*.log.gz")
	paths = append(paths, gzPaths...)
	if len(paths) == 0 {
		t.Skip("no sample logs in module root")
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n, err := ingest.BulkFromFiles(ctx, store, paths, ingest.BulkOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no events ingested")
	}
	t.Logf("ingested %d events", n)

	ips, moved, err := ingest.FinalizeAttacks(ctx, store, cls, sqlitestore.DefaultThresholds, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("flagged %d attacker IPs, relocated %d rows", ips, moved)

	if err := store.MarkIngestComplete(ctx, nil); err != nil {
		t.Fatal(err)
	}

	// Malicious overview
	mal, err := store.Query(ctx, backend.Query{Table: backend.TableMalicious, Kind: backend.KindOverview})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("malicious overview: %+v", mal.Overview)
	if mal.Overview.Hits == 0 {
		t.Error("expected some malicious rows from sample logs")
	}
	// Classification breakdown
	cc, err := store.Classification(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("classification: %+v", cc)
	if cc.MaliciousDoc+cc.MaliciousStatic == 0 {
		t.Error("malicious cells are zero")
	}

	// Overview
	ov, err := store.Query(ctx, backend.Query{Table: backend.TableDynamic, Kind: backend.KindOverview})
	if err != nil {
		t.Fatal(err)
	}
	if ov.Overview.Hits == 0 {
		t.Fatal("overview hits = 0")
	}
	t.Logf("dynamic overview: %+v", ov.Overview)

	// Span must agree with the overview's First/Last.
	sp, err := store.Query(ctx, backend.Query{Table: backend.TableDynamic, Kind: backend.KindSpan})
	if err != nil {
		t.Fatal(err)
	}
	if !sp.Overview.First.Equal(ov.Overview.First) || !sp.Overview.Last.Equal(ov.Overview.Last) {
		t.Errorf("span = [%v, %v], overview = [%v, %v]",
			sp.Overview.First, sp.Overview.Last, ov.Overview.First, ov.Overview.Last)
	}
	if sp.Overview.Hits != 0 {
		t.Errorf("span should not count hits, got %d", sp.Overview.Hits)
	}
	// Span of an impossible filter is empty, not an error.
	empty, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindSpan,
		Filter: backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {"203.0.113.254"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Overview.First.IsZero() || !empty.Overview.Last.IsZero() {
		t.Errorf("expected zero span for no rows, got %+v", empty.Overview)
	}

	// Top IPs
	top, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindTopN,
		GroupBy: backend.DimIP, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(top.TopN) == 0 {
		t.Fatal("no top IPs")
	}
	t.Logf("top IPs: %v", top.TopN)

	// Status class
	sc, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindStatusClass,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status classes: %v", sc.Statuses)

	// Timeline
	tl, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindTimeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Timeline) == 0 {
		t.Fatal("no timeline buckets")
	}
	t.Logf("timeline buckets: %d", len(tl.Timeline))

	// Raw rows
	rows, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindRows, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) == 0 {
		t.Fatal("no rows returned")
	}
	t.Logf("first row: %+v", rows.Rows[0])

	// Drill into the top IP and re-query.
	topIP := top.TopN[0].Key
	filtered := backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {topIP}}}
	ov2, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindOverview, Filter: filtered,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ov2.Overview.Hits == 0 {
		t.Fatalf("drilled overview for %s has zero hits", topIP)
	}
	t.Logf("drilled overview for %s: %+v", topIP, ov2.Overview)
}
