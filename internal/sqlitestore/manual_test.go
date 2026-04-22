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

// TestManualTag_MovesRows verifies that ApplyManualTag relocates rows
// between the three request tables (dynamic ↔ malicious) and that the
// stored tag is readable back via WithManualTags.
func TestManualTag_MovesRows(t *testing.T) {
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
	evs := []parser.Event{
		{Timestamp: now, Status: 200, Method: "GET", Host: "h", URI: "/a", RemoteIP: "8.8.8.8"},
		{Timestamp: now.Add(time.Second), Status: 200, Method: "GET", Host: "h", URI: "/b.css", RemoteIP: "8.8.8.8"},
		{Timestamp: now.Add(2 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/c", RemoteIP: "1.1.1.1"},
	}
	if err := store.Ingest(ctx, evs); err != nil {
		t.Fatal(err)
	}

	// Before tagging: 8.8.8.8 rows live in dynamic+static.
	count := func(table backend.Table, ip string) int64 {
		r, err := store.Query(ctx, backend.Query{
			Table: table, Kind: backend.KindOverview,
			Filter: backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {ip}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return r.Overview.Hits
	}
	if got := count(backend.TableDynamic, "8.8.8.8"); got != 1 {
		t.Fatalf("dynamic before tag: got %d, want 1", got)
	}
	if got := count(backend.TableStatic, "8.8.8.8"); got != 1 {
		t.Fatalf("static before tag: got %d, want 1", got)
	}

	// Tag as malicious → both rows should move to the malicious table.
	if err := store.ApplyManualTag(ctx, "8.8.8.8", classify.ManualTagMalicious); err != nil {
		t.Fatal(err)
	}
	if got := count(backend.TableDynamic, "8.8.8.8"); got != 0 {
		t.Errorf("dynamic after malicious tag: got %d, want 0", got)
	}
	if got := count(backend.TableStatic, "8.8.8.8"); got != 0 {
		t.Errorf("static after malicious tag: got %d, want 0", got)
	}
	if got := count(backend.TableMalicious, "8.8.8.8"); got != 2 {
		t.Errorf("malicious after malicious tag: got %d, want 2", got)
	}

	// Now re-tag as real → rows move back, split by is_static.
	if err := store.ApplyManualTag(ctx, "8.8.8.8", classify.ManualTagReal); err != nil {
		t.Fatal(err)
	}
	if got := count(backend.TableMalicious, "8.8.8.8"); got != 0 {
		t.Errorf("malicious after real tag: got %d, want 0", got)
	}
	if got := count(backend.TableDynamic, "8.8.8.8"); got != 1 {
		t.Errorf("dynamic after real tag: got %d, want 1", got)
	}
	if got := count(backend.TableStatic, "8.8.8.8"); got != 1 {
		t.Errorf("static after real tag: got %d, want 1", got)
	}

	// The tag should be persisted and iterable.
	seen := map[string]classify.ManualTag{}
	if err := store.WithManualTags(ctx, func(ip string, tag classify.ManualTag, at int64) {
		seen[ip] = tag
	}); err != nil {
		t.Fatal(err)
	}
	if seen["8.8.8.8"] != classify.ManualTagReal {
		t.Errorf("persisted tag: got %v, want %v", seen["8.8.8.8"], classify.ManualTagReal)
	}

	// Contains filter: substring match via SQL LIKE. Should find the
	// /b.css row by "b.c" but exclude rows where uri is "/a" or "/c".
	r2, err := store.Query(ctx, backend.Query{
		Table: backend.TableStatic, Kind: backend.KindRows, Limit: 10,
		Filter: backend.Filter{Contains: map[backend.Dimension][]string{backend.DimURI: {"b.c"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Rows) != 1 || r2.Rows[0].URI != "/b.css" {
		t.Errorf("contains filter: got %+v, want single /b.css", r2.Rows)
	}

	// Tag as bot → flags should flip on existing rows.
	if err := store.ApplyManualTag(ctx, "1.1.1.1", classify.ManualTagBot); err != nil {
		t.Fatal(err)
	}
	r, err := store.Query(ctx, backend.Query{
		Table: backend.TableDynamic, Kind: backend.KindRows, Limit: 5,
		Filter: backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {"1.1.1.1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 1 || !r.Rows[0].IsBot || r.Rows[0].IsLocal {
		t.Errorf("bot tag did not update flags: %+v", r.Rows)
	}
}
