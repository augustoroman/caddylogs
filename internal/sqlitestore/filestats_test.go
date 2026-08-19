package sqlitestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

func TestIngestFileStats_Roundtrip(t *testing.T) {
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
	ctx := context.Background()

	t0 := time.Unix(1700000000, 0).UTC()
	newer := backend.IngestFileStat{
		Path: "/logs/site.log", DiskBytes: 900, RawBytes: 900,
		Entries: 5, First: t0.Add(48 * time.Hour), Last: t0.Add(72 * time.Hour),
		IngestedAt: t0.Add(100 * time.Hour),
	}
	older := backend.IngestFileStat{
		Path: "/logs/site-1.log.gz", DiskBytes: 100, RawBytes: 1200, Compressed: true,
		Entries: 10, BadLines: 2, First: t0, Last: t0.Add(24 * time.Hour),
		IngestedAt: t0.Add(100 * time.Hour),
	}
	empty := backend.IngestFileStat{
		Path: "/logs/empty.log", IngestedAt: t0.Add(100 * time.Hour),
	}
	for _, st := range []backend.IngestFileStat{newer, older, empty} {
		if err := store.SaveIngestFileStat(ctx, st); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.IngestFileStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d stats, want 3", len(got))
	}
	// Oldest data first; the no-entry file (first_ts=0) sorts last.
	if got[0].Path != older.Path || got[1].Path != newer.Path || got[2].Path != empty.Path {
		t.Fatalf("order = %s, %s, %s; want %s, %s, %s",
			got[0].Path, got[1].Path, got[2].Path, older.Path, newer.Path, empty.Path)
	}
	if g := got[0]; !g.Compressed || g.DiskBytes != 100 || g.RawBytes != 1200 ||
		g.Entries != 10 || g.BadLines != 2 ||
		!g.First.Equal(older.First) || !g.Last.Equal(older.Last) {
		t.Errorf("compressed file roundtrip mismatch: %+v", g)
	}
	if !got[2].First.IsZero() || !got[2].Last.IsZero() {
		t.Errorf("empty file should roundtrip zero timestamps: %+v", got[2])
	}

	// Upsert: re-saving the same path replaces rather than duplicates.
	newer.Entries = 42
	if err := store.SaveIngestFileStat(ctx, newer); err != nil {
		t.Fatal(err)
	}
	got, err = store.IngestFileStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].Entries != 42 {
		t.Fatalf("upsert failed: len=%d entries=%d", len(got), got[1].Entries)
	}
}
