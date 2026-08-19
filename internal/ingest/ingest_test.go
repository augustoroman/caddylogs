package ingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/progress"
)

// nopStore is the minimal backend.Store for exercising BulkFromFiles without
// a real database.
type nopStore struct{ ingested int64 }

func (n *nopStore) Ingest(ctx context.Context, events []parser.Event) error {
	n.ingested += int64(len(events))
	return nil
}
func (n *nopStore) Query(ctx context.Context, q backend.Query) (*backend.Result, error) {
	return nil, fmt.Errorf("not implemented")
}
func (n *nopStore) MarkIngestComplete(ctx context.Context, p progress.Func) error { return nil }
func (n *nopStore) Close() error                                                  { return nil }

func TestBulkFromFiles_FileStats(t *testing.T) {
	dir := t.TempDir()
	var content []byte
	for i := 0; i < 7; i++ {
		content = append(content, fmt.Sprintf(
			`{"ts":%d.0,"status":200,"size":10,"request":{"method":"GET","uri":"/x","host":"h","remote_ip":"1.2.3.4"}}`+"\n",
			1700000000+i*3600)...)
	}
	content = append(content, "not json at all\n"...)
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	store := &nopStore{}
	var stats []backend.IngestFileStat
	total, err := BulkFromFiles(context.Background(), store, []string{path}, BulkOpts{
		OnFileDone: func(st backend.IngestFileStat) { stats = append(stats, st) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 7 || store.ingested != 7 {
		t.Fatalf("total=%d ingested=%d; want 7", total, store.ingested)
	}
	if len(stats) != 1 {
		t.Fatalf("got %d stats, want 1", len(stats))
	}
	st := stats[0]
	if st.Path != path || st.Entries != 7 || st.BadLines != 1 || st.Compressed {
		t.Errorf("stat mismatch: %+v", st)
	}
	if want := int64(len(content)); st.DiskBytes != want || st.RawBytes != want {
		t.Errorf("disk=%d raw=%d; want both %d", st.DiskBytes, st.RawBytes, want)
	}
	if st.First.Unix() != 1700000000 || st.Last.Unix() != 1700000000+6*3600 {
		t.Errorf("timespan = %v → %v; want 1700000000 → +6h", st.First, st.Last)
	}
	if st.IngestedAt.IsZero() {
		t.Error("IngestedAt not set")
	}
}
