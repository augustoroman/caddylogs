package ingest

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/progress"
)

// BulkFromFiles parses every file in paths (.log or .log.gz) into the store.
// It batches writes into the store for speed and reports progress through
// prog. On context cancellation it returns ctx.Err().
func BulkFromFiles(ctx context.Context, store backend.Store, paths []string, prog progress.Func) (int64, error) {
	if prog == nil {
		prog = progress.Nop
	}
	// Sort by size so we roughly process smaller (older .gz) files before
	// the big live log. Not a correctness concern, but improves perceived
	// speed.
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)

	var total int64
	const batchSize = 1000
	batch := make([]parser.Event, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := store.Ingest(ctx, batch); err != nil {
			return err
		}
		total += int64(len(batch))
		batch = batch[:0]
		return nil
	}

	for _, p := range sorted {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		prog("ingest", filepath.Base(p), total, -1)
		ch, err := parser.ReadFile(ctx, p)
		if err != nil {
			return total, fmt.Errorf("open %s: %w", p, err)
		}
		for r := range ch {
			if r.Err != nil {
				if r.Err == io.EOF {
					break
				}
				// Skip malformed lines silently.
				continue
			}
			batch = append(batch, r.Event)
			if len(batch) >= batchSize {
				if err := flush(); err != nil {
					return total, err
				}
				prog("ingest", filepath.Base(p), total, -1)
			}
		}
		if err := flush(); err != nil {
			return total, err
		}
		prog("ingest", "finished "+filepath.Base(p), total, -1)
	}
	prog("ingest", "done", total, total)
	return total, nil
}
