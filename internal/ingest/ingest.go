package ingest

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/parser"
)

// Progress is a simple progress callback for initial ingestion. It is called
// periodically during BulkFromFiles with the running total of parsed events
// and an optional per-file completion fraction for the current file.
type Progress func(totalEvents int64, currentFile string, fileFrac float64)

// BulkFromFiles parses every file in paths (.log or .log.gz) into the store.
// It batches writes into the store for speed and periodically reports
// progress. On context cancellation it returns ctx.Err().
func BulkFromFiles(ctx context.Context, store backend.Store, paths []string, progress Progress) (int64, error) {
	// Sort by size so we roughly process smaller (older .gz) files before the
	// big live log. Not a correctness concern, but improves perceived speed.
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
	lastReport := time.Now()
	report := func(path string, frac float64) {
		if progress != nil && time.Since(lastReport) > 200*time.Millisecond {
			progress(total+int64(len(batch)), path, frac)
			lastReport = time.Now()
		}
	}

	for _, p := range sorted {
		if err := ctx.Err(); err != nil {
			return total, err
		}
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
				report(p, -1)
			}
		}
		if err := flush(); err != nil {
			return total, err
		}
		report(p, 1.0)
	}
	if progress != nil {
		progress(total, "", 1.0)
	}
	return total, nil
}
