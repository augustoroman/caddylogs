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

// BulkOpts configures BulkFromFiles.
type BulkOpts struct {
	// Progress receives throttled per-batch updates during ingest.
	// Nil disables reporting (useful in tests).
	Progress progress.Func
	// OnFile, if non-nil, is invoked once per input file just before
	// that file's events are ingested. Unthrottled — it runs on every
	// file even when the caller's Progress func is throttled — so a
	// human operator watching stderr sees a line per file in real
	// time rather than "one update every 5 seconds".
	//
	// index is the 1-based position; ofN is the total count. totalSoFar
	// is the running event total from preceding files.
	OnFile func(path string, index, ofN int, totalSoFar int64)
}

// BulkFromFiles parses every file in paths (.log or .log.gz) into the store.
// It batches writes into the store for speed and reports progress through
// opts.Progress (throttled) and opts.OnFile (unthrottled, one call per
// file). On context cancellation it returns ctx.Err().
func BulkFromFiles(ctx context.Context, store backend.Store, paths []string, opts BulkOpts) (int64, error) {
	prog := opts.Progress
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

	for i, p := range sorted {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		// Announce the file BEFORE we start reading so the operator
		// sees movement on short files too. The redundant prog call
		// that used to live here has been dropped — OnFile covers the
		// "we just started file X" signal and the throttled prog
		// inside the batch loop covers "we're making progress inside
		// a big file". Same goes for the "finished X" phase tick
		// that used to fire after flush: OnFile of the next file (or
		// the terminal "done" event) makes it superfluous.
		if opts.OnFile != nil {
			opts.OnFile(p, i+1, len(sorted), total)
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
				prog("ingest", filepath.Base(p), total, -1)
			}
		}
		if err := flush(); err != nil {
			return total, err
		}
	}
	prog("ingest", "done", total, total)
	return total, nil
}
