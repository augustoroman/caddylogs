// Package livetail watches active (non-gzipped) log files for new rows,
// pushes them into the store, and broadcasts each non-static row to the
// websocket hub via a user-supplied callback.
package livetail

import (
	"context"
	"strings"
	"sync"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
)

// Broadcaster receives each non-static classified event as it arrives.
type Broadcaster func(backend.EventRow)

// Run starts tail goroutines for every path that isn't gzipped. It returns
// once ctx is canceled, after all tail goroutines exit.
func Run(ctx context.Context, paths []string, store backend.Store, cls *classify.Classifier, bc Broadcaster) {
	var wg sync.WaitGroup
	for _, p := range paths {
		if strings.HasSuffix(p, ".gz") {
			continue // rotated archives are ingested once and don't grow
		}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			ch := parser.Tail(ctx, path, parser.TailOptions{FromStart: false})
			for r := range ch {
				if r.Err != nil {
					continue
				}
				classified := cls.Classify(r.Event)
				// Ingest single-row batch into the store so the data is
				// queryable immediately.
				_ = store.Ingest(ctx, []parser.Event{r.Event})
				if classified.IsStatic {
					continue
				}
				if bc != nil {
					bc(toEventRow(classified))
				}
			}
		}(p)
	}
	wg.Wait()
}

// toEventRow converts a Classified into the wire-shape backend.EventRow.
func toEventRow(c classify.Classified) backend.EventRow {
	return backend.EventRow{
		Timestamp:       c.Timestamp,
		Status:          c.Status,
		Method:          c.Method,
		Host:            c.Host,
		URI:             c.URI,
		IP:              c.RemoteIP,
		Country:         c.Country,
		City:            c.City,
		Browser:         c.Browser,
		OS:              c.OS,
		Device:          c.Device,
		Duration:        c.Duration,
		Size:            c.Size,
		UserAgent:       c.UserAgent,
		Referer:         c.Referer,
		Proto:           c.Proto,
		IsBot:           c.IsBot,
		IsLocal:         c.IsLocal,
		IsStatic:        c.IsStatic,
		MaliciousReason: c.MaliciousReason,
	}
}
