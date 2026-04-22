// Package progress provides a small, throttled progress-reporting callback
// used by every long-running phase of caddylogs (ingest, index build,
// behavioral scan, malicious promotion).
package progress

import (
	"sync"
	"time"
)

// Func is the callback shape. Implementations are expected to be cheap and
// non-blocking; throttling is the caller's job.
//
//   - phase  : short stable label ("ingest", "index", "behavioral", "promote", ...)
//   - detail : free-form context (file name, table, IP count, etc.)
//   - done   : units processed so far; -1 when indeterminate
//   - total  : total units expected;  -1 when unknown / indeterminate
type Func func(phase, detail string, done, total int64)

// Nop is a no-op progress callback; handy as a default when no reporter
// has been configured.
func Nop(phase, detail string, done, total int64) {}

// Throttle returns a Func that only forwards to inner at most once per
// interval (plus always on the initial call and on the final call where
// done == total). 100% calls are never dropped; intermediate ones may be.
func Throttle(interval time.Duration, inner Func) Func {
	if inner == nil {
		return Nop
	}
	var (
		mu        sync.Mutex
		last      time.Time
		lastPhase string
	)
	return func(phase, detail string, done, total int64) {
		if inner == nil {
			return
		}
		final := total > 0 && done >= total
		mu.Lock()
		phaseChange := phase != lastPhase
		ready := phaseChange || final || time.Since(last) >= interval
		if !ready {
			mu.Unlock()
			return
		}
		last = time.Now()
		lastPhase = phase
		mu.Unlock()
		inner(phase, detail, done, total)
	}
}
