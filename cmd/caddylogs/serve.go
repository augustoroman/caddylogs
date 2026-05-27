package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/httpserver"
	"github.com/augustoroman/caddylogs/internal/livetail"
)

func runServe(ctx context.Context, opts *serveFlags) error {
	paths, err := expandPaths(opts.Paths)
	if err != nil {
		return err
	}
	cls, err := buildClassifier(opts.commonFlags)
	if err != nil {
		return err
	}
	defer cls.Close()

	store, cached, err := openStore(ctx, opts.commonFlags, cls, paths)
	if err != nil {
		return err
	}
	defer store.Close()

	// Load persistent tags BEFORE ingest so Classify honors them during
	// initial classification; persistence lives outside the cache dir so
	// tags survive a cache-key invalidation (e.g. the live log grew).
	if err := loadManualTags(ctx, store, cls, opts.commonFlags); err != nil {
		return err
	}

	if err := initialIngest(ctx, store, cls, paths, cached, opts.commonFlags); err != nil {
		return err
	}

	// Replay tags into the DB so row placement reflects the external set.
	// Cheap when the DB is already in sync (fresh ingest that just ran
	// with these tags), necessary when a cached DB predates new tags.
	if err := replayManualTags(ctx, store, cls); err != nil {
		return err
	}

	// Run heuristic classifiers over the stored data. The runner handles
	// the diff vs. the previous tag set for each classifier and respects
	// operator overrides (see Runner.Run). Default-on; skip with
	// --no-classifiers.
	//
	// Spawned in the background so the dashboard comes up immediately —
	// classifier runs can take a minute or more on a big DB and there's
	// no reason to make the operator wait. ManualTagSet is sync.RWMutex
	// guarded and the SQLite store is in WAL mode, so the goroutine and
	// HTTP handlers can read/write concurrently. The dashboard reads
	// fresh from the DB on every request so newly-applied tags are
	// visible to anyone who refreshes (or runs a new query) once the
	// classifiers finish.
	classifiers, err := buildClassifiers(opts.commonFlags)
	if err != nil {
		return err
	}
	runner := classifier.NewRunner(store, cls.ManualTags)

	// classifierMu serializes ALL classifier execution — the periodic
	// batch below and the manual run/clear handlers wired later both take
	// it, so a run can never overlap another (the Runner reconciles a
	// shared tag set and must not have two writers at once).
	var classifierMu sync.Mutex
	// dirty is set by live-tail on each new non-static row; the periodic
	// loop runs a batch only when it's set, then clears it.
	var dirty atomic.Bool
	runBatch := func() {
		classifierMu.Lock()
		defer classifierMu.Unlock()
		if err := runBuiltInClassifiers(ctx, runner, classifiers); err != nil {
			fmt.Fprintf(os.Stderr, "caddylogs: classifier batch error: %v\n", err)
		}
	}
	if !opts.NoClassifiers {
		// Single owner goroutine: run once at startup, then re-run at
		// most once per interval and only when there's new traffic. The
		// timer is reset AFTER each batch completes (not a fixed Ticker),
		// so ticks can't pile up behind a multi-minute run.
		go func() {
			runBatch()
			if opts.ClassifierInterval <= 0 {
				return // periodic re-runs disabled
			}
			timer := time.NewTimer(opts.ClassifierInterval)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					if dirty.Swap(false) {
						runBatch()
					}
					timer.Reset(opts.ClassifierInterval)
				}
			}
		}()
	}

	server := httpserver.New(store, httpserver.Assets(), httpserver.DefaultFilter{
		ExcludeBots:  !opts.IncludeBots,
		ExcludeLocal: !opts.IncludeLocal,
	})
	// Wire the SQLite-specific classification breakdown through the server's
	// optional classification hook.
	server.SetClassificationFn(func(ctx context.Context, fromNs, toNs int64) (any, error) {
		return store.Classification(ctx, fromNs, toNs)
	})
	// Wire manual IP tagging: the HTTP handler persists the tag to the
	// external file (so it survives cache-key invalidation), updates
	// existing rows in the store, and teaches the classifier so live-tail
	// events for that IP are classified consistently.
	server.SetTagFn(func(ctx context.Context, ip, tag string) error {
		t := classify.ManualTag(tag)
		if !classify.ValidManualTag(t) {
			return fmt.Errorf("invalid tag %q", tag)
		}
		if err := store.ApplyManualTag(ctx, ip, t); err != nil {
			return err
		}
		return cls.ManualTags.Set(ip, t)
	})
	// Wire tag inspection + removal. Removing a tag clears the DB's
	// manual_tags entry and deletes from the persistent set, but does NOT
	// revert already-classified rows — re-ingest or re-tag to correct
	// those. This is a deliberate simplicity trade: auto-reclassification
	// would need per-row UA/URI re-scoring and is out of scope.
	server.SetTagListFn(func(ctx context.Context) (any, error) {
		return map[string]any{
			"tags": cls.ManualTags.List(),
			"path": cls.ManualTags.Path(),
		}, nil
	})
	server.SetTagRemoveFn(func(ctx context.Context, ip string) error {
		if err := store.RemoveManualTag(ctx, ip); err != nil {
			return err
		}
		return cls.ManualTags.Delete(ip)
	})
	server.SetClassifierListFn(func(ctx context.Context) (any, error) {
		infos := make([]classifier.Info, 0, len(classifiers))
		for _, c := range classifiers {
			infos = append(infos, classifier.Info{Name: c.Name(), Description: c.Description()})
		}
		return classifier.InfoList{Classifiers: infos}, nil
	})
	server.SetClassifierRunFn(func(ctx context.Context, name string) (any, error) {
		c := classifier.ByName(classifiers, name)
		if c == nil {
			return nil, fmt.Errorf("unknown classifier %q", name)
		}
		// Wait for any in-flight batch so manual and periodic runs never
		// reconcile the shared tag set concurrently.
		classifierMu.Lock()
		defer classifierMu.Unlock()
		return runner.Run(ctx, c)
	})
	server.SetClassifierClearFn(func(ctx context.Context, name string) (any, error) {
		c := classifier.ByName(classifiers, name)
		if c == nil {
			return nil, fmt.Errorf("unknown classifier %q", name)
		}
		classifierMu.Lock()
		defer classifierMu.Unlock()
		return runner.Clear(ctx, c)
	})

	// Live tail on a separate goroutine. Cancellation via ctx.
	if !opts.NoTail {
		go livetail.Run(ctx, paths, store, cls, server.Broadcast, func() { dirty.Store(true) })
	}

	fmt.Fprintf(os.Stderr, "caddylogs: dashboard at http://%s\n", opts.Listen)
	if opts.OpenBrowser {
		go openBrowser("http://" + opts.Listen)
	}
	// httpserver.Start blocks until ctx is canceled.
	return server.Start(ctx, opts.Listen)
}

// openBrowser best-effort launches the default browser. Errors are swallowed;
// this is a convenience, not a dependency.
func openBrowser(url string) {
	time.Sleep(200 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return
	}
	_ = cmd.Start()
}
