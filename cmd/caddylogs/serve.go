package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

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

	if err := initialIngest(ctx, store, cls, paths, cached, opts.commonFlags); err != nil {
		return err
	}

	// Seed the classifier's manual-tag set from whatever was persisted in
	// the cached DB so the live tail routes the same IPs consistently with
	// what the user has already tagged.
	if err := store.WithManualTags(ctx, func(ip string, tag classify.ManualTag) {
		cls.ManualTags.Set(ip, tag)
	}); err != nil {
		return err
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
	// Wire manual IP tagging: the HTTP handler persists the tag and updates
	// existing rows via the store; we also update the classifier's in-memory
	// set so live-tail events for that IP are classified consistently.
	server.SetTagFn(func(ctx context.Context, ip, tag string) error {
		t := classify.ManualTag(tag)
		if !classify.ValidManualTag(t) {
			return fmt.Errorf("invalid tag %q", tag)
		}
		if err := store.ApplyManualTag(ctx, ip, t); err != nil {
			return err
		}
		cls.ManualTags.Set(ip, t)
		return nil
	})

	// Live tail on a separate goroutine. Cancellation via ctx.
	if !opts.NoTail {
		go livetail.Run(ctx, paths, store, cls, server.Broadcast)
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
