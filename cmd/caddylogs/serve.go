package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

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

	if err := initialIngest(ctx, store, paths, cached); err != nil {
		return err
	}

	server := httpserver.New(store, httpserver.Assets(), httpserver.DefaultFilter{
		ExcludeBots:  !opts.IncludeBots,
		ExcludeLocal: !opts.IncludeLocal,
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
