package main

import (
	"context"
	"fmt"
	"os"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/httpserver"
)

func runReport(ctx context.Context, opts *reportFlags) error {
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

	f, err := os.Create(opts.Out)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(os.Stderr, "caddylogs: rendering report to %s\n", opts.Out)
	return httpserver.RenderReport(ctx, store,
		httpserver.DefaultFilter{
			ExcludeBots:  !opts.IncludeBots,
			ExcludeLocal: !opts.IncludeLocal,
		},
		f, httpserver.ReportOptions{
			Inputs:        paths,
			Filter:        backend.Filter{},
			TopN:          10,
			IncludeStatic: true,
			Version:       "0.1.0-dev",
		})
}
