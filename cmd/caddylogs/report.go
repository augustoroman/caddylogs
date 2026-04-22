package main

import (
	"context"
	"fmt"
	"os"
)

// runReport is the entry point for the "report" command. Static HTML
// rendering is added in a follow-on commit; for now this validates ingestion
// and flag wiring.
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

	fmt.Fprintf(os.Stderr, "caddylogs: ingest complete; report rendering not yet wired up.\n")
	fmt.Fprintf(os.Stderr, "caddylogs: would write %s\n", opts.Out)
	return nil
}
