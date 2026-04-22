package main

import (
	"context"
	"fmt"
	"os"
)

// runServe is the entry point for the "serve" command. The real HTTP server
// lives in internal/httpserver and is wired up in a follow-on commit; for
// now this verifies ingestion and query wiring by printing a quick overview
// to stderr before exiting.
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

	fmt.Fprintf(os.Stderr, "caddylogs: ingest complete; HTTP dashboard and live tail not yet wired up.\n")
	fmt.Fprintf(os.Stderr, "caddylogs: would listen on %s\n", opts.Listen)
	// TODO: start HTTP server + websocket + live tailer.
	return nil
}
