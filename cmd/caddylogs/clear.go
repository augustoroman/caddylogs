package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/augustoroman/caddylogs/internal/ingest"
)

// clearCacheFlags configures the clear-cache subcommand. Either paths
// (resolved through the same cache-key computation as `serve`) or --all
// must be supplied so we never silently delete nothing.
type clearCacheFlags struct {
	Paths    []string
	CacheDir string
	All      bool
}

func bindClearCacheFlags(cmd *kingpin.CmdClause) *clearCacheFlags {
	c := &clearCacheFlags{}
	cmd.Arg("paths", "Log files whose cached ingest DB should be removed. Same paths you'd pass to `serve`.").
		StringsVar(&c.Paths)
	cmd.Flag("cache-dir", "Cache directory. Empty means the OS cache dir.").
		StringVar(&c.CacheDir)
	cmd.Flag("all", "Delete every cached DB in the cache directory.").
		BoolVar(&c.All)
	return c
}

// runClearCache removes cached SQLite databases and exits. Two modes:
//
//   - With paths: computes the same cache key the ingest path uses and
//     removes the .db plus its -wal/-shm/-journal sidecars.
//   - With --all: removes every *.db (and sidecars) in the cache dir.
func runClearCache(ctx context.Context, opts *clearCacheFlags) error {
	dir := opts.CacheDir
	if dir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(d, "caddylogs")
	}

	if opts.All {
		if len(opts.Paths) > 0 {
			return fmt.Errorf("--all cannot be combined with explicit paths")
		}
		return wipeCacheDir(dir)
	}
	if len(opts.Paths) == 0 {
		return fmt.Errorf("provide at least one log path, or use --all")
	}
	paths, err := expandPaths(opts.Paths)
	if err != nil {
		return err
	}
	key, err := ingest.CacheKey(paths)
	if err != nil {
		return err
	}
	return removeDBFiles(filepath.Join(dir, key+".db"))
}

// wipeCacheDir removes every .db/.db-wal/.db-shm/.db-journal file directly
// under dir. Subdirectories and other files are left alone so unrelated
// junk (if any) isn't collateral damage.
func wipeCacheDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "caddylogs: cache dir %s does not exist\n", dir)
			return nil
		}
		return err
	}
	var removed int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isSQLiteArtifact(name) {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
		removed++
	}
	fmt.Fprintf(os.Stderr, "caddylogs: removed %d file(s) from %s\n", removed, dir)
	return nil
}

// removeDBFiles removes base and its three SQLite sidecars, tolerating
// missing files. Reports how many were actually removed.
func removeDBFiles(base string) error {
	suffixes := []string{"", "-wal", "-shm", "-journal"}
	var removed int
	for _, suf := range suffixes {
		p := base + suf
		if err := os.Remove(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("remove %s: %w", p, err)
		}
		removed++
	}
	if removed == 0 {
		fmt.Fprintf(os.Stderr, "caddylogs: no cached DB for these paths (expected %s)\n", base)
		return nil
	}
	fmt.Fprintf(os.Stderr, "caddylogs: removed %d file(s) for %s\n", removed, base)
	return nil
}

func isSQLiteArtifact(name string) bool {
	for _, suf := range []string{".db", ".db-wal", ".db-shm", ".db-journal"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}
