package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/ingest"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// expandPaths runs the user-supplied positional args through filepath.Glob so
// unquoted shell globs that were already expanded by the shell pass through
// unchanged, and quoted globs still get expanded by us.
func expandPaths(args []string) ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, a := range args {
		// Fast path: if the arg exists as a file, no glob needed.
		if fi, err := os.Stat(a); err == nil && !fi.IsDir() {
			if _, ok := seen[a]; !ok {
				out = append(out, a)
				seen[a] = struct{}{}
			}
			continue
		}
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", a, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match %q", a)
		}
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil || fi.IsDir() {
				continue
			}
			if _, ok := seen[m]; !ok {
				out = append(out, m)
				seen[m] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no input files resolved")
	}
	return out, nil
}

// buildClassifier composes a Classifier from the common flags.
func buildClassifier(c commonFlags) (*classify.Classifier, error) {
	opts := classify.Options{
		StaticExtensions: c.StaticExts,
		GeoIPPath:        maybeGeoIP(c.GeoIPPath),
		ExtraBotPatterns: c.BotPatterns,
		AttackPatterns:   c.AttackPatterns,
		AttackListPath:   c.AttackList,
		DisableAttacks:   c.NoAttackDetection,
	}
	cls, err := classify.New(opts)
	if err != nil {
		return nil, err
	}
	if c.BotList != "" {
		extra, err := readPatternFile(c.BotList)
		if err != nil {
			cls.Close()
			return nil, fmt.Errorf("read --bot-list: %w", err)
		}
		// Replace rather than append so users can opt out of the embedded list.
		cls.Bots = classify.NewBotDetector(extra, true)
	}
	return cls, nil
}

// attackThresholds extracts the behavioral detection thresholds from the
// flag set.
func attackThresholds(c commonFlags) sqlitestore.AttackerThresholds {
	return sqlitestore.AttackerThresholds{
		MinHits:       c.AttackMinHits,
		MinErrorRate:  c.AttackErrRate,
		MinAttackHits: c.AttackMinURIHits,
	}
}

// maybeGeoIP returns the path only if the file exists; otherwise empty so
// the classifier runs without geo lookups. This makes the "./GeoLite2-City.mmdb"
// default a soft preference rather than a hard requirement.
func maybeGeoIP(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func readPatternFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// openStore opens (or creates) the SQLite DB appropriate for the given
// classifier + input paths + cache options.
func openStore(ctx context.Context, c commonFlags, cls *classify.Classifier, paths []string) (*sqlitestore.Store, bool, error) {
	if c.NoCache {
		store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
		return store, false, err
	}
	dir := c.CacheDir
	if dir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return nil, false, err
		}
		dir = filepath.Join(d, "caddylogs")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	key, err := ingest.CacheKey(paths)
	if err != nil {
		return nil, false, err
	}
	dbPath := filepath.Join(dir, key+".db")
	store, err := sqlitestore.Open(sqlitestore.Options{Path: dbPath, Classifier: cls})
	if err != nil {
		return nil, false, err
	}
	done, err := store.IngestComplete(ctx)
	if err != nil {
		store.Close()
		return nil, false, err
	}
	return store, done, nil
}

// initialIngest runs a progress-reported bulk ingest into store unless it's
// already complete. After ingest it runs the attack-flagging finalization
// pass so the malicious table is ready by the time the dashboard comes up.
func initialIngest(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier, paths []string, cacheHit bool, c commonFlags) error {
	if cacheHit {
		fmt.Fprintln(os.Stderr, "caddylogs: using cached ingest")
		// When a cache is reused, reseed the classifier's flagged-IP set from
		// the stored rows so live tail continues to route those IPs to the
		// malicious table without waiting for another URI match.
		if cls.Attacks != nil {
			if err := reseedAttackersFromStore(ctx, store, cls); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "caddylogs: ingesting %d file(s)...\n", len(paths))
	last := ""
	_, err := ingest.BulkFromFiles(ctx, store, paths, func(total int64, cur string, frac float64) {
		if cur != "" && cur != last {
			fmt.Fprintf(os.Stderr, "  %s\n", filepath.Base(cur))
			last = cur
		}
		fmt.Fprintf(os.Stderr, "\r  %d events", total)
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if !c.NoAttackDetection {
		ips, rows, err := ingest.FinalizeAttacks(ctx, store, cls, attackThresholds(c))
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "caddylogs: flagged %d attacker IPs, relocated %d rows\n", ips, rows)
	}
	return store.MarkIngestComplete(ctx)
}

// reseedAttackersFromStore reads the distinct (ip, malicious_reason) pairs
// out of the cached malicious table and pushes them into the classifier so
// the in-memory flagged-IP set is consistent with what's on disk.
func reseedAttackersFromStore(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier) error {
	return store.WithIPs(ctx, func(ip, reason string) {
		cls.Attacks.FlagIP(ip, reason)
	})
}

// applyDefaultFilters adds is_bot=false / is_local=false exclusions unless
// the user opted in.
func applyDefaultFilters(f *backend.Filter, flags commonFlags) {
	if f.Exclude == nil {
		f.Exclude = map[backend.Dimension][]string{}
	}
	if !flags.IncludeBots {
		f.Exclude[backend.DimIsBot] = append(f.Exclude[backend.DimIsBot], "true")
	}
	if !flags.IncludeLocal {
		f.Exclude[backend.DimIsLocal] = append(f.Exclude[backend.DimIsLocal], "true")
	}
}
