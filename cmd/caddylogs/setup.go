package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/ingest"
	"github.com/augustoroman/caddylogs/internal/progress"
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
		if cls.Attacks != nil {
			if err := reseedAttackersFromStore(ctx, store, cls); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "caddylogs: ingesting %d file(s)...\n", len(paths))
	prog := progress.Throttle(5*time.Second, cliProgress)

	start := time.Now()
	n, err := ingest.BulkFromFiles(ctx, store, paths, ingest.BulkOpts{
		Progress: prog,
		// Print one line per file as soon as ingest touches it. Bypasses
		// the throttle so short files don't get swallowed by the 5s
		// window and the operator has real-time visibility into which
		// file is currently being processed.
		OnFile: func(path string, index, ofN int, totalSoFar int64) {
			// Break from any in-place cliProgress line (which uses \r
			// to overwrite itself) before printing a sticky line per
			// file. On the first file there's nothing to break from,
			// so skip the leading newline to avoid a blank line.
			prefix := "\n"
			if index == 1 {
				prefix = ""
			}
			fmt.Fprintf(os.Stderr, "%scaddylogs: [%d/%d] %s (running total: %s events)\n",
				prefix, index, ofN, path, commaInt(totalSoFar))
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "caddylogs: ingested %s events in %s\n",
		commaInt(n), time.Since(start).Round(100*time.Millisecond))

	if !c.NoAttackDetection {
		start := time.Now()
		ips, rows, err := ingest.FinalizeAttacks(ctx, store, cls, attackThresholds(c), prog)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "caddylogs: flagged %d attacker IPs, relocated %s rows in %s\n",
			ips, commaInt(rows), time.Since(start).Round(100*time.Millisecond))
	}
	start = time.Now()
	if err := store.MarkIngestComplete(ctx, prog); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "caddylogs: indexes built in %s\n", time.Since(start).Round(100*time.Millisecond))
	return nil
}

// cliProgress is the base (unthrottled) progress printer used by the CLI.
// It writes a single line per phase+tick to stderr with a carriage return
// so the line refreshes in-place when running in a terminal.
func cliProgress(phase, detail string, done, total int64) {
	var line string
	switch {
	case total > 0 && done >= 0:
		if done > total {
			done = total
		}
		pct := float64(done) / float64(total) * 100
		line = fmt.Sprintf("[%s] %s %s/%s (%.0f%%)",
			phase, detail, commaInt(done), commaInt(total), pct)
	case done >= 0 && total <= 0:
		line = fmt.Sprintf("[%s] %s %s", phase, detail, commaInt(done))
	default:
		line = fmt.Sprintf("[%s] %s", phase, detail)
	}
	// Pad + CR so the next update overwrites this one cleanly.
	fmt.Fprintf(os.Stderr, "\r%-120s", line)
	// If this is a terminal phase boundary (total and done equal and > 0),
	// drop to a new line so the next phase starts on a fresh row.
	if total > 0 && done >= total {
		fmt.Fprintln(os.Stderr)
	}
}

// commaInt formats an int64 with thousand separators.
func commaInt(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	var out []byte
	pre := len(s) % 3
	if pre > 0 {
		out = append(out, s[:pre]...)
		if len(s) > pre {
			out = append(out, ',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		out = append(out, s[i:i+3]...)
		if i+3 < len(s) {
			out = append(out, ',')
		}
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// reseedAttackersFromStore reads the distinct (ip, malicious_reason) pairs
// out of the cached malicious table and pushes them into the classifier so
// the in-memory flagged-IP set is consistent with what's on disk.
func reseedAttackersFromStore(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier) error {
	return store.WithIPs(ctx, func(ip, reason string) {
		cls.Attacks.FlagIP(ip, reason)
	})
}

// resolveTagsFile returns the path to the persistent tags JSON file. An
// empty override yields ~/.config/caddylogs/tags.json (OS-appropriate
// location via os.UserConfigDir). Lives in the config dir rather than the
// cache dir because tags are user-curated data and must survive
// `clear-cache` and cache-key invalidation caused by a growing live log.
func resolveTagsFile(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "caddylogs", "tags.json"), nil
}

// loadManualTags wires a persistent ManualTagSet into the classifier. On
// first run, when the JSON file is empty but the cached DB still holds
// tags from the old in-DB scheme, we migrate them to the external file
// so the next cache-key invalidation doesn't lose them.
//
// Runs BEFORE bulk ingest so Classify honors tags during initial
// classification and rows land in the right table from the start.
func loadManualTags(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier, c commonFlags) error {
	path, err := resolveTagsFile(c.TagsFile)
	if err != nil {
		return err
	}
	set, err := classify.LoadManualTagSet(path)
	if err != nil {
		return err
	}
	cls.ManualTags = set
	if set.Count() == 0 {
		var migrated int
		err := store.WithManualTags(ctx, func(ip string, tag classify.ManualTag, at int64) {
			set.PutAt(ip, tag, at, classify.SourceManual, "")
			migrated++
		})
		if err != nil {
			return err
		}
		if migrated > 0 {
			if err := set.Save(); err != nil {
				return fmt.Errorf("save migrated tags: %w", err)
			}
			fmt.Fprintf(os.Stderr, "caddylogs: migrated %d manual tag(s) to %s\n", migrated, path)
		}
	}
	if set.Count() > 0 {
		fmt.Fprintf(os.Stderr, "caddylogs: loaded %d manual tag(s) from %s\n", set.Count(), path)
	}
	return nil
}

// resolveProbeURIsFile mirrors resolveTagsFile: empty override ⇒
// $XDG_CONFIG_HOME/caddylogs/probe-uris.json.
func resolveProbeURIsFile(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "caddylogs", "probe-uris.json"), nil
}

// buildClassifiers returns the heuristic classifier slice for this
// invocation, with the probe-only-uri rule's URI list overridden by a
// config file when one is present. Missing-at-default-path is silent
// (the user never opted in); any other load error is fatal, including
// a missing file when --probe-uris-file was explicitly passed.
func buildClassifiers(c commonFlags) ([]classifier.Classifier, error) {
	classifiers := classifier.BuiltIn()
	path, err := resolveProbeURIsFile(c.ProbeURIsFile)
	if err != nil {
		return nil, err
	}
	probes, err := classifier.LoadProbeURIs(path)
	if err != nil {
		if c.ProbeURIsFile == "" && errors.Is(err, fs.ErrNotExist) {
			return classifiers, nil
		}
		return nil, fmt.Errorf("probe-uris: %w", err)
	}
	for _, cf := range classifiers {
		if p, ok := cf.(*classifier.ProbeOnlyURI); ok {
			p.Probes = probes
			break
		}
	}
	fmt.Fprintf(os.Stderr, "caddylogs: loaded %d probe URI(s) from %s\n", len(probes), path)
	return classifiers, nil
}

// runBuiltInClassifiers executes each registered heuristic classifier
// and prints a one-line summary per run. Runner.Run is idempotent, so
// a failure in one classifier doesn't abort the batch — we surface the
// error and continue so startup is never blocked by a single broken
// rule.
func runBuiltInClassifiers(ctx context.Context, runner *classifier.Runner, classifiers []classifier.Classifier) error {
	for _, c := range classifiers {
		res, err := runner.Run(ctx, c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "caddylogs: classifier %s failed: %v\n", c.Name(), err)
			continue
		}
		fmt.Fprintf(os.Stderr,
			"caddylogs: classifier %s: +%d / -%d / skipped %d (%dms)\n",
			c.Name(), len(res.Added), len(res.Removed), len(res.Skipped), res.Elapsed,
		)
	}
	return nil
}

// replayManualTags calls Store.ApplyManualTag for every loaded tag. After
// initialIngest this guarantees the DB reflects the current external tag
// state — useful when a cache-key change has rebuilt the DB from logs
// (bulk ingest already classifies via the loaded set, but replay also
// populates the DB's manual_tags table for SQL-level inspection) or when
// the cached DB is from before the tag was added.
func replayManualTags(ctx context.Context, store *sqlitestore.Store, cls *classify.Classifier) error {
	if cls == nil || cls.ManualTags == nil || cls.ManualTags.Count() == 0 {
		return nil
	}
	for _, e := range cls.ManualTags.List() {
		if err := store.ApplyManualTag(ctx, e.IP, e.Tag); err != nil {
			return fmt.Errorf("apply tag %s=%s: %w", e.IP, e.Tag, err)
		}
	}
	return nil
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
