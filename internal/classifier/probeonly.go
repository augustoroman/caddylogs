package classifier

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// ProbeOnlyURIName is the stable identifier this rule uses as the tag's
// Source field.
const ProbeOnlyURIName = "probe-only-uri"

// probeIndexSignatureKey is the meta-table key recording the probe URI
// list the partial indexes were last built for. EnsureIndexes uses it
// to short-circuit when nothing has changed and to detect when a
// config change requires a drop + rebuild.
const probeIndexSignatureKey = "probe_only_uri_index_signature"

// ProbeURI pairs a probe URL with the tag to apply to IPs whose entire
// non-local request history sits inside the probe set.
//
// URI may be either an exact path ("/cdn-cgi/trace") or a SQLite GLOB
// pattern ("/dl/*.uf2") — auto-detected by the presence of '*', '?',
// or '['. Glob entries get their own partial index so the candidate
// scan stays index-driven.
type ProbeURI struct {
	URI string
	Tag classify.ManualTag
}

// DefaultProbeURIs ships with the binary. Cloudflare's
// /.well-known/traffic-advice is a published crawler-disclosure
// mechanism — IPs probing it are almost all legitimate scanners, so
// the tag is "bot", not "malicious". /ip and /cdn-cgi/trace are
// classic proxy / SSRF probes (attackers fingerprinting outbound
// egress through a misconfigured proxy); those lean malicious.
//
// Operators override this list at startup with --probe-uris-file
// (see LoadProbeURIs); the file's contents replace the defaults
// wholesale rather than merging, so the author has one authoritative
// source of truth for the site's canary set. Override entries may use
// glob patterns (e.g. "/dl/*.uf2") in addition to exact paths.
var DefaultProbeURIs = []ProbeURI{
	{URI: "/.well-known/traffic-advice", Tag: classify.ManualTagBot},
	{URI: "/ip", Tag: classify.ManualTagMalicious},
	{URI: "/cdn-cgi/trace", Tag: classify.ManualTagMalicious},
	{URI: "/.vscode/sftp.json", Tag: classify.ManualTagMalicious},
	{URI: "/sftp-config.json", Tag: classify.ManualTagMalicious},
	{URI: "/sitemap.xml", Tag: classify.ManualTagBot},
	{URI: "/vendor/phpunit/phpunit/phpunit.xsd", Tag: classify.ManualTagMalicious},
	{URI: "/my-account/", Tag: classify.ManualTagMalicious},
	{URI: "/", Tag: classify.ManualTagBot},
}

// ProbeOnlyURI flags IPs whose entire non-local request history falls
// inside the probe-URI list. Unlike the threshold-based rules, a single
// request is enough — the signal is "this IP did exactly one thing and
// that thing is a well-known canary probe". Real users touching /ip
// by accident survive because their browsers always fetch at least
// one other URI (the home page, a favicon, etc.).
//
// When an IP hits probe URIs carrying different tags, the most severe
// wins: malicious > bot. So an IP that hit only /.well-known/traffic-
// advice is a bot; an IP that hit /ip (alone or alongside traffic-
// advice) is malicious.
type ProbeOnlyURI struct {
	Probes []ProbeURI
}

// NewProbeOnlyURI returns the rule with the default probe URI list.
func NewProbeOnlyURI() *ProbeOnlyURI {
	return &ProbeOnlyURI{Probes: append([]ProbeURI(nil), DefaultProbeURIs...)}
}

// LoadProbeURIs reads a probe-URI list from path. The JSON shape is an
// array of {"uri": ..., "tag": ...} objects where tag is "bot" or
// "malicious"; anything else is a hard error. URI strings may use
// SQLite GLOB metacharacters ('*', '?', '[...]') for pattern matches.
// If the file is missing, the error wraps os.ErrNotExist so callers can
// distinguish "no override, use defaults" from "override was requested
// but broken".
//
// A present-but-empty list is rejected: the probable intent is "don't
// run this classifier" and the cleaner way to express that is to omit
// it from BuiltIn (or pass --no-classifiers). Silently accepting an
// empty list would hide a config bug.
func LoadProbeURIs(path string) ([]ProbeURI, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var raw []struct {
		URI string `json:"uri"`
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: probe list is empty", path)
	}
	out := make([]ProbeURI, 0, len(raw))
	for i, r := range raw {
		if r.URI == "" {
			return nil, fmt.Errorf("%s: entry %d: uri is empty", path, i)
		}
		tag := classify.ManualTag(r.Tag)
		if tag != classify.ManualTagBot && tag != classify.ManualTagMalicious {
			return nil, fmt.Errorf("%s: entry %d (%s): tag %q must be \"bot\" or \"malicious\"",
				path, i, r.URI, r.Tag)
		}
		out = append(out, ProbeURI{URI: r.URI, Tag: tag})
	}
	return out, nil
}

func (p *ProbeOnlyURI) Name() string { return ProbeOnlyURIName }

func (p *ProbeOnlyURI) Description() string {
	uris := make([]string, len(p.Probes))
	for i, e := range p.Probes {
		uris[i] = e.URI
	}
	return fmt.Sprintf(
		"IPs whose entire history is only request(s) to a known probe URI (%s)",
		strings.Join(uris, ", "),
	)
}

// hasGlobMeta reports whether s contains a SQLite GLOB metacharacter
// ('*', '?', '['). Used to bucket a probe entry as exact (fast IN-list
// path) vs. glob (one partial index per pattern).
func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// probeBuckets partitions a probe set into exact and glob entries, both
// sorted by URI so the SQL emitted from them and the index names derived
// from them are deterministic across runs.
type probeBuckets struct {
	exacts []ProbeURI
	globs  []ProbeURI
}

func splitProbes(probes []ProbeURI) probeBuckets {
	var b probeBuckets
	for _, e := range probes {
		if hasGlobMeta(e.URI) {
			b.globs = append(b.globs, e)
		} else {
			b.exacts = append(b.exacts, e)
		}
	}
	sort.Slice(b.exacts, func(i, j int) bool { return b.exacts[i].URI < b.exacts[j].URI })
	sort.Slice(b.globs, func(i, j int) bool { return b.globs[i].URI < b.globs[j].URI })
	return b
}

// sqlString returns a SQLite single-quoted string literal for s.
func sqlString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// exactInList renders exact probes as a comma-separated list of SQL
// string literals, ready to drop into "uri IN (...)".
func exactInList(exacts []ProbeURI) string {
	parts := make([]string, len(exacts))
	for i, e := range exacts {
		parts[i] = sqlString(e.URI)
	}
	return strings.Join(parts, ", ")
}

// EnsureIndexes creates partial indexes restricted to the current probe
// set so the candidate-finding step of Run becomes an index seek over a
// tiny set instead of a full scan. Two flavors:
//
//   - One IN-list index per request table covering all exact probes
//     (idx_<tbl>_probe_uri).
//   - One per-pattern index per request table for each glob probe
//     (idx_<tbl>_probe_glob_<i>, where i is the position in the
//     sorted glob list).
//
// SQLite's planner only uses a partial index when the query's WHERE
// predicate matches the index's WHERE predicate literally, so the probe
// URI literals are embedded as constants in both the DDL and the SQL
// rather than passing them via bind parameters.
//
// Idempotent: a meta-table signature lets repeat calls short-circuit
// when the list hasn't changed, and forces a drop + rebuild when the
// operator's probe-uris.json changes between runs. Stale indexes from
// a previous probe set are dropped via a sqlite_master sweep so leftover
// per-glob indexes don't accumulate.
func (p *ProbeOnlyURI) EnsureIndexes(ctx context.Context, db *sql.DB) error {
	if len(p.Probes) == 0 {
		return nil
	}
	sig := probeIndexSignature(p.Probes)
	var current string
	err := db.QueryRowContext(ctx,
		`SELECT v FROM meta WHERE k = ?`, probeIndexSignatureKey).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if current == sig {
		return nil
	}

	stale, err := listProbeIndexes(ctx, db)
	if err != nil {
		return fmt.Errorf("probe-only-uri index: %w", err)
	}
	for _, name := range stale {
		if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS `+name); err != nil {
			return fmt.Errorf("probe-only-uri drop %s: %w", name, err)
		}
	}

	buckets := splitProbes(p.Probes)
	var stmts []string
	if len(buckets.exacts) > 0 {
		inList := exactInList(buckets.exacts)
		stmts = append(stmts,
			fmt.Sprintf(`CREATE INDEX idx_dyn_probe_uri  ON requests_dynamic  (ip, uri) WHERE uri IN (%s) AND is_local = 0`, inList),
			fmt.Sprintf(`CREATE INDEX idx_stat_probe_uri ON requests_static   (ip, uri) WHERE uri IN (%s) AND is_local = 0`, inList),
			fmt.Sprintf(`CREATE INDEX idx_mal_probe_uri  ON requests_malicious(ip, uri) WHERE uri IN (%s)`, inList),
		)
	}
	for i, g := range buckets.globs {
		pat := sqlString(g.URI)
		stmts = append(stmts,
			fmt.Sprintf(`CREATE INDEX idx_dyn_probe_glob_%d  ON requests_dynamic  (ip, uri) WHERE uri GLOB %s AND is_local = 0`, i, pat),
			fmt.Sprintf(`CREATE INDEX idx_stat_probe_glob_%d ON requests_static   (ip, uri) WHERE uri GLOB %s AND is_local = 0`, i, pat),
			fmt.Sprintf(`CREATE INDEX idx_mal_probe_glob_%d  ON requests_malicious(ip, uri) WHERE uri GLOB %s`, i, pat),
		)
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("probe-only-uri index: %w", err)
		}
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO meta(k, v) VALUES(?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		probeIndexSignatureKey, sig)
	return err
}

// listProbeIndexes enumerates every index this rule has ever created
// (exact-list or per-glob) so a config change can drop them all before
// rebuilding the fresh set. Without this sweep, glob indexes from a
// removed pattern would linger.
func listProbeIndexes(ctx context.Context, db *sql.DB) ([]string, error) {
	const q = `
SELECT name FROM sqlite_master
 WHERE type = 'index'
   AND (name LIKE 'idx_dyn_probe_%'
     OR name LIKE 'idx_stat_probe_%'
     OR name LIKE 'idx_mal_probe_%')`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// probeIndexSignature is a stable fingerprint of the probe URI list
// used to decide whether the on-disk indexes match the in-memory
// configuration. Sorting is what makes it stable: callers may load
// the URIs in any order. Glob and exact entries share the same
// keyspace — switching "/foo" to "/foo*" is a config change that
// requires a rebuild, and the signature reflects that.
func probeIndexSignature(probes []ProbeURI) string {
	uris := make([]string, len(probes))
	for i, p := range probes {
		uris[i] = p.URI
	}
	sort.Strings(uris)
	return strings.Join(uris, "\n")
}

// Run returns the candidate set. An IP qualifies if it has at least one
// request matching the probe set (exact or glob) and zero requests
// outside of it, across requests_dynamic, requests_static, and (for IPs
// we've previously claimed) requests_malicious — since a malicious tag
// physically moves rows into that table, skipping it on re-runs would
// make the history vanish and the IP oscillate out of the candidate set.
//
// Strategy: the partial indexes built by EnsureIndexes turn the first
// step (find IPs that hit any probe URI) into an index seek over a
// tiny set. The candidate CTE is a UNION ALL with one branch per
// (table, probe-bucket) — exact probes share an IN-list branch per
// table, each glob gets its own. Each candidate is then disqualified
// by a single early-exit NOT EXISTS scan against the regular idx_*_ip
// indexes — most candidates have a non-probe row and bail out on the
// first match.
func (p *ProbeOnlyURI) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	if len(p.Probes) == 0 {
		return nil, nil
	}
	if err := p.EnsureIndexes(ctx, env.DB); err != nil {
		return nil, err
	}
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	picker := newTagPicker(p.Probes)
	buckets := splitProbes(p.Probes)

	candidateCTE := buildCandidateCTE(buckets)
	nonProbeFilter := buildNonProbeFilter(buckets)

	q := fmt.Sprintf(`
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
probe_hits(ip, uri) AS (
    %[1]s
),
candidates(ip) AS (
    SELECT DISTINCT ip FROM probe_hits
),
qualifying(ip) AS (
    SELECT c.ip FROM candidates c
     WHERE NOT EXISTS (
        SELECT 1 FROM requests_dynamic
         WHERE ip = c.ip AND is_local = 0
           AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
           AND %[2]s
         LIMIT 1
     )
       AND NOT EXISTS (
        SELECT 1 FROM requests_static
         WHERE ip = c.ip AND is_local = 0
           AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
           AND %[2]s
         LIMIT 1
     )
       AND NOT EXISTS (
        SELECT 1 FROM requests_malicious
         WHERE ip = c.ip AND ip IN (SELECT ip FROM claimed)
           AND %[2]s
         LIMIT 1
     )
)
SELECT ph.ip,
       COUNT(*) AS probe_hits,
       GROUP_CONCAT(DISTINCT ph.uri) AS matched
  FROM probe_hits ph
  JOIN qualifying q ON q.ip = ph.ip
 GROUP BY ph.ip
 ORDER BY probe_hits DESC`, candidateCTE, nonProbeFilter)

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Malicious outranks bot when the same IP matches multiple probe
	// URIs with different tags. No rank > 0 means "unknown tag," which
	// can't happen given the picker is populated from the same list the
	// SQL filters on, but falling back to bot is the safe default.
	rank := map[classify.ManualTag]int{
		classify.ManualTagBot:       1,
		classify.ManualTagMalicious: 2,
	}

	var out []Decision
	for rows.Next() {
		var ip, matched string
		var probeHits int
		if err := rows.Scan(&ip, &probeHits, &matched); err != nil {
			return nil, err
		}
		hitURIs := strings.Split(matched, ",")
		sort.Strings(hitURIs)
		tag := classify.ManualTagBot
		for _, u := range hitURIs {
			if t, ok := picker.tagFor(u); ok && rank[t] > rank[tag] {
				tag = t
			}
		}
		out = append(out, Decision{
			IP:     ip,
			Tag:    tag,
			Reason: fmt.Sprintf("%d probe hit(s): %s", probeHits, strings.Join(hitURIs, ", ")),
		})
	}
	return out, rows.Err()
}

// buildCandidateCTE emits the UNION ALL of probe-hit branches across
// the three request tables. Each branch is shaped to use exactly one
// of the partial indexes built by EnsureIndexes. The branch order
// follows splitProbes' sort so the SQL text is deterministic across
// runs.
func buildCandidateCTE(b probeBuckets) string {
	var branches []string
	if len(b.exacts) > 0 {
		inList := exactInList(b.exacts)
		branches = append(branches,
			fmt.Sprintf(`SELECT ip, uri FROM requests_dynamic
     WHERE uri IN (%s) AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))`, inList),
			fmt.Sprintf(`SELECT ip, uri FROM requests_static
     WHERE uri IN (%s) AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))`, inList),
			fmt.Sprintf(`SELECT ip, uri FROM requests_malicious
     WHERE uri IN (%s)
       AND ip IN (SELECT ip FROM claimed)`, inList),
		)
	}
	for _, g := range b.globs {
		pat := sqlString(g.URI)
		branches = append(branches,
			fmt.Sprintf(`SELECT ip, uri FROM requests_dynamic
     WHERE uri GLOB %s AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))`, pat),
			fmt.Sprintf(`SELECT ip, uri FROM requests_static
     WHERE uri GLOB %s AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))`, pat),
			fmt.Sprintf(`SELECT ip, uri FROM requests_malicious
     WHERE uri GLOB %s
       AND ip IN (SELECT ip FROM claimed)`, pat),
		)
	}
	return strings.Join(branches, "\n    UNION ALL\n    ")
}

// buildNonProbeFilter emits the predicate that's true when a row's URI
// does NOT match any probe in the set — used inside the NOT EXISTS
// subqueries that disqualify IPs whose history extends beyond the
// probe set. With only exacts it collapses to "uri NOT IN (...)";
// adding globs ANDs in a "NOT (uri GLOB ...)" per pattern.
func buildNonProbeFilter(b probeBuckets) string {
	var parts []string
	if len(b.exacts) > 0 {
		parts = append(parts, fmt.Sprintf("uri NOT IN (%s)", exactInList(b.exacts)))
	}
	for _, g := range b.globs {
		parts = append(parts, fmt.Sprintf("NOT (uri GLOB %s)", sqlString(g.URI)))
	}
	return strings.Join(parts, " AND ")
}

// tagPicker resolves a concrete URI back to its probe entry's tag. It
// keeps exact lookups in a map (O(1)) and walks the glob list in order
// (O(globs)) only for non-exact hits.
//
// The Go matcher uses path.Match, which differs from SQLite GLOB in
// that '*' does not cross '/' separators. For typical URI globs this
// is the more intuitive semantic; if the SQL matched a row that Go
// rejects (e.g. SQLite's '/dl/*.uf2' matched '/dl/sub/x.uf2'), the
// tag falls through to the default bot — a soft-fail, not a wrong
// classification.
type tagPicker struct {
	exactByURI map[string]classify.ManualTag
	globs      []ProbeURI
}

func newTagPicker(probes []ProbeURI) *tagPicker {
	tp := &tagPicker{exactByURI: make(map[string]classify.ManualTag, len(probes))}
	for _, e := range probes {
		if hasGlobMeta(e.URI) {
			tp.globs = append(tp.globs, e)
		} else {
			tp.exactByURI[e.URI] = e.Tag
		}
	}
	return tp
}

func (tp *tagPicker) tagFor(uri string) (classify.ManualTag, bool) {
	if t, ok := tp.exactByURI[uri]; ok {
		return t, true
	}
	for _, g := range tp.globs {
		if ok, _ := path.Match(g.URI, uri); ok {
			return g.Tag, true
		}
	}
	return "", false
}
