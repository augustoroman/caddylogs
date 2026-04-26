package classifier

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
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
// source of truth for the site's canary set.
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
// "malicious"; anything else is a hard error. If the file is missing,
// the error wraps os.ErrNotExist so callers can distinguish "no
// override, use defaults" from "override was requested but broken".
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

// EnsureIndexes creates partial indexes on (ip, uri) restricted to the
// current probe URI list. The indexes are tiny — one row per probe-URI
// hit across all of history — so they let the candidate-finding step
// of Run become an index seek instead of a full table scan, which is
// the entire point of this rule running in O(probes) rather than
// O(rows).
//
// SQLite's planner only uses a partial index when the query's WHERE
// predicate matches the index's WHERE predicate literally, so the
// probe URI list is embedded as constants in both the DDL and the SQL
// in Run rather than passing it via a bind parameter or json_each.
//
// Idempotent: a meta-table signature lets repeat calls short-circuit
// when the list hasn't changed, and forces a drop + rebuild when the
// operator's probe-uris.json changes between runs.
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
	inList := probeURIInList(p.Probes)
	stmts := []string{
		`DROP INDEX IF EXISTS idx_dyn_probe_uri`,
		`DROP INDEX IF EXISTS idx_stat_probe_uri`,
		`DROP INDEX IF EXISTS idx_mal_probe_uri`,
		fmt.Sprintf(`CREATE INDEX idx_dyn_probe_uri  ON requests_dynamic  (ip, uri) WHERE uri IN (%s) AND is_local = 0`, inList),
		fmt.Sprintf(`CREATE INDEX idx_stat_probe_uri ON requests_static   (ip, uri) WHERE uri IN (%s) AND is_local = 0`, inList),
		fmt.Sprintf(`CREATE INDEX idx_mal_probe_uri  ON requests_malicious(ip, uri) WHERE uri IN (%s)`, inList),
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

// probeIndexSignature is a stable fingerprint of the probe URI list
// used to decide whether the on-disk indexes match the in-memory
// configuration. Sorting is what makes it stable: callers may load
// the URIs in any order.
func probeIndexSignature(probes []ProbeURI) string {
	uris := make([]string, len(probes))
	for i, p := range probes {
		uris[i] = p.URI
	}
	sort.Strings(uris)
	return strings.Join(uris, "\n")
}

// probeURIInList renders the probe URIs as a comma-separated list of
// SQL string literals, ready to drop into "uri IN (...)". Used both
// for the partial index DDL and the Run query so SQLite recognizes
// the predicates as equivalent and uses the index.
func probeURIInList(probes []ProbeURI) string {
	uris := make([]string, len(probes))
	for i, p := range probes {
		uris[i] = "'" + strings.ReplaceAll(p.URI, "'", "''") + "'"
	}
	return strings.Join(uris, ", ")
}

// Run returns the candidate set. An IP qualifies if it has at least one
// request in the probe list and zero requests outside of it, across
// requests_dynamic, requests_static, and (for IPs we've previously
// claimed) requests_malicious — since a malicious tag physically moves
// rows into that table, skipping it on re-runs would make the history
// vanish and the IP oscillate out of the candidate set.
//
// Strategy: the partial indexes built by EnsureIndexes turn the first
// step (find IPs that hit any probe URI) into an index seek over a
// tiny set. Each candidate is then disqualified by a single early-exit
// NOT EXISTS scan against the regular idx_*_ip indexes — most
// candidates have a non-probe row and bail out on the first match.
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
	tagByURI := make(map[string]classify.ManualTag, len(p.Probes))
	for _, e := range p.Probes {
		tagByURI[e.URI] = e.Tag
	}
	inList := probeURIInList(p.Probes)

	q := fmt.Sprintf(`
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
probe_hits(ip, uri) AS (
    SELECT ip, uri FROM requests_dynamic
     WHERE uri IN (%[1]s) AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, uri FROM requests_static
     WHERE uri IN (%[1]s) AND is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, uri FROM requests_malicious
     WHERE uri IN (%[1]s)
       AND ip IN (SELECT ip FROM claimed)
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
           AND uri NOT IN (%[1]s)
         LIMIT 1
     )
       AND NOT EXISTS (
        SELECT 1 FROM requests_static
         WHERE ip = c.ip AND is_local = 0
           AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
           AND uri NOT IN (%[1]s)
         LIMIT 1
     )
       AND NOT EXISTS (
        SELECT 1 FROM requests_malicious
         WHERE ip = c.ip AND ip IN (SELECT ip FROM claimed)
           AND uri NOT IN (%[1]s)
         LIMIT 1
     )
)
SELECT ph.ip,
       COUNT(*) AS probe_hits,
       GROUP_CONCAT(DISTINCT ph.uri) AS matched
  FROM probe_hits ph
  JOIN qualifying q ON q.ip = ph.ip
 GROUP BY ph.ip
 ORDER BY probe_hits DESC`, inList)

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Malicious outranks bot when the same IP matches multiple probe
	// URIs with different tags. No rank > 0 means "unknown tag," which
	// can't happen given the map is populated from the same list the
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
			if t, ok := tagByURI[u]; ok && rank[t] > rank[tag] {
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
