package classifier

import (
	"context"
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

// Run returns the candidate set. An IP qualifies if it has at least one
// request in the probe list and zero requests outside of it, across
// requests_dynamic, requests_static, and (for IPs we've previously
// claimed) requests_malicious — since a malicious tag physically moves
// rows into that table, skipping it on re-runs would make the history
// vanish and the IP oscillate out of the candidate set.
func (p *ProbeOnlyURI) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	if len(p.Probes) == 0 {
		return nil, nil
	}
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	uris := make([]string, len(p.Probes))
	tagByURI := make(map[string]classify.ManualTag, len(p.Probes))
	for i, e := range p.Probes {
		uris[i] = e.URI
		tagByURI[e.URI] = e.Tag
	}
	probeJSON, err := json.Marshal(uris)
	if err != nil {
		return nil, err
	}

	// eligible is the per-IP request history we evaluate. A previously-
	// claimed IP may live in any of the three tables depending on the
	// tag we applied last time, so we union all three — but only pull
	// from requests_malicious for IPs in the claimed set, because
	// untagged malicious rows are out of scope for every classifier.
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
probe(uri) AS (
    SELECT value FROM json_each(?)
),
eligible(ip, uri) AS (
    SELECT ip, uri FROM requests_dynamic
     WHERE is_local = 0 AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, uri FROM requests_static
     WHERE is_local = 0 AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, uri FROM requests_malicious
     WHERE ip IN (SELECT ip FROM claimed)
)
SELECT ip,
       SUM(CASE WHEN uri IN (SELECT uri FROM probe) THEN 1 ELSE 0 END) AS probe_hits,
       GROUP_CONCAT(DISTINCT CASE WHEN uri IN (SELECT uri FROM probe) THEN uri END) AS matched
  FROM eligible
 GROUP BY ip
HAVING SUM(CASE WHEN uri NOT IN (SELECT uri FROM probe) THEN 1 ELSE 0 END) = 0
   AND SUM(CASE WHEN uri IN     (SELECT uri FROM probe) THEN 1 ELSE 0 END) >= 1
 ORDER BY probe_hits DESC`

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON), string(probeJSON))
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
