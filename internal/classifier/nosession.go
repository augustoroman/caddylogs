package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// NoBrowserSessionName is the stable source identifier.
const NoBrowserSessionName = "no-browser-session"

// NoBrowserSession is the positive-identification inversion of bot detection.
// Rather than enumerating bot patterns (an open-ended, UA-spoofable arms race),
// it keeps as "real" only IPs that demonstrably browsed like a human and tags
// everyone else in the real pool as bot. A human browser leaves a signature
// that is expensive to fake at scale:
//
//   - asset burst: a page (HTML doc) GET immediately followed by several of its
//     static assets (CSS/JS/images) within a few seconds — a real render; or
//   - referer chain: static assets carrying a same-origin referer (the page they
//     were loaded from) — real navigation even when the burst is cache-warmed.
//
// Sessions are grouped by visitor_hash (IP + User-Agent + day), so a browser's
// page and its assets fall in one session. An IP is spared if ANY of its
// sessions shows the signature. This is the catch-all that closes the
// UA-spoofing hole surfaced by browser-UA clients that only ever fetch a single
// resource: a "Mozilla/..." header no longer earns "real" on its own.
//
// Registered LAST so the specific bot classifiers (probe-only, root-only, …)
// claim their IPs with more informative reasons first; this rule mops up the
// residual real pool that never proved itself human.
//
// NOTE: it does not distinguish legitimate non-browser clients (device firmware
// fetchers, API clients, monitors) from abusive ones — both lack a browser
// session, so both land in "bot". "bot" here means "not a human browser", not
// "malicious". Verified crawlers that render pages (e.g. Googlebot) can still
// slip through on the session signature; catching those wants an IP-reputation
// / reverse-DNS layer, which this rule intentionally leaves out.
type NoBrowserSession struct {
	// BurstAssets is how many static assets must follow a page within
	// BurstWindow for the render to count as a browser session.
	BurstAssets int
	// BurstWindow is the span after a page GET in which asset fetches count.
	BurstWindow int64 // nanoseconds
	// RefererChain is how many same-origin-referer asset fetches count as a
	// browser session on their own (handles referer-only, cache-warm visits).
	RefererChain int
}

// NewNoBrowserSession returns the rule with defaults validated against real
// traffic (a ~200–700× separation between human navigation and known bots).
func NewNoBrowserSession() *NoBrowserSession {
	return &NoBrowserSession{
		BurstAssets:  3,
		BurstWindow:  3_000_000_000, // 3s
		RefererChain: 3,
	}
}

func (n *NoBrowserSession) Name() string { return NoBrowserSessionName }

func (n *NoBrowserSession) Description() string {
	return fmt.Sprintf(
		"real-pool IPs that never showed a browser session (a page + %d assets within %ds, or %d same-origin-referer fetches)",
		n.BurstAssets, n.BurstWindow/1_000_000_000, n.RefererChain,
	)
}

// sessEvent is one request within a visitor_hash session.
type sessEvent struct {
	ts       int64
	uri      string
	isStatic bool
	method   string
	status   int
	referer  string
}

// Run returns every candidate IP that lacks a browser session. Candidates are
// the real pool (is_bot=0, is_local=0) plus IPs this rule tagged last run — the
// latter re-included so our own is_bot=1 side effect doesn't drop them from the
// scan and cause every alternate run to untag (see rootonly.go / RunEnv docs).
func (n *NoBrowserSession) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}

	// Served hostnames drive the same-origin referer test.
	served := map[string]bool{}
	hrows, err := env.DB.QueryContext(ctx,
		`SELECT DISTINCT host FROM requests_dynamic UNION SELECT DISTINCT host FROM requests_static`)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var h string
		if err := hrows.Scan(&h); err != nil {
			hrows.Close()
			return nil, err
		}
		served[hostBase(h)] = true
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return nil, err
	}

	// Pull every request for candidate IPs (all rows, regardless of is_bot, so a
	// previously-claimed IP's session can still be reconstructed).
	const q = `
WITH claimed(ip) AS (SELECT value FROM json_each(?)),
cand(ip) AS (
    SELECT ip FROM requests_dynamic WHERE is_local = 0 AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION
    SELECT ip FROM requests_static  WHERE is_local = 0 AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
)
SELECT ip, visitor_hash, ts, uri, is_static, method, status, referer
  FROM requests_dynamic WHERE ip IN (SELECT ip FROM cand)
UNION ALL
SELECT ip, visitor_hash, ts, uri, is_static, method, status, referer
  FROM requests_static  WHERE ip IN (SELECT ip FROM cand)`

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := map[int64][]sessEvent{} // visitor_hash -> events
	vhIP := map[int64]string{}
	hits := map[string]int{}
	for rows.Next() {
		var ip, uri, method, referer string
		var vh, ts int64
		var isStatic, status int
		if err := rows.Scan(&ip, &vh, &ts, &uri, &isStatic, &method, &status, &referer); err != nil {
			return nil, err
		}
		sessions[vh] = append(sessions[vh], sessEvent{ts, uri, isStatic == 1, method, status, referer})
		vhIP[vh] = ip
		hits[ip]++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// An IP is real if any of its sessions shows the browser signature.
	real := map[string]bool{}
	for vh, evs := range sessions {
		if n.hasBrowserSession(evs, served) {
			real[vhIP[vh]] = true
		}
	}

	out := make([]Decision, 0, len(hits))
	for ip, h := range hits {
		if real[ip] {
			continue
		}
		out = append(out, Decision{
			IP:     ip,
			Tag:    classify.ManualTagBot,
			Reason: fmt.Sprintf("%d req(s); no browser session", h),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// hasBrowserSession reports whether a single visitor_hash session looks like a
// human browser render: a same-origin referer chain, or a page followed by an
// asset burst.
func (n *NoBrowserSession) hasBrowserSession(evs []sessEvent, served map[string]bool) bool {
	sort.Slice(evs, func(i, j int) bool { return evs[i].ts < evs[j].ts })
	var staticTs []int64
	chain := 0
	for _, e := range evs {
		if e.isStatic {
			staticTs = append(staticTs, e.ts)
			if refererSameOrigin(e.referer, served) {
				chain++
			}
		}
	}
	if chain >= n.RefererChain {
		return true
	}
	for _, e := range evs {
		if !isPageRequest(e) {
			continue
		}
		lo := sort.Search(len(staticTs), func(i int) bool { return staticTs[i] > e.ts })
		hi := sort.Search(len(staticTs), func(i int) bool { return staticTs[i] > e.ts+n.BurstWindow })
		if hi-lo >= n.BurstAssets {
			return true
		}
	}
	return false
}

// downloadExts are non-page endpoints that a browser navigates to without
// rendering assets — excluded so a lone firmware/media fetch isn't a "page".
var downloadExts = []string{
	".uf2", ".bin", ".hex", ".zip", ".gz", ".tar", ".pdf", ".exe", ".dmg",
	".apk", ".json", ".xml", ".txt", ".csv", ".ico", ".mp4",
}

// isPageRequest reports whether e looks like an HTML document GET (the anchor a
// browser fetches before its assets): dynamic, GET/HEAD, 2xx/3xx, and not a
// download or a file with a non-HTML extension.
func isPageRequest(e sessEvent) bool {
	if e.isStatic || (e.method != "GET" && e.method != "HEAD") || e.status < 200 || e.status >= 400 {
		return false
	}
	u := e.uri
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	u = strings.ToLower(u)
	for _, ext := range downloadExts {
		if strings.HasSuffix(u, ext) {
			return false
		}
	}
	seg := u
	if i := strings.LastIndexByte(strings.TrimRight(seg, "/"), '/'); i >= 0 {
		seg = seg[i+1:]
	}
	return !strings.Contains(seg, ".") || strings.HasSuffix(u, ".html") || strings.HasSuffix(u, ".htm") || strings.HasSuffix(u, "/")
}

// refererSameOrigin reports whether ref points at one of the served hosts.
func refererSameOrigin(ref string, served map[string]bool) bool {
	if ref == "" || ref == "-" {
		return false
	}
	i := strings.Index(ref, "://")
	if i < 0 {
		return false
	}
	host := ref[i+3:]
	if j := strings.IndexAny(host, "/:"); j >= 0 {
		host = host[:j]
	}
	return served[strings.ToLower(host)]
}

// hostBase strips an optional :port from a host value.
func hostBase(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}
