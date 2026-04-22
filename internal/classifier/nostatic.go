package classifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// NoStaticEverName is the stable source identifier.
const NoStaticEverName = "no-static-ever"

// NoStaticEver is the generalization of root-only-burst: an IP that
// made MinHits or more dynamic requests and never requested a static
// asset. The anti-criterion is the same — real browsers fetch CSS /
// JS / images — but the rule doesn't care whether the dynamic hits
// are to "/" or spread across many URIs, so it catches HTML scrapers
// and archivers that root-only would miss.
//
// Overlaps with root-only-burst by design: any root-only IP also
// qualifies for no-static-ever. The runner prevents double-claiming
// (first classifier to register wins), so registering root-only
// first means "most IPs end up with the more specific tag" — and
// no-static-ever picks up the rest.
type NoStaticEver struct {
	// MinHits is the per-IP dynamic-request threshold. Higher than
	// root-only (4 in a day) because the broader pattern needs more
	// signal to rule out honest browsers with locally-cached statics.
	MinHits int
	// IgnoredStatic is the list of URIs whose presence doesn't count
	// as "loaded a static asset" — favicons, robots.txt, social-card
	// previews. Shared default with RootOnly.
	IgnoredStatic []string
}

// NewNoStaticEver returns the rule with default thresholds.
func NewNoStaticEver() *NoStaticEver {
	return &NoStaticEver{
		MinHits:       6,
		IgnoredStatic: append([]string(nil), DefaultIgnoredStatic...),
	}
}

func (n *NoStaticEver) Name() string { return NoStaticEverName }

func (n *NoStaticEver) Description() string {
	return fmt.Sprintf(
		"IPs with %d+ dynamic requests and no static asset requests (excluding favicons/robots.txt)",
		n.MinHits,
	)
}

// Run returns the complete candidate set. See rootonly.go for notes on
// the claimed/json_each pattern and why is_bot=1 rows are re-included
// when we previously tagged them.
func (n *NoStaticEver) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	ignored := n.IgnoredStatic
	if ignored == nil {
		ignored = []string{}
	}
	ignoredJSON, err := json.Marshal(ignored)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
ignored_static(uri) AS (
    SELECT value FROM json_each(?)
),
candidates AS (
    SELECT ip, COUNT(*) AS hits
      FROM requests_dynamic
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
     GROUP BY ip
    HAVING COUNT(*) >= ?
)
SELECT c.ip, c.hits
  FROM candidates c
 WHERE NOT EXISTS (
        SELECT 1 FROM requests_static s
         WHERE s.ip = c.ip
           AND s.is_local = 0
           AND s.uri NOT IN (SELECT uri FROM ignored_static)
         LIMIT 1)
 ORDER BY c.hits DESC`

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON), string(ignoredJSON), n.MinHits)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var ip string
		var hits int
		if err := rows.Scan(&ip, &hits); err != nil {
			return nil, err
		}
		out = append(out, Decision{
			IP:     ip,
			Tag:    classify.ManualTagBot,
			Reason: fmt.Sprintf("%d dynamic hit(s); no static", hits),
		})
	}
	return out, rows.Err()
}
