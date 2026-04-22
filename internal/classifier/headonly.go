package classifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// HeadOnlyName is the stable source identifier.
const HeadOnlyName = "head-only"

// HeadOnly flags IPs whose requests are all HEAD. HEAD is almost
// exclusively used by uptime monitors and link checkers; browsers
// essentially never send HEAD. Cheap and high-signal when it fires.
type HeadOnly struct {
	// MinHits is the floor that separates a drive-by HEAD from a
	// bot that's persistently probing.
	MinHits int
}

// NewHeadOnly returns the rule with default thresholds.
func NewHeadOnly() *HeadOnly {
	return &HeadOnly{MinHits: 4}
}

func (h *HeadOnly) Name() string { return HeadOnlyName }

func (h *HeadOnly) Description() string {
	return fmt.Sprintf("IPs with %d+ requests, all HEAD (no GET/POST/etc.)", h.MinHits)
}

// Run unions dynamic+static to catch a HEAD-only bot that happens to
// probe /favicon.ico too. A single non-HEAD anywhere disqualifies.
func (h *HeadOnly) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
all_reqs AS (
    SELECT ip, method FROM requests_dynamic
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, method FROM requests_static
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
)
SELECT ip, COUNT(*) AS hits
  FROM all_reqs
 GROUP BY ip
HAVING COUNT(*) >= ?
   AND SUM(CASE WHEN method <> 'HEAD' THEN 1 ELSE 0 END) = 0
 ORDER BY hits DESC`

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON), h.MinHits)
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
			Reason: fmt.Sprintf("%d HEAD requests; no other methods", hits),
		})
	}
	return out, rows.Err()
}
