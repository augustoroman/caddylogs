package classifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// HTTP10OnlyName is the stable source identifier.
const HTTP10OnlyName = "http10-only"

// HTTP10Only flags IPs that only ever speak HTTP/1.0. Every mainstream
// browser has defaulted to HTTP/2 for years; a pure-HTTP/1.0 client
// is almost always a legacy scraper, an unsophisticated bot, or a
// misconfigured monitoring tool.
type HTTP10Only struct {
	MinHits int
}

// NewHTTP10Only returns the rule with default thresholds.
func NewHTTP10Only() *HTTP10Only {
	return &HTTP10Only{MinHits: 4}
}

func (h *HTTP10Only) Name() string { return HTTP10OnlyName }

func (h *HTTP10Only) Description() string {
	return fmt.Sprintf("IPs with %d+ requests, all HTTP/1.0", h.MinHits)
}

// Run unions dynamic+static. A single non-HTTP/1.0 request
// disqualifies — mixed clients (browsers behind a proxy that
// downgrades some paths) are rare but real, and we don't want to
// flag them.
func (h *HTTP10Only) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
all_reqs AS (
    SELECT ip, proto FROM requests_dynamic
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
    UNION ALL
    SELECT ip, proto FROM requests_static
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
)
SELECT ip, COUNT(*) AS hits
  FROM all_reqs
 GROUP BY ip
HAVING COUNT(*) >= ?
   AND SUM(CASE WHEN proto <> 'HTTP/1.0' THEN 1 ELSE 0 END) = 0
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
			Reason: fmt.Sprintf("%d requests, all HTTP/1.0", hits),
		})
	}
	return out, rows.Err()
}
