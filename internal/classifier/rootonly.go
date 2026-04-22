package classifier

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// RootOnlyName is the stable identifier this rule uses as the tag's
// Source field. Exposed so the runner's diff keys on the same name the
// rule reports from Name().
const RootOnlyName = "root-only-burst"

// RootOnly flags IPs that made MinDailyRoot or more requests to "/" in
// some UTC day and never requested a static asset. The hypothesis: a
// real browser loading the home page always follows up with a flurry
// of CSS / JS / image / font fetches, so an IP that only ever GETs /
// (and does so repeatedly) is almost certainly automated — a liveness
// probe, a cheap content scraper, or a reconnaissance scan. UA-based
// bot detection frequently misses these because they go out of their
// way to spoof Chrome.
//
// The rule deliberately operates only on the "real" pool
// (is_bot=0, is_local=0 in the dynamic+static tables); promoted-
// malicious rows are excluded by virtue of living in a different table.
// Manual overrides win: the runner skips any IP that the operator has
// already tagged via the UI.
type RootOnly struct {
	// MinDailyRoot is the per-day threshold. The user's original spec
	// was "more than 3", so the default is 4.
	MinDailyRoot int
}

// NewRootOnly returns the rule with default thresholds.
func NewRootOnly() *RootOnly {
	return &RootOnly{MinDailyRoot: 4}
}

func (r *RootOnly) Name() string { return RootOnlyName }

func (r *RootOnly) Description() string {
	return fmt.Sprintf(
		"IPs with %d+ hits to '/' in a UTC day and no static asset requests",
		r.MinDailyRoot,
	)
}

// Run resolves candidates in two index-friendly passes joined by the
// ip index the schema already builds:
//
//  1. root_day_counts aggregates (ip, utc-day) root hits in the dynamic
//     table and keeps only buckets at/above the threshold.
//  2. The outer SELECT keeps only the IPs with (a) zero non-root real
//     hits in requests_dynamic and (b) zero real hits in
//     requests_static.
//
// The NOT EXISTS form short-circuits on the first hit per IP, so the
// cost is bounded by |candidate_ips| index lookups per clause rather
// than a full scan of the hot tables.
func (r *RootOnly) Run(ctx context.Context, db *sql.DB) ([]Decision, error) {
	const nsPerDay = int64(24 * time.Hour)
	const q = `
WITH root_day_counts AS (
    SELECT ip,
           ts / ?           AS day_bucket,
           COUNT(*)         AS hits
      FROM requests_dynamic
     WHERE is_bot = 0 AND is_local = 0 AND uri = '/'
     GROUP BY ip, day_bucket
    HAVING COUNT(*) >= ?
),
candidates AS (
    SELECT ip, MAX(hits) AS max_daily
      FROM root_day_counts
     GROUP BY ip
)
SELECT c.ip, c.max_daily
  FROM candidates c
 WHERE NOT EXISTS (
        SELECT 1 FROM requests_dynamic d
         WHERE d.ip = c.ip
           AND d.is_bot = 0 AND d.is_local = 0
           AND d.uri <> '/'
         LIMIT 1)
   AND NOT EXISTS (
        SELECT 1 FROM requests_static s
         WHERE s.ip = c.ip
           AND s.is_bot = 0 AND s.is_local = 0
         LIMIT 1)
 ORDER BY c.max_daily DESC`

	rows, err := db.QueryContext(ctx, q, nsPerDay, r.MinDailyRoot)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var ip string
		var maxDaily int
		if err := rows.Scan(&ip, &maxDaily); err != nil {
			return nil, err
		}
		out = append(out, Decision{
			IP:     ip,
			Tag:    classify.ManualTagBot,
			Reason: fmt.Sprintf("%d hit(s) to / in a UTC day; no static", maxDaily),
		})
	}
	return out, rows.Err()
}
