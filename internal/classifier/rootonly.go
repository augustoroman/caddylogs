package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// RootOnlyName is the stable identifier this rule uses as the tag's
// Source field. Exposed so the runner's diff keys on the same name the
// rule reports from Name().
const RootOnlyName = "root-only-burst"

// RootOnly flags IPs whose hit pattern indicates an automated client.
// Two complementary bot signatures qualify, both conditional on the IP
// never having requested a static asset:
//
//   - Burst: MinDailyRoot or more hits to "/" in a single UTC day.
//     One-shot liveness probes, cheap scrapers, recon scans — they
//     fire a handful of / GETs in minutes and never come back.
//   - Revisit: / hits on MinDistinctDays or more distinct UTC days.
//     Persistent monitoring bots ping / once a day; a real user would
//     either browse deeper or, at the very least, have their browser
//     re-fetch CSS/JS/images on subsequent visits.
//
// In both cases the anti-criterion "never loaded any static asset" is
// the strong signal: a real browser rendering the home page always
// triggers a flurry of CSS/JS/image/font fetches. UA-based bot
// detection frequently misses these patterns because the clients go
// out of their way to spoof Chrome.
//
// The rule operates on the "real" pool (is_bot=0, is_local=0) plus any
// IPs it already claimed (so re-runs don't oscillate — see Claimed in
// RunEnv). Promoted-malicious rows are naturally excluded by living in
// a different table. Manual overrides always win: the runner skips any
// IP the operator has tagged via the UI.
type RootOnly struct {
	// MinDailyRoot is the single-day burst threshold. The original spec
	// was "more than 3", so the default is 4.
	MinDailyRoot int
	// MinDistinctDays is the multi-day revisit threshold. Two days of
	// root-only activity is already enough to rule out a one-off visit.
	MinDistinctDays int
}

// NewRootOnly returns the rule with default thresholds.
func NewRootOnly() *RootOnly {
	return &RootOnly{MinDailyRoot: 4, MinDistinctDays: 2}
}

func (r *RootOnly) Name() string { return RootOnlyName }

func (r *RootOnly) Description() string {
	return fmt.Sprintf(
		"IPs with %d+ hits to '/' in a UTC day OR / hits across %d+ distinct UTC days, and no static asset requests",
		r.MinDailyRoot, r.MinDistinctDays,
	)
}

// Run resolves candidates in three index-friendly passes:
//
//  1. daily groups (ip, utc-day) root hits in the dynamic table. IPs
//     already claimed by this classifier are included even if their
//     rows now carry is_bot=1 (set by a prior ApplyManualTag) —
//     otherwise every re-run would untag them and the next run would
//     re-add them, an infinite oscillation.
//  2. ip_stats collapses daily into per-IP (total, distinct_days,
//     max_daily) triples and applies the HAVING: burst OR multi-day
//     revisit.
//  3. The outer SELECT keeps only IPs with (a) zero non-root hits in
//     requests_dynamic and (b) zero hits in requests_static.
//
// The NOT EXISTS form short-circuits on the first hit per IP, so the
// cost is bounded by |candidate_ips| index lookups per clause rather
// than a full scan of the hot tables.
func (r *RootOnly) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	const nsPerDay = int64(24 * time.Hour)
	// json_each on an empty array returns zero rows, so a classifier
	// that has never tagged anything naturally degrades to the
	// is_bot=0 path.
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
daily AS (
    SELECT ip,
           ts / ?           AS day_bucket,
           COUNT(*)         AS hits
      FROM requests_dynamic
     WHERE is_local = 0 AND uri = '/'
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
     GROUP BY ip, day_bucket
),
ip_stats AS (
    SELECT ip,
           SUM(hits)  AS total_hits,
           COUNT(*)   AS distinct_days,
           MAX(hits)  AS max_daily
      FROM daily
     GROUP BY ip
    HAVING max_daily     >= ?
        OR distinct_days >= ?
)
SELECT s.ip, s.total_hits, s.distinct_days, s.max_daily
  FROM ip_stats s
 WHERE NOT EXISTS (
        SELECT 1 FROM requests_dynamic d
         WHERE d.ip = s.ip
           AND d.is_local = 0
           AND d.uri <> '/'
         LIMIT 1)
   AND NOT EXISTS (
        SELECT 1 FROM requests_static x
         WHERE x.ip = s.ip
           AND x.is_local = 0
         LIMIT 1)
 ORDER BY s.distinct_days DESC, s.max_daily DESC`

	rows, err := env.DB.QueryContext(ctx, q,
		string(claimedJSON), nsPerDay, r.MinDailyRoot, r.MinDistinctDays,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var ip string
		var totalHits, distinctDays, maxDaily int
		if err := rows.Scan(&ip, &totalHits, &distinctDays, &maxDaily); err != nil {
			return nil, err
		}
		out = append(out, Decision{
			IP:     ip,
			Tag:    classify.ManualTagBot,
			Reason: rootOnlyReason(totalHits, distinctDays, maxDaily),
		})
	}
	return out, rows.Err()
}

// rootOnlyReason picks a human-readable explanation that highlights
// whichever signature fired most strongly. The UI surfaces this as the
// source-cell tooltip in the Manual IP tags panel.
func rootOnlyReason(total, days, maxDaily int) string {
	if days >= 2 {
		return fmt.Sprintf("%d / hit(s) across %d UTC day(s); no static", total, days)
	}
	return fmt.Sprintf("%d / hit(s) in a single UTC day; no static", maxDaily)
}
