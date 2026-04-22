package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// CadencePollingName is the stable source identifier.
const CadencePollingName = "cadence-polling"

// CadencePolling flags IPs whose request timing is suspiciously
// regular — the fingerprint of a cron job, uptime monitor, or
// status-page scraper. The rule computes the coefficient of variation
// (σ/μ) of inter-request intervals per IP and tags anyone whose CV is
// below the threshold, provided they've made enough requests for the
// statistic to mean anything and their average cadence isn't so tight
// it looks more like a burst than a poll.
//
// The rule deliberately avoids sqrt so it works on SQLite builds
// without the math extension loaded: comparing variance / μ² to
// MaxCV² is equivalent to comparing σ/μ to MaxCV.
//
// Implementation notes:
//   - Uses LAG() (SQLite >= 3.25) to compute per-row interval.
//   - Intervals are scaled to seconds (float) before the variance
//     math to keep double precision safe; raw nanosecond values
//     overflow double precision at the variance step for long
//     intervals.
//   - Runs against the dynamic table only. A static-asset cadence
//     is usually an if-modified-since loop from a real browser
//     cache, not a bot.
type CadencePolling struct {
	// MinIntervals is the minimum number of inter-request intervals
	// required to compute CV. N intervals = N+1 requests. Seven is
	// enough to reject coincidences but low enough that monitoring
	// cadences appear within a day or two.
	MinIntervals int
	// MinMeanSeconds filters out bursts (many requests in a short
	// window). Those should match attack heuristics, not cadence.
	MinMeanSeconds float64
	// MaxCV is the upper bound on σ/μ. Real polling bots typically
	// sit below 0.05; 0.25 leaves room for network jitter while
	// keeping the false-positive rate low on human traffic.
	MaxCV float64
}

// NewCadencePolling returns the rule with default thresholds.
func NewCadencePolling() *CadencePolling {
	return &CadencePolling{
		MinIntervals:   7,
		MinMeanSeconds: 60,
		MaxCV:          0.25,
	}
}

func (c *CadencePolling) Name() string { return CadencePollingName }

func (c *CadencePolling) Description() string {
	return fmt.Sprintf(
		"IPs with %d+ inter-request intervals whose cadence varies by less than %.0f%% (mean interval ≥%.0fs)",
		c.MinIntervals, c.MaxCV*100, c.MinMeanSeconds,
	)
}

// Run returns the complete candidate set.
func (c *CadencePolling) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
),
ordered AS (
    SELECT ip,
           ts,
           LAG(ts) OVER (PARTITION BY ip ORDER BY ts) AS prev_ts
      FROM requests_dynamic
     WHERE is_local = 0
       AND (is_bot = 0 OR ip IN (SELECT ip FROM claimed))
),
intervals AS (
    SELECT ip, (ts - prev_ts) / 1000000000.0 AS iv_seconds
      FROM ordered
     WHERE prev_ts IS NOT NULL
),
stats AS (
    SELECT ip,
           COUNT(*)         AS n,
           AVG(iv_seconds)  AS mean_iv,
           -- variance = E[X²] - (E[X])². Clamp to 0 for the
           -- floating-point edge case where the two terms should be
           -- equal but differ by a ULP.
           MAX(0.0,
               AVG(iv_seconds * iv_seconds)
               - AVG(iv_seconds) * AVG(iv_seconds)) AS variance_iv
      FROM intervals
     GROUP BY ip
    HAVING COUNT(*) >= ?
       AND AVG(iv_seconds) >= ?
)
SELECT s.ip, s.n + 1 AS total_hits, s.mean_iv, s.variance_iv
  FROM stats s
 WHERE s.variance_iv < ? * s.mean_iv * s.mean_iv
 ORDER BY s.variance_iv / (s.mean_iv * s.mean_iv) ASC`

	maxCV2 := c.MaxCV * c.MaxCV
	rows, err := env.DB.QueryContext(ctx, q,
		string(claimedJSON),
		c.MinIntervals,
		c.MinMeanSeconds,
		maxCV2,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var ip string
		var totalHits int
		var meanIV, varianceIV float64
		if err := rows.Scan(&ip, &totalHits, &meanIV, &varianceIV); err != nil {
			return nil, err
		}
		cv := 0.0
		if meanIV > 0 {
			cv = sqrt(varianceIV) / meanIV
		}
		out = append(out, Decision{
			IP:  ip,
			Tag: classify.ManualTagBot,
			Reason: fmt.Sprintf(
				"%d hits, mean interval %s, CV %.0f%%",
				totalHits, humanDuration(meanIV), cv*100,
			),
		})
	}
	return out, rows.Err()
}

// sqrt without importing math just for the Reason string. Newton's
// method converges in a handful of iterations for our range; avoids
// a single-use import at the top of the file.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 12; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// humanDuration formats seconds into a terse "42s" / "3.5m" / "2.0h"
// / "1.2d" form for the UI source tooltip.
func humanDuration(s float64) string {
	switch {
	case s < 90:
		return fmt.Sprintf("%.0fs", s)
	case s < 90*60:
		return fmt.Sprintf("%.1fm", s/60)
	case s < 36*60*60:
		return fmt.Sprintf("%.1fh", s/3600)
	default:
		return fmt.Sprintf("%.1fd", s/float64(24*time.Hour/time.Second))
	}
}
