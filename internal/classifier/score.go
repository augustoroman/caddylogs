package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// ScoreName is the stable source identifier.
const ScoreName = "score"

// Score flags IPs by a per-request point system processed in timestamp
// order. Normal traffic earns small negative points; probe/scrape
// signals earn large positive points. The running total is clamped at a
// floor of zero so a long-lived legitimate IP cannot bank credit that
// would immunize it against a later probe. An IP is a candidate when its
// FINAL running score is at or above Threshold — because clean traffic
// decays the score back toward zero, a one-off scraper that resumes
// normal behavior eventually drops below threshold and the Runner
// reverts it to the real pool.
//
// The floor-at-zero clamp is path-dependent (it depends on the order
// points arrive), which a plain aggregate SQL query cannot express, so
// Run streams every row in (ip, ts) order and folds the score in Go —
// one ordered pass over the IP's whole history.
//
// Rows from all three pools are considered: static and normal-dynamic
// rows supply the decay credit, while requests_malicious holds the
// single-shot attack hits (a lone .env / .php) that the behavioral
// promoter leaves unflagged because it requires repeat hits.
type Score struct {
	// Negative (decay) weights.
	NormalDoc   int // per non-static 2xx/3xx dynamic request
	StaticAsset int // per static-asset request (any status)

	// Positive (suspicion) weights.
	PHP          int // URI ends in ".php"
	AttackReason int // row carries a non-empty malicious_reason (attack.list match)
	DynamicError int // non-static 4xx not already counted as an attack
	Rapid        int // non-static request within RapidWindow of this IP's previous request

	// RapidWindow is the inter-request gap below which a non-static
	// request earns the Rapid bonus (scraper signal).
	RapidWindow time.Duration

	// Threshold is the final clamped score at or above which an IP is
	// tagged.
	Threshold int
}

// NewScore returns the rule with default weights. A single attack hit
// (.env / attack.list match, +100) reaches the default threshold on its
// own; a .php probe (+1000) is effectively sticky; a burst scraper needs
// ~50 rapid hits to cross the line and then decays out once it behaves.
func NewScore() *Score {
	return &Score{
		NormalDoc:    -1,
		StaticAsset:  -1,
		PHP:          1000,
		AttackReason: 100,
		DynamicError: 1,
		Rapid:        2,
		RapidWindow:  time.Second,
		Threshold:    100,
	}
}

func (s *Score) Name() string { return ScoreName }

func (s *Score) Description() string {
	return fmt.Sprintf(
		"IPs whose running suspicion score (.php +%d, attack-URI +%d, rapid +%d, normal %d, clamped ≥0) reaches %d",
		s.PHP, s.AttackReason, s.Rapid, s.NormalDoc, s.Threshold,
	)
}

// scoreAcc folds one IP's request stream into a running score plus the
// per-category sub-totals used to pick the tag and itemize the reason.
type scoreAcc struct {
	running     int // clamped ≥ 0
	attackPts   int // raw sum of attack-category points (for tag selection)
	behaviorPts int // raw sum of behavior-category points

	php, attack, errs, rapid, clean int // counts for the reason string
	lastTS                          int64
	hasLast                         bool
}

func (a *scoreAcc) add(uri string, status int, isStatic bool, reason string, ts int64, w *Score) {
	pts := 0
	switch {
	case strings.HasSuffix(strings.ToLower(uri), ".php"):
		pts += w.PHP
		a.attackPts += w.PHP
		a.php++
	case reason != "":
		pts += w.AttackReason
		a.attackPts += w.AttackReason
		a.attack++
	case isStatic:
		pts += w.StaticAsset
		a.clean++
	case status >= 400 && status < 500:
		pts += w.DynamicError
		a.attackPts += w.DynamicError
		a.errs++
	default:
		pts += w.NormalDoc
		a.clean++
	}

	// Rapid-succession bonus applies on top, for non-static requests
	// that arrive within the window of this IP's previous request.
	if !isStatic && a.hasLast && ts-a.lastTS < int64(w.RapidWindow) {
		pts += w.Rapid
		a.behaviorPts += w.Rapid
		a.rapid++
	}
	a.lastTS = ts
	a.hasLast = true

	a.running += pts
	if a.running < 0 {
		a.running = 0
	}
}

func (a *scoreAcc) decision(ip string, w *Score) (Decision, bool) {
	if a.running < w.Threshold {
		return Decision{}, false
	}
	// Attack-driven => malicious; pure behavioral burst => bot. Ties
	// favor malicious (an attack signal present is the stronger claim).
	tag := classify.ManualTagBot
	if a.attackPts >= a.behaviorPts && a.attackPts > 0 {
		tag = classify.ManualTagMalicious
	}
	var parts []string
	if a.php > 0 {
		parts = append(parts, fmt.Sprintf("%d×.php", a.php))
	}
	if a.attack > 0 {
		parts = append(parts, fmt.Sprintf("%d×attack-uri", a.attack))
	}
	if a.errs > 0 {
		parts = append(parts, fmt.Sprintf("%d×4xx", a.errs))
	}
	if a.rapid > 0 {
		parts = append(parts, fmt.Sprintf("%d×rapid", a.rapid))
	}
	reason := fmt.Sprintf("score %d: %s; %d clean",
		a.running, strings.Join(parts, ", "), a.clean)
	return Decision{IP: ip, Tag: tag, Reason: reason}, true
}

// Run streams every public-IP row in (ip, ts) order and emits a Decision
// for each IP whose final clamped score reaches Threshold.
func (s *Score) Run(ctx context.Context, env RunEnv) ([]Decision, error) {
	claimedJSON, err := json.Marshal(env.Claimed)
	if err != nil {
		return nil, err
	}
	const q = `
WITH claimed(ip) AS (
    SELECT value FROM json_each(?)
)
SELECT ip, ts, uri, status, is_static, malicious_reason
  FROM (
    SELECT ip, ts, uri, status, is_static, malicious_reason, is_bot, is_local
      FROM requests_dynamic
    UNION ALL
    SELECT ip, ts, uri, status, is_static, malicious_reason, is_bot, is_local
      FROM requests_static
    UNION ALL
    SELECT ip, ts, uri, status, is_static, malicious_reason, is_bot, is_local
      FROM requests_malicious
  ) t
 WHERE t.is_local = 0
   AND (t.is_bot = 0 OR t.ip IN (SELECT ip FROM claimed))
 ORDER BY t.ip, t.ts`

	rows, err := env.DB.QueryContext(ctx, q, string(claimedJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	var curIP string
	var acc scoreAcc
	flush := func() {
		if curIP == "" {
			return
		}
		if d, ok := acc.decision(curIP, s); ok {
			out = append(out, d)
		}
	}
	for rows.Next() {
		var ip, uri, reason string
		var ts int64
		var status, isStatic int
		if err := rows.Scan(&ip, &ts, &uri, &status, &isStatic, &reason); err != nil {
			return nil, err
		}
		if ip != curIP {
			flush()
			curIP = ip
			acc = scoreAcc{}
		}
		acc.add(uri, status, isStatic == 1, reason, ts, s)
	}
	flush()
	return out, rows.Err()
}
