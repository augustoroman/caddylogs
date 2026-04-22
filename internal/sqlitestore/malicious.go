package sqlitestore

import (
	"context"
	"fmt"
	"strings"
)

// AttackerThresholds controls behavioral flagging of IPs that aren't caught
// by a URI pattern but still look suspicious.
type AttackerThresholds struct {
	MinHits        int     // ignore IPs with fewer than this many requests
	MinErrorRate   float64 // [0..1]; fraction of 4xx among their requests
	MinAttackHits  int     // ignore IPs with fewer than this many URI-flagged hits
}

// DefaultThresholds is the baseline used when no CLI override is given.
var DefaultThresholds = AttackerThresholds{
	MinHits:       15,
	MinErrorRate:  0.70,
	MinAttackHits: 2,
}

// ComputeBehavioralAttackers returns a map of (ip → reason) of IPs that the
// behavioral heuristic believes to be malicious. This queries all three
// tables because a promotion pass may not have run yet.
func (s *Store) ComputeBehavioralAttackers(ctx context.Context, t AttackerThresholds) (map[string]string, error) {
	out := map[string]string{}

	// Rule A: any IP with >= MinAttackHits rows already in requests_malicious.
	if t.MinAttackHits > 0 {
		rows, err := s.db.QueryContext(ctx, `
            SELECT ip, COUNT(*) FROM requests_malicious
            GROUP BY ip HAVING COUNT(*) >= ?`, t.MinAttackHits)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			var n int
			if err := rows.Scan(&ip, &n); err != nil {
				rows.Close()
				return nil, err
			}
			out[ip] = fmt.Sprintf("behavior:repeat_attack_uris=%d", n)
		}
		rows.Close()
	}

	// Rule B: high 4xx rate across the whole union. We do this per table and
	// merge, because one IP could be split between tables.
	if t.MinHits > 0 {
		// Aggregate hits + 4xx count per IP across dynamic + static + malicious.
		const q = `
            SELECT ip, SUM(hits), SUM(err)
            FROM (
              SELECT ip, 1 AS hits, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END AS err
                FROM requests_dynamic
              UNION ALL
              SELECT ip, 1, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END
                FROM requests_static
              UNION ALL
              SELECT ip, 1, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END
                FROM requests_malicious
            )
            GROUP BY ip
            HAVING SUM(hits) >= ? AND (SUM(err) * 1.0 / SUM(hits)) >= ?`
		rows, err := s.db.QueryContext(ctx, q, t.MinHits, t.MinErrorRate)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			var hits, errs int
			if err := rows.Scan(&ip, &hits, &errs); err != nil {
				rows.Close()
				return nil, err
			}
			if _, already := out[ip]; already {
				continue // URI-based reason is more specific, keep it
			}
			rate := float64(errs) / float64(hits)
			out[ip] = fmt.Sprintf("behavior:err_rate=%.0f%%/%d_hits", rate*100, hits)
		}
		rows.Close()
	}

	return out, nil
}

// PromoteFlaggedIPs moves every row owned by an IP in ips (keyed by IP,
// value = reason) from requests_dynamic and requests_static into
// requests_malicious. The per-row malicious_reason is set to the IP-level
// reason so the UI can show why an otherwise-benign-looking request was
// relocated.
func (s *Store) PromoteFlaggedIPs(ctx context.Context, ips map[string]string) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Moving row-by-row with parameterized IP + reason, per source table. The
	// INSERT column lists are identical across tables, and we set
	// malicious_reason to the supplied IP reason (overriding whatever may
	// have been there for non-malicious rows).
	moveSQL := func(src string) string {
		return fmt.Sprintf(`
            INSERT INTO requests_malicious (
                %[1]s
            ) SELECT
                ts, status, status_class, method, host, uri, ip, country, city,
                browser, os, device, duration_ns, size, bytes_read, proto,
                is_bot, is_local, is_static, ?,
                user_agent, referer, visitor_hash
              FROM %[2]s WHERE ip = ?`, insertColumnList, src)
	}
	dynMove := moveSQL("requests_dynamic")
	statMove := moveSQL("requests_static")
	dynDel := `DELETE FROM requests_dynamic WHERE ip = ?`
	statDel := `DELETE FROM requests_static  WHERE ip = ?`

	var moved int64
	for ip, reason := range ips {
		if err := ctx.Err(); err != nil {
			return moved, err
		}
		if res, err := tx.ExecContext(ctx, dynMove, reason, ip); err == nil {
			n, _ := res.RowsAffected()
			moved += n
		} else {
			return moved, err
		}
		if _, err := tx.ExecContext(ctx, dynDel, ip); err != nil {
			return moved, err
		}
		if res, err := tx.ExecContext(ctx, statMove, reason, ip); err == nil {
			n, _ := res.RowsAffected()
			moved += n
		} else {
			return moved, err
		}
		if _, err := tx.ExecContext(ctx, statDel, ip); err != nil {
			return moved, err
		}
	}
	return moved, tx.Commit()
}

// ClassificationCounts returns the six-cell breakdown used by the dashboard
// header strip: hits and bytes in {real, bot, malicious} × {static, dynamic}.
// "real" means is_bot=0; "bot" means is_bot=1; "malicious" is everything
// in requests_malicious regardless of bot flag.
type ClassificationCounts struct {
	RealStatic           int64 `json:"real_static"`
	RealStaticBytes      int64 `json:"real_static_bytes"`
	RealDynamic          int64 `json:"real_dynamic"`
	RealDynamicBytes     int64 `json:"real_dynamic_bytes"`
	BotStatic            int64 `json:"bot_static"`
	BotStaticBytes       int64 `json:"bot_static_bytes"`
	BotDynamic           int64 `json:"bot_dynamic"`
	BotDynamicBytes      int64 `json:"bot_dynamic_bytes"`
	MaliciousStatic      int64 `json:"malicious_static"`
	MaliciousStaticBytes int64 `json:"malicious_static_bytes"`
	MaliciousDoc         int64 `json:"malicious_dynamic"`
	MaliciousDocBytes    int64 `json:"malicious_dynamic_bytes"`
	FlaggedIPs           int64 `json:"flagged_ips"`
}

// Classification fans out six COUNT/SUM queries. Uses the supplied filter's
// time range only (per-dim filters are meaningful to the individual panels,
// not the whole-traffic breakdown).
func (s *Store) Classification(ctx context.Context, timeFromNs, timeToNs int64) (*ClassificationCounts, error) {
	tsClause, tsArgs := tsClauseFor(timeFromNs, timeToNs)
	out := &ClassificationCounts{}

	run := func(table, extra string, dstHits, dstBytes *int64) error {
		w := tsClause
		if extra != "" {
			if w == "" {
				w = " WHERE " + extra
			} else {
				w += " AND " + extra
			}
		}
		q := `SELECT COUNT(*), COALESCE(SUM(size),0) FROM ` + table + w
		return s.db.QueryRowContext(ctx, q, tsArgs...).Scan(dstHits, dstBytes)
	}

	if err := run("requests_static", "is_bot=0", &out.RealStatic, &out.RealStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_dynamic", "is_bot=0", &out.RealDynamic, &out.RealDynamicBytes); err != nil {
		return nil, err
	}
	if err := run("requests_static", "is_bot=1", &out.BotStatic, &out.BotStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_dynamic", "is_bot=1", &out.BotDynamic, &out.BotDynamicBytes); err != nil {
		return nil, err
	}
	if err := run("requests_malicious", "is_static=1", &out.MaliciousStatic, &out.MaliciousStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_malicious", "is_static=0", &out.MaliciousDoc, &out.MaliciousDocBytes); err != nil {
		return nil, err
	}
	// Count distinct flagged IPs.
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip) FROM requests_malicious`+tsClause, tsArgs...,
	).Scan(&out.FlaggedIPs); err != nil {
		return nil, err
	}
	return out, nil
}

// WithIPs iterates the distinct (ip, malicious_reason) pairs currently in
// requests_malicious, calling fn for each. Used when a cached DB is
// reopened so the in-memory attacker set can be rebuilt.
func (s *Store) WithIPs(ctx context.Context, fn func(ip, reason string)) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, COALESCE(malicious_reason,'') FROM requests_malicious GROUP BY ip`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, reason string
		if err := rows.Scan(&ip, &reason); err != nil {
			return err
		}
		fn(ip, reason)
	}
	return rows.Err()
}

func tsClauseFor(from, to int64) (string, []any) {
	var parts []string
	var args []any
	if from > 0 {
		parts = append(parts, "ts >= ?")
		args = append(args, from)
	}
	if to > 0 {
		parts = append(parts, "ts < ?")
		args = append(args, to)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}
