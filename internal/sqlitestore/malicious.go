package sqlitestore

import (
	"context"
	"fmt"
	"strings"

	"github.com/augustoroman/caddylogs/internal/progress"
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
func (s *Store) ComputeBehavioralAttackers(ctx context.Context, t AttackerThresholds, p progress.Func) (map[string]string, error) {
	if p == nil {
		p = progress.Nop
	}
	out := map[string]string{}

	// Rule A: any IP with >= MinAttackHits rows already in requests_malicious.
	// Exclude local IPs defensively — the classifier already refuses to
	// flag them, but a cached DB from an older build might contain some.
	if t.MinAttackHits > 0 {
		p("behavioral", "rule A: IPs with repeated attack URIs", -1, -1)
		rows, err := s.db.QueryContext(ctx, `
            SELECT ip, COUNT(*) FROM requests_malicious
            WHERE is_local = 0
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
	// merge, because one IP could be split between tables. Local IPs are
	// excluded — a router doing health-check probes shouldn't be tagged as
	// an attacker.
	if t.MinHits > 0 {
		p("behavioral", "rule B: IPs with high 4xx rate", -1, -1)
		// Aggregate hits + 4xx count per IP across dynamic + static + malicious.
		const q = `
            SELECT ip, SUM(hits), SUM(err)
            FROM (
              SELECT ip, 1 AS hits, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END AS err
                FROM requests_dynamic  WHERE is_local = 0
              UNION ALL
              SELECT ip, 1, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END
                FROM requests_static   WHERE is_local = 0
              UNION ALL
              SELECT ip, 1, CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END
                FROM requests_malicious WHERE is_local = 0
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

	p("behavioral", fmt.Sprintf("identified %d attacker IPs", len(out)), int64(len(out)), int64(len(out)))
	return out, nil
}

// PromoteFlaggedIPs moves every row owned by an IP in ips (keyed by IP,
// value = reason) from requests_dynamic and requests_static into
// requests_malicious. Each moved row's malicious_reason is set to the
// IP-level reason from ips so the UI can show why an otherwise-benign-
// looking request was relocated.
//
// Implementation: a temporary ephemeral `flagged_ips(ip, reason)` table is
// populated with the caller's set, then a single INSERT ... SELECT ... JOIN
// + DELETE pair runs per source table. With the ip index in place (see
// BuildPreIngestIndexes) the JOIN is O(|ips|) index lookups rather than the
// O(|ips| × rows) per-IP loop the previous implementation performed. At
// 900k rows and ~500 flagged IPs this takes seconds instead of minutes.
func (s *Store) PromoteFlaggedIPs(ctx context.Context, ips map[string]string, p progress.Func) (int64, error) {
	if p == nil {
		p = progress.Nop
	}
	if len(ips) == 0 {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`CREATE TEMP TABLE IF NOT EXISTS flagged_ips (ip TEXT PRIMARY KEY, reason TEXT NOT NULL)`,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM flagged_ips`); err != nil {
		return 0, err
	}
	p("promote", fmt.Sprintf("loading %d flagged IPs", len(ips)), 0, int64(len(ips)))

	ins, err := tx.PrepareContext(ctx, `INSERT INTO flagged_ips(ip, reason) VALUES (?, ?)`)
	if err != nil {
		return 0, err
	}
	var i int64
	for ip, reason := range ips {
		if err := ctx.Err(); err != nil {
			ins.Close()
			return 0, err
		}
		if _, err := ins.ExecContext(ctx, ip, reason); err != nil {
			ins.Close()
			return 0, err
		}
		i++
		if i%1000 == 0 {
			p("promote", "loading flagged IPs", i, int64(len(ips)))
		}
	}
	ins.Close()

	movePair := func(src string, phase string) (int64, error) {
		p("promote", "relocating rows from "+src, -1, -1)
		moveSQL := fmt.Sprintf(`
            INSERT INTO requests_malicious (%[1]s)
            SELECT ts, status, status_class, method, host, uri, r.ip, country, city,
                   browser, os, device, duration_ns, size, bytes_read, proto,
                   is_bot, is_local, is_static, f.reason,
                   user_agent, referer, visitor_hash
              FROM %[2]s r
              JOIN flagged_ips f ON r.ip = f.ip`, insertColumnList, src)
		res, err := tx.ExecContext(ctx, moveSQL)
		if err != nil {
			return 0, err
		}
		moved, _ := res.RowsAffected()
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE ip IN (SELECT ip FROM flagged_ips)`, src),
		); err != nil {
			return moved, err
		}
		p("promote", fmt.Sprintf("relocated %d rows from %s", moved, src), moved, moved)
		return moved, nil
	}

	var total int64
	n, err := movePair("requests_dynamic", "dyn")
	total += n
	if err != nil {
		return total, err
	}
	n, err = movePair("requests_static", "static")
	total += n
	if err != nil {
		return total, err
	}
	p("promote", "committing", -1, -1)
	return total, tx.Commit()
}

// ClassificationCounts returns the eight-cell breakdown used by the
// dashboard header strip: hits and bytes in
// {real, bot, local, malicious} × {static, dynamic}.
//
//   - real      = is_local=0 AND is_bot=0 (public human-ish traffic)
//   - bot       = is_local=0 AND is_bot=1 (public crawler traffic)
//   - local     = is_local=1              (RFC1918 / loopback / link-local;
//                                          never routed to the malicious table)
//   - malicious = any row in requests_malicious (always is_local=0 by design)
type ClassificationCounts struct {
	RealStatic           int64 `json:"real_static"`
	RealStaticBytes      int64 `json:"real_static_bytes"`
	RealDynamic          int64 `json:"real_dynamic"`
	RealDynamicBytes     int64 `json:"real_dynamic_bytes"`
	BotStatic            int64 `json:"bot_static"`
	BotStaticBytes       int64 `json:"bot_static_bytes"`
	BotDynamic           int64 `json:"bot_dynamic"`
	BotDynamicBytes      int64 `json:"bot_dynamic_bytes"`
	LocalStatic          int64 `json:"local_static"`
	LocalStaticBytes     int64 `json:"local_static_bytes"`
	LocalDynamic         int64 `json:"local_dynamic"`
	LocalDynamicBytes    int64 `json:"local_dynamic_bytes"`
	MaliciousStatic      int64 `json:"malicious_static"`
	MaliciousStaticBytes int64 `json:"malicious_static_bytes"`
	MaliciousDoc         int64 `json:"malicious_dynamic"`
	MaliciousDocBytes    int64 `json:"malicious_dynamic_bytes"`
	FlaggedIPs           int64 `json:"flagged_ips"`
}

// Classification fans out COUNT/SUM queries for each cell. Uses only the
// supplied filter's time range (per-dim filters are meaningful to the
// individual panels, not the whole-traffic breakdown).
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

	// Real: public, non-bot
	if err := run("requests_static", "is_local=0 AND is_bot=0", &out.RealStatic, &out.RealStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_dynamic", "is_local=0 AND is_bot=0", &out.RealDynamic, &out.RealDynamicBytes); err != nil {
		return nil, err
	}
	// Bot: public, bot-UA
	if err := run("requests_static", "is_local=0 AND is_bot=1", &out.BotStatic, &out.BotStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_dynamic", "is_local=0 AND is_bot=1", &out.BotDynamic, &out.BotDynamicBytes); err != nil {
		return nil, err
	}
	// Local: RFC1918 / loopback / link-local. Grouped regardless of bot flag.
	if err := run("requests_static", "is_local=1", &out.LocalStatic, &out.LocalStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_dynamic", "is_local=1", &out.LocalDynamic, &out.LocalDynamicBytes); err != nil {
		return nil, err
	}
	// Malicious: never local, but split by static vs dynamic content.
	if err := run("requests_malicious", "is_static=1", &out.MaliciousStatic, &out.MaliciousStaticBytes); err != nil {
		return nil, err
	}
	if err := run("requests_malicious", "is_static=0", &out.MaliciousDoc, &out.MaliciousDocBytes); err != nil {
		return nil, err
	}
	// Count distinct flagged attacker IPs (never local by construction).
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
