package sqlitestore

import (
	"context"
	"database/sql"
	"strings"
)

// ApplyUAAllow retroactively reclassifies every already-ingested row whose
// user_agent contains pattern as trusted first-party traffic: is_bot is
// cleared across the dynamic and static pools, and any rows sitting in the
// malicious pool for that UA are moved back out. It returns the number of
// rows affected so the UI can report what changed.
//
// This mirrors the "real" branch of ApplyManualTag but keys on a UA substring
// instead of an exact IP. user_agent is not indexed, so the UPDATEs are full
// scans — acceptable because this runs once, on an explicit operator action
// (adding an allowlist pattern), not on the hot path. New live-tail events
// are handled for free by Classify honoring the same allowlist set.
//
// Locality is deliberately left untouched: a UA says nothing about where the
// client is, so an allowlisted request on the LAN stays local.
func (s *Store) ApplyUAAllow(ctx context.Context, pattern string) (int64, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return 0, nil
	}
	// LIKE is case-insensitive for ASCII in SQLite, matching UAAllowSet.Match.
	// Escape the LIKE metacharacters in the operator-supplied pattern so a
	// literal % or _ in a UA token can't widen the match.
	like := "%" + escapeLike(pattern) + "%"

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var affected int64

	// Move any matching rows out of the malicious pool first (rare for a
	// firmware/download client, but keeps the invariant that an allowlisted
	// UA is never malicious). moveFromMaliciousUA drops them back into the
	// dynamic/static pools with is_bot already cleared.
	moved, err := moveFromMaliciousUA(ctx, tx, like)
	if err != nil {
		return 0, err
	}
	affected += moved

	for _, t := range []string{"requests_dynamic", "requests_static"} {
		res, err := tx.ExecContext(ctx,
			`UPDATE `+t+` SET is_bot=0 WHERE is_bot=1 AND user_agent LIKE ? ESCAPE '\'`,
			like,
		)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		affected += n
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return affected, nil
}

// AllowlistedIPs returns the set of client IPs that have at least one request
// whose user_agent matches any of the given patterns (case-insensitive
// substring, the same shape as UAAllowSet.Match). The classifier runner uses
// it to keep behavioral rules from re-flagging trusted first-party traffic:
// an allowlisted firmware box behaves like a bot (no browser session, polling
// cadence), so every heuristic would otherwise want to tag it, undoing the
// allowlist's is_bot=0. Empty patterns yield an empty set with no query.
func (s *Store) AllowlistedIPs(ctx context.Context, patterns []string) (map[string]bool, error) {
	out := map[string]bool{}
	var likes strings.Builder
	args := make([]any, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if likes.Len() > 0 {
			likes.WriteString(" OR ")
		}
		likes.WriteString(`user_agent LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(p)+"%")
	}
	if likes.Len() == 0 {
		return out, nil
	}
	where := likes.String()
	q := `SELECT ip FROM requests_dynamic   WHERE ` + where +
		` UNION SELECT ip FROM requests_static    WHERE ` + where +
		` UNION SELECT ip FROM requests_malicious WHERE ` + where
	// The WHERE fragment is repeated once per UNIONed SELECT, so the bound
	// args must be repeated to match.
	allArgs := make([]any, 0, len(args)*3)
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, args...)
	rows, err := s.db.QueryContext(ctx, q, allArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

// moveFromMaliciousUA relocates every malicious row whose user_agent matches
// like back into the dynamic/static pools (by is_static), clearing is_bot and
// the malicious_reason. Returns the number of rows moved.
func moveFromMaliciousUA(ctx context.Context, tx *sql.Tx, like string) (int64, error) {
	toDyn := `
        INSERT INTO requests_dynamic (` + insertColumnList + `)
        SELECT ts, status, status_class, method, host, uri, ip, country, city,
               browser, os, device, duration_ns, size, bytes_read, proto,
               0, is_local, is_static, '',
               user_agent, referer, visitor_hash
          FROM requests_malicious WHERE user_agent LIKE ? ESCAPE '\' AND is_static=0`
	toStatic := `
        INSERT INTO requests_static (` + insertColumnList + `)
        SELECT ts, status, status_class, method, host, uri, ip, country, city,
               browser, os, device, duration_ns, size, bytes_read, proto,
               0, is_local, is_static, '',
               user_agent, referer, visitor_hash
          FROM requests_malicious WHERE user_agent LIKE ? ESCAPE '\' AND is_static=1`
	if _, err := tx.ExecContext(ctx, toDyn, like); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, toStatic, like); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`DELETE FROM requests_malicious WHERE user_agent LIKE ? ESCAPE '\'`, like)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
