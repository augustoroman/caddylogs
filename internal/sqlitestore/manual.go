package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
)

// ApplyManualTag records a manual tag for ip in the manual_tags table and
// updates every existing row across the three request tables so the
// dashboard sees the IP in its new category immediately. Subsequent
// live-tail events for ip must be classified through a classifier whose
// ManualTagSet has been told about this tag (see SetManualTagInClassifier
// used by the HTTP layer) for the change to persist forward.
//
// Semantics:
//   - real      : is_bot=0, is_local=0. Rows are moved out of
//                 requests_malicious back into requests_dynamic or
//                 requests_static based on their is_static flag.
//   - local     : is_local=1, is_bot=0. Rows moved out of malicious likewise.
//   - bot       : is_bot=1, is_local=0. Rows moved out of malicious likewise.
//   - malicious : rows moved from requests_dynamic and requests_static into
//                 requests_malicious with malicious_reason='manual:tagged'.
//                 Existing malicious rows have their reason overwritten.
func (s *Store) ApplyManualTag(ctx context.Context, ip string, tag classify.ManualTag) error {
	if ip == "" {
		return fmt.Errorf("empty ip")
	}
	if !classify.ValidManualTag(tag) {
		return fmt.Errorf("invalid tag %q", tag)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO manual_tags(ip, tag, at) VALUES (?,?,?)
         ON CONFLICT(ip) DO UPDATE SET tag=excluded.tag, at=excluded.at`,
		ip, string(tag), time.Now().UnixNano(),
	); err != nil {
		return err
	}

	switch tag {
	case classify.ManualTagMalicious:
		if err := moveToMalicious(ctx, tx, "requests_dynamic", ip); err != nil {
			return err
		}
		if err := moveToMalicious(ctx, tx, "requests_static", ip); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE requests_malicious SET malicious_reason='manual:tagged' WHERE ip=?`, ip,
		); err != nil {
			return err
		}
	case classify.ManualTagReal, classify.ManualTagLocal, classify.ManualTagBot:
		var isBot, isLocal int
		switch tag {
		case classify.ManualTagReal:
			isBot, isLocal = 0, 0
		case classify.ManualTagLocal:
			isBot, isLocal = 0, 1
		case classify.ManualTagBot:
			isBot, isLocal = 1, 0
		}
		if err := moveFromMalicious(ctx, tx, ip); err != nil {
			return err
		}
		for _, t := range []string{"requests_dynamic", "requests_static", "requests_malicious"} {
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf(`UPDATE %s SET is_bot=?, is_local=? WHERE ip=?`, t),
				isBot, isLocal, ip,
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// WithManualTags iterates every persisted (ip, tag, at) triple in the DB's
// manual_tags table. Used once, at startup, to migrate a legacy DB's tags
// into the external JSON file when the JSON file is empty.
func (s *Store) WithManualTags(ctx context.Context, fn func(ip string, tag classify.ManualTag, at int64)) error {
	rows, err := s.db.QueryContext(ctx, `SELECT ip, tag, at FROM manual_tags`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, tag string
		var at int64
		if err := rows.Scan(&ip, &tag, &at); err != nil {
			return err
		}
		fn(ip, classify.ManualTag(tag), at)
	}
	return rows.Err()
}

// RemoveManualTag deletes the tag record for ip from the manual_tags
// table. It does NOT change the classification of already-ingested rows
// (they stay where ApplyManualTag put them); callers are responsible for
// also removing the tag from the classifier's in-memory set so future
// live-tail events revert to auto-classification.
func (s *Store) RemoveManualTag(ctx context.Context, ip string) error {
	if ip == "" {
		return fmt.Errorf("empty ip")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM manual_tags WHERE ip=?`, ip)
	return err
}

func moveToMalicious(ctx context.Context, tx *sql.Tx, src, ip string) error {
	moveSQL := fmt.Sprintf(`
        INSERT INTO requests_malicious (%[1]s)
        SELECT ts, status, status_class, method, host, uri, ip, country, city,
               browser, os, device, duration_ns, size, bytes_read, proto,
               is_bot, is_local, is_static, 'manual:tagged',
               user_agent, referer, visitor_hash
          FROM %[2]s WHERE ip=?`, insertColumnList, src)
	if _, err := tx.ExecContext(ctx, moveSQL, ip); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE ip=?`, src), ip)
	return err
}

func moveFromMalicious(ctx context.Context, tx *sql.Tx, ip string) error {
	toDyn := fmt.Sprintf(`
        INSERT INTO requests_dynamic (%[1]s)
        SELECT ts, status, status_class, method, host, uri, ip, country, city,
               browser, os, device, duration_ns, size, bytes_read, proto,
               is_bot, is_local, is_static, '',
               user_agent, referer, visitor_hash
          FROM requests_malicious WHERE ip=? AND is_static=0`, insertColumnList)
	toStatic := fmt.Sprintf(`
        INSERT INTO requests_static (%[1]s)
        SELECT ts, status, status_class, method, host, uri, ip, country, city,
               browser, os, device, duration_ns, size, bytes_read, proto,
               is_bot, is_local, is_static, '',
               user_agent, referer, visitor_hash
          FROM requests_malicious WHERE ip=? AND is_static=1`, insertColumnList)
	if _, err := tx.ExecContext(ctx, toDyn, ip); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, toStatic, ip); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM requests_malicious WHERE ip=?`, ip)
	return err
}
