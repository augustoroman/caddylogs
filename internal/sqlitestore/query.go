package sqlitestore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
)

// Query implements backend.Store.
func (s *Store) Query(ctx context.Context, q backend.Query) (*backend.Result, error) {
	table, err := tableName(q.Table)
	if err != nil {
		return nil, err
	}
	where, args, err := buildWhere(q.Filter)
	if err != nil {
		return nil, err
	}
	switch q.Kind {
	case backend.KindOverview:
		return s.queryOverview(ctx, table, where, args)
	case backend.KindStatusClass:
		return s.queryStatusClass(ctx, table, where, args)
	case backend.KindTopN:
		return s.queryTopN(ctx, table, where, args, q)
	case backend.KindTimeline:
		return s.queryTimeline(ctx, table, where, args, q)
	case backend.KindRows:
		return s.queryRows(ctx, table, where, args, q)
	}
	return nil, fmt.Errorf("unknown query kind %q", q.Kind)
}

// buildWhere turns a Filter into a "WHERE ..." fragment plus args. An empty
// filter returns an empty fragment.
func buildWhere(f backend.Filter) (string, []any, error) {
	var clauses []string
	var args []any

	for dim, vals := range f.Include {
		col := dimColumn(dim)
		if col == "" {
			return "", nil, fmt.Errorf("unknown dimension %q in include", dim)
		}
		if len(vals) == 0 {
			continue
		}
		placeholders := strings.Repeat("?,", len(vals))
		placeholders = placeholders[:len(placeholders)-1]
		clauses = append(clauses, quote(col)+" IN ("+placeholders+")")
		for _, v := range vals {
			args = append(args, mapFilterValue(dim, v))
		}
	}
	for dim, vals := range f.Exclude {
		col := dimColumn(dim)
		if col == "" {
			return "", nil, fmt.Errorf("unknown dimension %q in exclude", dim)
		}
		if len(vals) == 0 {
			continue
		}
		placeholders := strings.Repeat("?,", len(vals))
		placeholders = placeholders[:len(placeholders)-1]
		clauses = append(clauses, quote(col)+" NOT IN ("+placeholders+")")
		for _, v := range vals {
			args = append(args, mapFilterValue(dim, v))
		}
	}
	if !f.TimeFrom.IsZero() {
		clauses = append(clauses, "ts >= ?")
		args = append(args, f.TimeFrom.UnixNano())
	}
	if !f.TimeTo.IsZero() {
		clauses = append(clauses, "ts < ?")
		args = append(args, f.TimeTo.UnixNano())
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

// mapFilterValue coerces string filter values to the DB-native type. Bool
// dimensions store 0/1 ints.
func mapFilterValue(dim backend.Dimension, v string) any {
	switch dim {
	case backend.DimIsBot, backend.DimIsLocal, backend.DimIsStatic:
		if v == "true" || v == "1" {
			return 1
		}
		return 0
	}
	return v
}

func (s *Store) queryOverview(ctx context.Context, table, where string, args []any) (*backend.Result, error) {
	const q = `SELECT
        COUNT(*),
        COUNT(DISTINCT visitor_hash),
        COALESCE(SUM(size), 0),
        COALESCE(MIN(ts), 0),
        COALESCE(MAX(ts), 0)
    FROM ` + "%s" + `%s`
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(q, table, where), args...)
	var hits, visitors, bytes, minTs, maxTs int64
	if err := row.Scan(&hits, &visitors, &bytes, &minTs, &maxTs); err != nil {
		return nil, err
	}
	r := &backend.Result{Kind: backend.KindOverview}
	r.Overview.Hits = hits
	r.Overview.Visitors = visitors
	r.Overview.Bytes = bytes
	if hits > 0 {
		r.Overview.First = time.Unix(0, minTs).UTC()
		r.Overview.Last = time.Unix(0, maxTs).UTC()
	}
	return r, nil
}

func (s *Store) queryStatusClass(ctx context.Context, table, where string, args []any) (*backend.Result, error) {
	q := fmt.Sprintf(
		`SELECT status_class, COUNT(*) FROM %s%s GROUP BY status_class ORDER BY status_class`,
		table, where,
	)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return &backend.Result{Kind: backend.KindStatusClass, Statuses: out}, rows.Err()
}

func (s *Store) queryTopN(ctx context.Context, table, where string, args []any, q backend.Query) (*backend.Result, error) {
	col := dimColumn(q.GroupBy)
	if col == "" {
		return nil, fmt.Errorf("topn requires a valid GroupBy, got %q", q.GroupBy)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 10
	}
	// For slow-requests panel, we want to include max/avg duration regardless
	// of grouping. They're cheap; always compute them.
	sqlStr := fmt.Sprintf(
		`SELECT %s AS k,
                COUNT(*) AS hits,
                COUNT(DISTINCT visitor_hash) AS visitors,
                COALESCE(SUM(size), 0) AS bytes,
                COALESCE(MAX(duration_ns), 0) AS max_dur,
                COALESCE(AVG(duration_ns), 0) AS avg_dur
         FROM %s%s
         GROUP BY k
         ORDER BY %s DESC
         LIMIT ?`,
		quote(col), table, where, topnOrderBy(q),
	)
	allArgs := append(append([]any{}, args...), limit)
	rows, err := s.db.QueryContext(ctx, sqlStr, allArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backend.Group
	for rows.Next() {
		var g backend.Group
		var maxDur, avgDur float64
		if err := rows.Scan(&g.Key, &g.Hits, &g.Visitors, &g.Bytes, &maxDur, &avgDur); err != nil {
			return nil, err
		}
		g.MaxMs = int64(maxDur / 1e6)
		g.AvgMs = int64(avgDur / 1e6)
		out = append(out, g)
	}
	return &backend.Result{Kind: backend.KindTopN, TopN: out}, rows.Err()
}

// topnOrderBy picks the ORDER BY column. Callers can request duration-based
// ranking by passing OrderBy="max_dur".
func topnOrderBy(q backend.Query) string {
	switch strings.ToLower(q.OrderBy) {
	case "max_dur", "max_ms", "slowest":
		return "max_dur"
	case "avg_dur", "avg_ms":
		return "avg_dur"
	case "bytes":
		return "bytes"
	case "visitors":
		return "visitors"
	}
	return "hits"
}

func (s *Store) queryTimeline(ctx context.Context, table, where string, args []any, q backend.Query) (*backend.Result, error) {
	bucketNs := int64(q.Bucket)
	if bucketNs <= 0 {
		// Auto-tier: look at the range and pick a width that gives us roughly
		// 60-120 buckets.
		var minTs, maxTs int64
		row := s.db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COALESCE(MIN(ts),0), COALESCE(MAX(ts),0) FROM %s%s`, table, where),
			args...)
		if err := row.Scan(&minTs, &maxTs); err != nil {
			return nil, err
		}
		bucketNs = autoBucket(maxTs - minTs)
	}
	if bucketNs <= 0 {
		return &backend.Result{Kind: backend.KindTimeline}, nil
	}
	sqlStr := fmt.Sprintf(
		`SELECT (ts / ?) * ? AS bucket_start,
                COUNT(*),
                COUNT(DISTINCT visitor_hash),
                COALESCE(SUM(size),0)
         FROM %s%s
         GROUP BY bucket_start
         ORDER BY bucket_start`,
		table, where,
	)
	allArgs := append([]any{bucketNs, bucketNs}, args...)
	rows, err := s.db.QueryContext(ctx, sqlStr, allArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backend.Bucket
	for rows.Next() {
		var startNs, hits, visitors, bytes int64
		if err := rows.Scan(&startNs, &hits, &visitors, &bytes); err != nil {
			return nil, err
		}
		out = append(out, backend.Bucket{
			Start:    time.Unix(0, startNs).UTC(),
			Hits:     hits,
			Visitors: visitors,
			Bytes:    bytes,
		})
	}
	return &backend.Result{Kind: backend.KindTimeline, Timeline: out}, rows.Err()
}

func autoBucket(spanNs int64) int64 {
	if spanNs <= 0 {
		return int64(time.Minute)
	}
	target := int64(80) // aim for ~80 points
	candidates := []time.Duration{
		time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second,
		time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
		time.Hour, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour,
		24 * time.Hour, 7 * 24 * time.Hour,
	}
	for _, c := range candidates {
		if spanNs/int64(c) <= target {
			return int64(c)
		}
	}
	return int64(30 * 24 * time.Hour)
}

func (s *Store) queryRows(ctx context.Context, table, where string, args []any, q backend.Query) (*backend.Result, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	order := "ts DESC"
	switch strings.ToLower(q.OrderBy) {
	case "", "ts desc":
		order = "ts DESC"
	case "ts asc":
		order = "ts ASC"
	case "duration desc":
		order = "duration_ns DESC"
	case "duration asc":
		order = "duration_ns ASC"
	case "status desc":
		order = "status DESC"
	case "status asc":
		order = "status ASC"
	}
	sqlStr := fmt.Sprintf(
		`SELECT ts, status, method, host, uri, ip, country, city, browser, os, device,
                duration_ns, size, user_agent, referer, proto,
                is_bot, is_local, is_static, malicious_reason
         FROM %s%s
         ORDER BY %s
         LIMIT ? OFFSET ?`,
		table, where, order,
	)
	allArgs := append(append([]any{}, args...), limit, q.Offset)
	rows, err := s.db.QueryContext(ctx, sqlStr, allArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backend.EventRow
	for rows.Next() {
		var r backend.EventRow
		var tsNs, durNs int64
		var isBot, isLocal, isStatic int
		if err := rows.Scan(
			&tsNs, &r.Status, &r.Method, &r.Host, &r.URI, &r.IP,
			&r.Country, &r.City, &r.Browser, &r.OS, &r.Device,
			&durNs, &r.Size, &r.UserAgent, &r.Referer, &r.Proto,
			&isBot, &isLocal, &isStatic, &r.MaliciousReason,
		); err != nil {
			return nil, err
		}
		r.Timestamp = time.Unix(0, tsNs).UTC()
		r.Duration = time.Duration(durNs)
		r.IsBot = isBot != 0
		r.IsLocal = isLocal != 0
		r.IsStatic = isStatic != 0
		out = append(out, r)
	}
	return &backend.Result{Kind: backend.KindRows, Rows: out}, rows.Err()
}
