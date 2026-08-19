package sqlitestore

import (
	"context"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
)

// SaveIngestFileStat upserts one input file's ingest-time statistics snapshot.
// Keyed by path, so re-ingesting the same file (e.g. after clear-cache)
// replaces its previous row rather than accumulating duplicates.
func (s *Store) SaveIngestFileStat(ctx context.Context, st backend.IngestFileStat) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ingest_files
			(path, disk_bytes, raw_bytes, compressed, entries, bad_lines,
			 first_ts, last_ts, ingested_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET
			disk_bytes=excluded.disk_bytes, raw_bytes=excluded.raw_bytes,
			compressed=excluded.compressed, entries=excluded.entries,
			bad_lines=excluded.bad_lines, first_ts=excluded.first_ts,
			last_ts=excluded.last_ts, ingested_at=excluded.ingested_at`,
		st.Path, st.DiskBytes, st.RawBytes, boolInt(st.Compressed),
		st.Entries, st.BadLines, nanosOrZero(st.First), nanosOrZero(st.Last),
		nanosOrZero(st.IngestedAt))
	return err
}

// IngestFileStats returns every recorded input-file snapshot, oldest data
// first (files with no parseable entries sort last, by path). Empty — not an
// error — for DBs ingested before stats were recorded.
func (s *Store) IngestFileStats(ctx context.Context) ([]backend.IngestFileStat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT path, disk_bytes, raw_bytes, compressed, entries, bad_lines,
		       first_ts, last_ts, ingested_at
		FROM ingest_files
		ORDER BY CASE WHEN first_ts = 0 THEN 1 ELSE 0 END, first_ts, path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backend.IngestFileStat
	for rows.Next() {
		var st backend.IngestFileStat
		var compressed int
		var first, last, at int64
		if err := rows.Scan(&st.Path, &st.DiskBytes, &st.RawBytes, &compressed,
			&st.Entries, &st.BadLines, &first, &last, &at); err != nil {
			return nil, err
		}
		st.Compressed = compressed != 0
		st.First = timeOrZero(first)
		st.Last = timeOrZero(last)
		st.IngestedAt = timeOrZero(at)
		out = append(out, st)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nanosOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func timeOrZero(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
