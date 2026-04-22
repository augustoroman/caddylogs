// Package sqlitestore implements backend.Store on top of an embedded SQLite
// database (modernc.org/sqlite, no CGO). It splits rows into requests_dynamic
// and requests_static so the hot path never touches static-asset rows unless
// the caller explicitly asks.
package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"os"
	"strings"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/progress"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed implementation of backend.Store.
type Store struct {
	db      *sql.DB
	cls     *classify.Classifier
	cleanup func() // extra cleanup (e.g. remove tempfile) run after db.Close
}

// Options configures Open.
type Options struct {
	Path       string // file path; use "" for an ephemeral tempfile
	Classifier *classify.Classifier
}

// Open opens or creates a SQLite database at opts.Path. An empty Path yields
// an ephemeral tempfile that is removed on Close.
func Open(opts Options) (*Store, error) {
	path := opts.Path
	ephemeral := false
	if path == "" {
		f, err := os.CreateTemp("", "caddylogs-*.db")
		if err != nil {
			return nil, err
		}
		f.Close()
		path = f.Name()
		ephemeral = true
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=foreign_keys(ON)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// WAL allows multiple concurrent readers; we cap open conns at a small
	// number so we don't starve the writer.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, cls: opts.Classifier}
	if ephemeral {
		s.cleanup = func() {
			_ = os.Remove(path)
			_ = os.Remove(path + "-journal")
			_ = os.Remove(path + "-wal")
			_ = os.Remove(path + "-shm")
		}
	}
	return s, nil
}

// Close implements backend.Store.
func (s *Store) Close() error {
	err := s.db.Close()
	if s.cleanup != nil {
		s.cleanup()
	}
	return err
}

// IngestComplete reports whether the meta row says this DB has already
// finished an ingest (cache hit on a prior run).
func (s *Store) IngestComplete(ctx context.Context) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k='ingest_complete'`)
	var v string
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return v == "1", nil
}

// SetMeta upserts a meta key. Useful for recording ingest signatures.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta(k, v) VALUES(?,?)
         ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, value)
	return err
}

// GetMeta reads a meta key. Missing keys return "", nil.
func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k=?`, key)
	var v string
	err := row.Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// BuildPreIngestIndexes creates the indexes needed for PromoteFlaggedIPs
// to be fast (ip column only). Safe to call at any time; uses IF NOT EXISTS.
func (s *Store) BuildPreIngestIndexes(ctx context.Context, p progress.Func) error {
	if p == nil {
		p = progress.Nop
	}
	total := int64(len(preIngestIndexes))
	for i, stmt := range preIngestIndexes {
		p("index", stmtName(stmt), int64(i), total)
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	p("index", "pre-ingest done", total, total)
	return nil
}

// MarkIngestComplete builds the remaining secondary indices, ANALYZEs, and
// flips the ingest_complete meta flag. Assumes BuildPreIngestIndexes has
// already run (safe either way: indexes use IF NOT EXISTS).
func (s *Store) MarkIngestComplete(ctx context.Context, p progress.Func) error {
	if p == nil {
		p = progress.Nop
	}
	total := int64(len(preIngestIndexes) + len(postIngestIndexes))
	i := int64(0)
	for _, stmt := range preIngestIndexes {
		p("index", stmtName(stmt), i, total)
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
		i++
	}
	for _, stmt := range postIngestIndexes {
		p("index", stmtName(stmt), i, total)
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
		i++
	}
	p("analyze", "running ANALYZE", -1, -1)
	if _, err := s.db.ExecContext(ctx, `ANALYZE`); err != nil {
		return err
	}
	p("index", "done", total, total)
	return s.SetMeta(ctx, "ingest_complete", "1")
}

// stmtName extracts the index name from a CREATE INDEX statement for use
// in progress messages. Returns the trimmed statement if extraction fails.
func stmtName(stmt string) string {
	const marker = "idx_"
	i := strings.Index(stmt, marker)
	if i < 0 {
		return stmt
	}
	j := i
	for j < len(stmt) && (isIdentChar(stmt[j])) {
		j++
	}
	return stmt[i:j]
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// Ingest writes a batch of events, classifying and routing each row to the
// dynamic, static, or malicious table.
func (s *Store) Ingest(ctx context.Context, events []parser.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmtDyn, err := tx.PrepareContext(ctx, insertSQL("requests_dynamic"))
	if err != nil {
		return err
	}
	defer stmtDyn.Close()
	stmtStatic, err := tx.PrepareContext(ctx, insertSQL("requests_static"))
	if err != nil {
		return err
	}
	defer stmtStatic.Close()
	stmtMal, err := tx.PrepareContext(ctx, insertSQL("requests_malicious"))
	if err != nil {
		return err
	}
	defer stmtMal.Close()

	for _, ev := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		c := s.cls.Classify(ev)
		var target = stmtDyn
		switch {
		case c.IsMalicious:
			target = stmtMal
		case c.IsStatic:
			target = stmtStatic
		}
		args := rowArgs(c)
		if _, err := target.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// rowArgs returns the argument list in the order insertSQL expects.
func rowArgs(c classify.Classified) []any {
	return []any{
		c.Timestamp.UnixNano(),
		c.Status,
		statusClass(c.Status),
		c.Method,
		c.Host,
		c.URI,
		c.RemoteIP,
		c.Country,
		c.City,
		c.Browser,
		c.OS,
		c.Device,
		int64(c.Duration),
		c.Size,
		c.BytesRead,
		c.Proto,
		boolToInt(c.IsBot),
		boolToInt(c.IsLocal),
		boolToInt(c.IsStatic),
		c.MaliciousReason,
		c.UserAgent,
		c.Referer,
		int64(visitorHash(c.RemoteIP, c.UserAgent, c.Timestamp.Format("2006-01-02"))),
	}
}

func visitorHash(ip, ua, day string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ip))
	h.Write([]byte{0})
	h.Write([]byte(ua))
	h.Write([]byte{0})
	h.Write([]byte(day))
	return h.Sum64()
}

func statusClass(s int) string {
	switch {
	case s >= 500:
		return "5xx"
	case s >= 400:
		return "4xx"
	case s >= 300:
		return "3xx"
	case s >= 200:
		return "2xx"
	case s >= 100:
		return "1xx"
	default:
		return "other"
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// statically-verified backend.Store implementation.
var _ backend.Store = (*Store)(nil)

// dimColumn maps a public Dimension to its SQL column name. Returning "" for
// an unknown dimension keeps us safe from injection: every caller must check
// before building SQL.
func dimColumn(d backend.Dimension) string {
	switch d {
	case backend.DimIP:
		return "ip"
	case backend.DimHost:
		return "host"
	case backend.DimURI:
		return "uri"
	case backend.DimStatus:
		return "status"
	case backend.DimStatusClass:
		return "status_class"
	case backend.DimMethod:
		return "method"
	case backend.DimReferrer:
		return "referer"
	case backend.DimBrowser:
		return "browser"
	case backend.DimOS:
		return "os"
	case backend.DimDevice:
		return "device"
	case backend.DimCountry:
		return "country"
	case backend.DimCity:
		return "city"
	case backend.DimProto:
		return "proto"
	case backend.DimIsBot:
		return "is_bot"
	case backend.DimIsLocal:
		return "is_local"
	case backend.DimIsStatic:
		return "is_static"
	case backend.DimMalReason:
		return "malicious_reason"
	}
	return ""
}

// tableName validates and returns the physical table for a backend.Table.
func tableName(t backend.Table) (string, error) {
	switch t {
	case backend.TableDynamic:
		return "requests_dynamic", nil
	case backend.TableStatic:
		return "requests_static", nil
	case backend.TableMalicious:
		return "requests_malicious", nil
	}
	return "", fmt.Errorf("unknown table %q", t)
}

// quote returns an identifier quoted for SQLite. Only used with allow-listed
// column names from dimColumn.
func quote(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}
