package sqlitestore

// Common columns for both the dynamic and static request tables. The two
// tables share the same schema so that panel queries over them are literally
// the same SQL with a different table name.
const schemaColumns = `
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,  -- unix nanoseconds
    status       INTEGER NOT NULL,
    status_class TEXT    NOT NULL,
    method       TEXT    NOT NULL,
    host         TEXT    NOT NULL,
    uri          TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    country      TEXT    NOT NULL,
    city         TEXT    NOT NULL,
    browser      TEXT    NOT NULL,
    os           TEXT    NOT NULL,
    device       TEXT    NOT NULL,
    duration_ns  INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    bytes_read   INTEGER NOT NULL,
    proto        TEXT    NOT NULL,
    is_bot       INTEGER NOT NULL,
    is_local     INTEGER NOT NULL,
    user_agent   TEXT    NOT NULL,
    referer      TEXT    NOT NULL,
    visitor_hash INTEGER NOT NULL
`

const schemaSQL = `
CREATE TABLE IF NOT EXISTS requests_dynamic (` + schemaColumns + `);
CREATE TABLE IF NOT EXISTS requests_static  (` + schemaColumns + `);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
`

// indexStatements are applied at MarkIngestComplete time so that the bulk
// insert is fast and the dashboard queries that follow are indexed.
var indexStatements = []string{
	`CREATE INDEX IF NOT EXISTS idx_dyn_ts      ON requests_dynamic(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_ip      ON requests_dynamic(ip)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_isbot   ON requests_dynamic(is_bot)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_islocal ON requests_dynamic(is_local)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_status  ON requests_dynamic(status)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_host    ON requests_dynamic(host)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_ts     ON requests_static(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_ip     ON requests_static(ip)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_isbot  ON requests_static(is_bot)`,
}

// insertSQL returns the INSERT statement for a given table.
func insertSQL(table string) string {
	return `INSERT INTO ` + table + `(
        ts, status, status_class, method, host, uri, ip, country, city,
        browser, os, device, duration_ns, size, bytes_read, proto,
        is_bot, is_local, user_agent, referer, visitor_hash
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
}
