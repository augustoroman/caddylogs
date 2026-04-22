package sqlitestore

// Common columns for every request table. All three physical pools share
// this layout so panel queries against any of them are the same SQL modulo
// table name.
const schemaColumns = `
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,  -- unix nanoseconds
    status          INTEGER NOT NULL,
    status_class    TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    uri             TEXT    NOT NULL,
    ip              TEXT    NOT NULL,
    country         TEXT    NOT NULL,
    city            TEXT    NOT NULL,
    browser         TEXT    NOT NULL,
    os              TEXT    NOT NULL,
    device          TEXT    NOT NULL,
    duration_ns     INTEGER NOT NULL,
    size            INTEGER NOT NULL,
    bytes_read      INTEGER NOT NULL,
    proto           TEXT    NOT NULL,
    is_bot          INTEGER NOT NULL,
    is_local        INTEGER NOT NULL,
    is_static       INTEGER NOT NULL,
    malicious_reason TEXT   NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL,
    referer         TEXT    NOT NULL,
    visitor_hash    INTEGER NOT NULL
`

const schemaSQL = `
CREATE TABLE IF NOT EXISTS requests_dynamic   (` + schemaColumns + `);
CREATE TABLE IF NOT EXISTS requests_static    (` + schemaColumns + `);
CREATE TABLE IF NOT EXISTS requests_malicious (` + schemaColumns + `);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manual_tags (
    ip  TEXT PRIMARY KEY,
    tag TEXT NOT NULL,
    at  INTEGER NOT NULL
);
`

// preIngestIndexes are the indexes required for PromoteFlaggedIPs to run
// in O(flagged_ips) rather than O(flagged_ips × table_size). They are
// created after bulk ingest but before behavioral analysis + promotion.
var preIngestIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_dyn_ip   ON requests_dynamic(ip)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_ip  ON requests_static(ip)`,
	`CREATE INDEX IF NOT EXISTS idx_mal_ip   ON requests_malicious(ip)`,
}

// postIngestIndexes are the remaining indexes the panel queries use. They
// are built once promotion is done so they don't slow promotion itself.
var postIngestIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_dyn_ts       ON requests_dynamic(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_isbot    ON requests_dynamic(is_bot)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_islocal  ON requests_dynamic(is_local)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_status   ON requests_dynamic(status)`,
	`CREATE INDEX IF NOT EXISTS idx_dyn_host     ON requests_dynamic(host)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_ts      ON requests_static(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_stat_isbot   ON requests_static(is_bot)`,
	`CREATE INDEX IF NOT EXISTS idx_mal_ts       ON requests_malicious(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_mal_status   ON requests_malicious(status)`,
	`CREATE INDEX IF NOT EXISTS idx_mal_isstatic ON requests_malicious(is_static)`,
	`CREATE INDEX IF NOT EXISTS idx_mal_reason   ON requests_malicious(malicious_reason)`,
}

const insertColumnList = `ts, status, status_class, method, host, uri, ip, country, city,
    browser, os, device, duration_ns, size, bytes_read, proto,
    is_bot, is_local, is_static, malicious_reason,
    user_agent, referer, visitor_hash`

const insertPlaceholders = `?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?`

// insertSQL returns the INSERT statement for a given table.
func insertSQL(table string) string {
	return `INSERT INTO ` + table + `(` + insertColumnList + `) VALUES (` + insertPlaceholders + `)`
}
