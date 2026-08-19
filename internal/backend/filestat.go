package backend

import "time"

// IngestFileStat is a per-input-file snapshot recorded during bulk ingest,
// kept so the operator can inspect what each log file contributed — entry
// counts, on-disk vs. uncompressed size (⇒ compression ratio), and the
// timespan covered — primarily to tune log-rotation settings. Stats are a
// point-in-time capture: the live tail appends events afterwards without
// updating them, which is fine for rotation tuning where the rotated
// (historical) files are the interesting ones.
type IngestFileStat struct {
	Path       string    `json:"path"`
	DiskBytes  int64     `json:"disk_bytes"`  // on-disk size (compressed for .gz)
	RawBytes   int64     `json:"raw_bytes"`   // uncompressed bytes scanned
	Compressed bool      `json:"compressed"`  // true for .gz inputs
	Entries    int64     `json:"entries"`     // parsed access-log events
	BadLines   int64     `json:"bad_lines"`   // malformed lines skipped
	First      time.Time `json:"first"`       // earliest event timestamp; zero if no entries
	Last       time.Time `json:"last"`        // latest event timestamp; zero if no entries
	IngestedAt time.Time `json:"ingested_at"` // when this file was ingested
}
