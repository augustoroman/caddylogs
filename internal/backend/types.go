// Package backend defines the narrow storage interface used by the dashboard.
// The concrete implementation is SQLite; other impls (e.g. a stream-re-parse
// backend for hostile memory environments) can be slotted in because every
// query goes through Store.Query with a single parameterized Query value.
package backend

import "time"

// Dimension names a field you can group-by or filter on.
type Dimension string

const (
	DimIP          Dimension = "ip"
	DimHost        Dimension = "host"
	DimURI         Dimension = "uri"
	DimStatus      Dimension = "status"
	DimStatusClass Dimension = "status_class" // "2xx","3xx","4xx","5xx"
	DimMethod      Dimension = "method"
	DimReferrer    Dimension = "referer"
	DimBrowser     Dimension = "browser"
	DimOS          Dimension = "os"
	DimDevice      Dimension = "device"
	DimCountry     Dimension = "country"
	DimCity        Dimension = "city"
	DimProto       Dimension = "proto"
	DimIsBot       Dimension = "is_bot"    // value "true"/"false"
	DimIsLocal     Dimension = "is_local"  // value "true"/"false"
	DimIsStatic    Dimension = "is_static" // value "true"/"false"
	DimMalReason   Dimension = "malicious_reason"
)

// Filter expresses the active drill-down state. Include[d] values are OR'd
// within the dimension; dimensions AND together. Exclude[d] removes matches
// (AND NOT across dims).
type Filter struct {
	Include  map[Dimension][]string `json:"include,omitempty"`
	Exclude  map[Dimension][]string `json:"exclude,omitempty"`
	TimeFrom time.Time              `json:"time_from,omitempty"`
	TimeTo   time.Time              `json:"time_to,omitempty"`
}

// Table selects which physical pool to read.
type Table string

const (
	TableDynamic   Table = "dynamic"
	TableStatic    Table = "static"
	TableMalicious Table = "malicious"
)

// QueryKind discriminates the shape of the response.
type QueryKind string

const (
	KindOverview    QueryKind = "overview"
	KindTopN        QueryKind = "topn"
	KindTimeline    QueryKind = "timeline"
	KindRows        QueryKind = "rows"
	KindStatusClass QueryKind = "status_class"
)

// Query is the single parameterized request the backend accepts.
type Query struct {
	Table  Table     `json:"table"`
	Kind   QueryKind `json:"kind"`
	Filter Filter    `json:"filter"`

	// KindTopN: group by this dimension, return Limit rows.
	GroupBy Dimension `json:"group_by,omitempty"`
	Limit   int       `json:"limit,omitempty"`

	// KindTimeline: bucket width. 0 means auto-tier from the filtered range.
	Bucket time.Duration `json:"bucket,omitempty"`

	// KindRows: pagination + ordering.
	Offset  int    `json:"offset,omitempty"`
	OrderBy string `json:"order_by,omitempty"` // e.g. "ts desc", "duration desc"
}

// Result is the uniform response; only the field(s) corresponding to Kind are
// populated.
type Result struct {
	Kind     QueryKind      `json:"kind"`
	Overview Overview       `json:"overview,omitempty"`
	TopN     []Group        `json:"topn,omitempty"`
	Timeline []Bucket       `json:"timeline,omitempty"`
	Rows     []EventRow     `json:"rows,omitempty"`
	Statuses map[string]int64 `json:"statuses,omitempty"`
}

// Overview is the high-level summary of all events matching the filter.
type Overview struct {
	Hits     int64     `json:"hits"`
	Visitors int64     `json:"visitors"`
	Bytes    int64     `json:"bytes"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// Group is one row of a top-N panel.
type Group struct {
	Key      string `json:"key"`
	Hits     int64  `json:"hits"`
	Visitors int64  `json:"visitors"`
	Bytes    int64  `json:"bytes"`
	MaxMs    int64  `json:"max_ms,omitempty"` // for slow-requests panel
	AvgMs    int64  `json:"avg_ms,omitempty"`
}

// Bucket is one point of the timeline.
type Bucket struct {
	Start    time.Time `json:"start"`
	Hits     int64     `json:"hits"`
	Visitors int64     `json:"visitors"`
	Bytes    int64     `json:"bytes"`
}

// EventRow is a single log line as surfaced in the raw-events list. It
// includes the ingest-time classifications so the UI does not need to
// recompute them.
type EventRow struct {
	Timestamp time.Time     `json:"ts"`
	Status    int           `json:"status"`
	Method    string        `json:"method"`
	Host      string        `json:"host"`
	URI       string        `json:"uri"`
	IP        string        `json:"ip"`
	Country   string        `json:"country,omitempty"`
	City      string        `json:"city,omitempty"`
	Browser   string        `json:"browser,omitempty"`
	OS        string        `json:"os,omitempty"`
	Device    string        `json:"device,omitempty"`
	Duration  time.Duration `json:"duration"`
	Size      int64         `json:"size"`
	UserAgent       string        `json:"user_agent,omitempty"`
	Referer         string        `json:"referer,omitempty"`
	Proto           string        `json:"proto,omitempty"`
	IsBot           bool          `json:"is_bot,omitempty"`
	IsLocal         bool          `json:"is_local,omitempty"`
	IsStatic        bool          `json:"is_static,omitempty"`
	MaliciousReason string        `json:"malicious_reason,omitempty"`
}
