// Package parser reads Caddy JSON access log lines and converts them to a
// normalized Event representation.
package parser

import (
	"encoding/json"
	"fmt"
	"time"
)

// Event is a normalized representation of one Caddy access log entry.
type Event struct {
	Timestamp     time.Time
	Status        int
	Method        string
	Host          string
	URI           string
	Proto         string
	RemoteIP      string
	Duration      time.Duration
	Size          int64
	BytesRead     int64
	UserAgent     string
	Referer       string
	TLSServerName string
}

// raw mirrors the subset of Caddy's JSON log we care about. All string-slice
// headers come through as []string; we normalize to the first element.
type raw struct {
	TS       float64 `json:"ts"`
	Msg      string  `json:"msg"`
	Status   int     `json:"status"`
	Size     int64   `json:"size"`
	BytesIn  int64   `json:"bytes_read"`
	Duration float64 `json:"duration"`
	Request  struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Proto    string              `json:"proto"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
		TLS      struct {
			ServerName string `json:"server_name"`
		} `json:"tls"`
	} `json:"request"`
}

// Parse decodes a single JSON log line into an Event. An empty line returns
// io.EOF-equivalent (Event{}, nil is intentionally avoided — callers should
// skip empty lines before calling).
func Parse(line []byte) (Event, error) {
	var r raw
	if err := json.Unmarshal(line, &r); err != nil {
		return Event{}, fmt.Errorf("parse caddy log: %w", err)
	}
	// Caddy emits many msg types; only "handled request" carries access data.
	// We accept anything with a request.method though, since msg might vary by
	// version or middleware.
	if r.Request.Method == "" {
		return Event{}, errNotAccessLog
	}
	ip := r.Request.ClientIP
	if ip == "" {
		ip = r.Request.RemoteIP
	}
	ua := firstHeader(r.Request.Headers, "User-Agent")
	ref := firstHeader(r.Request.Headers, "Referer")
	if ref == "" {
		ref = firstHeader(r.Request.Headers, "Referrer")
	}
	return Event{
		Timestamp:     floatSecondsToTime(r.TS),
		Status:        r.Status,
		Method:        r.Request.Method,
		Host:          r.Request.Host,
		URI:           r.Request.URI,
		Proto:         r.Request.Proto,
		RemoteIP:      ip,
		Duration:      time.Duration(r.Duration * float64(time.Second)),
		Size:          r.Size,
		BytesRead:     r.BytesIn,
		UserAgent:     ua,
		Referer:       ref,
		TLSServerName: r.Request.TLS.ServerName,
	}, nil
}

// errNotAccessLog is returned for JSON lines that aren't access log entries
// (e.g. Caddy's startup/info messages that share the same log file).
var errNotAccessLog = fmt.Errorf("not an access log entry")

// IsNotAccessLog reports whether err indicates a non-access-log line.
func IsNotAccessLog(err error) bool { return err == errNotAccessLog }

func firstHeader(h map[string][]string, key string) string {
	if v, ok := h[key]; ok && len(v) > 0 {
		return v[0]
	}
	// Case-insensitive fallback — Caddy usually canonicalizes, but be tolerant.
	for k, v := range h {
		if len(v) > 0 && equalFold(k, key) {
			return v[0]
		}
	}
	return ""
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func floatSecondsToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}
