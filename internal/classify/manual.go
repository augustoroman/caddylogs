package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ManualTag is a user-supplied override for a specific IP. A tag bypasses
// auto-detection: a manually-tagged IP is always classified according to
// its tag regardless of user-agent, IP range, or attack heuristics.
type ManualTag string

const (
	ManualTagReal      ManualTag = "real"
	ManualTagLocal     ManualTag = "local"
	ManualTagBot       ManualTag = "bot"
	ManualTagMalicious ManualTag = "malicious"
)

// ValidManualTag reports whether t is one of the recognized tag values.
func ValidManualTag(t ManualTag) bool {
	switch t {
	case ManualTagReal, ManualTagLocal, ManualTagBot, ManualTagMalicious:
		return true
	}
	return false
}

// SourceManual is the source label for operator-applied tags (via the
// dashboard's right-click menu or the /api/tag endpoint). Classifier-
// applied tags use the classifier's name as their source.
const SourceManual = "manual"

// ManualTagEntry is a single tagged IP with the time it was set. Stored
// in memory and serialized to the tags file. Source records who applied
// the tag (SourceManual, or a classifier name); Reason is an optional
// human-readable explanation stored with classifier tags so the UI can
// show what heuristic fired.
type ManualTagEntry struct {
	Tag    ManualTag `json:"tag"`
	At     int64     `json:"at"` // unix nanoseconds
	Source string    `json:"source,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

// ManualTagListEntry is the listing-form, including the IP key.
type ManualTagListEntry struct {
	IP     string    `json:"ip"`
	Tag    ManualTag `json:"tag"`
	At     int64     `json:"at"`
	Source string    `json:"source,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

// ManualTagSet is a concurrent-safe in-memory map of IP → tag with
// optional JSON-file backing. A set with an empty path stays in memory;
// a set built via LoadManualTagSet writes every mutation to disk so
// manual tags survive across cache rebuilds (which happen whenever a
// tailed log file's size or mtime changes, invalidating the ingest cache
// key).
type ManualTagSet struct {
	mu   sync.RWMutex
	m    map[string]ManualTagEntry
	path string // empty = in-memory only
}

// NewManualTagSet builds an empty in-memory set (no file backing). Useful
// for tests and for callers that manage persistence themselves.
func NewManualTagSet() *ManualTagSet {
	return &ManualTagSet{m: map[string]ManualTagEntry{}}
}

// LoadManualTagSet reads path (if it exists) and returns a set that will
// persist every subsequent Set/Delete back to the same path. A missing
// file is treated as an empty set, so callers can point at a new location
// without preseeding it.
func LoadManualTagSet(path string) (*ManualTagSet, error) {
	s := &ManualTagSet{m: map[string]ManualTagEntry{}, path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the file the set is backed by, or "" for in-memory sets.
func (s *ManualTagSet) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *ManualTagSet) load() error {
	if s.path == "" {
		return nil
	}
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var m map[string]ManualTagEntry
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return fmt.Errorf("parse tags file %q: %w", s.path, err)
	}
	if m != nil {
		// Forward-migrate pre-source entries: anything without a source
		// field was written before classifiers existed, so by definition
		// it came from the operator.
		for ip, e := range m {
			if e.Source == "" {
				e.Source = SourceManual
				m[ip] = e
			}
		}
		s.m = m
	}
	return nil
}

// saveLocked writes the current map to disk atomically. Caller must hold
// the write lock. No-op when path is empty (in-memory set).
func (s *ManualTagSet) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.m); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}

// Save flushes the current in-memory state to disk. Used after a batch of
// Put calls (e.g. migration from the DB).
func (s *ManualTagSet) Save() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// Put records a tag in memory without writing to disk. Callers that want
// durability follow with Save (or use Set, which combines both). Source
// defaults to SourceManual when empty so legacy callers behave the same.
func (s *ManualTagSet) Put(ip string, t ManualTag) {
	s.PutAt(ip, t, time.Now().UnixNano(), SourceManual, "")
}

// PutAt is Put with caller-supplied timestamp, source, and reason. Used
// by the classifier runner and by the migration path (which preserves
// the original timestamps from the DB so the UI's "since" column stays
// meaningful).
func (s *ManualTagSet) PutAt(ip string, t ManualTag, at int64, source, reason string) {
	if s == nil {
		return
	}
	if source == "" {
		source = SourceManual
	}
	s.mu.Lock()
	s.m[ip] = ManualTagEntry{Tag: t, At: at, Source: source, Reason: reason}
	s.mu.Unlock()
}

// Set records an operator-applied tag and persists it atomically. A save
// error bubbles up so the caller (typically the /api/tag handler) can
// surface it. The source is hardcoded to SourceManual — classifier hooks
// go through SetFrom.
func (s *ManualTagSet) Set(ip string, t ManualTag) error {
	return s.SetFrom(ip, t, SourceManual, "")
}

// SetFrom records a tag with a specific source (e.g. a classifier name)
// and reason, and persists atomically.
func (s *ManualTagSet) SetFrom(ip string, t ManualTag, source, reason string) error {
	if s == nil {
		return nil
	}
	if source == "" {
		source = SourceManual
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ip] = ManualTagEntry{Tag: t, At: time.Now().UnixNano(), Source: source, Reason: reason}
	return s.saveLocked()
}

// Delete removes the tag for ip (and persists). Returns nil if ip wasn't
// tagged — callers treat "remove a nonexistent tag" as success.
func (s *ManualTagSet) Delete(ip string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, ip)
	return s.saveLocked()
}

// Get returns the tag for ip, or ("", false) if it is not tagged.
func (s *ManualTagSet) Get(ip string) (ManualTag, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	e, ok := s.m[ip]
	s.mu.RUnlock()
	return e.Tag, ok
}

// Count returns the number of tagged IPs.
func (s *ManualTagSet) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// List returns a snapshot of all tags, sorted most-recent-first.
func (s *ManualTagSet) List() []ManualTagListEntry {
	return s.listMatching("")
}

// ListBySource returns only tags whose source equals source (e.g. a
// classifier name) — used by the classifier runner's diff to figure out
// which tags it previously applied.
func (s *ManualTagSet) ListBySource(source string) []ManualTagListEntry {
	return s.listMatching(source)
}

func (s *ManualTagSet) listMatching(source string) []ManualTagListEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ManualTagListEntry, 0, len(s.m))
	for ip, e := range s.m {
		if source != "" && e.Source != source {
			continue
		}
		out = append(out, ManualTagListEntry{
			IP: ip, Tag: e.Tag, At: e.At, Source: e.Source, Reason: e.Reason,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}
