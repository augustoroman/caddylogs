package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// UAAllowSet is a concurrent-safe, optionally file-backed list of User-Agent
// substring patterns that mark a request as trusted first-party traffic.
// A request whose UA contains any pattern is forced to real (is_bot=0) and
// skips attack detection — the intended use is allowlisting your own devices
// (firmware updaters, download agents, monitoring boxes) that would otherwise
// trip the bot heuristic because they use curl/wget/Go-http-client-style UAs.
//
// It is a near-mirror of ManualTagSet: an empty path keeps the set in memory;
// a set built via LoadUAAllowSet writes every Add/Remove back to disk so the
// allowlist survives cache-key invalidation (which happens whenever a tailed
// log's size or mtime changes). Matching is case-insensitive substring, the
// same shape as BotDetector so patterns behave predictably alongside it.
//
// Precedence in Classify: an explicit per-IP manual tag still wins over the
// allowlist (an operator who tags a specific IP as bot/malicious means it),
// but the allowlist beats the UA bot heuristic and attack-URI detection.
type UAAllowSet struct {
	mu   sync.RWMutex
	m    map[string]UAAllowEntry
	path string // empty = in-memory only
}

// UAAllowEntry is a single allowlisted pattern with the time it was added and
// an optional operator note ("scoring boxes", "firmware updater", …).
type UAAllowEntry struct {
	At   int64  `json:"at"` // unix nanoseconds
	Note string `json:"note,omitempty"`
}

// UAAllowListEntry is the listing form, including the pattern key.
type UAAllowListEntry struct {
	Pattern string `json:"pattern"`
	At      int64  `json:"at"`
	Note    string `json:"note,omitempty"`
}

// NewUAAllowSet builds an empty in-memory set (no file backing).
func NewUAAllowSet() *UAAllowSet {
	return &UAAllowSet{m: map[string]UAAllowEntry{}}
}

// LoadUAAllowSet reads path (if it exists) and returns a set that persists
// every subsequent Add/Remove back to the same path. A missing file is an
// empty set, so callers can point at a not-yet-created location.
func LoadUAAllowSet(path string) (*UAAllowSet, error) {
	s := &UAAllowSet{m: map[string]UAAllowEntry{}, path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the file the set is backed by, or "" for in-memory sets.
func (s *UAAllowSet) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *UAAllowSet) load() error {
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
	var m map[string]UAAllowEntry
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return fmt.Errorf("parse allowlist file %q: %w", s.path, err)
	}
	if m != nil {
		s.m = m
	}
	return nil
}

// saveLocked writes the current map to disk atomically. Caller holds the
// write lock. No-op for in-memory sets.
func (s *UAAllowSet) saveLocked() error {
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

// Add records an allowlist pattern (trimmed) and persists atomically. An
// empty/whitespace-only pattern is rejected — a bare "" would match every
// request. Adding an existing pattern refreshes its timestamp/note.
func (s *UAAllowSet) Add(pattern, note string) error {
	if s == nil {
		return nil
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return fmt.Errorf("empty allowlist pattern")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[pattern] = UAAllowEntry{At: time.Now().UnixNano(), Note: strings.TrimSpace(note)}
	return s.saveLocked()
}

// Remove deletes pattern (and persists). Returns nil if pattern wasn't
// present — callers treat "remove a nonexistent pattern" as success.
func (s *UAAllowSet) Remove(pattern string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, strings.TrimSpace(pattern))
	return s.saveLocked()
}

// Match reports whether ua contains any allowlisted pattern (case-insensitive
// substring), returning the matched pattern. An empty UA never matches — an
// empty UA on a public site is almost always automated, and the allowlist is
// for identifying known first-party clients, which always send a UA.
func (s *UAAllowSet) Match(ua string) (string, bool) {
	if s == nil || ua == "" {
		return "", false
	}
	low := strings.ToLower(ua)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for p := range s.m {
		if strings.Contains(low, strings.ToLower(p)) {
			return p, true
		}
	}
	return "", false
}

// Count returns the number of allowlisted patterns.
func (s *UAAllowSet) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// List returns a snapshot of all patterns, most-recent-first.
func (s *UAAllowSet) List() []UAAllowListEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UAAllowListEntry, 0, len(s.m))
	for p, e := range s.m {
		out = append(out, UAAllowListEntry{Pattern: p, At: e.At, Note: e.Note})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}
