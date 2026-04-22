package classify

import "sync"

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

// ManualTagSet is a concurrent-safe in-memory map of IP → tag. The dashboard
// populates this from persisted rows at startup; subsequent /api/tag calls
// update it so the live tailer classifies new requests consistently with
// what the user just tagged.
type ManualTagSet struct {
	mu sync.RWMutex
	m  map[string]ManualTag
}

// NewManualTagSet builds an empty set.
func NewManualTagSet() *ManualTagSet {
	return &ManualTagSet{m: map[string]ManualTag{}}
}

// Set overwrites (or inserts) the tag for ip.
func (s *ManualTagSet) Set(ip string, t ManualTag) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.m[ip] = t
	s.mu.Unlock()
}

// Get returns the tag for ip, or ("", false) if it is not tagged.
func (s *ManualTagSet) Get(ip string) (ManualTag, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	t, ok := s.m[ip]
	s.mu.RUnlock()
	return t, ok
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
