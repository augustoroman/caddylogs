package classify

import (
	_ "embed"
	"regexp"
	"strings"
	"sync"
)

//go:embed attacks.list
var embeddedAttacksList string

// AttackMatcher labels URIs that look like known attack probes (WordPress
// scans, environment-file fishing, admin-panel probes, path traversal,
// router exploits, etc.). It also carries the growing set of IPs that have
// been flagged via URI match or behavioral analysis — any future request
// from one of those IPs is malicious regardless of its URI.
type AttackMatcher struct {
	mu          sync.RWMutex
	substrings  []patternEntry
	regexps     []regexEntry
	flaggedIPs  map[string]string // ip -> reason
}

type patternEntry struct {
	pat    string // lowercased substring to match against the URI path
	reason string
}

type regexEntry struct {
	re     *regexp.Regexp
	reason string
}

// DefaultAttacks builds a matcher seeded with the embedded attacks.list plus
// a built-in regex for any scripting-language extension (.php/.asp/.jsp/.cgi)
// even when followed by a querystring or extra path segment. Callers can
// replace the patterns entirely via NewAttackMatcher or extend them via
// AddPatterns.
func DefaultAttacks() *AttackMatcher {
	m := NewAttackMatcher(nil)
	m.AddPatternFile(embeddedAttacksList)
	m.AddRegex(`(?i)\.(php|phtml|php5|php7|asp|aspx|jsp|cgi)(\?|/|$)`, "script-extension")
	return m
}

// NewAttackMatcher returns an empty matcher; callers add patterns with
// AddPatterns/AddRegex/AddPatternFile.
func NewAttackMatcher(patterns []string) *AttackMatcher {
	m := &AttackMatcher{flaggedIPs: map[string]string{}}
	m.AddPatterns(patterns)
	return m
}

// AddPatterns adds case-insensitive substring patterns. Each pattern uses
// "reason=pattern" format to pick a human-readable reason, or just
// "pattern" to reuse the pattern text as the reason.
func (m *AttackMatcher) AddPatterns(patterns []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		reason, pat := splitReason(p)
		m.substrings = append(m.substrings, patternEntry{pat: strings.ToLower(pat), reason: reason})
	}
}

// AddPatternFile parses a whole file's worth of patterns; blank lines and
// lines starting with # are ignored. A line beginning with "re:" is treated
// as a regex rather than a substring.
func (m *AttackMatcher) AddPatternFile(data string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "re:") {
			reason, rest := splitReason(strings.TrimPrefix(line, "re:"))
			m.AddRegex(rest, reason)
			continue
		}
		m.AddPatterns([]string{line})
	}
}

// AddRegex adds a compiled regex matcher with a named reason.
func (m *AttackMatcher) AddRegex(expr, reason string) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.regexps = append(m.regexps, regexEntry{re: re, reason: reason})
	m.mu.Unlock()
}

// splitReason accepts "reason=pattern" or "pattern" and returns (reason,
// pattern). When no "=" is present, the pattern itself is used as the reason
// (trimmed to something human-scanable).
func splitReason(s string) (reason, pat string) {
	if i := strings.Index(s, "="); i > 0 && i < 40 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return shortReason(s), s
}

// shortReason returns a compact label derived from the pattern text.
func shortReason(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimLeft(p, "/")
	if len(p) > 40 {
		p = p[:40]
	}
	return p
}

// MatchURI reports the reason a URI is malicious, if any. The URI is matched
// case-insensitively against the substring patterns and case-sensitively
// against the regexes (callers may include (?i) in their expressions).
func (m *AttackMatcher) MatchURI(uri string) (reason string, ok bool) {
	if uri == "" {
		return "", false
	}
	low := strings.ToLower(uri)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.substrings {
		if strings.Contains(low, p.pat) {
			return "attack_uri:" + p.reason, true
		}
	}
	for _, re := range m.regexps {
		if re.re.MatchString(uri) {
			return "attack_uri:" + re.reason, true
		}
	}
	return "", false
}

// FlagIP adds an IP to the "known attacker" set with a given reason.
func (m *AttackMatcher) FlagIP(ip, reason string) {
	if ip == "" {
		return
	}
	m.mu.Lock()
	if _, ok := m.flaggedIPs[ip]; !ok {
		m.flaggedIPs[ip] = reason
	}
	m.mu.Unlock()
}

// IPReason returns the flag reason for ip, or ("", false) if ip is not
// flagged.
func (m *AttackMatcher) IPReason(ip string) (string, bool) {
	m.mu.RLock()
	r, ok := m.flaggedIPs[ip]
	m.mu.RUnlock()
	return r, ok
}

// FlaggedIPCount returns how many IPs are currently in the set. Useful for
// status output.
func (m *AttackMatcher) FlaggedIPCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flaggedIPs)
}

// FlaggedIPs returns a copy of the flagged-IP set.
func (m *AttackMatcher) FlaggedIPs() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.flaggedIPs))
	for ip, r := range m.flaggedIPs {
		out[ip] = r
	}
	return out
}
