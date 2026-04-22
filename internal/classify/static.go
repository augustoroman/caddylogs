package classify

import (
	"path"
	"strings"
)

// DefaultStaticExtensions matches the clog list plus a few common web asset
// extensions. PHP is intentionally NOT included here: requests for .php on a
// non-PHP site are almost always scans, and the user will usually want those
// visible on the main dashboard rather than hidden in the static section.
var DefaultStaticExtensions = []string{
	".js", ".mjs", ".css", ".map", ".scss", ".less",
	".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".cur", ".bmp", ".tiff",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp4", ".webm", ".mov", ".ogv", ".m4v",
	".mp3", ".wav", ".m4a", ".ogg", ".flac", ".aac", ".opus",
	".pdf",
	".webmanifest", ".appcache",
	".txt", // robots.txt etc.
}

// StaticMatcher decides whether a URI refers to a static asset based on its
// extension. Lookups are O(1).
type StaticMatcher struct {
	exts map[string]struct{}
}

// NewStaticMatcher builds a matcher from a list of extensions. Each extension
// is normalized to lowercase and leading-dot form; entries without a leading
// dot have one prepended.
func NewStaticMatcher(exts []string) *StaticMatcher {
	m := &StaticMatcher{exts: make(map[string]struct{}, len(exts))}
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		m.exts[e] = struct{}{}
	}
	return m
}

// IsStatic returns true if uri's path portion has an extension in the list.
func (s *StaticMatcher) IsStatic(uri string) bool {
	// Strip query and fragment.
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	base := path.Base(uri)
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 || dot == len(base)-1 {
		return false
	}
	ext := strings.ToLower(base[dot:])
	_, ok := s.exts[ext]
	return ok
}
