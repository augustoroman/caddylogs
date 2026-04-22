// Package classify labels Caddy log events with derived attributes that the
// backend indexes on: is_bot, is_local, browser/os/device, static-vs-dynamic,
// and country/city (when a GeoIP DB is configured).
package classify

import (
	_ "embed"
	"strings"
)

//go:embed browsers.list
var embeddedBrowsersList string

// BotDetector does substring matching against a list of crawler tokens plus a
// generic heuristic over well-known substrings ("bot", "crawler", "spider").
type BotDetector struct {
	patterns  []string // lowercased substrings
	heuristic bool     // also flag UAs containing generic bot tokens
}

// DefaultBots returns a detector seeded with goaccess's browsers.list (only
// entries marked "Crawlers") plus a supplemental list of bots the goaccess
// file misses (Googlebot, bingbot, AhrefsBot, etc.). The generic heuristic is
// enabled by default.
func DefaultBots() *BotDetector {
	patterns := parseCrawlers(embeddedBrowsersList)
	patterns = append(patterns, supplementalBots...)
	return newBotDetector(patterns, true)
}

// NewBotDetector builds a detector from an explicit list of substring
// patterns. Heuristic is whether to also flag UAs containing "bot"/"crawler"/
// "spider"/"fetch" as a fallback.
func NewBotDetector(patterns []string, heuristic bool) *BotDetector {
	return newBotDetector(patterns, heuristic)
}

// AddPatterns appends user-specified patterns to an existing detector.
func (b *BotDetector) AddPatterns(extra []string) {
	for _, p := range extra {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			b.patterns = append(b.patterns, p)
		}
	}
}

// IsBot reports whether the user agent matches any pattern or hits the
// generic heuristic.
func (b *BotDetector) IsBot(ua string) bool {
	if ua == "" {
		return true // empty UA on a public site is almost always automated
	}
	low := strings.ToLower(ua)
	for _, p := range b.patterns {
		if strings.Contains(low, p) {
			return true
		}
	}
	if b.heuristic {
		for _, g := range genericBotTokens {
			if strings.Contains(low, g) {
				return true
			}
		}
	}
	return false
}

func newBotDetector(raw []string, heuristic bool) *BotDetector {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return &BotDetector{patterns: out, heuristic: heuristic}
}

// parseCrawlers reads a browsers.list-formatted file and returns the names
// tagged "Crawlers". Lines look like `<name>\t+<type>`; the name may contain
// internal tabs (e.g. "Speedy\tSpider"), which we collapse to spaces.
func parseCrawlers(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on runs of tabs. The final non-empty field is the type; the
		// rest form the name.
		fields := splitTabs(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[len(fields)-1]
		if !strings.EqualFold(kind, "Crawlers") {
			continue
		}
		name := strings.Join(fields[:len(fields)-1], " ")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func splitTabs(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		} else {
			cur.WriteByte(s[i])
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// supplementalBots covers common crawlers that goaccess's shipped list is
// missing. These are substring-matched case-insensitively.
var supplementalBots = []string{
	"Googlebot",
	"bingbot",
	"AdsBot-Google",
	"APIs-Google",
	"Mediapartners-Google",
	"Storebot-Google",
	"Google-InspectionTool",
	"Google-Extended",
	"GoogleOther",
	"AhrefsBot",
	"SemrushBot",
	"MJ12bot",
	"Baiduspider",
	"YandexBot",
	"YandexImages",
	"DuckDuckBot",
	"facebookexternalhit",
	"meta-externalagent",
	"meta-externalfetcher",
	"Twitterbot",
	"LinkedInBot",
	"Applebot",
	"Pinterest",
	"SkypeUriPreview",
	"TelegramBot",
	"Discordbot",
	"Slackbot",
	"WhatsApp",
	"PetalBot",
	"Bytespider",
	"DataForSeoBot",
	"SeznamBot",
	"Qwantify",
	"archive.org_bot",
	"ia_archiver",
	"CCBot",
	"ClaudeBot",
	"anthropic-ai",
	"GPTBot",
	"ChatGPT-User",
	"OAI-SearchBot",
	"PerplexityBot",
	"cohere-ai",
	"Amazonbot",
	"YouBot",
	"Diffbot",
	"ImagesiftBot",
	"Timpibot",
	"Omgilibot",
	"Bytedance",
	"headless",      // chrome-headless-shell, HeadlessChrome
	"python-requests",
	"curl/",
	"wget/",
	"Go-http-client",
	"okhttp",
	"axios",
	"node-fetch",
	"libwww-perl",
	"Java/",
	"Scrapy",
	"Apache-HttpClient",
	"Jakarta Commons-HttpClient",
	"masscan",
	"nmap",
	"zgrab",
	"Nuclei",
	"SecurityScanner",
}

// genericBotTokens catches UAs that explicitly identify as automated but
// aren't on a named list.
var genericBotTokens = []string{
	"bot",
	"crawl",
	"spider",
	"slurp",
	"check_http",
	"monitoring",
	"pingdom",
	"uptime",
}
