package classify

import (
	"os"

	"github.com/augustoroman/caddylogs/internal/parser"
)

func readAttackFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Classified is the per-event labeling produced by a Classifier.
type Classified struct {
	parser.Event
	IsBot           bool
	IsLocal         bool
	IsStatic        bool
	IsMalicious     bool
	MaliciousReason string // empty when IsMalicious=false
	Browser         string
	OS              string
	Device          string
	Country         string
	City            string
}

// Classifier bundles all the labelers so a caller can pass one object to the
// backend and get every derived attribute filled in.
type Classifier struct {
	Bots    *BotDetector
	Static  *StaticMatcher
	Attacks *AttackMatcher // may be nil when attack detection is disabled
	Geo     *Geo
}

// Options configures New().
type Options struct {
	StaticExtensions []string // nil means use DefaultStaticExtensions
	GeoIPPath        string   // empty means no geo lookups
	ExtraBotPatterns []string
	AttackPatterns   []string // extra substring/regex patterns
	AttackListPath   string   // if non-empty, REPLACES embedded defaults
	DisableAttacks   bool     // skip attack detection entirely
}

// New builds a Classifier from Options.
func New(opts Options) (*Classifier, error) {
	exts := opts.StaticExtensions
	if exts == nil {
		exts = DefaultStaticExtensions
	}
	bots := DefaultBots()
	if len(opts.ExtraBotPatterns) > 0 {
		bots.AddPatterns(opts.ExtraBotPatterns)
	}
	var attacks *AttackMatcher
	if !opts.DisableAttacks {
		if opts.AttackListPath != "" {
			attacks = NewAttackMatcher(nil)
			data, err := readAttackFile(opts.AttackListPath)
			if err != nil {
				return nil, err
			}
			attacks.AddPatternFile(data)
		} else {
			attacks = DefaultAttacks()
		}
		if len(opts.AttackPatterns) > 0 {
			attacks.AddPatterns(opts.AttackPatterns)
		}
	}
	geo, err := OpenGeo(opts.GeoIPPath)
	if err != nil {
		return nil, err
	}
	return &Classifier{
		Bots:    bots,
		Static:  NewStaticMatcher(exts),
		Attacks: attacks,
		Geo:     geo,
	}, nil
}

// Close releases resources held by the classifier (currently just the GeoIP
// DB).
func (c *Classifier) Close() error {
	return c.Geo.Close()
}

// Classify returns the full labeling for an event. It checks in order:
// known-bad IP set (fast path), URI attack patterns (tags and flags the IP),
// then the orthogonal static / bot / local / geo dimensions.
func (c *Classifier) Classify(ev parser.Event) Classified {
	ua := ParseUA(ev.UserAgent)
	country, city := c.Geo.Lookup(ev.RemoteIP)
	isMal := false
	reason := ""
	if c.Attacks != nil {
		if r, ok := c.Attacks.IPReason(ev.RemoteIP); ok {
			isMal = true
			reason = "ip_flag:" + r
		} else if r, ok := c.Attacks.MatchURI(ev.URI); ok {
			isMal = true
			reason = r
			c.Attacks.FlagIP(ev.RemoteIP, r)
		}
	}
	return Classified{
		Event:           ev,
		IsBot:           c.Bots.IsBot(ev.UserAgent),
		IsLocal:         IsLocalIP(ev.RemoteIP),
		IsStatic:        c.Static.IsStatic(ev.URI),
		IsMalicious:     isMal,
		MaliciousReason: reason,
		Browser:         ua.Browser,
		OS:              ua.OS,
		Device:          ua.Device,
		Country:         country,
		City:            city,
	}
}
