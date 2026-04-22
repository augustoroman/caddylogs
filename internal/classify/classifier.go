package classify

import (
	"github.com/augustoroman/caddylogs/internal/parser"
)

// Classified is the per-event labeling produced by a Classifier.
type Classified struct {
	parser.Event
	IsBot    bool
	IsLocal  bool
	IsStatic bool
	Browser  string
	OS       string
	Device   string
	Country  string
	City     string
}

// Classifier bundles all the labelers so a caller can pass one object to the
// backend and get every derived attribute filled in.
type Classifier struct {
	Bots   *BotDetector
	Static *StaticMatcher
	Geo    *Geo
}

// NewClassifier builds a Classifier with default settings. Extensions can be
// overridden via opts; pass a nil *Geo to disable geo lookups.
type Options struct {
	StaticExtensions []string // nil means use DefaultStaticExtensions
	GeoIPPath        string   // empty means no geo lookups
	ExtraBotPatterns []string
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
	geo, err := OpenGeo(opts.GeoIPPath)
	if err != nil {
		return nil, err
	}
	return &Classifier{
		Bots:   bots,
		Static: NewStaticMatcher(exts),
		Geo:    geo,
	}, nil
}

// Close releases resources held by the classifier (currently just the GeoIP
// DB).
func (c *Classifier) Close() error {
	return c.Geo.Close()
}

// Classify returns the full labeling for an event.
func (c *Classifier) Classify(ev parser.Event) Classified {
	ua := ParseUA(ev.UserAgent)
	country, city := c.Geo.Lookup(ev.RemoteIP)
	return Classified{
		Event:    ev,
		IsBot:    c.Bots.IsBot(ev.UserAgent),
		IsLocal:  IsLocalIP(ev.RemoteIP),
		IsStatic: c.Static.IsStatic(ev.URI),
		Browser:  ua.Browser,
		OS:       ua.OS,
		Device:   ua.Device,
		Country:  country,
		City:     city,
	}
}
