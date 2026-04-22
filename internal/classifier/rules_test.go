package classifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// newTestStore is a small helper that a bunch of these tests share.
func newTestStore(t *testing.T) (*sqlitestore.Store, *classify.Classifier, context.Context, func()) {
	t.Helper()
	cls, err := classify.New(classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	if err != nil {
		cls.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	return store, cls, ctx, func() { cancel(); store.Close(); cls.Close() }
}

// humanBrowser builds an event with a plausibly-real user agent so the
// classifier's is_bot=0 filter doesn't accidentally hide test fixtures.
func humanBrowser(ip, uri, method, proto string, ts time.Time) parser.Event {
	return parser.Event{
		Timestamp: ts, Status: 200, Method: method, Host: "example.com",
		URI: uri, RemoteIP: ip, Proto: proto,
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
	}
}

// TestNoStaticEver_FlagsHTMLScrapers covers the broader-than-root-only
// path: the candidate visits multiple real URIs but never a static
// asset, while the control has one static hit and stays clean.
func TestNoStaticEver_FlagsHTMLScrapers(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		// 1.1.1.1: 6 varied dynamic hits, no static — candidate.
		humanBrowser("1.1.1.1", "/", "GET", "HTTP/2.0", base),
		humanBrowser("1.1.1.1", "/about", "GET", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("1.1.1.1", "/blog/1", "GET", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("1.1.1.1", "/blog/2", "GET", "HTTP/2.0", base.Add(3*time.Minute)),
		humanBrowser("1.1.1.1", "/blog/3", "GET", "HTTP/2.0", base.Add(4*time.Minute)),
		humanBrowser("1.1.1.1", "/blog/4", "GET", "HTTP/2.0", base.Add(5*time.Minute)),

		// 2.2.2.2: same pattern but with a real static hit — not a candidate.
		humanBrowser("2.2.2.2", "/", "GET", "HTTP/2.0", base),
		humanBrowser("2.2.2.2", "/about", "GET", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("2.2.2.2", "/blog/1", "GET", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("2.2.2.2", "/blog/2", "GET", "HTTP/2.0", base.Add(3*time.Minute)),
		humanBrowser("2.2.2.2", "/blog/3", "GET", "HTTP/2.0", base.Add(4*time.Minute)),
		humanBrowser("2.2.2.2", "/blog/4", "GET", "HTTP/2.0", base.Add(5*time.Minute)),
		humanBrowser("2.2.2.2", "/style.css", "GET", "HTTP/2.0", base.Add(6*time.Minute)),

		// 3.3.3.3: 6 hits + a favicon fetch — favicon is in the ignore
		// list, so this one IS a candidate.
		humanBrowser("3.3.3.3", "/", "GET", "HTTP/2.0", base),
		humanBrowser("3.3.3.3", "/a", "GET", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("3.3.3.3", "/b", "GET", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("3.3.3.3", "/c", "GET", "HTTP/2.0", base.Add(3*time.Minute)),
		humanBrowser("3.3.3.3", "/d", "GET", "HTTP/2.0", base.Add(4*time.Minute)),
		humanBrowser("3.3.3.3", "/e", "GET", "HTTP/2.0", base.Add(5*time.Minute)),
		humanBrowser("3.3.3.3", "/favicon.ico", "GET", "HTTP/2.0", base.Add(6*time.Minute)),

		// 4.4.4.4: only 3 dynamic hits — below MinHits, not a candidate.
		humanBrowser("4.4.4.4", "/", "GET", "HTTP/2.0", base),
		humanBrowser("4.4.4.4", "/a", "GET", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("4.4.4.4", "/b", "GET", "HTTP/2.0", base.Add(2*time.Minute)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := classifier.NewNoStaticEver().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, d := range got {
		flagged[d.IP] = true
	}
	for ip, want := range map[string]bool{
		"1.1.1.1": true, "2.2.2.2": false,
		"3.3.3.3": true, "4.4.4.4": false,
	} {
		if flagged[ip] != want {
			t.Errorf("no-static-ever ip %s flagged=%v, want %v", ip, flagged[ip], want)
		}
	}
}

// TestCadencePolling_FlagsRegularIntervals uses clean 60s intervals
// for a bot and a mix of short/long gaps for a human control.
func TestCadencePolling_FlagsRegularIntervals(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)

	// 1.1.1.1: every 60s for 8 hits — CV ~= 0, candidate.
	var events []parser.Event
	for i := 0; i < 10; i++ {
		events = append(events, humanBrowser("1.1.1.1", "/health",
			"GET", "HTTP/2.0", base.Add(time.Duration(i)*time.Minute)))
	}
	// 2.2.2.2: irregular intervals (30s, 300s, 90s, 10s, ...) — not
	// a candidate even though total hits is plenty.
	offsets := []int{0, 30, 330, 420, 430, 2000, 2700, 5000, 9000, 14000}
	for _, sec := range offsets {
		events = append(events, humanBrowser("2.2.2.2", "/page",
			"GET", "HTTP/2.0", base.Add(time.Duration(sec)*time.Second)))
	}
	// 3.3.3.3: regular but only 5 hits total — below MinIntervals.
	for i := 0; i < 5; i++ {
		events = append(events, humanBrowser("3.3.3.3", "/x",
			"GET", "HTTP/2.0", base.Add(time.Duration(i)*time.Minute)))
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := classifier.NewCadencePolling().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, d := range got {
		flagged[d.IP] = true
	}
	for ip, want := range map[string]bool{
		"1.1.1.1": true, "2.2.2.2": false, "3.3.3.3": false,
	} {
		if flagged[ip] != want {
			t.Errorf("cadence ip %s flagged=%v, want %v", ip, flagged[ip], want)
		}
	}
}

// TestHeadOnly_FlagsAllHead verifies both tables are considered.
func TestHeadOnly_FlagsAllHead(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()
	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		// 1.1.1.1: 4 HEADs — candidate.
		humanBrowser("1.1.1.1", "/", "HEAD", "HTTP/2.0", base),
		humanBrowser("1.1.1.1", "/", "HEAD", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("1.1.1.1", "/", "HEAD", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("1.1.1.1", "/", "HEAD", "HTTP/2.0", base.Add(3*time.Minute)),

		// 2.2.2.2: 3 HEADs + 1 GET /favicon.ico in static — a single
		// non-HEAD kicks it out.
		humanBrowser("2.2.2.2", "/", "HEAD", "HTTP/2.0", base),
		humanBrowser("2.2.2.2", "/", "HEAD", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("2.2.2.2", "/", "HEAD", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("2.2.2.2", "/favicon.ico", "GET", "HTTP/2.0", base.Add(3*time.Minute)),

		// 3.3.3.3: 3 HEADs — below MinHits.
		humanBrowser("3.3.3.3", "/", "HEAD", "HTTP/2.0", base),
		humanBrowser("3.3.3.3", "/", "HEAD", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("3.3.3.3", "/", "HEAD", "HTTP/2.0", base.Add(2*time.Minute)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := classifier.NewHeadOnly().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, d := range got {
		flagged[d.IP] = true
	}
	for ip, want := range map[string]bool{
		"1.1.1.1": true, "2.2.2.2": false, "3.3.3.3": false,
	} {
		if flagged[ip] != want {
			t.Errorf("head-only ip %s flagged=%v, want %v", ip, flagged[ip], want)
		}
	}
}

// TestHTTP10Only_FlagsLegacyClients regresses the proto filter.
func TestHTTP10Only_FlagsLegacyClients(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()
	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		// 1.1.1.1: 4 HTTP/1.0 requests — candidate.
		humanBrowser("1.1.1.1", "/", "GET", "HTTP/1.0", base),
		humanBrowser("1.1.1.1", "/a", "GET", "HTTP/1.0", base.Add(time.Minute)),
		humanBrowser("1.1.1.1", "/b", "GET", "HTTP/1.0", base.Add(2*time.Minute)),
		humanBrowser("1.1.1.1", "/c", "GET", "HTTP/1.0", base.Add(3*time.Minute)),

		// 2.2.2.2: mostly HTTP/1.0 but one HTTP/1.1 — disqualified.
		humanBrowser("2.2.2.2", "/", "GET", "HTTP/1.0", base),
		humanBrowser("2.2.2.2", "/a", "GET", "HTTP/1.0", base.Add(time.Minute)),
		humanBrowser("2.2.2.2", "/b", "GET", "HTTP/1.0", base.Add(2*time.Minute)),
		humanBrowser("2.2.2.2", "/c", "GET", "HTTP/1.1", base.Add(3*time.Minute)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}
	got, err := classifier.NewHTTP10Only().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, d := range got {
		flagged[d.IP] = true
	}
	if !flagged["1.1.1.1"] || flagged["2.2.2.2"] {
		t.Errorf("http10-only flagged=%v, want only 1.1.1.1", flagged)
	}
}

// TestRunner_SkipsIPsOwnedByOtherClassifier: once classifier A claims
// an IP, classifier B sees it in Skipped and leaves the tag alone.
// This is the guardrail that keeps overlapping rules (root-only ⊂
// no-static-ever) from oscillating ownership.
func TestRunner_SkipsIPsOwnedByOtherClassifier(t *testing.T) {
	_, cls, ctx, cleanup := newTestStore(t)
	defer cleanup()
	store, _ := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	defer store.Close()

	runner := classifier.NewRunner(store, cls.ManualTags)
	// Classifier A tags 1.1.1.1.
	a := &ownershipFake{name: "A", candidates: []classifier.Decision{
		{IP: "1.1.1.1", Tag: classify.ManualTagBot, Reason: "a"},
	}}
	if _, err := runner.Run(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Classifier B now wants the same IP.
	b := &ownershipFake{name: "B", candidates: []classifier.Decision{
		{IP: "1.1.1.1", Tag: classify.ManualTagBot, Reason: "b"},
	}}
	res, err := runner.Run(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 0 {
		t.Errorf("B added = %+v, want empty (owned by A)", res.Added)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "1.1.1.1" {
		t.Errorf("B skipped = %+v, want [1.1.1.1]", res.Skipped)
	}
	// Source must still be A.
	entries := cls.ManualTags.ListBySource("A")
	if len(entries) != 1 {
		t.Errorf("tag ownership leaked: ListBySource(A) = %+v", entries)
	}
}

type ownershipFake struct {
	name       string
	candidates []classifier.Decision
}

func (f *ownershipFake) Name() string        { return f.name }
func (f *ownershipFake) Description() string { return "test" }
func (f *ownershipFake) Run(ctx context.Context, _ classifier.RunEnv) ([]classifier.Decision, error) {
	return f.candidates, nil
}
