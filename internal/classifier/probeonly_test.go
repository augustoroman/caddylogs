package classifier_test

import (
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
)

// TestProbeOnlyURI_FlagsSingleRequestProbers exercises the happy path
// plus every disqualifying shape: a probe hit alongside real activity,
// real activity alone, and probe hits from a locally-classified IP.
func TestProbeOnlyURI_FlagsSingleRequestProbers(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		// 1.1.1.1: single probe request to a bot-tagged URI — candidate (bot).
		humanBrowser("1.1.1.1", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base),

		// 2.2.2.2: single probe request to a malicious-tagged URI — candidate (malicious).
		humanBrowser("2.2.2.2", "/ip", "GET", "HTTP/2.0", base),

		// 3.3.3.3: both a bot probe and a malicious probe — candidate,
		// most-severe wins → malicious.
		humanBrowser("3.3.3.3", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base),
		humanBrowser("3.3.3.3", "/ip", "GET", "HTTP/2.0", base.Add(time.Minute)),

		// 4.4.4.4: probe + one real dynamic hit — NOT a candidate.
		humanBrowser("4.4.4.4", "/ip", "GET", "HTTP/2.0", base),
		humanBrowser("4.4.4.4", "/about", "GET", "HTTP/2.0", base.Add(time.Minute)),

		// 5.5.5.5: probe + one static hit — NOT a candidate.
		humanBrowser("5.5.5.5", "/ip", "GET", "HTTP/2.0", base),
		humanBrowser("5.5.5.5", "/style.css", "GET", "HTTP/2.0", base.Add(time.Minute)),

		// 6.6.6.6: real activity only — NOT a candidate.
		humanBrowser("6.6.6.6", "/", "GET", "HTTP/2.0", base),
		humanBrowser("6.6.6.6", "/about", "GET", "HTTP/2.0", base.Add(time.Minute)),

		// 7.7.7.7: multiple probe hits to the same URI — candidate (bot).
		humanBrowser("7.7.7.7", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base),
		humanBrowser("7.7.7.7", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base.Add(time.Hour)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	decisions, err := classifier.NewProbeOnlyURI().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]classify.ManualTag{}
	for _, d := range decisions {
		got[d.IP] = d.Tag
	}

	want := map[string]classify.ManualTag{
		"1.1.1.1": classify.ManualTagBot,
		"2.2.2.2": classify.ManualTagMalicious,
		"3.3.3.3": classify.ManualTagMalicious,
		"7.7.7.7": classify.ManualTagBot,
	}
	for ip, tag := range want {
		if got[ip] != tag {
			t.Errorf("ip %s tag=%q, want %q", ip, got[ip], tag)
		}
	}
	for _, ip := range []string{"4.4.4.4", "5.5.5.5", "6.6.6.6"} {
		if _, ok := got[ip]; ok {
			t.Errorf("ip %s was flagged, want no decision", ip)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d decisions, want %d (%v)", len(got), len(want), got)
	}
}

// TestProbeOnlyURI_IdempotentAcrossClaimed regresses the oscillation
// bug for both bot and malicious tags. A probe IP tagged bot stays in
// requests_dynamic with is_bot=1; a probe IP tagged malicious has its
// rows physically moved into requests_malicious. Both paths must be
// re-included when the runner passes the IP in Claimed, otherwise the
// next run would untag and bounce them.
func TestProbeOnlyURI_IdempotentAcrossClaimed(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		humanBrowser("1.1.1.1", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base),
		humanBrowser("2.2.2.2", "/ip", "GET", "HTTP/2.0", base),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	// First run would tag 1.1.1.1 bot and 2.2.2.2 malicious. Simulate
	// the post-run state directly so the test doesn't depend on the
	// Runner wiring.
	if err := store.ApplyManualTag(ctx, "1.1.1.1", classify.ManualTagBot); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyManualTag(ctx, "2.2.2.2", classify.ManualTagMalicious); err != nil {
		t.Fatal(err)
	}

	// Without Claimed: both IPs are filtered out (is_bot=1 for 1.1.1.1;
	// rows moved to requests_malicious for 2.2.2.2).
	got, err := classifier.NewProbeOnlyURI().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("no-claimed run: got %d decisions, want 0", len(got))
	}

	// With Claimed: both IPs come back with their original tags.
	got, err = classifier.NewProbeOnlyURI().Run(ctx, classifier.RunEnv{
		DB:      store.DB(),
		Claimed: []string{"1.1.1.1", "2.2.2.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]classify.ManualTag{}
	for _, d := range got {
		byIP[d.IP] = d.Tag
	}
	if byIP["1.1.1.1"] != classify.ManualTagBot {
		t.Errorf("1.1.1.1 after reclaim: tag=%q, want bot", byIP["1.1.1.1"])
	}
	if byIP["2.2.2.2"] != classify.ManualTagMalicious {
		t.Errorf("2.2.2.2 after reclaim: tag=%q, want malicious", byIP["2.2.2.2"])
	}
}
