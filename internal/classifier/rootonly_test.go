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

// TestRootOnly_FlagsBotsOnlyWhenAllConditionsMet exercises every
// qualifying/disqualifying path of the root-only classifier so that a
// regression in the SQL (a stray OR, a flipped join) surfaces as a
// specific flipped assertion rather than a silent mis-tag.
func TestRootOnly_FlagsBotsOnlyWhenAllConditionsMet(t *testing.T) {
	cls, err := classify.New(classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cls.Close()
	store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	day0 := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	mk := func(ip, uri string, offset time.Duration) parser.Event {
		return parser.Event{
			Timestamp: day0.Add(offset),
			Status:    200,
			Method:    "GET",
			Host:      "example.com",
			URI:       uri,
			RemoteIP:  ip,
			UserAgent: "Mozilla/5.0 (X11; Linux x86_64)", // not a known bot UA
		}
	}
	h := func(n int) time.Duration { return time.Duration(n) * time.Hour }
	d := func(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

	events := []parser.Event{
		// 1.1.1.1: 4 root hits in one day, no static — candidate (burst).
		mk("1.1.1.1", "/", h(0)), mk("1.1.1.1", "/", h(1)),
		mk("1.1.1.1", "/", h(2)), mk("1.1.1.1", "/", h(3)),

		// 2.2.2.2: 4 root hits AND one static hit — NOT a candidate.
		mk("2.2.2.2", "/", h(0)), mk("2.2.2.2", "/", h(1)),
		mk("2.2.2.2", "/", h(2)), mk("2.2.2.2", "/", h(3)),
		mk("2.2.2.2", "/style.css", h(4)),

		// 3.3.3.3: 4 root hits AND a non-root dynamic hit — NOT a candidate.
		mk("3.3.3.3", "/", h(0)), mk("3.3.3.3", "/", h(1)),
		mk("3.3.3.3", "/", h(2)), mk("3.3.3.3", "/", h(3)),
		mk("3.3.3.3", "/about", h(4)),

		// 4.4.4.4: 3 root hits in a single day — below burst threshold
		// and only spans one day, NOT a candidate.
		mk("4.4.4.4", "/", h(0)), mk("4.4.4.4", "/", h(1)), mk("4.4.4.4", "/", h(2)),

		// 5.5.5.5: one root hit on each of two distinct days, no
		// static — candidate (multi-day revisit).
		mk("5.5.5.5", "/", d(0)), mk("5.5.5.5", "/", d(3)),

		// 6.6.6.6: root hits on three days AND a static hit — NOT a
		// candidate (static disqualifies even though the multi-day
		// pattern matches).
		mk("6.6.6.6", "/", d(0)), mk("6.6.6.6", "/", d(1)),
		mk("6.6.6.6", "/", d(2)), mk("6.6.6.6", "/script.js", d(3)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	decisions, err := classifier.NewRootOnly().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}

	flagged := map[string]bool{}
	for _, d := range decisions {
		flagged[d.IP] = true
		if d.Tag != classify.ManualTagBot {
			t.Errorf("decision %s tag = %q, want bot", d.IP, d.Tag)
		}
	}

	want := map[string]bool{"1.1.1.1": true, "5.5.5.5": true}
	for ip, expected := range map[string]bool{
		"1.1.1.1": true, "2.2.2.2": false,
		"3.3.3.3": false, "4.4.4.4": false,
		"5.5.5.5": true, "6.6.6.6": false,
	} {
		if flagged[ip] != expected {
			t.Errorf("ip %s flagged=%v, want %v", ip, flagged[ip], expected)
		}
	}
	if len(flagged) != len(want) {
		t.Errorf("flagged %d IPs, want exactly %d (%v)", len(flagged), len(want), flagged)
	}
}

// TestRootOnly_IdempotentAcrossClaimed regresses the oscillation bug:
// when the runner passes the previously-claimed IPs through RunEnv,
// the classifier must still return them even though their rows now
// carry is_bot=1 (as a side effect of the prior ApplyManualTag). If
// it doesn't, every other run would untag them.
func TestRootOnly_IdempotentAcrossClaimed(t *testing.T) {
	cls, err := classify.New(classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cls.Close()
	store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	day := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		{Timestamp: day, Status: 200, Method: "GET", Host: "h", URI: "/", RemoteIP: "1.1.1.1"},
		{Timestamp: day.Add(time.Hour), Status: 200, Method: "GET", Host: "h", URI: "/", RemoteIP: "1.1.1.1"},
		{Timestamp: day.Add(2 * time.Hour), Status: 200, Method: "GET", Host: "h", URI: "/", RemoteIP: "1.1.1.1"},
		{Timestamp: day.Add(3 * time.Hour), Status: 200, Method: "GET", Host: "h", URI: "/", RemoteIP: "1.1.1.1"},
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Simulate the post-first-run state: mark all 1.1.1.1 rows is_bot=1
	// (what ApplyManualTag(bot) does) and verify the classifier still
	// returns the IP when told it's claimed.
	if err := store.ApplyManualTag(ctx, "1.1.1.1", classify.ManualTagBot); err != nil {
		t.Fatal(err)
	}

	// Without Claimed: SQL's is_bot=0 filter excludes the IP.
	got, err := classifier.NewRootOnly().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("no-claimed run: got %d decisions, want 0 (is_bot=1 excludes them)", len(got))
	}

	// With Claimed: the IP is re-included.
	got, err = classifier.NewRootOnly().Run(ctx, classifier.RunEnv{
		DB:      store.DB(),
		Claimed: []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "1.1.1.1" {
		t.Errorf("claimed run: got %+v, want 1.1.1.1 retained", got)
	}
}

// TestRunner_DiffAppliesAddsAndRemoves confirms the runner applies new
// candidates, removes IPs it previously tagged but no longer sees, and
// respects operator overrides.
func TestRunner_DiffAppliesAddsAndRemoves(t *testing.T) {
	cls, err := classify.New(classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cls.Close()
	store, err := sqlitestore.Open(sqlitestore.Options{Classifier: cls})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty set; pass a fake classifier so we can control the candidate
	// list without setting up data for the real SQL.
	tags := cls.ManualTags
	runner := classifier.NewRunner(store, tags)

	fake := &fakeClassifier{name: "fake", candidates: []classifier.Decision{
		{IP: "1.1.1.1", Tag: classify.ManualTagBot, Reason: "first run"},
		{IP: "2.2.2.2", Tag: classify.ManualTagBot, Reason: "first run"},
	}}

	res, err := runner.Run(ctx, fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 2 || len(res.Removed) != 0 {
		t.Fatalf("first run: added=%d removed=%d", len(res.Added), len(res.Removed))
	}
	if tag, ok := tags.Get("1.1.1.1"); !ok || tag != classify.ManualTagBot {
		t.Errorf("1.1.1.1 tag after run: %q/%v", tag, ok)
	}

	// Second run: 1.1.1.1 is still a candidate, 2.2.2.2 dropped, 3.3.3.3 new.
	fake.candidates = []classifier.Decision{
		{IP: "1.1.1.1", Tag: classify.ManualTagBot, Reason: "persistent"},
		{IP: "3.3.3.3", Tag: classify.ManualTagBot, Reason: "new"},
	}
	res, err = runner.Run(ctx, fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0].IP != "3.3.3.3" {
		t.Errorf("second-run adds: %+v", res.Added)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "2.2.2.2" {
		t.Errorf("second-run removes: %+v", res.Removed)
	}
	if _, ok := tags.Get("2.2.2.2"); ok {
		t.Errorf("2.2.2.2 should be untagged after it left the candidate list")
	}

	// Operator override: manually tag 3.3.3.3 as real. Classifier must
	// then leave 3.3.3.3 alone on re-run.
	if err := tags.Set("3.3.3.3", classify.ManualTagReal); err != nil {
		t.Fatal(err)
	}
	res, err = runner.Run(ctx, fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "3.3.3.3" {
		t.Errorf("skipped on manual override: %+v", res.Skipped)
	}
	if tag, _ := tags.Get("3.3.3.3"); tag != classify.ManualTagReal {
		t.Errorf("3.3.3.3 tag after manual override + run: %q, want real", tag)
	}
}

type fakeClassifier struct {
	name       string
	candidates []classifier.Decision
}

func (f *fakeClassifier) Name() string        { return f.name }
func (f *fakeClassifier) Description() string { return "test fake" }
func (f *fakeClassifier) Run(ctx context.Context, _ classifier.RunEnv) ([]classifier.Decision, error) {
	return f.candidates, nil
}
