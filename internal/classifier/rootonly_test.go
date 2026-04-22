package classifier_test

import (
	"context"
	"database/sql"
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

	day := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	mk := func(ip, uri string, hour int) parser.Event {
		return parser.Event{
			Timestamp: day.Add(time.Duration(hour) * time.Hour),
			Status:    200,
			Method:    "GET",
			Host:      "example.com",
			URI:       uri,
			RemoteIP:  ip,
			UserAgent: "Mozilla/5.0 (X11; Linux x86_64)", // not a known bot UA
		}
	}

	events := []parser.Event{
		// 1.1.1.1: 4 root hits, no static — candidate.
		mk("1.1.1.1", "/", 0), mk("1.1.1.1", "/", 1),
		mk("1.1.1.1", "/", 2), mk("1.1.1.1", "/", 3),

		// 2.2.2.2: 4 root hits AND one static hit — NOT a candidate.
		mk("2.2.2.2", "/", 0), mk("2.2.2.2", "/", 1),
		mk("2.2.2.2", "/", 2), mk("2.2.2.2", "/", 3),
		mk("2.2.2.2", "/style.css", 4),

		// 3.3.3.3: 4 root hits AND a non-root dynamic hit — NOT a candidate.
		mk("3.3.3.3", "/", 0), mk("3.3.3.3", "/", 1),
		mk("3.3.3.3", "/", 2), mk("3.3.3.3", "/", 3),
		mk("3.3.3.3", "/about", 4),

		// 4.4.4.4: only 3 root hits — below threshold, NOT a candidate.
		mk("4.4.4.4", "/", 0), mk("4.4.4.4", "/", 1), mk("4.4.4.4", "/", 2),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	decisions, err := classifier.NewRootOnly().Run(ctx, store.DB())
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

	want := map[string]bool{"1.1.1.1": true}
	for ip, expected := range map[string]bool{
		"1.1.1.1": true, "2.2.2.2": false,
		"3.3.3.3": false, "4.4.4.4": false,
	} {
		if flagged[ip] != expected {
			t.Errorf("ip %s flagged=%v, want %v", ip, flagged[ip], expected)
		}
	}
	if len(flagged) != len(want) {
		t.Errorf("flagged %d IPs, want exactly %d (%v)", len(flagged), len(want), flagged)
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
func (f *fakeClassifier) Run(ctx context.Context, _ *sql.DB) ([]classifier.Decision, error) {
	return f.candidates, nil
}
