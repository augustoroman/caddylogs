package classifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"

	"github.com/augustoroman/caddylogs/internal/classifier"
)

// TestRunner_SkipsAllowlistedIPs verifies the runner drops IPs whose traffic
// matches an allowlisted UA from a classifier's candidate set, and reverts an
// already-owned tag when its IP later becomes allowlisted. Without this, a
// behavioral rule (which sees a firmware box as bot-like) would keep undoing
// the allowlist's is_bot=0.
func TestRunner_SkipsAllowlistedIPs(t *testing.T) {
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

	// Seed rows so AllowlistedIPs has UAs to match against: a scoring box and
	// an unrelated curl client.
	now := time.Now()
	if err := store.Ingest(ctx, []parser.Event{
		{Timestamp: now, Status: 200, Method: "GET", Host: "h", URI: "/fw", RemoteIP: "5.5.5.5", UserAgent: "ScoreBox/2.1 (curl/8.4)"},
		{Timestamp: now.Add(time.Second), Status: 404, Method: "GET", Host: "h", URI: "/x", RemoteIP: "6.6.6.6", UserAgent: "curl/8.4"},
	}); err != nil {
		t.Fatal(err)
	}

	runner := classifier.NewRunner(store, cls.ManualTags, cls.Allow)
	fake := &fakeClassifier{name: "fake", candidates: []classifier.Decision{
		{IP: "5.5.5.5", Tag: classify.ManualTagBot, Reason: "behaves like a bot"},
		{IP: "6.6.6.6", Tag: classify.ManualTagBot, Reason: "behaves like a bot"},
	}}

	// First run, no allowlist: both flagged.
	res, err := runner.Run(ctx, fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 2 {
		t.Fatalf("no allowlist: expected both flagged, added=%d", len(res.Added))
	}

	// Allowlist the scoring box, re-run: 5.5.5.5 is dropped from candidates
	// (skipped) and its prior classifier tag is reverted; 6.6.6.6 stays.
	if err := cls.Allow.Add("ScoreBox/", ""); err != nil {
		t.Fatal(err)
	}
	res, err = runner.Run(ctx, fake)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Skipped, "5.5.5.5") {
		t.Errorf("5.5.5.5 should be skipped as allowlisted, skipped=%v", res.Skipped)
	}
	if !contains(res.Removed, "5.5.5.5") {
		t.Errorf("5.5.5.5 prior tag should be reverted, removed=%v", res.Removed)
	}
	if _, ok := cls.ManualTags.Get("5.5.5.5"); ok {
		t.Errorf("5.5.5.5 should no longer carry a classifier tag")
	}
	if tag, ok := cls.ManualTags.Get("6.6.6.6"); !ok || tag != classify.ManualTagBot {
		t.Errorf("6.6.6.6 should stay bot-tagged, got %q/%v", tag, ok)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
