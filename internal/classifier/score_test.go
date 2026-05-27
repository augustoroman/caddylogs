package classifier_test

import (
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
)

// runScore ingests events, runs the given Score rule, and returns the
// per-IP tag it assigned (zero value when not flagged).
func runScore(t *testing.T, s *classifier.Score, events []parser.Event) map[string]classify.ManualTag {
	t.Helper()
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}
	got, err := s.Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]classify.ManualTag{}
	for _, d := range got {
		tags[d.IP] = d.Tag
	}
	return tags
}

// TestScore_BoxesSingleAttackProbe: a lone .env or .php hit mixed into
// otherwise-normal traffic must box the IP as malicious — the gap the
// behavioral promoter leaves because it needs repeat hits.
func TestScore_BoxesSingleAttackProbe(t *testing.T) {
	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	events := []parser.Event{
		// 1.1.1.1: one /.env (attack.list match) — malicious.
		humanBrowser("1.1.1.1", "/.env", "GET", "HTTP/2.0", base),
		// 2.2.2.2: one /shell.php — malicious via the .php weight.
		humanBrowser("2.2.2.2", "/wp-content/shell.php", "GET", "HTTP/2.0", base),
		// 3.3.3.3: five ordinary page views — stays clean.
		humanBrowser("3.3.3.3", "/", "GET", "HTTP/2.0", base),
		humanBrowser("3.3.3.3", "/about", "GET", "HTTP/2.0", base.Add(time.Minute)),
		humanBrowser("3.3.3.3", "/blog/1", "GET", "HTTP/2.0", base.Add(2*time.Minute)),
		humanBrowser("3.3.3.3", "/blog/2", "GET", "HTTP/2.0", base.Add(3*time.Minute)),
		humanBrowser("3.3.3.3", "/blog/3", "GET", "HTTP/2.0", base.Add(4*time.Minute)),
	}
	tags := runScore(t, classifier.NewScore(), events)
	if tags["1.1.1.1"] != classify.ManualTagMalicious {
		t.Errorf("1.1.1.1 (/.env) = %q, want malicious", tags["1.1.1.1"])
	}
	if tags["2.2.2.2"] != classify.ManualTagMalicious {
		t.Errorf("2.2.2.2 (.php) = %q, want malicious", tags["2.2.2.2"])
	}
	if _, flagged := tags["3.3.3.3"]; flagged {
		t.Errorf("3.3.3.3 (clean) = %q, want unflagged", tags["3.3.3.3"])
	}
}

// TestScore_BurstScraperIsBotThenDecays: a rapid burst boxes the IP as a
// bot (behavioral, not attack); the same burst followed by enough quiet
// normal traffic decays the score back below threshold and un-boxes it.
func TestScore_BurstScraperIsBotThenDecays(t *testing.T) {
	s := classifier.NewScore()
	s.Threshold = 10 // keep the fixture small; net +1 per rapid hit

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	var events []parser.Event
	// 1.1.1.1: 20 hits 100ms apart -> ~19 rapid net points -> boxed bot,
	// then 30 slow normal hits (>1s apart) decay it back to 0.
	for i := 0; i < 20; i++ {
		events = append(events, humanBrowser("1.1.1.1", "/firmware/f.uf2",
			"GET", "HTTP/2.0", base.Add(time.Duration(i)*100*time.Millisecond)))
	}
	quiet := base.Add(time.Hour)
	for i := 0; i < 30; i++ {
		events = append(events, humanBrowser("1.1.1.1", "/page",
			"GET", "HTTP/2.0", quiet.Add(time.Duration(i)*time.Minute)))
	}
	// 2.2.2.2: the same 20-hit burst with no trailing quiet traffic —
	// stays boxed as a bot.
	for i := 0; i < 20; i++ {
		events = append(events, humanBrowser("2.2.2.2", "/firmware/f.uf2",
			"GET", "HTTP/2.0", base.Add(time.Duration(i)*100*time.Millisecond)))
	}
	tags := runScore(t, s, events)
	if _, flagged := tags["1.1.1.1"]; flagged {
		t.Errorf("1.1.1.1 (burst then quiet) = %q, want unflagged (decayed)", tags["1.1.1.1"])
	}
	if tags["2.2.2.2"] != classify.ManualTagBot {
		t.Errorf("2.2.2.2 (burst) = %q, want bot", tags["2.2.2.2"])
	}
}

// TestScore_NoBanking: a long clean history (clamped at 0) must NOT
// immunize an IP against a later probe. With a naive un-clamped sum the
// credit would absorb the +100 and the probe would slip through.
func TestScore_NoBanking(t *testing.T) {
	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	var events []parser.Event
	// 50 clean page views first (running floors at 0), THEN one /.env.
	for i := 0; i < 50; i++ {
		events = append(events, humanBrowser("1.1.1.1", "/page",
			"GET", "HTTP/2.0", base.Add(time.Duration(i)*time.Minute)))
	}
	events = append(events, humanBrowser("1.1.1.1", "/.env",
		"GET", "HTTP/2.0", base.Add(time.Hour)))
	tags := runScore(t, classifier.NewScore(), events)
	if tags["1.1.1.1"] != classify.ManualTagMalicious {
		t.Errorf("1.1.1.1 (clean history then /.env) = %q, want malicious", tags["1.1.1.1"])
	}
}
