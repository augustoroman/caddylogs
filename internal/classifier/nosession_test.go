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

// TestNoBrowserSession exercises the positive-human inversion: an IP is spared
// only when a visitor_hash session shows a real render (page + asset burst) or a
// same-origin referer chain; everyone else in the real pool is tagged bot.
func TestNoBrowserSession(t *testing.T) {
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

	t0 := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	const ua = "Mozilla/5.0 (X11; Linux x86_64)" // browser UA, not a known bot
	mk := func(ip, uri, ref string, off time.Duration) parser.Event {
		return parser.Event{
			Timestamp: t0.Add(off), Status: 200, Method: "GET", Host: "example.com",
			URI: uri, RemoteIP: ip, UserAgent: ua, Referer: ref,
		}
	}
	sec := func(n int) time.Duration { return time.Duration(n) * time.Second }
	self := "https://example.com/page"

	events := []parser.Event{
		// real-burst: page then 3 assets within ~1s -> browser render.
		mk("1.1.1.1", "/page", "", sec(0)),
		mk("1.1.1.1", "/main.css", self, sec(1)),
		mk("1.1.1.1", "/app.js", self, sec(1)),
		mk("1.1.1.1", "/logo.png", self, sec(1)),

		// real-referer-chain: 3 same-origin-referer assets, no burst timing.
		mk("2.2.2.2", "/a.css", self, sec(0)),
		mk("2.2.2.2", "/b.js", self, sec(30)),
		mk("2.2.2.2", "/c.png", self, sec(60)),

		// bot-spoof: lone page GET, browser UA, no assets, no referer.
		mk("3.3.3.3", "/page", "", sec(0)),

		// bot-thin: page + only 2 assets (< burst threshold), no referer.
		mk("4.4.4.4", "/page", "", sec(0)),
		mk("4.4.4.4", "/x.css", "", sec(1)),
		mk("4.4.4.4", "/y.js", "", sec(1)),

		// bot-foreign-referer: 3 assets but referer is a different origin.
		mk("5.5.5.5", "/a.css", "https://evil.example.net/", sec(0)),
		mk("5.5.5.5", "/b.js", "https://evil.example.net/", sec(1)),
		mk("5.5.5.5", "/c.png", "https://evil.example.net/", sec(2)),
	}
	if err := store.Ingest(ctx, events); err != nil {
		t.Fatal(err)
	}

	got, err := classifier.NewNoBrowserSession().Run(ctx, classifier.RunEnv{DB: store.DB()})
	if err != nil {
		t.Fatal(err)
	}
	tagged := map[string]bool{}
	for _, d := range got {
		if d.Tag != classify.ManualTagBot {
			t.Errorf("%s tagged %q, want bot", d.IP, d.Tag)
		}
		tagged[d.IP] = true
	}

	spared := []string{"1.1.1.1", "2.2.2.2"}
	flagged := []string{"3.3.3.3", "4.4.4.4", "5.5.5.5"}
	for _, ip := range spared {
		if tagged[ip] {
			t.Errorf("%s tagged bot, want spared (has a browser session)", ip)
		}
	}
	for _, ip := range flagged {
		if !tagged[ip] {
			t.Errorf("%s not tagged, want bot (no browser session)", ip)
		}
	}
}
