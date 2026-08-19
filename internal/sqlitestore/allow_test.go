package sqlitestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/backend"
	"github.com/augustoroman/caddylogs/internal/classify"
	"github.com/augustoroman/caddylogs/internal/parser"
	"github.com/augustoroman/caddylogs/internal/sqlitestore"
)

// TestApplyUAAllow_ReclassifiesByUA verifies that ApplyUAAllow clears is_bot
// on rows whose user_agent contains the pattern (across the dynamic + static
// pools), moves matching rows back out of the malicious pool, and leaves
// non-matching rows untouched.
func TestApplyUAAllow_ReclassifiesByUA(t *testing.T) {
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

	const boxUA = "ScoreBox/2.1 (firmware-updater; curl/8.4)"
	now := time.Now()
	evs := []parser.Event{
		// Firmware box: bot UA → flagged is_bot at ingest. Dynamic + static.
		{Timestamp: now, Status: 200, Method: "GET", Host: "h", URI: "/fw", RemoteIP: "203.0.113.1", UserAgent: boxUA},
		{Timestamp: now.Add(1 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/logo.css", RemoteIP: "203.0.113.1", UserAgent: boxUA},
		// Another box, will be forced into the malicious pool below.
		{Timestamp: now.Add(2 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/fw2", RemoteIP: "203.0.113.2", UserAgent: boxUA},
		// Control: unrelated curl client, bot but not a scoring box.
		{Timestamp: now.Add(3 * time.Second), Status: 200, Method: "GET", Host: "h", URI: "/api/x", RemoteIP: "198.51.100.9", UserAgent: "curl/8.4"},
	}
	if err := store.Ingest(ctx, evs); err != nil {
		t.Fatal(err)
	}

	isBot := func(table backend.Table, ip string) (bool, bool) {
		r, err := store.Query(ctx, backend.Query{
			Table: table, Kind: backend.KindRows, Limit: 5,
			Filter: backend.Filter{Include: map[backend.Dimension][]string{backend.DimIP: {ip}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Rows) == 0 {
			return false, false
		}
		return r.Rows[0].IsBot, true
	}

	// Baseline: the box rows are bots, and so is the control.
	if bot, ok := isBot(backend.TableDynamic, "203.0.113.1"); !ok || !bot {
		t.Fatalf("baseline: box dynamic row should be a bot (ok=%v bot=%v)", ok, bot)
	}
	if bot, ok := isBot(backend.TableStatic, "203.0.113.1"); !ok || !bot {
		t.Fatalf("baseline: box static row should be a bot (ok=%v bot=%v)", ok, bot)
	}

	// Force 203.0.113.2 into the malicious pool so we exercise the
	// move-out-of-malicious path (a UA says a request is trusted, not evil).
	if err := store.ApplyManualTag(ctx, "203.0.113.2", classify.ManualTagMalicious); err != nil {
		t.Fatal(err)
	}
	if _, ok := isBot(backend.TableMalicious, "203.0.113.2"); !ok {
		t.Fatalf("setup: expected 203.0.113.2 in the malicious pool")
	}

	// Apply the allowlist for the distinctive token.
	n, err := store.ApplyUAAllow(ctx, "ScoreBox/")
	if err != nil {
		t.Fatal(err)
	}
	// 2 dynamic/static bot flips + 1 moved out of malicious = 3.
	if n != 3 {
		t.Errorf("ApplyUAAllow affected: got %d, want 3", n)
	}

	// Box rows are no longer bots.
	if bot, ok := isBot(backend.TableDynamic, "203.0.113.1"); !ok || bot {
		t.Errorf("after allow: box dynamic row still bot (ok=%v bot=%v)", ok, bot)
	}
	if bot, ok := isBot(backend.TableStatic, "203.0.113.1"); !ok || bot {
		t.Errorf("after allow: box static row still bot (ok=%v bot=%v)", ok, bot)
	}
	// The forced-malicious box row moved back to dynamic and is no longer a bot.
	if _, ok := isBot(backend.TableMalicious, "203.0.113.2"); ok {
		t.Errorf("after allow: 203.0.113.2 should have left the malicious pool")
	}
	if bot, ok := isBot(backend.TableDynamic, "203.0.113.2"); !ok || bot {
		t.Errorf("after allow: 203.0.113.2 should be a non-bot dynamic row (ok=%v bot=%v)", ok, bot)
	}
	// Control curl client is untouched.
	if bot, ok := isBot(backend.TableDynamic, "198.51.100.9"); !ok || !bot {
		t.Errorf("after allow: control curl client should still be a bot (ok=%v bot=%v)", ok, bot)
	}

	// LIKE metacharacters in a pattern must be matched literally, not as
	// wildcards — a pattern of "%" should not sweep up every row.
	n2, err := store.ApplyUAAllow(ctx, "%")
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf(`ApplyUAAllow("%%") should match no UA literally, affected %d`, n2)
	}
}
