package classifier_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	_ "modernc.org/sqlite"
)

// TestNoBrowserSession_RealDB runs the classifier against a real ingested DB
// when CADDYLOGS_REAL_DB points at one, and reports how many real-pool IPs it
// would demote vs. how many it spares as human. Opt-in (skipped otherwise) so
// it never runs in CI.
func TestNoBrowserSession_RealDB(t *testing.T) {
	path := os.Getenv("CADDYLOGS_REAL_DB")
	if path == "" {
		t.Skip("set CADDYLOGS_REAL_DB to a caddylogs .db to run")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// size of the real pool being scanned
	var realPool int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT ip FROM requests_dynamic WHERE is_local=0 AND is_bot=0
		UNION SELECT ip FROM requests_static WHERE is_local=0 AND is_bot=0)`).Scan(&realPool)

	got, err := classifier.NewNoBrowserSession().Run(ctx, classifier.RunEnv{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("real-pool IPs (is_bot=0): %d", realPool)
	t.Logf("no-browser-session would tag BOT: %d", len(got))
	t.Logf("spared as human (real): %d", realPool-len(got))
	for i, d := range got {
		if i >= 5 {
			break
		}
		t.Logf("  sample bot: %s — %s", d.IP, d.Reason)
	}
}
