package classifier_test

import (
	"strings"
	"testing"
	"time"

	"github.com/augustoroman/caddylogs/internal/classifier"
	"github.com/augustoroman/caddylogs/internal/parser"
)

// TestProbeOnlyURI_PartialIndexUsed regresses the planner-match contract
// that powers the optimization: the partial indexes built by
// EnsureIndexes are only useful if SQLite's query planner actually picks
// them when Run() executes its query. The planner is sensitive to the
// exact shape of the WHERE clause (uri IN (...) AND is_local = 0) — if
// the SQL or the DDL drift apart the query silently falls back to a
// full scan and the slowness this rewrite was meant to fix returns. The
// cheapest insurance is asserting via EXPLAIN QUERY PLAN that the
// partial index appears in the plan for the candidate-step shape.
func TestProbeOnlyURI_PartialIndexUsed(t *testing.T) {
	store, _, ctx, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	if err := store.Ingest(ctx, []parser.Event{
		humanBrowser("1.1.1.1", "/.well-known/traffic-advice", "GET", "HTTP/2.0", base),
		humanBrowser("2.2.2.2", "/about", "GET", "HTTP/2.0", base),
	}); err != nil {
		t.Fatal(err)
	}
	if err := classifier.NewProbeOnlyURI().EnsureIndexes(ctx, store.DB()); err != nil {
		t.Fatal(err)
	}

	// Mirror the WHERE shape the rewritten Run() uses for the candidate
	// step so the planner has a real chance to use the partial index.
	rows, err := store.DB().QueryContext(ctx, `
EXPLAIN QUERY PLAN
SELECT ip FROM requests_dynamic
 WHERE uri IN ('/.well-known/traffic-advice', '/ip', '/cdn-cgi/trace',
               '/.vscode/sftp.json', '/sftp-config.json', '/sitemap.xml',
               '/vendor/phpunit/phpunit/phpunit.xsd', '/my-account/', '/')
   AND is_local = 0`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	if !strings.Contains(plan.String(), "idx_dyn_probe_uri") {
		t.Errorf("planner did not use idx_dyn_probe_uri; plan was:\n%s", plan.String())
	}
}
