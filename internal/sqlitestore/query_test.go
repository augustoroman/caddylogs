package sqlitestore

import (
	"testing"

	"github.com/augustoroman/caddylogs/internal/backend"
)

// TestBuildWhereUserAgentContains pins the raw-UA substring filter: it
// must target the user_agent column with an escaped LIKE pattern.
func TestBuildWhereUserAgentContains(t *testing.T) {
	where, args, err := buildWhere(backend.Filter{
		Contains: map[backend.Dimension][]string{backend.DimUserAgent: {"skvrs-app/1.7"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := ` WHERE "user_agent" LIKE ? ESCAPE '\'`
	if where != want {
		t.Errorf("where = %q, want %q", where, want)
	}
	if len(args) != 1 || args[0] != "%skvrs-app/1.7%" {
		t.Errorf("args = %#v", args)
	}
}
