package classify

import "testing"

func TestDefaultAttacks(t *testing.T) {
	m := DefaultAttacks()
	cases := []struct {
		uri      string
		wantHit  bool
		wantSub  string // substring expected in reason, "" = don't care
	}{
		{"/wp-login.php", true, "wordpress"},
		{"/wp-includes/images/smilies/about.php", true, ""},
		{"/rh.php", true, ""}, // matches script-extension regex
		{"/.env", true, "env"},
		{"/.env.production", true, ""},
		{"/phpmyadmin/index.php", true, ""},
		{"/server-status", true, "server-info"},
		{"/actuator/env", true, "actuator"},
		{"/GponForm/diag_Form", true, "router"},
		{"/autodiscover/autodiscover.xml", true, "exchange"},
		{"/index.html", false, ""},
		{"/api/v1/users", false, ""},
		{"/style.css?v=1", false, ""},
		{"/favicon.ico", false, ""},
		{"", false, ""},
	}
	for _, tc := range cases {
		got, ok := m.MatchURI(tc.uri)
		if ok != tc.wantHit {
			t.Errorf("MatchURI(%q) ok=%v, want %v (reason=%q)", tc.uri, ok, tc.wantHit, got)
			continue
		}
		if tc.wantSub != "" && !containsStr(got, tc.wantSub) {
			t.Errorf("MatchURI(%q) reason=%q, expected substring %q", tc.uri, got, tc.wantSub)
		}
	}
}

func TestFlagIP(t *testing.T) {
	m := DefaultAttacks()
	if _, ok := m.IPReason("1.2.3.4"); ok {
		t.Error("expected no flag initially")
	}
	m.FlagIP("1.2.3.4", "attack_uri:wp-login.php")
	r, ok := m.IPReason("1.2.3.4")
	if !ok {
		t.Fatal("expected flagged")
	}
	if r == "" {
		t.Fatal("expected non-empty reason")
	}
	if m.FlaggedIPCount() != 1 {
		t.Errorf("count = %d, want 1", m.FlaggedIPCount())
	}
}

func containsStr(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexSub(haystack, needle) >= 0)
}

func indexSub(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
