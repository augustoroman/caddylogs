package classify

import "testing"

func TestDefaultBots(t *testing.T) {
	b := DefaultBots()
	cases := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Mozilla/5.0 (compatible; bingbot/2.0)", true},
		{"Mozilla/5.0 (compatible; AhrefsBot/7.0)", true},
		{"Mozilla/5.0 (compatible; SecurityScanner/1.0)", true},
		{"curl/8.4.0", true},
		{"python-requests/2.31.0", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.1 Safari/605.1.15", false},
		{"", true}, // empty UA counted as bot
	}
	for _, tc := range cases {
		got := b.IsBot(tc.ua)
		if got != tc.want {
			t.Errorf("IsBot(%q) = %v, want %v", tc.ua, got, tc.want)
		}
	}
}

func TestStaticMatcher(t *testing.T) {
	m := NewStaticMatcher(DefaultStaticExtensions)
	cases := []struct {
		uri  string
		want bool
	}{
		{"/style.css", true},
		{"/foo/bar.js?v=1", true},
		{"/img/logo.png", true},
		{"/wp-login.php", false},
		{"/", false},
		{"/api/v1/users", false},
		{"/file.unknown", false},
	}
	for _, tc := range cases {
		if got := m.IsStatic(tc.uri); got != tc.want {
			t.Errorf("IsStatic(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestIsLocalIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.5", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.32.0.1", false},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2606:4700::1", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLocalIP(tc.ip); got != tc.want {
			t.Errorf("IsLocalIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestParseUA(t *testing.T) {
	ui := ParseUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	if ui.Browser == "" {
		t.Errorf("browser empty for Chrome UA")
	}
	if ui.OS == "" {
		t.Errorf("os empty for Windows UA")
	}
	if ui.Device == "" {
		t.Errorf("device empty")
	}
}
