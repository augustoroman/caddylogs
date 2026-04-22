package parser

import (
	"testing"
	"time"
)

const sampleLine = `{"level":"info","ts":1776320110.1892574,"logger":"http.log.access.log21","msg":"handled request","request":{"remote_ip":"103.215.74.213","remote_port":"25438","client_ip":"103.215.74.213","proto":"HTTP/1.1","method":"HEAD","host":"skewered-fencing.com","uri":"/wp-login.tar","headers":{"User-Agent":["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"],"Accept":["application/zip"]},"tls":{"server_name":"skewered-fencing.com"}},"bytes_read":0,"duration":0.000112761,"size":0,"status":404}`

func TestParseSample(t *testing.T) {
	ev, err := Parse([]byte(sampleLine))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Status != 404 {
		t.Errorf("status: got %d want 404", ev.Status)
	}
	if ev.Method != "HEAD" {
		t.Errorf("method: got %q", ev.Method)
	}
	if ev.Host != "skewered-fencing.com" {
		t.Errorf("host: got %q", ev.Host)
	}
	if ev.URI != "/wp-login.tar" {
		t.Errorf("uri: got %q", ev.URI)
	}
	if ev.RemoteIP != "103.215.74.213" {
		t.Errorf("ip: got %q", ev.RemoteIP)
	}
	if ev.Proto != "HTTP/1.1" {
		t.Errorf("proto: got %q", ev.Proto)
	}
	if ev.TLSServerName != "skewered-fencing.com" {
		t.Errorf("tls server_name: got %q", ev.TLSServerName)
	}
	if got := ev.Timestamp.Unix(); got != 1776320110 {
		t.Errorf("timestamp unix: got %d want 1776320110", got)
	}
	if ev.Duration <= 0 || ev.Duration > time.Second {
		t.Errorf("duration sanity: got %s", ev.Duration)
	}
	if !containsAny(ev.UserAgent, "Chrome/120") {
		t.Errorf("user-agent: got %q", ev.UserAgent)
	}
}

func TestParseSkipsNonAccess(t *testing.T) {
	_, err := Parse([]byte(`{"level":"info","ts":1776320000.0,"logger":"caddy","msg":"server running"}`))
	if !IsNotAccessLog(err) {
		t.Fatalf("expected IsNotAccessLog, got %v", err)
	}
}

func TestParseBadJSON(t *testing.T) {
	_, err := Parse([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error")
	}
	if IsNotAccessLog(err) {
		t.Fatal("bad json should not be IsNotAccessLog")
	}
}

func containsAny(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
