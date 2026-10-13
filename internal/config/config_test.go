package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	v, err := Parse(strings.NewReader("# comment\nListen = 192.168.1.5 , 10.0.0.1\nport=9300 # trailing\n\nwrites_enabled = yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.List("listen"); len(got) != 2 || got[1] != "10.0.0.1" {
		t.Fatalf("listen = %v", got)
	}
	if n, _ := v.Int("port", 1); n != 9300 {
		t.Fatalf("port = %d", n)
	}
	if b, _ := v.Bool("writes_enabled", false); !b {
		t.Fatal("writes_enabled should be true")
	}
	if _, err := Parse(strings.NewReader("nonsense\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDefaults(t *testing.T) {
	w, err := LoadWeb(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Port != 9200 || w.Listen[0] != "auto" || w.Allow[0] != "auto" || w.SmartPoll != 30*time.Minute {
		t.Fatalf("unexpected defaults: %+v", w)
	}
	h, err := LoadHelper(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if h.WritesEnabled {
		t.Fatal("writes must default to disabled")
	}
}

func TestTLSPair(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.conf")
	os.WriteFile(p, []byte("tls_cert = /x.pem\n"), 0o600)
	if _, err := LoadWeb(p); err == nil {
		t.Fatal("expected error for cert without key")
	}
}
