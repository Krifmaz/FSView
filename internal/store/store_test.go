package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsersAndSessions(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("admin", "short", true); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.SetPassword("Bad Name", "longenoughpw", true); err == nil {
		t.Fatal("bad user name accepted")
	}
	if err := s.SetPassword("admin", "longenoughpw", true); err != nil {
		t.Fatal(err)
	}
	if !s.CheckPassword("admin", "longenoughpw") || s.CheckPassword("admin", "nope") || s.CheckPassword("ghost", "longenoughpw") {
		t.Fatal("password check wrong")
	}
	tok, err := s.CreateSession("admin", "192.168.1.2")
	if err != nil {
		t.Fatal(err)
	}
	if sess, ok := s.Session(tok); !ok || sess.User != "admin" {
		t.Fatal("session lookup failed")
	}
	// Sessions survive a restart and tokens are not stored in clear.
	raw, _ := os.ReadFile(filepath.Join(dir, "sessions.json"))
	if string(raw) == "" || strings.Contains(string(raw), tok) {
		t.Fatal("token stored in clear text")
	}
	s2, _ := Open(dir)
	if _, ok := s2.Session(tok); !ok {
		t.Fatal("session lost across restart")
	}
	// Password change revokes sessions.
	s2.SetPassword("admin", "anotherlongpw", false)
	if _, ok := s2.Session(tok); ok {
		t.Fatal("session survived password change")
	}
	// Idle expiry.
	tok2, _ := s2.CreateSession("admin", "x")
	s2.mu.Lock()
	for _, x := range s2.sessions {
		x.LastSeen = time.Now().Add(-SessionIdle - time.Minute)
	}
	s2.mu.Unlock()
	if _, ok := s2.Session(tok2); ok {
		t.Fatal("idle session accepted")
	}
	fi, _ := os.Stat(filepath.Join(dir, "state.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json mode %v", fi.Mode().Perm())
	}
}
