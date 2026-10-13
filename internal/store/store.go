// Package store keeps FSView's small amount of persistent state (users,
// sessions, settings) in JSON files written atomically.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/krifmaz/fsview/internal/auth"
	"github.com/krifmaz/fsview/internal/smart"
)

type User struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

type Settings struct {
	Thresholds     smart.Thresholds `json:"thresholds"`
	LateDeviceSec  int              `json:"late_device_sec"`
	EventRetention int              `json:"event_retention"`
}

func DefaultSettings() Settings {
	return Settings{Thresholds: smart.DefaultThresholds(), LateDeviceSec: 60, EventRetention: 20000}
}

type state struct {
	Users         []User   `json:"users"`
	Settings      Settings `json:"settings"`
	JournalCursor string   `json:"journal_cursor,omitempty"`
}

type Session struct {
	TokenHash string    `json:"token_hash"`
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ClientIP  string    `json:"client_ip"`
}

const (
	SessionIdle     = 12 * time.Hour
	SessionAbsolute = 7 * 24 * time.Hour
)

type Store struct {
	dir string

	mu       sync.Mutex
	st       state
	sessions map[string]*Session
	lastSave time.Time
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, sessions: map[string]*Session{}}
	s.st.Settings = DefaultSettings()
	if err := readJSON(filepath.Join(dir, "state.json"), &s.st); err != nil {
		return nil, err
	}
	var sess []*Session
	if err := readJSON(filepath.Join(dir, "sessions.json"), &sess); err != nil {
		return nil, err
	}
	for _, x := range sess {
		s.sessions[x.TokenHash] = x
	}
	if s.st.Settings.EventRetention == 0 {
		s.st.Settings.EventRetention = 20000
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// WriteJSONAtomic writes v to path via a temp file and rename.
func WriteJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Store) saveStateLocked() error {
	return WriteJSONAtomic(filepath.Join(s.dir, "state.json"), s.st)
}

func (s *Store) saveSessionsLocked() error {
	l := make([]*Session, 0, len(s.sessions))
	for _, x := range s.sessions {
		l = append(l, x)
	}
	s.lastSave = time.Now()
	return WriteJSONAtomic(filepath.Join(s.dir, "sessions.json"), l)
}

// ---- users ----

var reUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

var ErrNotFound = errors.New("not found")

func (s *Store) SetPassword(name, password string, create bool) error {
	if !reUser.MatchString(name) {
		return fmt.Errorf("invalid user name %q", name)
	}
	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters")
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Users {
		if s.st.Users[i].Name == name {
			s.st.Users[i].Hash = h
			s.dropUserSessionsLocked(name)
			return s.saveStateLocked()
		}
	}
	if !create {
		return ErrNotFound
	}
	s.st.Users = append(s.st.Users, User{Name: name, Hash: h, CreatedAt: time.Now().UTC()})
	return s.saveStateLocked()
}

func (s *Store) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Users {
		if s.st.Users[i].Name == name {
			s.st.Users = append(s.st.Users[:i], s.st.Users[i+1:]...)
			s.dropUserSessionsLocked(name)
			return s.saveStateLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]User(nil), s.st.Users...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// dummyHash makes failed lookups cost the same as real verifications.
var (
	dummyOnce sync.Once
	dummyHash string
)

// verifySem bounds concurrent argon2id verifications (64 MiB each) so a
// burst of logins cannot exhaust memory.
var verifySem = make(chan struct{}, 2)

// CheckPassword verifies credentials.
func (s *Store) CheckPassword(name, password string) bool {
	verifySem <- struct{}{}
	defer func() { <-verifySem }()
	dummyOnce.Do(func() { dummyHash, _ = auth.HashPassword("fsview-dummy-password") })
	s.mu.Lock()
	hash := ""
	for _, u := range s.st.Users {
		if u.Name == name {
			hash = u.Hash
		}
	}
	s.mu.Unlock()
	if hash == "" {
		auth.VerifyPassword(password, dummyHash)
		return false
	}
	ok, _ := auth.VerifyPassword(password, hash)
	return ok
}

// ---- sessions ----

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (s *Store) CreateSession(user, ip string) (string, error) {
	tok, err := auth.RandomToken()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[hashToken(tok)] = &Session{TokenHash: hashToken(tok), User: user, CreatedAt: now, LastSeen: now, ClientIP: ip}
	return tok, s.saveSessionsLocked()
}

// Session validates a token and refreshes its idle timer.
func (s *Store) Session(tok string) (*Session, bool) {
	if tok == "" {
		return nil, false
	}
	h := hashToken(tok)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[h]
	if !ok {
		return nil, false
	}
	if now.Sub(x.LastSeen) > SessionIdle || now.Sub(x.CreatedAt) > SessionAbsolute || !s.userExistsLocked(x.User) {
		delete(s.sessions, h)
		_ = s.saveSessionsLocked()
		return nil, false
	}
	x.LastSeen = now
	if now.Sub(s.lastSave) > time.Minute {
		_ = s.saveSessionsLocked()
	}
	c := *x
	return &c, true
}

func (s *Store) userExistsLocked(name string) bool {
	for _, u := range s.st.Users {
		if u.Name == name {
			return true
		}
	}
	return false
}

func (s *Store) DeleteSession(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hashToken(tok))
	_ = s.saveSessionsLocked()
}

func (s *Store) dropUserSessionsLocked(name string) {
	for k, x := range s.sessions {
		if x.User == name {
			delete(s.sessions, k)
		}
	}
	_ = s.saveSessionsLocked()
}

// ---- settings & cursor ----

func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Settings
}

func (s *Store) SetSettings(v Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Settings = v
	return s.saveStateLocked()
}

func (s *Store) JournalCursor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.JournalCursor
}

func (s *Store) SetJournalCursor(c string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.JournalCursor == c {
		return nil
	}
	s.st.JournalCursor = c
	return s.saveStateLocked()
}
