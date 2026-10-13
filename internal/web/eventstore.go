package web

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/krifmaz/fsview/internal/events"
)

// EventStore keeps classified disk events in memory, persisted as JSONL.
type EventStore struct {
	mu     sync.Mutex
	path   string
	max    int
	events []events.Event // oldest first
	seen   map[string]bool
	subs   map[chan events.Event]struct{}
}

func NewEventStore(dir string, max int) *EventStore {
	if max <= 0 {
		max = 20000
	}
	es := &EventStore{path: filepath.Join(dir, "events.jsonl"), max: max, seen: map[string]bool{}, subs: map[chan events.Event]struct{}{}}
	es.load()
	return es
}

func (s *EventStore) load() {
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e events.Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && !s.seen[e.Cursor] {
			s.events = append(s.events, e)
			s.seen[e.Cursor] = true
		}
	}
	s.trimLocked(true)
}

// Add stores new events (duplicates by cursor are ignored) and notifies
// subscribers.
func (s *EventStore) Add(evs []events.Event) {
	if len(evs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []events.Event
	for _, e := range evs {
		if e.Cursor != "" && s.seen[e.Cursor] {
			continue
		}
		s.seen[e.Cursor] = true
		s.events = append(s.events, e)
		fresh = append(fresh, e)
	}
	if len(fresh) == 0 {
		return
	}
	if f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		w := bufio.NewWriter(f)
		for _, e := range fresh {
			b, _ := json.Marshal(e)
			w.Write(append(b, '\n'))
		}
		w.Flush()
		f.Close()
	}
	s.trimLocked(false)
	for ch := range s.subs {
		for _, e := range fresh {
			select {
			case ch <- e:
			default: // slow subscriber: drop rather than block
			}
		}
	}
}

func (s *EventStore) trimLocked(force bool) {
	if len(s.events) <= s.max && !force {
		return
	}
	if len(s.events) > s.max {
		for _, e := range s.events[:len(s.events)-s.max] {
			delete(s.seen, e.Cursor)
		}
		s.events = append([]events.Event(nil), s.events[len(s.events)-s.max:]...)
	}
	// Rewrite the file once it has grown well past the cap.
	if fi, err := os.Stat(s.path); err == nil && (force || fi.Size() > int64(s.max)*600) {
		tmp := s.path + ".tmp"
		if f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
			w := bufio.NewWriter(f)
			for _, e := range s.events {
				b, _ := json.Marshal(e)
				w.Write(append(b, '\n'))
			}
			w.Flush()
			f.Close()
			os.Rename(tmp, s.path)
		}
	}
}

type EventFilter struct {
	Severity string
	Category string
	Device   string
	Since    time.Time
	Limit    int
	Query    string
}

// List returns matching events, newest first.
func (s *EventStore) List(f EventFilter) []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	out := []events.Event{}
	for i := len(s.events) - 1; i >= 0 && len(out) < f.Limit; i-- {
		e := s.events[i]
		if f.Severity != "" && e.Severity != f.Severity {
			continue
		}
		if f.Category != "" && e.Category != f.Category {
			continue
		}
		if f.Device != "" && !strings.HasPrefix(e.Device, f.Device) {
			continue
		}
		if !f.Since.IsZero() && e.Time.Before(f.Since) {
			continue
		}
		if f.Query != "" && !strings.Contains(strings.ToLower(e.Message), strings.ToLower(f.Query)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Counts returns events per severity since t.
func (s *EventStore) Counts(since time.Time) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := map[string]int{"error": 0, "warn": 0, "info": 0}
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Time.Before(since) {
			break
		}
		c[s.events[i].Severity]++
	}
	return c
}

func (s *EventStore) Subscribe() chan events.Event {
	ch := make(chan events.Event, 256)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *EventStore) Unsubscribe(ch chan events.Event) {
	s.mu.Lock()
	delete(s.subs, ch)
	s.mu.Unlock()
}

func sortEvents(evs []events.Event) {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
}
