// Package events parses journald JSON output and classifies kernel
// messages that matter for disks.
package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Entry is a minimal journal entry.
type Entry struct {
	Cursor      string `json:"cursor"`
	RealtimeUS  int64  `json:"realtime_us"`
	MonotonicUS int64  `json:"monotonic_us"`
	BootID      string `json:"boot_id"`
	Priority    int    `json:"priority"`
	Identifier  string `json:"identifier,omitempty"`
	Message     string `json:"message"`
}

func (e Entry) Time() time.Time { return time.UnixMicro(e.RealtimeUS).UTC() }

// MonotonicSec is seconds since boot.
func (e Entry) MonotonicSec() float64 { return float64(e.MonotonicUS) / 1e6 }

// messageField handles journald's two encodings of MESSAGE: a string, or
// an array of bytes when the message is not valid UTF-8.
type messageField string

func (m *messageField) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*m = messageField(s)
		return nil
	}
	var bs []byte
	var ints []int
	if err := json.Unmarshal(b, &ints); err == nil {
		bs = make([]byte, len(ints))
		for i, v := range ints {
			bs[i] = byte(v)
		}
		*m = messageField(strings.ToValidUTF8(string(bs), "�"))
		return nil
	}
	*m = ""
	return nil
}

type rawEntry struct {
	Cursor     string       `json:"__CURSOR"`
	Realtime   string       `json:"__REALTIME_TIMESTAMP"`
	Monotonic  string       `json:"__MONOTONIC_TIMESTAMP"`
	BootID     string       `json:"_BOOT_ID"`
	Priority   string       `json:"PRIORITY"`
	Identifier string       `json:"SYSLOG_IDENTIFIER"`
	Message    messageField `json:"MESSAGE"`
}

// ParseJSONLines parses `journalctl -o json` output (one object per line).
func ParseJSONLines(data []byte) []Entry {
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r rawEntry
		if json.Unmarshal(line, &r) != nil {
			continue
		}
		e := Entry{Cursor: r.Cursor, BootID: r.BootID, Identifier: r.Identifier, Message: string(r.Message), Priority: 6}
		e.RealtimeUS, _ = strconv.ParseInt(r.Realtime, 10, 64)
		e.MonotonicUS, _ = strconv.ParseInt(r.Monotonic, 10, 64)
		if p, err := strconv.Atoi(r.Priority); err == nil {
			e.Priority = p
		}
		out = append(out, e)
	}
	return out
}
