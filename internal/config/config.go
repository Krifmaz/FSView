// Package config reads FSView's simple "key = value" configuration files.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Values is a parsed config file.
type Values map[string]string

// Parse reads "key = value" lines. '#' starts a comment.
func Parse(r io.Reader) (Values, error) {
	v := Values{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", n)
		}
		v[strings.TrimSpace(strings.ToLower(k))] = strings.TrimSpace(val)
	}
	return v, sc.Err()
}

// Load parses a file. A missing file yields empty values.
func Load(path string) (Values, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Values{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func (v Values) String(k, def string) string {
	if s, ok := v[k]; ok && s != "" {
		return s
	}
	return def
}

func (v Values) Bool(k string, def bool) (bool, error) {
	s, ok := v[k]
	if !ok || s == "" {
		return def, nil
	}
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on", "enabled":
		return true, nil
	case "0", "false", "no", "off", "disabled":
		return false, nil
	}
	return def, fmt.Errorf("%s: invalid boolean %q", k, s)
}

func (v Values) Int(k string, def int) (int, error) {
	s, ok := v[k]
	if !ok || s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def, fmt.Errorf("%s: invalid integer %q", k, s)
	}
	return n, nil
}

func (v Values) Duration(k string, def time.Duration) (time.Duration, error) {
	s, ok := v[k]
	if !ok || s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def, fmt.Errorf("%s: invalid duration %q", k, s)
	}
	return d, nil
}

func (v Values) List(k string) []string {
	s := v[k]
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Web is the configuration for "fsview serve".
type Web struct {
	Listen       []string // "auto" or explicit ip[:port] entries
	Port         int
	Allow        []string // "auto" or CIDRs
	TLSCert      string
	TLSKey       string
	DataDir      string
	HelperSocket string
	SmartPoll    time.Duration
	JournalPoll  time.Duration
}

func LoadWeb(path string) (*Web, error) {
	v, err := Load(path)
	if err != nil {
		return nil, err
	}
	w := &Web{
		Listen:       v.List("listen"),
		Allow:        v.List("allow"),
		TLSCert:      v.String("tls_cert", ""),
		TLSKey:       v.String("tls_key", ""),
		DataDir:      v.String("data_dir", "/var/lib/fsview"),
		HelperSocket: v.String("helper_socket", "/run/fsview/helper.sock"),
	}
	if len(w.Listen) == 0 {
		w.Listen = []string{"auto"}
	}
	if len(w.Allow) == 0 {
		w.Allow = []string{"auto"}
	}
	if w.Port, err = v.Int("port", 9200); err != nil {
		return nil, err
	}
	if w.SmartPoll, err = v.Duration("smart_poll", 30*time.Minute); err != nil {
		return nil, err
	}
	if w.JournalPoll, err = v.Duration("journal_poll", 3*time.Second); err != nil {
		return nil, err
	}
	if (w.TLSCert == "") != (w.TLSKey == "") {
		return nil, fmt.Errorf("tls_cert and tls_key must be set together")
	}
	return w, nil
}

// Helper is the configuration for "fsview helper". It is root-owned so the
// web process cannot change it.
type Helper struct {
	Socket        string
	ClientUser    string
	WritesEnabled bool
	AuditLog      string
	IncludeLoop   bool
}

func LoadHelper(path string) (*Helper, error) {
	v, err := Load(path)
	if err != nil {
		return nil, err
	}
	h := &Helper{
		Socket:     v.String("socket", "/run/fsview/helper.sock"),
		ClientUser: v.String("client_user", "fsview"),
		AuditLog:   v.String("audit_log", "/var/log/fsview/audit.log"),
	}
	if h.WritesEnabled, err = v.Bool("writes_enabled", false); err != nil {
		return nil, err
	}
	if h.IncludeLoop, err = v.Bool("include_loop_devices", false); err != nil {
		return nil, err
	}
	return h, nil
}
