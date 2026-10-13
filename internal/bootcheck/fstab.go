// Package bootcheck reports fstab entries that failed to mount or mounted
// late during the current boot, and disks that appeared after the mount
// timeout.
package bootcheck

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry is one fstab line.
type Entry struct {
	Line    int      `json:"line"`
	Spec    string   `json:"spec"`
	File    string   `json:"file"`
	VFSType string   `json:"vfstype"`
	Options []string `json:"options"`
	Freq    int      `json:"freq"`
	Pass    int      `json:"pass"`
}

func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ParseFstab parses fstab text. Malformed lines are returned as errors but
// do not stop parsing.
func ParseFstab(text string) ([]Entry, []error) {
	var out []Entry
	var errs []error
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		f := strings.Fields(trimmed)
		if len(f) < 3 {
			errs = append(errs, fmt.Errorf("line %d: expected at least 3 fields", i+1))
			continue
		}
		e := Entry{Line: i + 1, Spec: unescapeOctal(f[0]), File: unescapeOctal(f[1]), VFSType: f[2], Options: []string{"defaults"}}
		if len(f) > 3 {
			e.Options = strings.Split(f[3], ",")
		}
		if len(f) > 4 {
			e.Freq, _ = strconv.Atoi(f[4])
		}
		if len(f) > 5 {
			e.Pass, _ = strconv.Atoi(f[5])
		}
		out = append(out, e)
	}
	return out, errs
}

// Opt returns the value of option name ("" if it has none) and whether it
// is present.
func (e Entry) Opt(name string) (string, bool) {
	for _, o := range e.Options {
		k, v, _ := strings.Cut(o, "=")
		if k == name {
			return v, true
		}
	}
	return "", false
}

func (e Entry) Has(name string) bool { _, ok := e.Opt(name); return ok }

var virtualTypes = map[string]bool{
	"proc": true, "sysfs": true, "tmpfs": true, "devpts": true, "devtmpfs": true, "cgroup": true, "cgroup2": true,
	"debugfs": true, "securityfs": true, "efivarfs": true, "hugetlbfs": true, "mqueue": true, "configfs": true,
	"fusectl": true, "binfmt_misc": true, "pstore": true, "bpf": true, "tracefs": true, "ramfs": true,
}

var networkTypes = map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "sshfs": true, "fuse.sshfs": true, "glusterfs": true, "ceph": true, "9p": true, "virtiofs": true}

func (e Entry) IsVirtual() bool { return virtualTypes[e.VFSType] }
func (e Entry) IsSwap() bool    { return e.VFSType == "swap" }
func (e Entry) IsNetwork() bool { return networkTypes[e.VFSType] || e.Has("_netdev") }
func (e Entry) IsMergerFS() bool {
	return e.VFSType == "fuse.mergerfs" || e.VFSType == "mergerfs" || (e.VFSType == "fuse" && strings.HasPrefix(e.Spec, "mergerfs#"))
}
func (e Entry) IsBind() bool { return e.Has("bind") || e.Has("rbind") }

// DeviceTimeout is x-systemd.device-timeout (systemd's default is 90s).
func (e Entry) DeviceTimeout() time.Duration {
	if v, ok := e.Opt("x-systemd.device-timeout"); ok {
		if d, err := ParseSystemdDuration(v); err == nil {
			return d
		}
	}
	return 90 * time.Second
}

var durRE = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(usec|us|msec|ms|seconds|second|sec|s|minutes|minute|min|m|hours|hour|hr|h|days|day|d)?`)

// ParseSystemdDuration parses systemd time spans like "10s", "1min 30s",
// "90" (seconds) or "infinity".
func ParseSystemdDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "infinity" || s == "0" {
		return 0, nil
	}
	ms := durRE.FindAllStringSubmatch(s, -1)
	if len(ms) == 0 || strings.TrimSpace(durRE.ReplaceAllString(s, "")) != "" {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	var total time.Duration
	for _, m := range ms {
		f, _ := strconv.ParseFloat(m[1], 64)
		unit := time.Second
		switch m[2] {
		case "us", "usec":
			unit = time.Microsecond
		case "ms", "msec":
			unit = time.Millisecond
		case "m", "min", "minute", "minutes":
			unit = time.Minute
		case "h", "hr", "hour", "hours":
			unit = time.Hour
		case "d", "day", "days":
			unit = 24 * time.Hour
		}
		total += time.Duration(f * float64(unit))
	}
	return total, nil
}

// MergerFSBranches returns branch paths from a mergerfs source spec like
// "/mnt/disk1:/mnt/disk2=RO:/mnt/disk*".
func (e Entry) MergerFSBranches() []string {
	spec := strings.TrimPrefix(e.Spec, "mergerfs#")
	var out []string
	for _, b := range strings.Split(spec, ":") {
		b, _, _ = strings.Cut(b, "=")
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	return out
}

// EscapePath implements `systemd-escape --path`.
func EscapePath(p string) string {
	parts := []string{}
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	joined := strings.Join(parts, "/")
	var b strings.Builder
	for i := 0; i < len(joined); i++ {
		c := joined[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c == '.' && i == 0:
			fmt.Fprintf(&b, `\x%02x`, c)
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ':', c == '_', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}

// MountUnit is the systemd unit name for an fstab entry.
func (e Entry) MountUnit() string {
	if e.IsSwap() {
		if dev := e.DevicePath(); dev != "" {
			return EscapePath(dev) + ".swap"
		}
		return ""
	}
	return EscapePath(e.File) + ".mount"
}

// DevicePath turns the fs_spec into a /dev path if it names a block device.
func (e Entry) DevicePath() string {
	s := e.Spec
	for prefix, dir := range map[string]string{"UUID=": "by-uuid", "LABEL=": "by-label", "PARTUUID=": "by-partuuid", "PARTLABEL=": "by-partlabel"} {
		if v, ok := strings.CutPrefix(s, prefix); ok {
			return "/dev/disk/" + dir + "/" + strings.Trim(v, `"`)
		}
	}
	if strings.HasPrefix(s, "/dev/") {
		return s
	}
	return ""
}

// DeviceUnit is the systemd device unit the mount waits for, if any.
func (e Entry) DeviceUnit() string {
	if e.IsVirtual() || e.IsNetwork() || e.IsBind() || e.IsMergerFS() {
		return ""
	}
	if dev := e.DevicePath(); dev != "" {
		return EscapePath(dev) + ".device"
	}
	return ""
}
