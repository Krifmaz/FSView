package inventory

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// EnclosureElement is one non-slot SES element (PSU, fan, sensor...).
type EnclosureElement struct {
	Type   string `json:"type"`
	Index  int    `json:"index"`
	Status string `json:"status"` // SES status text, e.g. "OK", "Critical"
	Level  string `json:"level"`  // ok | warn | crit | absent
	Detail string `json:"detail,omitempty"`
}

var (
	reSESType    = regexp.MustCompile(`^\s*Element type: ([^,]+),`)
	reSESElement = regexp.MustCompile(`^\s*Element (\d+) descriptor:`)
	reSESOverall = regexp.MustCompile(`^\s*Overall descriptor:`)
	reSESStatus  = regexp.MustCompile(`status: ([A-Za-z ]+?)\s*$`)
	reSESTemp    = regexp.MustCompile(`Temperature=(-?\d+) C`)
	reSESSpeed   = regexp.MustCompile(`Actual speed=(\d+) rpm`)
	reSESVolt    = regexp.MustCompile(`Voltage: ([\d.]+) Volts`)
	reSESAmps    = regexp.MustCompile(`Current: ([\d.]+) Amps`)
	reSESFlag    = regexp.MustCompile(`(Fail|AC fail|DC fail|Off|Overtmp fail|Temperature warn|DC overvoltage|DC undervoltage|DC overcurrent|OT failure|OT warning|Failure indication|Warning indication)=1`)
)

var sesTypes = map[string]bool{
	"Power supply": true, "Cooling": true, "Temperature sensor": true, "Voltage sensor": true,
	"Current sensor": true, "Enclosure services controller electronics": true, "Enclosure": true,
}

func sesLevel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "critical", "unrecoverable":
		return "crit"
	case "noncritical", "non-critical":
		return "warn"
	case "not installed", "unsupported", "unavailable", "no access allowed":
		return "absent"
	}
	return "ok"
}

// ParseSESStatus parses the text of `sg_ses -p 0x2`. Device slots are
// skipped (sysfs already maps them to disks), as are vendor-specific
// element types.
func ParseSESStatus(text string) []EnclosureElement {
	var out []EnclosureElement
	var cur *EnclosureElement
	typ := ""
	inOverall := false
	var flags []string
	flush := func() {
		if cur != nil {
			if len(flags) > 0 {
				f := strings.Join(flags, ", ")
				if cur.Detail != "" {
					cur.Detail += "; "
				}
				cur.Detail += f
			}
			out = append(out, *cur)
		}
		cur, flags = nil, nil
	}
	for _, line := range strings.Split(text, "\n") {
		if m := reSESType.FindStringSubmatch(line); m != nil {
			flush()
			typ = strings.TrimSpace(m[1])
			continue
		}
		if reSESOverall.MatchString(line) {
			flush()
			inOverall = true
			continue
		}
		if m := reSESElement.FindStringSubmatch(line); m != nil {
			flush()
			inOverall = false
			if !sesTypes[typ] {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			cur = &EnclosureElement{Type: typ, Index: n}
			continue
		}
		if cur == nil || inOverall {
			continue
		}
		if m := reSESStatus.FindStringSubmatch(line); m != nil {
			cur.Status = m[1]
			cur.Level = sesLevel(m[1])
		}
		if m := reSESTemp.FindStringSubmatch(line); m != nil {
			cur.Detail = m[1] + " °C"
		}
		if m := reSESSpeed.FindStringSubmatch(line); m != nil {
			cur.Detail = m[1] + " rpm"
		}
		if m := reSESVolt.FindStringSubmatch(line); m != nil {
			cur.Detail = m[1] + " V"
		}
		if m := reSESAmps.FindStringSubmatch(line); m != nil {
			cur.Detail = m[1] + " A"
		}
		for _, m := range reSESFlag.FindAllStringSubmatch(line, -1) {
			flags = append(flags, strings.ToLower(m[1]))
		}
	}
	flush()
	// "Failure indication" on the enclosure element is the fault LED.
	for i := range out {
		if out[i].Type == "Enclosure" && strings.Contains(out[i].Detail, "failure indication") && out[i].Level == "ok" {
			out[i].Level = "warn"
		}
	}
	return out
}

// EnclosureLevel summarizes elements: crit > warn > ok.
func EnclosureLevel(els []EnclosureElement) string {
	lvl := "ok"
	for _, e := range els {
		switch e.Level {
		case "crit":
			return "crit"
		case "warn":
			lvl = "warn"
		}
	}
	return lvl
}

// sgForEnclosure finds the SCSI generic device of an enclosure (H:C:T:L).
func (s Sysfs) sgForEnclosure(id string) string {
	dirs, _ := filepath.Glob(s.path("class", "scsi_generic", "sg*"))
	for _, d := range dirs {
		if readTrim(filepath.Join(d, "device", "type")) != "13" {
			continue
		}
		if real, err := filepath.EvalSymlinks(filepath.Join(d, "device")); err == nil && filepath.Base(real) == id {
			return filepath.Base(d)
		}
	}
	return ""
}

var reSG = regexp.MustCompile(`^sg[0-9]{1,4}$`)

// enclosureHealth adds sg_ses element status to each enclosure. SES
// queries go to the enclosure processor, never to disks.
func (c *Collector) enclosureHealth(ctx context.Context, encs []Enclosure) []string {
	var warns []string
	for i := range encs {
		sg := c.Sysfs.sgForEnclosure(encs[i].ID)
		if !reSG.MatchString(sg) {
			continue
		}
		encs[i].SGDevice = sg
		res, err := c.Runner.Run(ctx, "sg_ses", "-p", "0x2", "/dev/"+sg)
		if err != nil {
			if !errors.Is(err, exec.ErrNotFound) {
				warns = append(warns, fmt.Sprintf("sg_ses on %s: %v", sg, err))
			}
			continue
		}
		if res.ExitCode != 0 {
			warns = append(warns, fmt.Sprintf("sg_ses on %s exited %d", sg, res.ExitCode))
			continue
		}
		encs[i].Elements = ParseSESStatus(string(res.Stdout))
		encs[i].Status = EnclosureLevel(encs[i].Elements)
	}
	return warns
}
