package bootcheck

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/runner"
)

// Data is the raw material the helper collects for a boot check.
type Data struct {
	BootID      string                       `json:"boot_id"`
	CollectedAt time.Time                    `json:"collected_at"`
	Fstab       string                       `json:"fstab"`
	Units       map[string]map[string]string `json:"units"`
	Manager     map[string]string            `json:"manager"`
	Kernel      []events.Entry               `json:"kernel"`
	Systemd     []events.Entry               `json:"systemd"`
	Mounts      []inventory.Mount            `json:"mounts"`
}

var unitProps = "Id,LoadState,ActiveState,SubState,Result,ActiveEnterTimestampMonotonic,InactiveExitTimestampMonotonic"

// Collect gathers Data. It only reads.
func Collect(ctx context.Context, r runner.Runner, fstabPath string) (*Data, error) {
	b, err := os.ReadFile(fstabPath)
	if err != nil {
		return nil, err
	}
	d := &Data{Fstab: string(b), CollectedAt: time.Now().UTC(), Units: map[string]map[string]string{}}
	if id, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		d.BootID = strings.ReplaceAll(strings.TrimSpace(string(id)), "-", "")
	}
	entries, _ := ParseFstab(d.Fstab)
	var units []string
	for _, e := range entries {
		if u := e.MountUnit(); u != "" && !e.IsVirtual() {
			units = append(units, u)
		}
		if u := e.DeviceUnit(); u != "" {
			units = append(units, u)
		}
	}
	if len(units) > 0 {
		args := append([]string{"show", "--no-pager", "-p", unitProps, "--"}, units...)
		res, err := r.Run(ctx, "systemctl", args...)
		if err == nil {
			for _, blk := range ParseShow(string(res.Stdout)) {
				if id := blk["Id"]; id != "" {
					d.Units[id] = blk
				}
			}
		}
	}
	res, err := r.Run(ctx, "systemctl", "show", "--no-pager", "-p", "UserspaceTimestampMonotonic,FinishTimestampMonotonic,KernelTimestamp")
	if err == nil {
		if blks := ParseShow(string(res.Stdout)); len(blks) > 0 {
			d.Manager = blks[0]
		}
	}
	res, err = r.Run(ctx, "journalctl", "-k", "-b", "-o", "json", "--no-pager")
	if err == nil {
		for _, e := range events.ParseJSONLines(res.Stdout) {
			if events.AttachedDevice(e.Message) != "" {
				d.Kernel = append(d.Kernel, e)
			}
		}
	}
	res, err = r.Run(ctx, "journalctl", "-b", "_PID=1", "-o", "json", "--no-pager")
	if err == nil {
		for _, e := range events.ParseJSONLines(res.Stdout) {
			if systemdInteresting(e.Message) {
				d.Systemd = append(d.Systemd, e)
			}
		}
	}
	res, err = r.Run(ctx, "findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
	if err == nil {
		d.Mounts, _ = inventory.ParseFindmnt(res.Stdout)
	}
	return d, nil
}

func systemdInteresting(msg string) bool {
	for _, k := range []string{"Timed out waiting for device", "Dependency failed for", "Failed to mount", "Mounted ", "Activated swap", "Failed to activate swap", "Job dev-"} {
		if strings.Contains(msg, k) {
			return true
		}
	}
	return false
}

// ParseShow parses `systemctl show` output (blank-line separated blocks).
func ParseShow(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return out
}

// Report is the result of a boot check.
type Report struct {
	BootID           string        `json:"boot_id"`
	CollectedAt      time.Time     `json:"collected_at"`
	UserspaceSec     float64       `json:"userspace_start_sec"`
	FinishedSec      float64       `json:"boot_finished_sec"`
	Entries          []EntryResult `json:"entries"`
	LateDevices      []LateDevice  `json:"late_devices"`
	Summary          Summary       `json:"summary"`
	FstabParseErrors []string      `json:"fstab_errors,omitempty"`
}

type Summary struct {
	OK      int `json:"ok"`
	Failed  int `json:"failed"`
	Late    int `json:"late"`
	Skipped int `json:"skipped"`
}

type EntryResult struct {
	Line             int      `json:"line"`
	Spec             string   `json:"spec"`
	Mountpoint       string   `json:"mountpoint"`
	FSType           string   `json:"fstype"`
	Options          string   `json:"options"`
	Status           string   `json:"status"` // ok | failed | late | skipped
	Problems         []string `json:"problems,omitempty"`
	Hints            []string `json:"hints,omitempty"`
	Device           string   `json:"device,omitempty"` // node name, e.g. sda1
	Disk             string   `json:"disk,omitempty"`   // whole disk, e.g. sda
	Mounted          bool     `json:"mounted"`
	MountedSec       *float64 `json:"mounted_sec,omitempty"`
	DeviceSec        *float64 `json:"device_appeared_sec,omitempty"`
	DeviceTimeoutSec float64  `json:"device_timeout_sec"`
	Nofail           bool     `json:"nofail"`
	Noauto           bool     `json:"noauto"`
	DependsOn        []string `json:"depends_on,omitempty"`
}

type LateDevice struct {
	Device       string   `json:"device"`
	AppearedSec  float64  `json:"appeared_sec"`
	AfterTimeout bool     `json:"after_timeout"`
	Mountpoints  []string `json:"mountpoints,omitempty"`
	Message      string   `json:"message"`
}

func usecProp(m map[string]string, k string) float64 {
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[k], 10, 64)
	return float64(n) / 1e6
}

var lvPathRE = regexp.MustCompile(`^/dev/([^/]+)/([^/]+)$`)

// resolveSpec finds the lsblk node and whole disk for an fstab spec.
func resolveSpec(spec string, inv *inventory.Inventory) (node, disk string) {
	if inv == nil {
		return "", ""
	}
	key, val := "", ""
	for _, p := range []string{"UUID=", "LABEL=", "PARTUUID=", "PARTLABEL="} {
		if v, ok := strings.CutPrefix(spec, p); ok {
			key, val = p, strings.Trim(v, `"`)
		}
	}
	for _, p := range [][2]string{{"/dev/disk/by-uuid/", "UUID="}, {"/dev/disk/by-label/", "LABEL="}, {"/dev/disk/by-partuuid/", "PARTUUID="}, {"/dev/disk/by-partlabel/", "PARTLABEL="}} {
		if v, ok := strings.CutPrefix(spec, p[0]); ok {
			key, val = p[1], v
		}
	}
	lvName := ""
	if m := lvPathRE.FindStringSubmatch(spec); m != nil && m[1] != "mapper" && m[1] != "disk" {
		lvName = strings.ReplaceAll(m[1], "-", "--") + "-" + strings.ReplaceAll(m[2], "-", "--")
	}
	match := func(name, path, uuid, label, partuuid, partlabel string) bool {
		switch key {
		case "UUID=":
			return strings.EqualFold(uuid, val)
		case "LABEL=":
			return label == val
		case "PARTUUID=":
			return strings.EqualFold(partuuid, val)
		case "PARTLABEL=":
			return partlabel == val
		}
		return path == spec || "/dev/"+name == spec || (lvName != "" && name == lvName)
	}
	for _, d := range inv.Disks {
		if match(d.Name, d.Path, d.UUID, d.Label, "", "") {
			return d.Name, d.Name
		}
		found := ""
		d.Walk(func(n *inventory.Node) {
			if found == "" && match(n.Name, n.Path, n.UUID, n.Label, n.PartUUID, n.PartLabel) {
				found = n.Name
			}
		})
		if found != "" {
			return found, d.Name
		}
	}
	return "", ""
}

func f64(v float64) *float64 { return &v }

// Analyze turns collected data into a report.
func Analyze(d *Data, inv *inventory.Inventory) *Report {
	rep := &Report{BootID: d.BootID, CollectedAt: d.CollectedAt}
	rep.UserspaceSec = usecProp(d.Manager, "UserspaceTimestampMonotonic")
	rep.FinishedSec = usecProp(d.Manager, "FinishTimestampMonotonic")

	entries, perrs := ParseFstab(d.Fstab)
	for _, e := range perrs {
		rep.FstabParseErrors = append(rep.FstabParseErrors, e.Error())
	}
	mounted := map[string]bool{}
	for _, m := range d.Mounts {
		mounted[m.Target] = true
	}
	attached := map[string]events.Entry{}
	for _, k := range d.Kernel {
		if dev := events.AttachedDevice(k.Message); dev != "" {
			if _, seen := attached[dev]; !seen {
				attached[dev] = k
			}
		}
	}

	results := make([]EntryResult, 0, len(entries))
	byMount := map[string]*EntryResult{}
	minTimeout := 0.0
	for _, e := range entries {
		r := EntryResult{
			Line: e.Line, Spec: e.Spec, Mountpoint: e.File, FSType: e.VFSType,
			Options: strings.Join(e.Options, ","), Nofail: e.Has("nofail"), Noauto: e.Has("noauto"),
			DeviceTimeoutSec: e.DeviceTimeout().Seconds(),
		}
		if e.IsVirtual() {
			r.Status = "skipped"
			r.Hints = append(r.Hints, "virtual filesystem")
			results = append(results, r)
			continue
		}
		r.Device, r.Disk = resolveSpec(e.Spec, inv)
		mu := d.Units[e.MountUnit()]
		if e.IsSwap() {
			r.Mounted = mu["ActiveState"] == "active"
		} else {
			r.Mounted = mounted[e.File]
		}
		if t := usecProp(mu, "ActiveEnterTimestampMonotonic"); t > 0 && r.Mounted {
			r.MountedSec = f64(t)
		}
		if du := e.DeviceUnit(); du != "" {
			if t := usecProp(d.Units[du], "ActiveEnterTimestampMonotonic"); t > 0 {
				r.DeviceSec = f64(t)
			}
			if !r.Noauto && (minTimeout == 0 || r.DeviceTimeoutSec < minTimeout) && r.DeviceTimeoutSec > 0 {
				minTimeout = r.DeviceTimeoutSec
			}
		}
		if r.DeviceSec == nil && r.Disk != "" {
			if k, ok := attached[r.Disk]; ok {
				r.DeviceSec = f64(k.MonotonicSec())
			}
		}
		if e.DeviceUnit() != "" && r.Device == "" {
			r.Problems = append(r.Problems, "device not found on this host (missing disk or wrong UUID/LABEL)")
		}
		if res := mu["Result"]; res != "" && res != "success" {
			r.Problems = append(r.Problems, "systemd unit result: "+res)
		}
		for _, s := range d.Systemd {
			mentions := (e.MountUnit() != "" && strings.Contains(s.Message, e.MountUnit())) ||
				strings.HasSuffix(strings.TrimSpace(s.Message), " "+e.File+".") ||
				(e.DeviceUnit() != "" && strings.Contains(s.Message, e.DeviceUnit()))
			if !mentions {
				continue
			}
			switch {
			case strings.Contains(s.Message, "Timed out waiting for device"):
				r.Problems = append(r.Problems, fmt.Sprintf("systemd timed out waiting for the device after %gs (at +%.1fs)", r.DeviceTimeoutSec, s.MonotonicSec()))
			case strings.Contains(s.Message, "Dependency failed for"):
				r.Problems = append(r.Problems, fmt.Sprintf("mount skipped: dependency failed (at +%.1fs)", s.MonotonicSec()))
			case strings.Contains(s.Message, "Failed to mount"):
				r.Problems = append(r.Problems, fmt.Sprintf("mount failed (at +%.1fs)", s.MonotonicSec()))
			}
		}
		if e.IsMergerFS() {
			for _, b := range e.MergerFSBranches() {
				r.DependsOn = append(r.DependsOn, b)
			}
		}
		results = append(results, r)
	}
	for i := range results {
		byMount[results[i].Mountpoint] = &results[i]
	}

	// Dependencies: mergerfs branches and nested mountpoints.
	depFailed := map[int]bool{}
	for i := range results {
		r := &results[i]
		for _, b := range r.DependsOn {
			dep := owningMount(b, byMount, r.Mountpoint)
			if dep == nil || dep.Mounted || dep.Noauto {
				continue
			}
			depFailed[i] = true
			if r.Mounted {
				r.Problems = append(r.Problems, fmt.Sprintf("branch %s is not mounted, but this pool is: files written to the pool land in the empty %s directory on the filesystem underneath (usually the root disk)", b, dep.Mountpoint))
				r.Hints = append(r.Hints, fmt.Sprintf("Use a subdirectory that only exists on the mounted disk as the branch (e.g. %s/data) and add x-systemd.requires-mounts-for=%s to this entry.", strings.TrimSuffix(dep.Mountpoint, "/"), dep.Mountpoint))
			} else {
				r.Problems = append(r.Problems, fmt.Sprintf("depends on %s, which is not mounted", dep.Mountpoint))
			}
		}
	}

	for i := range results {
		r := &results[i]
		if r.Status == "skipped" {
			rep.Summary.Skipped++
			continue
		}
		late := false
		if r.DeviceSec != nil && r.DeviceTimeoutSec > 0 && *r.DeviceSec > rep.UserspaceSec+r.DeviceTimeoutSec && rep.UserspaceSec > 0 {
			late = true
			r.Problems = append(r.Problems, fmt.Sprintf("device %s appeared at +%s, %s after userspace start; its device timeout is %gs",
				firstNonEmpty(r.Disk, r.Device), fmtSec(*r.DeviceSec), fmtSec(*r.DeviceSec-rep.UserspaceSec), r.DeviceTimeoutSec))
			r.Hints = append(r.Hints, "The disk is enumerated too late for this timeout. Check spin-up/staggered start on the HBA or shelf, or raise x-systemd.device-timeout.")
		}
		if r.MountedSec != nil && rep.FinishedSec > 0 && *r.MountedSec > rep.FinishedSec+1 {
			late = true
			r.Problems = append(r.Problems, fmt.Sprintf("mounted at +%s, after boot finished at +%s (manual mount or late retry)", fmtSec(*r.MountedSec), fmtSec(rep.FinishedSec)))
		}
		switch {
		case depFailed[i]:
			r.Status = "failed"
			if !r.Mounted {
				r.Problems = append([]string{"not mounted"}, r.Problems...)
			}
			rep.Summary.Failed++
		case r.Noauto && !r.Mounted:
			r.Status = "skipped"
			r.Hints = append(r.Hints, "noauto: not mounted at boot by design")
			rep.Summary.Skipped++
		case !r.Mounted:
			r.Status = "failed"
			r.Problems = append([]string{"not mounted"}, r.Problems...)
			rep.Summary.Failed++
		case late:
			r.Status = "late"
			rep.Summary.Late++
		default:
			r.Status = "ok"
			rep.Summary.OK++
		}
	}
	rep.Entries = results

	// Disks that appeared after the shortest device timeout window.
	if rep.UserspaceSec > 0 {
		for dev, k := range attached {
			t := k.MonotonicSec()
			var mps []string
			after := false
			for _, r := range results {
				if r.Disk == dev {
					mps = append(mps, r.Mountpoint)
					if r.DeviceTimeoutSec > 0 && t > rep.UserspaceSec+r.DeviceTimeoutSec {
						after = true
					}
				}
			}
			window := minTimeout
			if window == 0 {
				window = 90
			}
			if t > rep.UserspaceSec+window || after {
				rep.LateDevices = append(rep.LateDevices, LateDevice{Device: dev, AppearedSec: t, AfterTimeout: after, Mountpoints: mps, Message: k.Message})
			}
		}
		sort.Slice(rep.LateDevices, func(i, j int) bool { return rep.LateDevices[i].AppearedSec < rep.LateDevices[j].AppearedSec })
	}
	return rep
}

// owningMount finds the fstab entry whose mountpoint contains path.
func owningMount(path string, byMount map[string]*EntryResult, self string) *EntryResult {
	var best *EntryResult
	for mp, r := range byMount {
		if mp == self || mp == "none" || !strings.HasPrefix(mp, "/") {
			continue
		}
		if path == mp || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			if best == nil || len(mp) > len(best.Mountpoint) {
				best = r
			}
		}
	}
	if best != nil && best.Mountpoint == "/" {
		return nil
	}
	return best
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return "?"
}

func fmtSec(s float64) string {
	d := time.Duration(s * float64(time.Second)).Round(100 * time.Millisecond)
	return d.String()
}
