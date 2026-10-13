package bootcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/inventory"
)

func TestEscapePath(t *testing.T) {
	cases := map[string]string{
		"/":                           "-",
		"/mnt/media1":                 "mnt-media1",
		"/boot/efi":                   "boot-efi",
		"/dev/disk/by-uuid/8B42-B13D": `dev-disk-by\x2duuid-8B42\x2dB13D`,
		"/mnt/my disk":                `mnt-my\x20disk`,
		"/.hidden/x":                  `\x2ehidden-x`,
		"//mnt//a/":                   "mnt-a",
	}
	for in, want := range cases {
		if got := EscapePath(in); got != want {
			t.Errorf("EscapePath(%q) = %q want %q", in, got, want)
		}
	}
}

func TestDurations(t *testing.T) {
	cases := map[string]time.Duration{"10s": 10 * time.Second, "90": 90 * time.Second, "1min 30s": 90 * time.Second, "2m": 2 * time.Minute, "500ms": 500 * time.Millisecond}
	for in, want := range cases {
		if got, err := ParseSystemdDuration(in); err != nil || got != want {
			t.Errorf("%q => %v %v", in, got, err)
		}
	}
	if _, err := ParseSystemdDuration("10 bananas"); err == nil {
		t.Error("expected error")
	}
}

func TestParseFstab(t *testing.T) {
	es, errs := ParseFstab("# c\nUUID=x /mnt/my\\040disk ext4 defaults,nofail 0 2\nbad\n/a:/b=RO /pool fuse.mergerfs allow_other 0 0\n")
	if len(es) != 2 || len(errs) != 1 {
		t.Fatalf("%v %v", es, errs)
	}
	if es[0].File != "/mnt/my disk" || !es[0].Has("nofail") || es[0].DeviceUnit() != `dev-disk-by\x2duuid-x.device` || es[0].DeviceTimeout() != 90*time.Second {
		t.Fatalf("%+v", es[0])
	}
	if b := es[1].MergerFSBranches(); len(b) != 2 || b[1] != "/b" || es[1].DeviceUnit() != "" {
		t.Fatalf("branches %v", b)
	}
}

func spiritlabData(t *testing.T) (*Data, *inventory.Inventory) {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "spiritlab")
	fstab, _ := os.ReadFile(filepath.Join(dir, "fstab"))
	lsblk, _ := os.ReadFile(filepath.Join(dir, "lsblk.json"))
	fm, _ := os.ReadFile(filepath.Join(dir, "findmnt.json"))
	disks, err := inventory.ParseLsblk(lsblk, false)
	if err != nil {
		t.Fatal(err)
	}
	mounts, _ := inventory.ParseFindmnt(fm)
	media1Dev := `dev-disk-by\x2duuid-c69cfb3b\x2d4f39\x2d449a\x2dbb21\x2dcd2e4ba23d49.device`
	cacheDev := `dev-disk-by\x2duuid-df81e242\x2ddf1f\x2d41a9\x2d87ea\x2db441da0ee820.device`
	d := &Data{
		BootID: "b1",
		Fstab:  string(fstab),
		Manager: map[string]string{
			"UserspaceTimestampMonotonic": "3200000",
			"FinishTimestampMonotonic":    "25000000",
		},
		Units: map[string]map[string]string{
			"mnt-media1.mount":    {"Id": "mnt-media1.mount", "ActiveState": "inactive", "Result": "success", "ActiveEnterTimestampMonotonic": "0"},
			"mnt-cache.mount":     {"Id": "mnt-cache.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "9100000"},
			"mnt-drivepool.mount": {"Id": "mnt-drivepool.mount", "ActiveState": "inactive", "Result": "success"},
			"boot-efi.mount":      {"Id": "boot-efi.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "6000000"},
			"-.mount":             {"Id": "-.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "1"},
			`dev-pve-swap.swap`:   {"Id": "dev-pve-swap.swap", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "5000000"},
			media1Dev:             {"Id": media1Dev, "ActiveState": "active", "ActiveEnterTimestampMonotonic": "1260000000"},
			cacheDev:              {"Id": cacheDev, "ActiveState": "active", "ActiveEnterTimestampMonotonic": "7600000"},
		},
		Kernel: []events.Entry{
			{MonotonicUS: 7_500_000, Message: "sd 2:0:1:0: [sda] Attached SCSI disk"},
			{MonotonicUS: 7_700_000, Message: "sd 2:0:2:0: [sdb] Attached SCSI disk"},
			{MonotonicUS: 1_260_000_000, Message: "sd 2:0:9:0: [sdi] Attached SCSI disk"},
		},
		Systemd: []events.Entry{
			{MonotonicUS: 13_300_000, Message: `Timed out waiting for device ` + media1Dev + ` - /dev/disk/by-uuid/c69cfb3b-4f39-449a-bb21-cd2e4ba23d49.`},
			{MonotonicUS: 13_300_000, Message: "Dependency failed for mnt-media1.mount - /mnt/media1."},
		},
		Mounts: mounts,
	}
	return d, &inventory.Inventory{Disks: disks}
}

func TestAnalyzeSpiritlab(t *testing.T) {
	d, inv := spiritlabData(t)
	rep := Analyze(d, inv)
	by := map[string]EntryResult{}
	for _, e := range rep.Entries {
		by[e.Mountpoint] = e
	}
	m1 := by["/mnt/media1"]
	if m1.Status != "failed" || m1.Disk != "sdi" || m1.DeviceTimeoutSec != 10 {
		t.Fatalf("media1: %+v", m1)
	}
	all := strings.Join(m1.Problems, "\n")
	for _, frag := range []string{"not mounted", "timed out waiting for the device after 10s", "dependency failed", "device sdi appeared at +21m0s"} {
		if !strings.Contains(all, frag) {
			t.Errorf("media1 problems missing %q:\n%s", frag, all)
		}
	}
	dp := by["/mnt/drivepool"]
	if dp.Status != "failed" || !strings.Contains(strings.Join(dp.Problems, "\n"), "depends on /mnt/media1") {
		t.Fatalf("drivepool: %+v", dp)
	}
	if c := by["/mnt/cache"]; c.Status != "ok" || c.Disk != "sda" || c.Device != "sda1" {
		t.Fatalf("cache: %+v", c)
	}
	if r := by["/"]; r.Status != "ok" || r.Device != "pve-root" {
		t.Fatalf("root: %+v", r)
	}
	if s := by["none"]; s.Status != "ok" || s.FSType != "swap" {
		t.Fatalf("swap: %+v", s)
	}
	if p := by["/proc"]; p.Status != "skipped" {
		t.Fatalf("proc: %+v", p)
	}
	if rep.Summary.Failed != 2 || rep.Summary.Skipped != 1 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	if len(rep.LateDevices) != 1 || rep.LateDevices[0].Device != "sdi" || !rep.LateDevices[0].AfterTimeout || rep.LateDevices[0].Mountpoints[0] != "/mnt/media1" {
		t.Fatalf("late devices %+v", rep.LateDevices)
	}
}

func TestParseShow(t *testing.T) {
	b := ParseShow("Id=a.mount\nActiveState=active\n\nId=b.mount\nActiveState=failed\nResult=exit-code\n")
	if len(b) != 2 || b[1]["Result"] != "exit-code" {
		t.Fatalf("%v", b)
	}
}

// Seen on spiritlab: the mergerfs pool mounted although its only branch
// (/mnt/media1) did not, so writes went to the root filesystem.
func TestPoolMountedOverMissingBranch(t *testing.T) {
	d, inv := spiritlabData(t)
	d.Mounts = append(d.Mounts, inventory.Mount{Target: "/mnt/drivepool", Source: "/mnt/media1", FSType: "fuse.mergerfs"})
	rep := Analyze(d, inv)
	for _, e := range rep.Entries {
		if e.Mountpoint != "/mnt/drivepool" {
			continue
		}
		all := strings.Join(e.Problems, "\n")
		if e.Status != "failed" || !e.Mounted || !strings.Contains(all, "branch /mnt/media1 is not mounted, but this pool is") || len(e.Hints) == 0 {
			t.Fatalf("%+v", e)
		}
		return
	}
	t.Fatal("drivepool entry missing")
}
