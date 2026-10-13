package inventory

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SystemMountpoints are mountpoints whose backing disks are protected.
var SystemMountpoints = []string{"/", "/boot", "/boot/efi", "/efi", "/usr", "/var"}

// Mount is one entry from findmnt.
type Mount struct {
	Target  string `json:"target"`
	Source  string `json:"source"`
	FSType  string `json:"fstype"`
	Options string `json:"options,omitempty"`
}

// ParseFindmnt flattens findmnt -J output.
func ParseFindmnt(data []byte) ([]Mount, error) {
	type fm struct {
		Mount
		Children []fm `json:"children"`
	}
	var doc struct {
		Filesystems []fm `json:"filesystems"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse findmnt: %w", err)
	}
	var out []Mount
	var rec func([]fm)
	rec = func(l []fm) {
		for _, f := range l {
			out = append(out, f.Mount)
			rec(f.Children)
		}
	}
	rec(doc.Filesystems)
	return out, nil
}

// SystemInfo is everything needed to decide which disks hold the system.
type SystemInfo struct {
	Mounts []Mount
	// SwapDevices are block devices (paths) used as active swap.
	SwapDevices []string
	// ExtraSystemDevices are device paths that also hold the system, e.g.
	// PVs of the root volume group or vdevs of the root ZFS pool. Key is a
	// device path, value is the reason.
	ExtraSystemDevices map[string]string
}

// Resolver turns a device path (possibly a symlink like /dev/mapper/x or
// /dev/disk/by-id/y) into its kernel name ("dm-1", "sda3").
type Resolver func(path string) string

// RealResolver resolves through the filesystem.
func RealResolver(path string) string {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Base(p)
	}
	return filepath.Base(path)
}

// MarkProtected flags every disk that holds a system mountpoint, active
// swap, or one of the extra system devices.
func MarkProtected(disks []Disk, sys SystemInfo, resolve Resolver) {
	if resolve == nil {
		resolve = RealResolver
	}
	type want struct {
		path, kname, reason string
	}
	var wants []want
	add := func(dev, reason string) {
		if !strings.HasPrefix(dev, "/dev/") {
			return
		}
		wants = append(wants, want{path: dev, kname: resolve(dev), reason: reason})
	}
	for _, mp := range SystemMountpoints {
		for _, m := range sys.Mounts {
			if m.Target == mp {
				add(sourceDevice(m.Source), fmt.Sprintf("holds %s", mp))
			}
		}
	}
	for _, s := range sys.SwapDevices {
		add(s, "active swap")
	}
	for dev, reason := range sys.ExtraSystemDevices {
		add(dev, reason)
	}

	for i := range disks {
		d := &disks[i]
		reasons := map[string]bool{}
		match := func(path, kname string, mounts []string, fstype, name string) {
			for _, w := range wants {
				if (w.path != "" && w.path == path) || (w.kname != "" && w.kname == kname) {
					reasons[fmt.Sprintf("%s (%s)", w.reason, name)] = true
				}
			}
			for _, m := range mounts {
				for _, mp := range SystemMountpoints {
					if m == mp {
						reasons[fmt.Sprintf("holds %s (%s)", mp, name)] = true
					}
				}
				if m == "[SWAP]" {
					reasons[fmt.Sprintf("active swap (%s)", name)] = true
				}
			}
		}
		match(d.Path, d.Name, d.Mounts, d.FSType, d.Name)
		d.Walk(func(n *Node) { match(n.Path, n.KName, n.Mounts, n.FSType, n.Name) })
		if len(reasons) > 0 {
			d.Protected = true
			d.ProtectedReasons = d.ProtectedReasons[:0]
			for r := range reasons {
				d.ProtectedReasons = append(d.ProtectedReasons, r)
			}
			sort.Strings(d.ProtectedReasons)
		}
	}
}

// sourceDevice strips a btrfs subvolume suffix like "/dev/sda2[/@]".
func sourceDevice(src string) string {
	if i := strings.Index(src, "["); i > 0 {
		return src[:i]
	}
	return src
}

// ParseProcSwaps returns block devices from /proc/swaps (swap files are
// covered because the filesystem holding them is a system mount anyway).
func ParseProcSwaps(data string) []string {
	var out []string
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 2 {
			continue
		}
		if f[1] == "partition" {
			out = append(out, strings.ReplaceAll(f[0], `\040`, " "))
		}
	}
	return out
}

// ParseLVMReport parses `lvs/pvs --reportformat json` output into rows.
func ParseLVMReport(data []byte, kind string) ([]map[string]string, error) {
	var doc struct {
		Report []map[string][]map[string]string `json:"report"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var rows []map[string]string
	for _, r := range doc.Report {
		rows = append(rows, r[kind]...)
	}
	return rows, nil
}

// ParseZpoolVdevs extracts device paths from `zpool list -v -H -P` output.
func ParseZpoolVdevs(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "/dev/") {
			out = append(out, f[0])
		}
	}
	return out
}
