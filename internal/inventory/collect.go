package inventory

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/krifmaz/fsview/internal/runner"
)

// Collector gathers an Inventory using external tools and sysfs.
type Collector struct {
	Runner      runner.Runner
	Sysfs       Sysfs
	ProcSwaps   string // path, default /proc/swaps
	IncludeLoop bool
	Resolve     Resolver
	UdevDataDir string // default /run/udev/data

	pciNames map[string]string
}

func NewCollector(r runner.Runner, includeLoop bool) *Collector {
	return &Collector{Runner: r, Sysfs: Sysfs{Root: "/sys"}, ProcSwaps: "/proc/swaps", IncludeLoop: includeLoop, Resolve: RealResolver}
}

func (c *Collector) Collect(ctx context.Context) (*Inventory, error) {
	inv := &Inventory{CollectedAt: time.Now().UTC()}
	inv.Hostname, _ = os.Hostname()

	res, err := c.Runner.Run(ctx, "lsblk", LsblkArgs...)
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("lsblk exited %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	disks, err := ParseLsblk(res.Stdout, c.IncludeLoop)
	if err != nil {
		return nil, err
	}

	if c.UdevDataDir == "" {
		c.UdevDataDir = "/run/udev/data"
	}
	if _, err := os.Stat(c.UdevDataDir); err != nil {
		// Without udev, lsblk cannot report filesystems. blkid probes the
		// devices directly (it reads them, so it is never used when udev
		// data exists: that would wake sleeping disks).
		if res, err := c.Runner.Run(ctx, "blkid", "-c", "/dev/null", "-o", "export"); err == nil {
			MergeBlkid(disks, ParseBlkidExport(string(res.Stdout)))
		}
		inv.Warnings = append(inv.Warnings, "udev database not found; filesystem details come from blkid probing")
	}

	sys, warns := c.systemInfo(ctx)
	inv.Warnings = append(inv.Warnings, warns...)
	MarkProtected(disks, sys, c.Resolve)

	hbas := map[string]*HBA{}
	for host, pci := range c.Sysfs.SASHosts() {
		h := hbas[pci]
		if h == nil {
			h = &HBA{PCI: pci}
			hbas[pci] = h
		}
		h.Hosts = appendUnique(h.Hosts, host)
	}
	for i := range disks {
		d := &disks[i]
		d.Topology = c.Sysfs.Topology(d.Name)
		if d.Transport == "" && strings.HasPrefix(d.Topology.Port, "usb") {
			d.Transport = "usb"
		}
		if pci := d.Topology.HBA; pci != "" {
			h := hbas[pci]
			if h == nil {
				h = &HBA{PCI: pci}
				hbas[pci] = h
			}
			if d.Topology.SCSIHost != "" {
				h.Hosts = appendUnique(h.Hosts, d.Topology.SCSIHost)
			}
			h.Disks = append(h.Disks, d.Name)
			if h.Driver == "" {
				h.Driver = d.Topology.HBADriver
			}
		}
	}
	for pci, h := range hbas {
		if h.Driver == "" {
			h.Driver = c.Sysfs.PCIDriver(pci)
		}
		h.Name = c.pciName(ctx, pci)
		sort.Strings(h.Hosts)
		inv.HBAs = append(inv.HBAs, *h)
	}
	sort.Slice(inv.HBAs, func(i, j int) bool { return inv.HBAs[i].PCI < inv.HBAs[j].PCI })
	for i := range disks {
		if h := hbas[disks[i].Topology.HBA]; h != nil {
			disks[i].Topology.HBAName = h.Name
		}
	}
	inv.Disks = disks
	inv.Enclosures = c.Sysfs.Enclosures()
	return inv, nil
}

func appendUnique(l []string, v string) []string {
	for _, x := range l {
		if x == v {
			return l
		}
	}
	return append(l, v)
}

// systemInfo collects mounts, swap, root VG PVs and root ZFS pool vdevs.
func (c *Collector) systemInfo(ctx context.Context) (SystemInfo, []string) {
	var sys SystemInfo
	var warns []string
	sys.ExtraSystemDevices = map[string]string{}

	res, err := c.Runner.Run(ctx, "findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS")
	if err == nil && res.ExitCode == 0 {
		if m, err := ParseFindmnt(res.Stdout); err == nil {
			sys.Mounts = m
		} else {
			warns = append(warns, err.Error())
		}
	} else {
		warns = append(warns, "findmnt failed; protected-disk detection relies on lsblk only")
	}
	if b, err := os.ReadFile(c.ProcSwaps); err == nil {
		sys.SwapDevices = ParseProcSwaps(string(b))
	}

	var root *Mount
	for i := range sys.Mounts {
		if sys.Mounts[i].Target == "/" {
			root = &sys.Mounts[i]
		}
	}
	if root == nil {
		return sys, warns
	}

	// LVM: protect every PV of the volume group holding /.
	if strings.HasPrefix(root.Source, "/dev/mapper/") || strings.HasPrefix(root.Source, "/dev/dm-") {
		rootK := c.Resolve(root.Source)
		lvs, err := c.Runner.Run(ctx, "lvs", "--reportformat", "json", "-o", "vg_name,lv_dm_path")
		if err == nil && lvs.ExitCode == 0 {
			rows, _ := ParseLVMReport(lvs.Stdout, "lv")
			vg := ""
			for _, r := range rows {
				if r["lv_dm_path"] != "" && (r["lv_dm_path"] == root.Source || c.Resolve(r["lv_dm_path"]) == rootK) {
					vg = r["vg_name"]
				}
			}
			if vg != "" {
				pvs, err := c.Runner.Run(ctx, "pvs", "--reportformat", "json", "-o", "pv_name,vg_name")
				if err == nil && pvs.ExitCode == 0 {
					prow, _ := ParseLVMReport(pvs.Stdout, "pv")
					for _, r := range prow {
						if r["vg_name"] == vg {
							sys.ExtraSystemDevices[r["pv_name"]] = fmt.Sprintf("LVM PV of root VG %s", vg)
						}
					}
				}
			}
		}
	}

	// ZFS root (Proxmox "rpool" installs): protect every vdev of the pools
	// holding / and /boot.
	for _, m := range sys.Mounts {
		if m.FSType != "zfs" || !(m.Target == "/" || m.Target == "/boot") {
			continue
		}
		pool, _, _ := strings.Cut(m.Source, "/")
		zr, err := c.Runner.Run(ctx, "zpool", "list", "-v", "-H", "-P", pool)
		if err != nil || zr.ExitCode != 0 {
			warns = append(warns, fmt.Sprintf("could not list vdevs of root pool %s", pool))
			continue
		}
		for _, dev := range ParseZpoolVdevs(string(zr.Stdout)) {
			sys.ExtraSystemDevices[dev] = fmt.Sprintf("vdev of root ZFS pool %s", pool)
		}
	}
	return sys, warns
}

// pciName asks lspci for a human-readable device name (cached).
func (c *Collector) pciName(ctx context.Context, pci string) string {
	if c.pciNames == nil {
		c.pciNames = map[string]string{}
	}
	if n, ok := c.pciNames[pci]; ok {
		return n
	}
	name := ""
	if res, err := c.Runner.Run(ctx, "lspci", "-mm", "-s", pci); err == nil && res.ExitCode == 0 {
		name = ParseLspciName(string(res.Stdout))
	}
	c.pciNames[pci] = name
	return name
}

// ParseLspciName parses one line of `lspci -mm` output:
// 0c:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 ..." -r05 ...
func ParseLspciName(line string) string {
	var fields []string
	for {
		i := strings.Index(line, `"`)
		if i < 0 {
			break
		}
		j := strings.Index(line[i+1:], `"`)
		if j < 0 {
			break
		}
		fields = append(fields, line[i+1:i+1+j])
		line = line[i+j+2:]
	}
	if len(fields) < 3 {
		return ""
	}
	return strings.TrimSpace(fields[1] + " " + fields[2])
}

// ParseBlkidExport parses `blkid -o export` output into device -> tags.
func ParseBlkidExport(out string) map[string]map[string]string {
	res := map[string]map[string]string{}
	cur := map[string]string{}
	flush := func() {
		if dev := cur["DEVNAME"]; dev != "" {
			res[dev] = cur
		}
		cur = map[string]string{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return res
}

// MergeBlkid fills empty filesystem fields from blkid tags.
func MergeBlkid(disks []Disk, tags map[string]map[string]string) {
	fill := func(path string, fstype, label, uuid *string) {
		t, ok := tags[path]
		if !ok {
			return
		}
		if *fstype == "" {
			*fstype = t["TYPE"]
		}
		if *label == "" {
			*label = t["LABEL"]
		}
		if *uuid == "" {
			*uuid = t["UUID"]
		}
	}
	for i := range disks {
		d := &disks[i]
		fill(d.Path, &d.FSType, &d.Label, &d.UUID)
		d.Walk(func(n *Node) {
			fill(n.Path, &n.FSType, &n.Label, &n.UUID)
			if t, ok := tags[n.Path]; ok && n.PartUUID == "" {
				n.PartUUID = t["PARTUUID"]
			}
		})
	}
}
