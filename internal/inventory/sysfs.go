package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Sysfs reads topology from a sysfs tree. Root is "/sys" in production and
// a temporary directory in tests.
type Sysfs struct {
	Root string
}

var (
	rePCI      = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$`)
	reHost     = regexp.MustCompile(`^host[0-9]+$`)
	reATA      = regexp.MustCompile(`^ata[0-9]+$`)
	reUSB      = regexp.MustCompile(`^[0-9]+-[0-9.]+$`)
	reExpander = regexp.MustCompile(`^expander-[0-9:]+$`)
	reEndDev   = regexp.MustCompile(`^end_device-[0-9:]+$`)
	reNVMeCtl  = regexp.MustCompile(`^nvme[0-9]+$`)
)

func (s Sysfs) path(p ...string) string {
	return filepath.Join(append([]string{s.Root}, p...)...)
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readInt(p string) *int {
	s := readTrim(p)
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

// Topology resolves where block device `name` is attached.
func (s Sysfs) Topology(name string) Topology {
	var t Topology
	real, err := filepath.EvalSymlinks(s.path("block", name))
	if err != nil {
		return t
	}
	rootReal, err := filepath.EvalSymlinks(s.Root)
	if err != nil {
		rootReal = s.Root
	}
	rel := strings.TrimPrefix(real, rootReal)
	t.DevPath = rel
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	lastPCI := -1
	for i, seg := range segs {
		switch {
		case rePCI.MatchString(seg):
			lastPCI = i
		case reHost.MatchString(seg) && t.SCSIHost == "":
			t.SCSIHost = seg
			if lastPCI >= 0 {
				t.HBA = segs[lastPCI]
			}
		case reNVMeCtl.MatchString(seg) && i > 0 && segs[i-1] == "nvme" && t.HBA == "":
			if lastPCI >= 0 {
				t.HBA = segs[lastPCI]
			}
			t.Port = seg
		case reATA.MatchString(seg):
			t.Port = seg
		case reUSB.MatchString(seg) && t.SCSIHost == "":
			t.Port = "usb " + seg
		case reExpander.MatchString(seg):
			t.Expander = seg
		case reEndDev.MatchString(seg):
			t.EndDevice = seg
		}
	}
	if t.HBA != "" && lastPCI >= 0 {
		pciDir := "/" + strings.Join(segs[:indexOf(segs, t.HBA)+1], "/")
		if drv, err := os.Readlink(filepath.Join(rootReal, pciDir, "driver")); err == nil {
			t.HBADriver = filepath.Base(drv)
		}
	}
	devDir := s.path("block", name, "device")
	t.SASAddress = readTrim(filepath.Join(devDir, "sas_address"))
	if t.EndDevice != "" {
		t.BayID = readInt(s.path("class", "sas_device", t.EndDevice, "bay_identifier"))
	}
	t.Enclosure = s.enclosureSlot(devDir)
	return t
}

func indexOf(ss []string, v string) int {
	for i, s := range ss {
		if s == v {
			return i
		}
	}
	return -1
}

// enclosureSlot follows the "enclosure_device:<component>" link the ses
// driver creates in the SCSI device directory.
func (s Sysfs) enclosureSlot(devDir string) *EnclosureSlot {
	matches, _ := filepath.Glob(filepath.Join(devDir, "enclosure_device:*"))
	if len(matches) == 0 {
		return nil
	}
	m := matches[0]
	comp, err := filepath.EvalSymlinks(m)
	if err != nil {
		return nil
	}
	es := &EnclosureSlot{
		Enclosure: filepath.Base(filepath.Dir(comp)),
		Component: strings.TrimPrefix(filepath.Base(m), "enclosure_device:"),
		Slot:      readInt(filepath.Join(comp, "slot")),
		Status:    readTrim(filepath.Join(comp, "status")),
		Fault:     readTrim(filepath.Join(comp, "fault")) == "1",
		Locate:    readTrim(filepath.Join(comp, "locate")) == "1",
	}
	return es
}

// Enclosures lists SES enclosures and their components.
func (s Sysfs) Enclosures() []Enclosure {
	dirs, _ := filepath.Glob(s.path("class", "enclosure", "*"))
	var out []Enclosure
	for _, d := range dirs {
		e := Enclosure{
			ID:        filepath.Base(d),
			LogicalID: readTrim(filepath.Join(d, "id")),
			Vendor:    readTrim(filepath.Join(d, "device", "vendor")),
			Model:     readTrim(filepath.Join(d, "device", "model")),
		}
		entries, _ := os.ReadDir(d)
		for _, ent := range entries {
			cd := filepath.Join(d, ent.Name())
			if st, err := os.Stat(cd); err != nil || !st.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(cd, "status")); err != nil {
				if _, err2 := os.Stat(filepath.Join(cd, "slot")); err2 != nil {
					continue
				}
			}
			c := EnclosureComponent{
				Name:   ent.Name(),
				Slot:   readInt(filepath.Join(cd, "slot")),
				Status: readTrim(filepath.Join(cd, "status")),
				Fault:  readTrim(filepath.Join(cd, "fault")) == "1",
				Locate: readTrim(filepath.Join(cd, "locate")) == "1",
				Active: readTrim(filepath.Join(cd, "active")) == "1",
			}
			if blk, _ := filepath.Glob(filepath.Join(cd, "device", "block", "*")); len(blk) > 0 {
				c.Disk = filepath.Base(blk[0])
			}
			e.Components = append(e.Components, c)
		}
		sort.SliceStable(e.Components, func(i, j int) bool {
			a, b := e.Components[i].Slot, e.Components[j].Slot
			if a != nil && b != nil {
				return *a < *b
			}
			return e.Components[i].Name < e.Components[j].Name
		})
		out = append(out, e)
	}
	return out
}

// SASHosts maps SCSI host names (host2) to their PCI address, so HBAs with
// no disks attached still show up.
func (s Sysfs) SASHosts() map[string]string {
	out := map[string]string{}
	dirs, _ := filepath.Glob(s.path("class", "sas_host", "*"))
	rootReal, err := filepath.EvalSymlinks(s.Root)
	if err != nil {
		rootReal = s.Root
	}
	for _, d := range dirs {
		real, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue
		}
		segs := strings.Split(strings.Trim(strings.TrimPrefix(real, rootReal), "/"), "/")
		pci := ""
		for _, seg := range segs {
			if rePCI.MatchString(seg) {
				pci = seg
			}
			if reHost.MatchString(seg) {
				break
			}
		}
		if pci != "" {
			out[filepath.Base(d)] = pci
		}
	}
	return out
}

// PCIDriver returns the kernel driver bound to a PCI device.
func (s Sysfs) PCIDriver(pci string) string {
	if drv, err := os.Readlink(s.path("bus", "pci", "devices", pci, "driver")); err == nil {
		return filepath.Base(drv)
	}
	return ""
}
