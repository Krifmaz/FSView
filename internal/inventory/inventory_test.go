package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krifmaz/fsview/internal/runner"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "spiritlab", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseLsblkSpiritlab(t *testing.T) {
	disks, err := ParseLsblk(fixture(t, "lsblk.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(disks) != 10 {
		t.Fatalf("want 10 disks (no zram/loop), got %d", len(disks))
	}
	var sdi, sda *Disk
	for i := range disks {
		switch disks[i].Name {
		case "sdi":
			sdi = &disks[i]
		case "sda":
			sda = &disks[i]
		}
	}
	if sdi == nil || sdi.Label != "media1" || sdi.FSType != "ext4" || sdi.SizeBytes != 28001039286272 {
		t.Fatalf("sdi wrong: %+v", sdi)
	}
	if sdi.Model != "ST28000N M000C-3WM103 SM" {
		t.Fatalf("model = %q", sdi.Model)
	}
	if !sdi.Rotational || sdi.Transport != "sas" {
		t.Fatalf("sdi flags wrong: %+v", sdi)
	}
	if len(sda.Children) != 1 || sda.Children[0].Mounts[0] != "/mnt/cache" || sda.Children[0].Usage == nil {
		t.Fatalf("sda1 wrong: %+v", sda.Children)
	}
	loop, _ := ParseLsblk(fixture(t, "lsblk.json"), true)
	if len(loop) != 10 { // loop0 has size 0 and is skipped even with includeLoop
		t.Fatalf("got %d", len(loop))
	}
}

func TestDisplayModel(t *testing.T) {
	cases := map[[2]string]string{
		{"ATA", "Samsung SSD 870"}:    "Samsung SSD 870",
		{"WDC     ", "WD7500BPKT"}:    "WDC WD7500BPKT",
		{"", "WDC CH SN530"}:          "WDC CH SN530",
		{"SEAGATE", "SEAGATE ST4000"}: "SEAGATE ST4000",
	}
	for in, want := range cases {
		if got := DisplayModel(in[0], in[1]); got != want {
			t.Errorf("DisplayModel(%q,%q) = %q want %q", in[0], in[1], got, want)
		}
	}
}

func spiritlabResolver(p string) string {
	m := map[string]string{
		"/dev/mapper/pve-root": "dm-1",
		"/dev/mapper/pve-swap": "dm-0",
		"/dev/pve/root":        "dm-1",
		"/dev/dm-0":            "dm-0",
		"/dev/nvme0n1p2":       "nvme0n1p2",
		"/dev/nvme0n1p3":       "nvme0n1p3",
		"/dev/sda1":            "sda1",
	}
	if k, ok := m[p]; ok {
		return k
	}
	return filepath.Base(p)
}

func TestProtectedSpiritlab(t *testing.T) {
	disks, _ := ParseLsblk(fixture(t, "lsblk.json"), false)
	mounts, err := ParseFindmnt(fixture(t, "findmnt.json"))
	if err != nil {
		t.Fatal(err)
	}
	sys := SystemInfo{
		Mounts:             mounts,
		SwapDevices:        ParseProcSwaps(string(fixture(t, "proc_swaps"))),
		ExtraSystemDevices: map[string]string{"/dev/nvme0n1p3": "LVM PV of root VG pve"},
	}
	MarkProtected(disks, sys, spiritlabResolver)
	for _, d := range disks {
		want := d.Name == "nvme0n1"
		if d.Protected != want {
			t.Errorf("%s protected=%v want %v (%v)", d.Name, d.Protected, want, d.ProtectedReasons)
		}
		if d.Name == "nvme0n1" {
			all := strings.Join(d.ProtectedReasons, ";")
			for _, frag := range []string{"holds /", "holds /boot/efi", "active swap", "LVM PV of root VG pve"} {
				if !strings.Contains(all, frag) {
					t.Errorf("missing reason %q in %q", frag, all)
				}
			}
		}
	}
}

func TestProtectedViaMountOnly(t *testing.T) {
	// No findmnt data: lsblk mountpoints alone must still protect the disk.
	disks, _ := ParseLsblk(fixture(t, "lsblk.json"), false)
	MarkProtected(disks, SystemInfo{}, spiritlabResolver)
	for _, d := range disks {
		if d.Name == "nvme0n1" && !d.Protected {
			t.Fatal("nvme0n1 must be protected from lsblk mountpoints alone")
		}
		if d.Name == "sda" && d.Protected {
			t.Fatal("sda (/mnt/cache) must not be protected")
		}
	}
}

func TestParseHelpers(t *testing.T) {
	rows, err := ParseLVMReport([]byte(`{"report":[{"pv":[{"pv_name":"/dev/nvme0n1p3","vg_name":"pve"},{"pv_name":"/dev/sdz1","vg_name":"other"}]}]}`), "pv")
	if err != nil || len(rows) != 2 || rows[0]["vg_name"] != "pve" {
		t.Fatalf("lvm rows %v %v", rows, err)
	}
	z := ParseZpoolVdevs("rpool\t928G\t2G\t-\n\tmirror-0\t928G\n\t/dev/disk/by-id/ata-X-part3\t-\n\t/dev/disk/by-id/ata-Y-part3\t-\n")
	if len(z) != 2 || !strings.HasSuffix(z[1], "ata-Y-part3") {
		t.Fatalf("zpool vdevs %v", z)
	}
	if n := ParseLspciName(`0c:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05 "Broadcom / LSI" "x"`); n != "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2" {
		t.Fatalf("lspci name %q", n)
	}
}

// buildSysfs creates a sysfs tree shaped like spiritlab's: an LSI SAS2308
// at 0000:0c:00.0, host2, an expander, end devices, and an SES enclosure.
func buildSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, v string) {
		mk(filepath.Dir(p))
		if err := os.WriteFile(filepath.Join(root, p), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		mk(filepath.Dir(p))
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	hba := "devices/pci0000:00/0000:00:03.2/0000:0a:00.0/0000:0b:01.0/0000:0c:00.0"
	mk("bus/pci/drivers/mpt3sas")
	link("../../../bus/pci/drivers/mpt3sas", hba+"/driver")
	host := hba + "/host2"
	exp := host + "/port-2:0/expander-2:0"
	// enclosure on end_device-2:0:0
	encDev := exp + "/port-2:0:0/end_device-2:0:0/target2:0:0/2:0:0:0"
	enc := encDev + "/enclosure/2:0:0:0"
	write(enc+"/id", "0x500605b000000abc")
	write(encDev+"/vendor", "LSI")
	write(encDev+"/model", "SAS2X36")
	link("../../"+enc, "class/enclosure/2:0:0:0")
	link("../..", enc+"/device")
	// disk sdi in slot 9 on end_device-2:0:9
	sdiDev := exp + "/port-2:0:9/end_device-2:0:9/target2:0:9/2:0:9:0"
	mk(sdiDev + "/block/sdi")
	write(sdiDev+"/sas_address", "0x500605ba0127a8d4")
	write(enc+"/Slot 09/slot", "9")
	write(enc+"/Slot 09/status", "OK")
	write(enc+"/Slot 09/fault", "0")
	write(enc+"/Slot 09/locate", "1")
	link(strings.Repeat("../", strings.Count(enc+"/Slot 09", "/")+1)+sdiDev, enc+"/Slot 09/device")
	link(strings.Repeat("../", strings.Count(sdiDev, "/")+1)+enc+"/Slot 09", sdiDev+"/enclosure_device:Slot 09")
	write(enc+"/Slot 03/slot", "3")
	write(enc+"/Slot 03/status", "Not Installed")
	link("../"+sdiDev+"/block/sdi", "block/sdi")
	link(strings.Repeat("../", strings.Count(sdiDev+"/block/sdi", "/")+1)+sdiDev, sdiDev+"/block/sdi/device")
	write("class/sas_device/end_device-2:0:9/bay_identifier", "9")
	link("../../"+host, "class/sas_host/host2")
	// second HBA with no disks
	host3 := "devices/pci0000:00/0000:00:03.2/0000:0a:00.0/0000:0b:09.0/0000:0e:00.0/host3"
	mk(host3)
	link("../../"+host3, "class/sas_host/host3")
	// nvme
	nv := "devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/nvme0/nvme0n1"
	mk(nv)
	link("../"+nv, "block/nvme0n1")
	return root
}

func TestSysfsTopology(t *testing.T) {
	s := Sysfs{Root: buildSysfs(t)}
	top := s.Topology("sdi")
	if top.HBA != "0000:0c:00.0" || top.SCSIHost != "host2" || top.Expander != "expander-2:0" || top.EndDevice != "end_device-2:0:9" {
		t.Fatalf("topology: %+v", top)
	}
	if top.HBADriver != "mpt3sas" {
		t.Errorf("driver = %q", top.HBADriver)
	}
	if top.SASAddress != "0x500605ba0127a8d4" || top.BayID == nil || *top.BayID != 9 {
		t.Errorf("sas info: %+v", top)
	}
	if top.Enclosure == nil || top.Enclosure.Enclosure != "2:0:0:0" || top.Enclosure.Component != "Slot 09" || *top.Enclosure.Slot != 9 || !top.Enclosure.Locate {
		t.Fatalf("enclosure: %+v", top.Enclosure)
	}
	nv := s.Topology("nvme0n1")
	if nv.HBA != "0000:01:00.0" || nv.Port != "nvme0" {
		t.Fatalf("nvme topology: %+v", nv)
	}
	encs := s.Enclosures()
	if len(encs) != 1 || len(encs[0].Components) != 2 || encs[0].Components[1].Disk != "sdi" || encs[0].Vendor != "LSI" {
		t.Fatalf("enclosures: %+v", encs)
	}
	hosts := s.SASHosts()
	if hosts["host2"] != "0000:0c:00.0" || hosts["host3"] != "0000:0e:00.0" {
		t.Fatalf("sas hosts: %v", hosts)
	}
}

func TestCollectWithFakes(t *testing.T) {
	root := buildSysfs(t)
	swaps := filepath.Join(t.TempDir(), "swaps")
	os.WriteFile(swaps, fixture(t, "proc_swaps"), 0o644)
	f := &runner.Fake{Responses: map[string]runner.Result{
		"lsblk " + strings.Join(LsblkArgs, " "):         {Stdout: fixture(t, "lsblk.json")},
		"findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS":    {Stdout: fixture(t, "findmnt.json")},
		"lvs --reportformat json -o vg_name,lv_dm_path": {Stdout: []byte(`{"report":[{"lv":[{"vg_name":"pve","lv_dm_path":"/dev/mapper/pve-root"}]}]}`)},
		"pvs --reportformat json -o pv_name,vg_name":    {Stdout: []byte(`{"report":[{"pv":[{"pv_name":"/dev/nvme0n1p3","vg_name":"pve"}]}]}`)},
		"lspci -mm -s 0000:0c:00.0":                     {Stdout: []byte(`0c:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05`)},
		"lspci -mm -s 0000:0e:00.0":                     {Stdout: []byte(`0e:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05`)},
		"lspci -mm -s 0000:01:00.0":                     {Stdout: []byte(`01:00.0 "Non-Volatile memory controller" "Sandisk Corp" "PC SN530 NVMe SSD" -r01`)},
	}}
	c := &Collector{Runner: f, Sysfs: Sysfs{Root: root}, ProcSwaps: swaps, Resolve: spiritlabResolver, UdevDataDir: root}
	inv, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.HBAs) != 3 {
		t.Fatalf("HBAs: %+v", inv.HBAs)
	}
	sdi := inv.FindDisk("sdi")
	if sdi.Topology.HBAName != "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2" {
		t.Fatalf("hba name %q", sdi.Topology.HBAName)
	}
	if !inv.FindDisk("nvme0n1").Protected || inv.FindDisk("sdi").Protected {
		t.Fatal("protection wrong")
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings: %v", inv.Warnings)
	}
}

func TestBlkidMerge(t *testing.T) {
	disks := []Disk{{Name: "loop0", Path: "/dev/loop0"}, {Name: "sdx", Path: "/dev/sdx", Children: []Node{{Name: "sdx1", Path: "/dev/sdx1"}}}}
	tags := ParseBlkidExport("DEVNAME=/dev/loop0\nLABEL=media1\nUUID=abc\nTYPE=ext4\n\nDEVNAME=/dev/sdx1\nTYPE=xfs\nPARTUUID=p1\n")
	MergeBlkid(disks, tags)
	if disks[0].FSType != "ext4" || disks[0].Label != "media1" || disks[1].Children[0].FSType != "xfs" || disks[1].Children[0].PartUUID != "p1" {
		t.Fatalf("%+v", disks)
	}
}
