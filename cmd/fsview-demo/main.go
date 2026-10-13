// Command fsview-demo serves the real UI and API against recorded fixtures
// (testdata/spiritlab) instead of the root helper. It is a development aid
// for UI work and screenshots; it never touches hardware.
//
//	go run ./cmd/fsview-demo -listen 127.0.0.1:9201
//	login: demo / demo-password
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/krifmaz/fsview/internal/bootcheck"
	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/helper"
	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/store"
	"github.com/krifmaz/fsview/internal/web"
)

type demoHelper struct {
	dir   string
	audit []helper.AuditRecord
}

func (h *demoHelper) read(n string) []byte {
	b, err := os.ReadFile(filepath.Join(h.dir, n))
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func ip(v int) *int { return &v }

func (h *demoHelper) inventory() inventory.Inventory {
	disks, _ := inventory.ParseLsblk(h.read("lsblk.json"), false)
	mounts, _ := inventory.ParseFindmnt(h.read("findmnt.json"))
	inventory.MarkProtected(disks, inventory.SystemInfo{Mounts: mounts, SwapDevices: []string{"/dev/mapper/pve-swap"},
		ExtraSystemDevices: map[string]string{"/dev/nvme0n1p3": "LVM PV of root VG pve"}}, filepath.Base)
	var comps []inventory.EnclosureComponent
	for i := range disks {
		d := &disks[i]
		if d.Transport == "sas" {
			slot := 0
			fmt.Sscanf(d.HCTL, "2:0:%d:0", &slot)
			d.Topology = inventory.Topology{HBA: "0000:0c:00.0", HBAName: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2", HBADriver: "mpt3sas",
				SCSIHost: "host2", Expander: "expander-2:0", EndDevice: fmt.Sprintf("end_device-2:0:%d", slot), SASAddress: d.WWN,
				Enclosure: &inventory.EnclosureSlot{Enclosure: "2:0:0:0", Component: fmt.Sprintf("Slot %02d", slot), Slot: ip(slot), Status: "OK"}}
			comps = append(comps, inventory.EnclosureComponent{Name: fmt.Sprintf("Slot %02d", slot), Slot: ip(slot), Status: "OK", Disk: d.Name})
		} else {
			d.Topology = inventory.Topology{HBA: "0000:01:00.0", HBAName: "Sandisk Corp PC SN530 NVMe SSD", HBADriver: "nvme", Port: "nvme0"}
		}
	}
	els := inventory.ParseSESStatus(string(h.read("sg_ses_p2.txt")))
	for _, s := range []int{10, 11, 12} {
		comps = append(comps, inventory.EnclosureComponent{Name: fmt.Sprintf("Slot %02d", s), Slot: ip(s), Status: "Not Installed"})
	}
	return inventory.Inventory{
		Hostname: "spiritlab (demo)", CollectedAt: time.Now().UTC(), Disks: disks,
		HBAs: []inventory.HBA{
			{PCI: "0000:01:00.0", Name: "Sandisk Corp PC SN530 NVMe SSD", Driver: "nvme", Disks: []string{"nvme0n1"}},
			{PCI: "0000:0c:00.0", Name: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2", Driver: "mpt3sas", Hosts: []string{"host2"}, Disks: []string{"sda", "sdb", "sdc", "sdd", "sde", "sdf", "sdg", "sdh", "sdi"}},
			{PCI: "0000:0e:00.0", Name: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2", Driver: "mpt3sas", Hosts: []string{"host3"}},
		},
		Enclosures: []inventory.Enclosure{{ID: "2:0:9:0", SGDevice: "sg9", Vendor: "NETAPP", Model: "DS424IOM6E", Components: comps,
			Elements: els, Status: inventory.EnclosureLevel(els)}},
	}
}

func (h *demoHelper) Call(ctx context.Context, req *proto.Request, out any) (*proto.Response, error) {
	var result any
	resp := &proto.Response{OK: true}
	switch req.Op {
	case proto.OpStatus:
		result = proto.StatusResult{Version: "demo", Hostname: "spiritlab (demo)", WritesEnabled: true, Tools: map[string]bool{"smartctl": true, "lsblk": true, "sg_ses": true, "lspci": true, "zpool": false, "mergerfs": true}}
	case proto.OpInventory:
		result = h.inventory()
	case proto.OpSmartGet:
		var p proto.SmartGetParams
		json.Unmarshal(req.Params, &p)
		files := map[string][2]string{"sdc": {"smart_sdc_scsi.json", ""}, "sdd": {"smart_sdc_scsi.json", ""}, "sdi": {"smart_sdi_scsi.json", ""},
			"nvme0n1": {"smart_nvme0n1.json", ""}, "sdb": {"smart_sdb_sat_synthetic.json", "sat"}}
		f, ok := files[p.Device]
		if !ok {
			if p.Device == "sdh" && !p.Wake {
				result = proto.SmartGetResult{Device: p.Device, Standby: true}
				break
			}
			f = [2]string{"smart_sdi_scsi.json", ""}
			raw := h.read(f[0])
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["temperature"] = map[string]any{"current": 29, "drive_trip": 60}
			raw, _ = json.Marshal(m)
			result = proto.SmartGetResult{Device: p.Device, Raw: raw}
			break
		}
		result = proto.SmartGetResult{Device: p.Device, DevType: f[1], Raw: h.read(f[0])}
	case proto.OpSmartSelfTest:
		var p proto.SmartSelfTestParams
		json.Unmarshal(req.Params, &p)
		cmd := fmt.Sprintf("smartctl -t %s /dev/%s", p.Test, p.Device)
		res := "ok"
		if req.DryRun {
			res = "dry-run"
		}
		h.audit = append([]helper.AuditRecord{{Time: time.Now().UTC(), Actor: req.Actor, ClientIP: req.ClientIP, Op: req.Op, Targets: []string{p.Device}, DryRun: req.DryRun, Commands: []string{cmd}, Result: res}}, h.audit...)
		resp.DryRun, resp.Plan = req.DryRun, []string{cmd}
		result = map[string]string{"summary": "demo"}
	case proto.OpJournalKernel:
		if req.Params != nil && string(req.Params) != "" {
			var p proto.JournalParams
			json.Unmarshal(req.Params, &p)
			if p.AfterCursor != "" {
				result = []events.Entry{}
				break
			}
		}
		boot := time.Now().Add(-25 * time.Minute)
		mk := func(i int, sec float64, prio int, msg string) events.Entry {
			return events.Entry{Cursor: fmt.Sprintf("demo-%d", i), RealtimeUS: boot.Add(time.Duration(sec * 1e9)).UnixMicro(), MonotonicUS: int64(sec * 1e6), BootID: "demo", Priority: prio, Message: msg}
		}
		result = []events.Entry{
			mk(1, 7.5, 5, "sd 2:0:1:0: [sda] Attached SCSI disk"),
			mk(2, 7.7, 5, "sd 2:0:3:0: [sdc] Attached SCSI disk"),
			mk(3, 300, 3, "sd 2:0:3:0: [sdc] tag#12 Sense Key : Medium Error [current]"),
			mk(4, 300.1, 3, "I/O error, dev sdc, sector 179177313 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2"),
			mk(5, 420, 4, "sd 2:0:4:0: attempting task abort!scmd(0x00000000a1b2c3d4), outstanding for 30060 ms & timeout 30000 ms"),
			mk(6, 1260, 5, "sd 2:0:9:0: [sdi] Attached SCSI disk"),
			mk(7, 1300, 6, "EXT4-fs (sda1): mounted filesystem df81e242-df1f-41a9-87ea-b441da0ee820 r/w with ordered data mode."),
		}
	case proto.OpBootCollect:
		inv := h.inventory()
		_ = inv
		mounts, _ := inventory.ParseFindmnt(h.read("findmnt.json"))
		mounts = append(mounts, inventory.Mount{Target: "/mnt/drivepool", Source: "/mnt/media1", FSType: "fuse.mergerfs"})
		m1 := `dev-disk-by\x2duuid-c69cfb3b\x2d4f39\x2d449a\x2dbb21\x2dcd2e4ba23d49.device`
		result = bootcheck.Data{
			BootID: "bede039a4a1e4487bf8a27be5fb490e8", CollectedAt: time.Now().UTC(), Fstab: string(h.read("fstab")),
			Manager: map[string]string{"UserspaceTimestampMonotonic": "3200000", "FinishTimestampMonotonic": "25000000"},
			Units: map[string]map[string]string{
				"mnt-media1.mount":  {"Id": "mnt-media1.mount", "ActiveState": "inactive", "Result": "success"},
				"mnt-cache.mount":   {"Id": "mnt-cache.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "9100000"},
				"boot-efi.mount":    {"Id": "boot-efi.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "6000000"},
				"-.mount":           {"Id": "-.mount", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "1"},
				"dev-pve-swap.swap": {"Id": "dev-pve-swap.swap", "ActiveState": "active", "Result": "success", "ActiveEnterTimestampMonotonic": "5000000"},
				m1:                  {"Id": m1, "ActiveState": "active", "ActiveEnterTimestampMonotonic": "1260000000"},
			},
			Kernel: []events.Entry{{MonotonicUS: 7_500_000, Message: "sd 2:0:1:0: [sda] Attached SCSI disk"}, {MonotonicUS: 1_260_000_000, Message: "sd 2:0:9:0: [sdi] Attached SCSI disk"}},
			Systemd: []events.Entry{
				{MonotonicUS: 13_300_000, Message: "Timed out waiting for device " + m1 + " - /dev/disk/by-uuid/c69cfb3b-4f39-449a-bb21-cd2e4ba23d49."},
				{MonotonicUS: 13_300_000, Message: "Dependency failed for mnt-media1.mount - /mnt/media1."},
			},
			Mounts: mounts,
		}
	case proto.OpAuditList:
		result = h.audit
		if h.audit == nil {
			result = []helper.AuditRecord{}
		}
	default:
		return nil, &helperclient.Error{Code: proto.CodeUnknownOp, Msg: "unknown op"}
	}
	b, _ := json.Marshal(result)
	resp.Result = b
	if out != nil {
		json.Unmarshal(b, out)
	}
	return resp, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9201", "address")
	dir := flag.String("fixtures", "testdata/spiritlab", "fixture directory")
	flag.Parse()
	data, _ := os.MkdirTemp("", "fsview-demo")
	defer os.RemoveAll(data)
	st, err := store.Open(data)
	if err != nil {
		log.Fatal(err)
	}
	st.SetPassword("demo", "demo-password", true)
	srv := web.New(web.Options{Version: "demo", Listen: []string{*listen},
		Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}, st, &demoHelper{dir: *dir})
	fmt.Printf("demo UI on http://%s  (login demo / demo-password)\n", *listen)
	if err := srv.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
