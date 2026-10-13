package events

import "testing"

const sample = `{"__CURSOR":"s=a;i=1","__REALTIME_TIMESTAMP":"1791850000000000","__MONOTONIC_TIMESTAMP":"7500000","_BOOT_ID":"b1","PRIORITY":"5","MESSAGE":"sd 2:0:1:0: [sda] Attached SCSI disk"}
{"__CURSOR":"s=a;i=2","__REALTIME_TIMESTAMP":"1791851100000000","__MONOTONIC_TIMESTAMP":"1260000000","_BOOT_ID":"b1","PRIORITY":"5","MESSAGE":"sd 2:0:9:0: [sdi] Attached SCSI disk"}
{"__CURSOR":"s=a;i=3","__REALTIME_TIMESTAMP":"1791851200000000","__MONOTONIC_TIMESTAMP":"1270000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"I/O error, dev sdc, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2"}
{"__CURSOR":"s=a;i=4","__REALTIME_TIMESTAMP":"1791851300000000","__MONOTONIC_TIMESTAMP":"1280000000","_BOOT_ID":"b1","PRIORITY":"4","MESSAGE":"sd 2:0:3:0: attempting task abort!scmd(0x000000001)"}
{"__CURSOR":"s=a;i=5","__REALTIME_TIMESTAMP":"1791851400000000","__MONOTONIC_TIMESTAMP":"1290000000","_BOOT_ID":"b1","PRIORITY":"6","MESSAGE":[104,105,255]}
{"__CURSOR":"s=a;i=6","__REALTIME_TIMESTAMP":"1791851500000000","__MONOTONIC_TIMESTAMP":"1300000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"sd 2:0:3:0: [sdc] tag#12 Sense Key : Medium Error [current]"}
{"__CURSOR":"s=a;i=7","__REALTIME_TIMESTAMP":"1791851600000000","__MONOTONIC_TIMESTAMP":"1310000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"EXT4-fs error (device sdi): ext4_find_entry:1234: inode #2: comm ls: reading directory lblock 0"}
{"__CURSOR":"s=a;i=8","__REALTIME_TIMESTAMP":"1791851700000000","__MONOTONIC_TIMESTAMP":"1320000000","_BOOT_ID":"b1","PRIORITY":"6","MESSAGE":"usb 1-1: new high-speed USB device number 2 using xhci_hcd"}
`

func TestParseAndClassify(t *testing.T) {
	es := ParseJSONLines([]byte(sample))
	if len(es) != 8 {
		t.Fatalf("got %d entries", len(es))
	}
	if es[4].Message != "hi�" {
		t.Fatalf("byte-array message: %q", es[4].Message)
	}
	want := []struct {
		cat, dev, sev string
		late          bool
	}{
		{CatAppeared, "sda", "info", false},
		{CatAppeared, "sdi", "warn", true},
		{CatIOError, "sdc", "error", false},
		{CatReset, "sd 2:0:3:0", "warn", false},
		{"", "", "", false},
		{CatMedium, "sdc", "error", false},
		{CatFS, "sdi", "error", false},
		{"", "", "", false},
	}
	for i, e := range es {
		ev, ok := Classify(e, 60)
		if want[i].cat == "" {
			if ok {
				t.Errorf("%d: unexpected event %+v", i, ev)
			}
			continue
		}
		if !ok || ev.Category != want[i].cat || ev.Device != want[i].dev || ev.Severity != want[i].sev || ev.Late != want[i].late {
			t.Errorf("%d: got %+v ok=%v want %+v", i, ev, ok, want[i])
		}
	}
	if AttachedDevice(es[1].Message) != "sdi" || AttachedDevice("nvme0n1: p1 p2 p3") != "nvme0n1" {
		t.Fatal("AttachedDevice")
	}
}
