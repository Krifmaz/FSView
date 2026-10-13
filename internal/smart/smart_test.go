package smart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name, devtype string) *Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "spiritlab", name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(b, devtype)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSCSIFailedSelfTest(t *testing.T) {
	r := load(t, "smart_sdc_scsi.json", "")
	if r.Protocol != "SCSI" || r.Model != "ST2000DM 006-2DM164 SM" || r.Serial != "Z4Z9WWC9" {
		t.Fatalf("identity: %+v", r)
	}
	if r.PowerOnHours != nil || len(r.Notes) == 0 {
		t.Fatalf("bridge power-on hours should be treated as unknown: %v %v", r.PowerOnHours, r.Notes)
	}
	if len(r.SelfTests) != 2 || r.SelfTests[0].Outcome != "failed" || r.SelfTests[0].Detail != "Medium Error" {
		t.Fatalf("self tests: %+v", r.SelfTests)
	}
	if !r.LooksLikeBridgedATA() {
		t.Fatal("should look like bridged ATA")
	}
	if r.LongMinutes != 208 {
		t.Fatalf("long minutes %d", r.LongMinutes)
	}
	a := Evaluate(r, DefaultThresholds())
	if a.Status != StatusCrit || !strings.Contains(a.Findings[0].Text, "Failed in segment") {
		t.Fatalf("assessment: %+v", a)
	}
}

func TestSCSINearTrip(t *testing.T) {
	r := load(t, "smart_sdi_scsi.json", "")
	if r.TemperatureC == nil || *r.TemperatureC != 36 || *r.TempTripC != 40 {
		t.Fatal("temperature parse")
	}
	// Two aborted tests then a pass: the pass decides.
	a := Evaluate(r, DefaultThresholds())
	if a.Status != StatusWarn || len(a.Findings) != 1 || !strings.Contains(a.Findings[0].Text, "trip point 40") {
		t.Fatalf("assessment: %+v", a)
	}
	// Huge LBA sentinel (18446744073709486080) must not break parsing.
	if r.SelfTests[0].Outcome != "aborted" {
		t.Fatalf("%+v", r.SelfTests[0])
	}
}

func TestNVMe(t *testing.T) {
	r := load(t, "smart_nvme0n1.json", "")
	if r.Protocol != "NVMe" || *r.PowerOnHours != 4883 || *r.NVMePercentUsed != 0 || *r.TempTripC != 79 {
		t.Fatalf("nvme: %+v", r)
	}
	if len(r.SelfTests) != 2 || r.SelfTests[0].Outcome != "aborted" || r.SelfTests[1].Outcome != "passed" {
		t.Fatalf("self tests %+v", r.SelfTests)
	}
	if r.NVMeDataWrittenTB == nil || *r.NVMeDataWrittenTB < 23 || *r.NVMeDataWrittenTB > 24 {
		t.Fatalf("written TB %v", r.NVMeDataWrittenTB)
	}
	if a := Evaluate(r, DefaultThresholds()); a.Status != StatusOK {
		t.Fatalf("assessment: %+v", a)
	}
}

func TestATAViaSAT(t *testing.T) {
	r := load(t, "smart_sdb_sat_synthetic.json", "sat")
	if r.Protocol != "ATA" || r.DevType != "sat" || *r.Reallocated != 8 || *r.Pending != 0 || *r.TemperatureC != 31 || *r.PowerOnHours != 36842 {
		t.Fatalf("ata: %+v", r)
	}
	if r.LongMinutes != 744 || r.ShortMinutes != 1 {
		t.Fatal("polling minutes")
	}
	if r.SelfTests[0].Outcome != "passed" || r.SelfTests[1].Outcome != "failed" {
		t.Fatalf("self tests %+v", r.SelfTests)
	}
	a := Evaluate(r, DefaultThresholds())
	if a.Status != StatusWarn || !strings.Contains(a.Findings[0].Text, "reallocated sectors: 8") {
		t.Fatalf("assessment %+v", a)
	}
}

func TestStandbyAndFailedOverall(t *testing.T) {
	r, err := Parse([]byte(`{"smartctl":{"exit_status":2,"messages":[{"string":"Device is in STANDBY mode, exit(2)","severity":"information"}]},"device":{"name":"/dev/sdx","type":"sat","protocol":"ATA"}}`), "sat")
	if err != nil || !r.Standby {
		t.Fatalf("standby: %+v %v", r, err)
	}
	f := false
	r = &Report{SmartAvailable: true, Passed: &f}
	if a := Evaluate(r, DefaultThresholds()); a.Status != StatusCrit {
		t.Fatal("failed overall health must be critical")
	}
	if a := Evaluate(&Report{}, DefaultThresholds()); a.Status != StatusUnknown {
		t.Fatal("no SMART must be unknown")
	}
}

func TestRealSATErrorLog(t *testing.T) {
	r := load(t, "smart_ZXA0R1KK_sat.json", "sat")
	if r.Serial != "ZXA0R1KK" || *r.Reallocated != 6 || *r.Pending != 4 || *r.OfflineUncorr != 4 || *r.ReportedUncorr != 138 || *r.TemperatureC != 37 {
		t.Fatalf("%+v", r)
	}
	if r.ATAErrorCount == nil || *r.ATAErrorCount != 1020 || !strings.Contains(r.ATALastError, "UNC") {
		t.Fatalf("error log: %v %q", r.ATAErrorCount, r.ATALastError)
	}
	if r.SelfTests[0].Outcome != "aborted" || r.SelfTests[2].Outcome != "passed" {
		t.Fatalf("self tests %+v", r.SelfTests)
	}
	a := Evaluate(r, DefaultThresholds())
	all := ""
	for _, f := range a.Findings {
		all += f.Text + "\n"
	}
	if a.Status != StatusWarn {
		t.Fatalf("status %s: %s", a.Status, all)
	}
	for _, frag := range []string{"reallocated sectors: 6", "pending sectors: 4", "offline uncorrectable sectors: 4", "reported uncorrectable errors: 138", "ATA error log: 1020 errors, latest at 10624 h"} {
		if !strings.Contains(all, frag) {
			t.Errorf("missing %q in\n%s", frag, all)
		}
	}
}
