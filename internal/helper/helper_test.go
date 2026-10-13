package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/runner"
)

func td(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "spiritlab", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestServer(t *testing.T, writes bool, fake *runner.Fake) (*Server, *AuditLog) {
	t.Helper()
	sys := t.TempDir()
	for _, d := range []string{"sdb", "sdc"} {
		os.MkdirAll(filepath.Join(sys, "block", d), 0o755)
	}
	audit, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.log"), -1)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{WritesEnabled: writes, SysRoot: sys, Version: "test"}, fake, audit)
	return s, audit
}

func req(op string, params any) *proto.Request {
	r := &proto.Request{Op: op, Actor: "admin", ClientIP: "192.168.1.10"}
	if params != nil {
		r.Params = helperclient.Params(params)
	}
	return r
}

func TestUnknownOpAndBadDevice(t *testing.T) {
	s, _ := newTestServer(t, true, &runner.Fake{})
	if r := s.Handle(context.Background(), req("shell.exec", nil), 1); r.OK || r.Code != proto.CodeUnknownOp {
		t.Fatalf("%+v", r)
	}
	for _, dev := range []string{"../../etc/passwd", "sdb; rm -rf /", "sdz", "loop0", "sda1"} {
		r := s.Handle(context.Background(), req(proto.OpSmartGet, proto.SmartGetParams{Device: dev}), 1)
		if r.OK || r.Code != proto.CodeBadRequest {
			t.Errorf("%q accepted: %+v", dev, r)
		}
	}
	// Unknown parameter fields are rejected.
	r := &proto.Request{Op: proto.OpSmartGet, Params: json.RawMessage(`{"device":"sdb","args":"-X"}`)}
	if resp := s.Handle(context.Background(), r, 1); resp.OK || resp.Code != proto.CodeBadRequest {
		t.Fatalf("unknown field accepted: %+v", resp)
	}
}

func TestWritesDisabledIsAudited(t *testing.T) {
	fake := &runner.Fake{}
	s, audit := newTestServer(t, false, fake)
	r := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "short"})
	r.Confirmed = true
	resp := s.Handle(context.Background(), r, 1000)
	if resp.OK || resp.Code != proto.CodeWritesOff {
		t.Fatalf("%+v", resp)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("commands ran: %v", fake.Calls)
	}
	recs, _ := audit.Tail(10)
	if len(recs) != 1 || recs[0].Result != "rejected" || recs[0].Actor != "admin" || recs[0].PeerUID != 1000 {
		t.Fatalf("audit %+v", recs)
	}
}

func TestSelfTestDryRunConfirmAndRun(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Result{
		"smartctl -t short /dev/sdb": {Stdout: []byte("Testing has begun."), ExitCode: 4},
	}}
	s, audit := newTestServer(t, true, fake)
	ctx := context.Background()

	r := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "short"})
	r.DryRun = true
	resp := s.Handle(ctx, r, 1)
	if !resp.OK || !resp.DryRun || len(resp.Plan) != 1 || resp.Plan[0] != "smartctl -t short /dev/sdb" {
		t.Fatalf("dry run: %+v", resp)
	}
	if len(fake.Calls) != 0 {
		t.Fatal("dry run executed commands")
	}

	r.DryRun = false
	if resp := s.Handle(ctx, r, 1); resp.OK || resp.Code != proto.CodeNeedConfirm {
		t.Fatalf("unconfirmed: %+v", resp)
	}

	r.Confirmed = true
	if resp := s.Handle(ctx, r, 1); !resp.OK {
		t.Fatalf("run: %+v", resp)
	}
	recs, _ := audit.Tail(10)
	if len(recs) != 3 || recs[0].Result != "ok" || recs[1].Result != "rejected" || recs[2].Result != "dry-run" {
		t.Fatalf("audit: %+v", recs)
	}
	if recs[0].Commands[0] != "smartctl -t short /dev/sdb" || recs[0].Targets[0] != "sdb" {
		t.Fatalf("audit record: %+v", recs[0])
	}

	bad := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "conveyance; reboot"})
	bad.Confirmed = true
	if resp := s.Handle(ctx, bad, 1); resp.OK || resp.Code != proto.CodeBadRequest {
		t.Fatalf("bad test type: %+v", resp)
	}
}

func TestSmartAutoSAT(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Result{
		"smartctl -j -a -n standby /dev/sdb":        {Stdout: td(t, "smart_sdb_scsi.json")},
		"smartctl -j -a -n standby -d sat /dev/sdb": {Stdout: td(t, "smart_sdb_sat_synthetic.json")},
		"smartctl -j -i /dev/sdb":                   {Stdout: td(t, "smart_sdb_scsi.json")},
		"smartctl -j -i -d sat /dev/sdb":            {Stdout: td(t, "smart_sdb_sat_synthetic.json")},
		"smartctl -d sat -t long /dev/sdb":          {Stdout: []byte("ok")},
	}}
	s, _ := newTestServer(t, true, fake)
	ctx := context.Background()
	var out proto.SmartGetResult
	resp := s.Handle(ctx, req(proto.OpSmartGet, proto.SmartGetParams{Device: "sdb"}), 1)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	json.Unmarshal(resp.Result, &out)
	if out.DevType != "sat" || !strings.Contains(string(out.Raw), "ST6000DM003") {
		t.Fatalf("expected sat result, got %+v", out.DevType)
	}
	// Cached: next call goes straight to -d sat.
	fake.Calls = nil
	s.Handle(ctx, req(proto.OpSmartGet, proto.SmartGetParams{Device: "sdb"}), 1)
	if len(fake.Calls) != 1 || !strings.Contains(fake.Calls[0], "-d sat") {
		t.Fatalf("calls %v", fake.Calls)
	}
	r := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "long"})
	r.Confirmed = true
	if resp := s.Handle(ctx, r, 1); !resp.OK || resp.Plan[0] != "smartctl -d sat -t long /dev/sdb" {
		t.Fatalf("%+v", resp)
	}
}

func TestCheckDestructive(t *testing.T) {
	disks, _ := inventory.ParseLsblk(td(t, "lsblk.json"), false)
	inventory.MarkProtected(disks, inventory.SystemInfo{}, func(p string) string { return filepath.Base(p) })
	inv := &inventory.Inventory{Disks: disks}
	if err := checkDestructive(inv, []string{"nvme0n1"}, "nvme0n1", true); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("protected disk allowed: %v", err)
	}
	if err := checkDestructive(inv, []string{"nvme0n1"}, "", false); err == nil {
		t.Fatal("protected disk allowed in dry run")
	}
	if err := checkDestructive(inv, []string{"sdi"}, "", true); err == nil {
		t.Fatal("missing confirmation allowed")
	}
	if err := checkDestructive(inv, []string{"sdi"}, "media2", true); err == nil {
		t.Fatal("wrong label allowed")
	}
	for _, ok := range []string{"sdi", "media1", " media1 "} {
		if err := checkDestructive(inv, []string{"sdi"}, ok, true); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	if err := checkDestructive(inv, []string{"sda"}, "cache", true); err != nil {
		t.Errorf("partition label rejected: %v", err)
	}
}

func TestSocketPeerCredentials(t *testing.T) {
	dir, err := os.MkdirTemp("", "fsv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for i, tc := range []struct {
		uids []int
		ok   bool
	}{{[]int{os.Getuid()}, true}, {[]int{424242}, false}} {
		sock := filepath.Join(dir, fmt.Sprintf("h%d.sock", i))
		s := New(Config{Socket: sock, AllowedUIDs: tc.uids, SocketGID: -1, Version: "t"}, &runner.Fake{}, nil)
		l, err := s.Listen()
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(sock)
		if fi.Mode().Perm() != 0o660 {
			t.Fatalf("socket mode %v", fi.Mode().Perm())
		}
		ctx, cancel := context.WithCancel(context.Background())
		go s.Serve(ctx, l)
		c := helperclient.Client{Socket: sock}
		var st proto.StatusResult
		_, err = c.Call(context.Background(), &proto.Request{Op: proto.OpStatus}, &st)
		if tc.ok && (err != nil || st.Version != "t") {
			t.Fatalf("allowed peer failed: %v", err)
		}
		if !tc.ok {
			he, isHE := err.(*helperclient.Error)
			if !isHE || he.Code != proto.CodeNotPermitted {
				t.Fatalf("foreign peer not rejected: %v", err)
			}
		}
		cancel()
	}
}

// Real spiritlab behaviour: `smartctl -d sat /dev/sdb` answered with the
// identity of a different disk. Pass-through must not be used then.
func TestSmartSATSerialMismatch(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Result{
		"smartctl -j -a -n standby /dev/sdb":        {Stdout: td(t, "smart_sdb_scsi.json")},
		"smartctl -j -a -n standby -d sat /dev/sdb": {Stdout: td(t, "smart_ZXA0R1KK_sat.json"), ExitCode: 64},
		"smartctl -t short /dev/sdb":                {Stdout: []byte("ok")},
	}}
	s, _ := newTestServer(t, true, fake)
	ctx := context.Background()
	resp := s.Handle(ctx, req(proto.OpSmartGet, proto.SmartGetParams{Device: "sdb"}), 1)
	var out proto.SmartGetResult
	json.Unmarshal(resp.Result, &out)
	if out.DevType != "" || !strings.Contains(string(out.Raw), "ZCT1RSPR") || !strings.Contains(string(out.Raw), "FSView: ATA pass-through") {
		t.Fatalf("mismatched pass-through was used or not flagged: devtype=%q", out.DevType)
	}
	r := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "short"})
	r.Confirmed = true
	if resp := s.Handle(ctx, r, 1); !resp.OK || resp.Plan[0] != "smartctl -t short /dev/sdb" {
		t.Fatalf("self-test must not use -d sat: %+v", resp)
	}
}

// If the bridge starts misrouting after detection, a write is refused.
func TestSelfTestReverifiesPassThrough(t *testing.T) {
	fake := &runner.Fake{Responses: map[string]runner.Result{
		"smartctl -j -a -n standby /dev/sdb":        {Stdout: td(t, "smart_sdb_scsi.json")},
		"smartctl -j -a -n standby -d sat /dev/sdb": {Stdout: td(t, "smart_sdb_sat_synthetic.json")},
		"smartctl -j -i /dev/sdb":                   {Stdout: td(t, "smart_sdb_scsi.json")},
		"smartctl -j -i -d sat /dev/sdb":            {Stdout: td(t, "smart_ZXA0R1KK_sat.json")},
	}}
	s, _ := newTestServer(t, true, fake)
	ctx := context.Background()
	s.Handle(ctx, req(proto.OpSmartGet, proto.SmartGetParams{Device: "sdb"}), 1)
	if s.cachedSmartType("sdb") != "sat" {
		t.Fatal("expected sat after matching detection")
	}
	r := req(proto.OpSmartSelfTest, proto.SmartSelfTestParams{Device: "sdb", Test: "short"})
	r.Confirmed = true
	resp := s.Handle(ctx, r, 1)
	if resp.OK || !strings.Contains(resp.Error, "ZXA0R1KK") {
		t.Fatalf("misrouted pass-through not refused: %+v", resp)
	}
	for _, c := range fake.Calls {
		if strings.Contains(c, " -t ") {
			t.Fatalf("self-test command ran: %s", c)
		}
	}
}
