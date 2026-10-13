//go:build integration

// Integration tests. They need root and loop-device support, and only ever
// touch loop devices backed by temporary files. Run in a privileged
// container:
//
//	go test -c -tags integration -o it.test ./test/integration
//	docker run --rm --privileged -v /dev:/dev -v $PWD:/src debian:trixie /src/it.test -test.v
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/krifmaz/fsview/internal/bootcheck"
	"github.com/krifmaz/fsview/internal/helper"
	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/runner"
)

const childEnv = "FSVIEW_IT_CHILD_SOCKET"

func TestMain(m *testing.M) {
	// Child mode: connect to the helper as an unprivileged user and print
	// the response.
	if sock := os.Getenv(childEnv); sock != "" {
		c, err := net.Dial("unix", sock)
		if err != nil {
			fmt.Println("DIAL-ERROR", err)
			os.Exit(0)
		}
		c.Write([]byte(`{"op":"status"}` + "\n"))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		fmt.Println(strings.TrimSpace(string(buf[:n])))
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		fmt.Println("integration tests require root; skipping")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type loopDisk struct {
	dev   string
	label string
	uuid  string
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newLoop(t *testing.T, label string) loopDisk {
	t.Helper()
	img := filepath.Join(t.TempDir(), label+".img")
	if err := os.Truncate(img, 0); err != nil {
		f, _ := os.Create(img)
		f.Close()
	}
	if err := os.Truncate(img, 128<<20); err != nil {
		t.Fatal(err)
	}
	dev := run(t, "losetup", "-f", "--show", img)
	t.Cleanup(func() { exec.Command("losetup", "-d", dev).Run() })
	run(t, "mkfs.ext4", "-q", "-F", "-L", label, dev)
	uuid := run(t, "blkid", "-s", "UUID", "-o", "value", dev)
	exec.Command("udevadm", "settle").Run()
	return loopDisk{dev: dev, label: label, uuid: uuid}
}

func mount(t *testing.T, dev string) string {
	t.Helper()
	mp := t.TempDir()
	run(t, "mount", dev, mp)
	t.Cleanup(func() { exec.Command("umount", "-l", mp).Run() })
	return mp
}

func TestInventoryOnLoopDevices(t *testing.T) {
	a := newLoop(t, "fsvtest1")
	b := newLoop(t, "fsvtest2")
	mp := mount(t, a.dev)

	c := inventory.NewCollector(runner.Exec{}, true)
	inv, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []loopDisk{a, b} {
		d := inv.FindDisk(filepath.Base(l.dev))
		if d == nil {
			t.Fatalf("%s missing from inventory", l.dev)
		}
		if d.FSType != "ext4" || d.Label != l.label || !strings.EqualFold(d.UUID, l.uuid) {
			t.Errorf("%s: fstype=%q label=%q uuid=%q", l.dev, d.FSType, d.Label, d.UUID)
		}
		if d.Protected {
			t.Errorf("%s must not be protected: %v", l.dev, d.ProtectedReasons)
		}
	}
	da := inv.FindDisk(filepath.Base(a.dev))
	if len(da.Mounts) != 1 || da.Mounts[0] != mp {
		t.Errorf("mountpoint: %v want %s", da.Mounts, mp)
	}
	if da.Usage == nil || da.Usage.SizeBytes == 0 {
		t.Errorf("usage missing for mounted fs")
	}
	// If / lives on a real block device, its disk must be protected.
	rootSrc := run(t, "findmnt", "-n", "-o", "SOURCE", "/")
	if strings.HasPrefix(rootSrc, "/dev/") {
		found := false
		for _, d := range inv.Disks {
			if d.Protected {
				found = true
			}
		}
		if !found {
			t.Errorf("root is on %s but no disk is protected", rootSrc)
		}
	} else {
		t.Logf("root filesystem is %q (not a block device); skipping protection check", rootSrc)
	}
}

func startHelper(t *testing.T, cfg helper.Config) (string, *helper.AuditLog) {
	t.Helper()
	dir, err := os.MkdirTemp("", "fsvit")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg.Socket = filepath.Join(dir, "helper.sock")
	audit, err := helper.NewAuditLog(filepath.Join(dir, "audit.log"), -1)
	if err != nil {
		t.Fatal(err)
	}
	s := helper.New(cfg, runner.Exec{}, audit)
	l, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, l)
	return cfg.Socket, audit
}

func TestHelperOverSocket(t *testing.T) {
	a := newLoop(t, "fsvtest3")
	name := filepath.Base(a.dev)
	sock, audit := startHelper(t, helper.Config{AllowedUIDs: []int{0}, SocketGID: -1, IncludeLoop: true, Version: "it"})
	c := &helperclient.Client{Socket: sock}
	ctx := context.Background()

	var inv inventory.Inventory
	if _, err := c.Call(ctx, &proto.Request{Op: proto.OpInventory}, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.FindDisk(name) == nil {
		t.Fatalf("%s not in helper inventory", name)
	}

	// Writes are disabled: the helper must refuse and audit the attempt.
	req := &proto.Request{Op: proto.OpSmartSelfTest, Actor: "it", Confirmed: true, Params: helperclient.Params(proto.SmartSelfTestParams{Device: name, Test: "short"})}
	_, err := c.Call(ctx, req, nil)
	he, ok := err.(*helperclient.Error)
	if !ok || he.Code != proto.CodeWritesOff {
		t.Fatalf("expected writes_disabled, got %v", err)
	}
	recs, _ := audit.Tail(5)
	if len(recs) != 1 || recs[0].Result != "rejected" || recs[0].Actor != "it" {
		t.Fatalf("audit: %+v", recs)
	}

	// Path traversal and shell metacharacters are rejected.
	for _, dev := range []string{"../" + name, name + ";id", "sda1"} {
		_, err := c.Call(ctx, &proto.Request{Op: proto.OpSmartGet, Params: helperclient.Params(proto.SmartGetParams{Device: dev})}, nil)
		if he, ok := err.(*helperclient.Error); !ok || he.Code != proto.CodeBadRequest {
			t.Errorf("%q: expected bad_request, got %v", dev, err)
		}
	}
}

func TestHelperDryRunWithWritesEnabled(t *testing.T) {
	a := newLoop(t, "fsvtest4")
	name := filepath.Base(a.dev)
	sock, audit := startHelper(t, helper.Config{AllowedUIDs: []int{0}, SocketGID: -1, IncludeLoop: true, WritesEnabled: true, Version: "it"})
	c := &helperclient.Client{Socket: sock}
	resp, err := c.Call(context.Background(), &proto.Request{Op: proto.OpSmartSelfTest, Actor: "it", DryRun: true,
		Params: helperclient.Params(proto.SmartSelfTestParams{Device: name, Test: "long"})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.DryRun || len(resp.Plan) != 1 || resp.Plan[0] != "smartctl -t long /dev/"+name {
		t.Fatalf("plan: %+v", resp)
	}
	recs, _ := audit.Tail(5)
	if len(recs) != 1 || recs[0].Result != "dry-run" {
		t.Fatalf("audit: %+v", recs)
	}
}

func TestPeerCredentialRejection(t *testing.T) {
	// Socket group "nogroup" (65534) lets the child connect at the file
	// permission level, so this exercises the SO_PEERCRED check itself.
	sock, _ := startHelper(t, helper.Config{AllowedUIDs: []int{0}, SocketGID: 65534, Version: "it"})
	os.Chmod(filepath.Dir(sock), 0o755)
	exe, _ := os.Executable()
	tmp, _ := os.MkdirTemp("", "fsvexe")
	defer os.RemoveAll(tmp)
	childExe := filepath.Join(tmp, "it.test")
	data, _ := os.ReadFile(exe)
	os.WriteFile(childExe, data, 0o755)
	os.Chmod(tmp, 0o755)
	cmd := exec.Command(childExe)
	cmd.Env = []string{childEnv + "=" + sock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	var resp proto.Response
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &resp); err != nil {
		t.Fatalf("child output %q", out)
	}
	if resp.OK || resp.Code != proto.CodeNotPermitted {
		t.Fatalf("unprivileged peer was not rejected: %+v", resp)
	}
}

func TestBootCheckWithLoopFstab(t *testing.T) {
	a := newLoop(t, "fsvtest5")
	b := newLoop(t, "fsvtest6")
	mpA := mount(t, a.dev)
	mpB := filepath.Join(t.TempDir(), "notmounted")
	fstab := filepath.Join(t.TempDir(), "fstab")
	content := fmt.Sprintf("UUID=%s %s ext4 defaults,nofail 0 2\nLABEL=%s %s ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2\nLABEL=missing-disk /mnt/nowhere ext4 nofail 0 0\n",
		a.uuid, mpA, b.label, mpB)
	os.WriteFile(fstab, []byte(content), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	data, err := bootcheck.Collect(ctx, runner.Exec{}, fstab)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.NewCollector(runner.Exec{}, true).Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep := bootcheck.Analyze(data, inv)
	if len(rep.Entries) != 3 {
		t.Fatalf("entries: %+v", rep.Entries)
	}
	if e := rep.Entries[0]; !e.Mounted || e.Disk != filepath.Base(a.dev) || e.Status == "failed" {
		t.Errorf("mounted entry: %+v", e)
	}
	if e := rep.Entries[1]; e.Mounted || e.Status != "failed" || e.Disk != filepath.Base(b.dev) || e.DeviceTimeoutSec != 5 {
		t.Errorf("unmounted entry: %+v", e)
	}
	if e := rep.Entries[2]; e.Status != "failed" || !strings.Contains(strings.Join(e.Problems, " "), "device not found") {
		t.Errorf("missing-device entry: %+v", e)
	}
}

// Reproduces the spiritlab incident: files written into a mountpoint
// directory while the disk was not mounted are hidden once it mounts.
func TestHiddenDataUnderMountpoint(t *testing.T) {
	parent := newLoop(t, "fsvparent")
	child := newLoop(t, "fsvchild")
	pmp := mount(t, parent.dev)
	stray := filepath.Join(pmp, "pool", "downloads")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, "movie.mkv"), make([]byte, 3<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, "mount", child.dev, filepath.Join(pmp, "pool"))
	t.Cleanup(func() { exec.Command("umount", "-l", filepath.Join(pmp, "pool")).Run() })
	before := run(t, "findmnt", "-rn", "-o", "TARGET")

	sock, _ := startHelper(t, helper.Config{AllowedUIDs: []int{0}, SocketGID: -1, Version: "it"})
	var res []proto.HiddenResult
	if _, err := (&helperclient.Client{Socket: sock}).Call(context.Background(),
		&proto.Request{Op: proto.OpHiddenScan, Params: helperclient.Params(proto.HiddenScanParams{All: true})}, &res); err != nil {
		t.Fatal(err)
	}
	var hit *proto.HiddenResult
	for i := range res {
		if res[i].Mountpoint == filepath.Join(pmp, "pool") {
			hit = &res[i]
		}
	}
	if hit == nil || hit.Files != 1 || hit.Bytes != 3<<20 || hit.Samples[0].Name != "downloads" {
		t.Fatalf("hidden data not found: %+v", res)
	}
	if after := run(t, "findmnt", "-rn", "-o", "TARGET"); after != before {
		t.Fatalf("scan leaked mounts into the host namespace:\n%s", after)
	}
}
