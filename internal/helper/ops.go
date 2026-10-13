package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/krifmaz/fsview/internal/bootcheck"
	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/runner"
)

// Class describes how dangerous an operation is.
type Class int

const (
	Read Class = iota
	Write
	Destructive
)

// Plan is what a write operation intends to do. Prepare must validate
// everything; Execute only runs Commands.
type Plan struct {
	Targets  []string   // whole-disk names affected
	Commands [][]string // exact argv lists, run in order
	Summary  string
}

type readFn func(ctx context.Context, s *Server, req *proto.Request) (any, error)
type prepareFn func(ctx context.Context, s *Server, req *proto.Request) (*Plan, error)

type opDef struct {
	class   Class
	read    readFn
	prepare prepareFn
}

var registry = map[string]opDef{
	proto.OpStatus:        {class: Read, read: opStatus},
	proto.OpInventory:     {class: Read, read: opInventory},
	proto.OpSmartGet:      {class: Read, read: opSmartGet},
	proto.OpJournalKernel: {class: Read, read: opJournal},
	proto.OpBootCollect:   {class: Read, read: opBootCollect},
	proto.OpAuditList:     {class: Read, read: opAuditList},
	proto.OpSmartSelfTest: {class: Write, prepare: prepSmartSelfTest},
}

type badRequest struct{ msg string }

func (e badRequest) Error() string { return e.msg }

func badReq(format string, args ...any) error { return badRequest{fmt.Sprintf(format, args...)} }

// Handle dispatches one request. uid is the verified peer uid.
func (s *Server) Handle(ctx context.Context, req *proto.Request, uid int) *proto.Response {
	def, ok := registry[req.Op]
	if !ok {
		return errResp(proto.CodeUnknownOp, "unknown operation %q", req.Op)
	}
	if def.class == Read {
		res, err := def.read(ctx, s, req)
		if err != nil {
			code := proto.CodeExecFailed
			if _, ok := err.(badRequest); ok {
				code = proto.CodeBadRequest
			}
			return errResp(code, "%v", err)
		}
		return okResp(res)
	}
	return s.handleWrite(ctx, def, req, uid)
}

func (s *Server) handleWrite(ctx context.Context, def opDef, req *proto.Request, uid int) *proto.Response {
	rec := AuditRecord{Actor: req.Actor, ClientIP: req.ClientIP, PeerUID: uid, Op: req.Op, Params: req.Params, DryRun: req.DryRun}
	reject := func(code, format string, args ...any) *proto.Response {
		rec.Result = "rejected"
		rec.Error = fmt.Sprintf(format, args...)
		s.writeAudit(rec)
		return errResp(code, "%s", rec.Error)
	}
	if !s.cfg.WritesEnabled {
		return reject(proto.CodeWritesOff, "write operations are disabled in the helper configuration (writes_enabled = false)")
	}
	plan, err := def.prepare(ctx, s, req)
	if err != nil {
		code := proto.CodeExecFailed
		if _, ok := err.(badRequest); ok {
			code = proto.CodeBadRequest
		}
		return reject(code, "%v", err)
	}
	rec.Targets = plan.Targets
	for _, c := range plan.Commands {
		rec.Commands = append(rec.Commands, runner.CommandLine(c[0], c[1:]...))
	}

	if def.class == Destructive {
		inv, err := s.inv.Collect(ctx)
		if err != nil {
			return reject(proto.CodeExecFailed, "cannot verify targets: %v", err)
		}
		if err := checkDestructive(inv, plan.Targets, req.ConfirmText, !req.DryRun); err != nil {
			code := proto.CodeNeedConfirm
			if strings.Contains(err.Error(), "protected") {
				code = proto.CodeProtected
			}
			return reject(code, "%v", err)
		}
	}

	if req.DryRun {
		rec.Result = "dry-run"
		s.writeAudit(rec)
		return &proto.Response{OK: true, DryRun: true, Plan: rec.Commands}
	}
	if def.class == Write && !req.Confirmed {
		return reject(proto.CodeNeedConfirm, "operation must be confirmed")
	}

	var out strings.Builder
	for _, c := range plan.Commands {
		res, err := s.run.Run(ctx, c[0], c[1:]...)
		out.Write(res.Stdout)
		out.Write(res.Stderr)
		if err != nil || res.ExitCode != 0 && !toleratedExit(c, res.ExitCode) {
			rec.Result = "error"
			if err != nil {
				rec.Error = err.Error()
			} else {
				rec.Error = fmt.Sprintf("%s exited with status %d", c[0], res.ExitCode)
			}
			rec.Output = out.String()
			s.writeAudit(rec)
			return &proto.Response{Code: proto.CodeExecFailed, Error: rec.Error + ": " + strings.TrimSpace(lastLines(out.String(), 5)), Plan: rec.Commands}
		}
	}
	rec.Result = "ok"
	rec.Output = out.String()
	s.writeAudit(rec)
	resp := okResp(map[string]string{"summary": plan.Summary, "output": rec.Output})
	resp.Plan = rec.Commands
	return resp
}

// toleratedExit allows informational exit bits (smartctl uses bits 2-7 to
// report disk state, not command failure).
func toleratedExit(cmd []string, code int) bool {
	return cmd[0] == "smartctl" && code&0x3 == 0
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (s *Server) writeAudit(rec AuditRecord) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Write(rec); err != nil {
		s.logger.Printf("AUDIT WRITE FAILED: %v (%+v)", err, rec)
	}
}

// checkDestructive enforces the protected-disk rule and the typed
// confirmation (device name or label of the target disk).
func checkDestructive(inv *inventory.Inventory, targets []string, confirm string, requireConfirm bool) error {
	if len(targets) == 0 {
		return fmt.Errorf("destructive operation without targets")
	}
	for _, t := range targets {
		d := inv.FindDisk(t)
		if d == nil {
			return fmt.Errorf("target %s not found", t)
		}
		if d.Protected {
			return fmt.Errorf("%s is a protected system disk: %s", t, strings.Join(d.ProtectedReasons, "; "))
		}
	}
	if !requireConfirm {
		return nil
	}
	confirm = strings.TrimSpace(confirm)
	if confirm == "" {
		return fmt.Errorf("type the disk's device name or label to confirm")
	}
	for _, t := range targets {
		d := inv.FindDisk(t)
		ok := confirm == d.Name || (d.Label != "" && confirm == d.Label)
		d.Walk(func(n *inventory.Node) {
			if n.Label != "" && confirm == n.Label {
				ok = true
			}
		})
		if !ok {
			return fmt.Errorf("confirmation text does not match %s (expected its device name or label)", t)
		}
	}
	return nil
}

var reDiskName = regexp.MustCompile(`^(sd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,3}|xvd[a-z]{1,3}|hd[a-z]|mmcblk[0-9]{1,3}|loop[0-9]{1,4})$`)

// validDisk checks a disk name syntactically and that it exists as a whole
// disk right now.
func (s *Server) validDisk(name string) error {
	if !reDiskName.MatchString(name) {
		return badReq("invalid device name %q", name)
	}
	if strings.HasPrefix(name, "loop") && !s.cfg.IncludeLoop {
		return badReq("loop devices are not enabled")
	}
	if _, err := os.Stat(s.cfg.SysRoot + "/block/" + name); err != nil {
		return badReq("device %s does not exist", name)
	}
	return nil
}

func decode(req *proto.Request, v any) error {
	if len(req.Params) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(req.Params)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badReq("invalid params: %v", err)
	}
	return nil
}

// ---- read operations ----

func opStatus(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	host, _ := os.Hostname()
	st := proto.StatusResult{Version: s.cfg.Version, Hostname: host, WritesEnabled: s.cfg.WritesEnabled, Tools: map[string]bool{}}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		st.BootID = strings.ReplaceAll(strings.TrimSpace(string(b)), "-", "")
	}
	for _, t := range []string{"smartctl", "lsblk", "findmnt", "journalctl", "lspci", "sg_ses", "zpool", "mdadm", "mergerfs", "lvs"} {
		st.Tools[t] = toolExists(t)
	}
	return st, nil
}

func toolExists(name string) bool {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if fi, err := os.Stat(dir + "/" + name); err == nil && fi.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

func opInventory(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	return s.inv.Collect(ctx)
}

func opSmartGet(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	var p proto.SmartGetParams
	if err := decode(req, &p); err != nil {
		return nil, err
	}
	if err := s.validDisk(p.Device); err != nil {
		return nil, err
	}
	return s.smartGet(ctx, p.Device, p.Wake)
}

func opJournal(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	var p proto.JournalParams
	if err := decode(req, &p); err != nil {
		return nil, err
	}
	if p.Lines <= 0 || p.Lines > 20000 {
		p.Lines = 2000
	}
	args := []string{"-k", "-o", "json", "--no-pager", "-n", fmt.Sprint(p.Lines)}
	if p.CurrentBoot {
		args = append(args, "-b")
	}
	if p.AfterCursor != "" {
		if len(p.AfterCursor) > 512 || !regexp.MustCompile(`^[A-Za-z0-9=;_\-]+$`).MatchString(p.AfterCursor) {
			return nil, badReq("invalid cursor")
		}
		args = append(args, "--after-cursor", p.AfterCursor)
	}
	res, err := s.run.Run(ctx, "journalctl", args...)
	if err != nil {
		return nil, err
	}
	return events.ParseJSONLines(res.Stdout), nil
}

func opBootCollect(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	return bootcheck.Collect(ctx, s.run, s.cfg.FstabPath)
}

func opAuditList(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	var p proto.AuditListParams
	if err := decode(req, &p); err != nil {
		return nil, err
	}
	if p.Limit <= 0 || p.Limit > 5000 {
		p.Limit = 500
	}
	if s.audit == nil {
		return []AuditRecord{}, nil
	}
	recs, err := s.audit.Tail(p.Limit)
	if recs == nil {
		recs = []AuditRecord{}
	}
	return recs, err
}

// ---- write operations ----

func prepSmartSelfTest(ctx context.Context, s *Server, req *proto.Request) (*Plan, error) {
	var p proto.SmartSelfTestParams
	if err := decode(req, &p); err != nil {
		return nil, err
	}
	if err := s.validDisk(p.Device); err != nil {
		return nil, err
	}
	flag := map[string]string{"short": "short", "long": "long", "abort": "X"}[p.Test]
	if flag == "" {
		return nil, badReq("test must be short, long or abort")
	}
	devtype := s.cachedSmartType(p.Device)
	if devtype == "sat" {
		if err := s.verifyPassThrough(ctx, p.Device); err != nil {
			return nil, err
		}
	}
	args := []string{"smartctl"}
	if devtype != "" {
		args = append(args, "-d", devtype)
	}
	if flag == "X" {
		args = append(args, "-X", "/dev/"+p.Device)
	} else {
		args = append(args, "-t", flag, "/dev/"+p.Device)
	}
	return &Plan{Targets: []string{p.Device}, Commands: [][]string{args}, Summary: fmt.Sprintf("SMART %s self-test on /dev/%s", p.Test, p.Device)}, nil
}
