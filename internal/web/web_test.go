package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/store"
)

type fakeHelper struct {
	t      *testing.T
	writes bool
	reqs   []*proto.Request
}

func fx(t *testing.T, n string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "spiritlab", n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fakeHelper) Call(ctx context.Context, req *proto.Request, out any) (*proto.Response, error) {
	f.reqs = append(f.reqs, req)
	var result any
	resp := &proto.Response{OK: true}
	switch req.Op {
	case proto.OpInventory:
		disks, _ := inventory.ParseLsblk(fx(f.t, "lsblk.json"), false)
		inventory.MarkProtected(disks, inventory.SystemInfo{}, func(p string) string { return filepath.Base(p) })
		result = inventory.Inventory{Hostname: "spiritlab", Disks: disks}
	case proto.OpSmartGet:
		var p proto.SmartGetParams
		json.Unmarshal(req.Params, &p)
		switch p.Device {
		case "sdc":
			result = proto.SmartGetResult{Device: "sdc", Raw: fx(f.t, "smart_sdc_scsi.json")}
		case "sdb":
			result = proto.SmartGetResult{Device: "sdb", DevType: "sat", Raw: fx(f.t, "smart_sdb_sat_synthetic.json")}
		default:
			return &proto.Response{Code: proto.CodeExecFailed}, &helperclient.Error{Code: proto.CodeExecFailed, Msg: "no data"}
		}
	case proto.OpSmartSelfTest:
		if !f.writes {
			return &proto.Response{Code: proto.CodeWritesOff}, &helperclient.Error{Code: proto.CodeWritesOff, Msg: "writes disabled"}
		}
		resp.DryRun = req.DryRun
		resp.Plan = []string{"smartctl -d sat -t short /dev/sdb"}
		result = map[string]string{"summary": "x"}
	case proto.OpJournalKernel:
		result = events.ParseJSONLines([]byte(`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1791851200000000","__MONOTONIC_TIMESTAMP":"1270000000","PRIORITY":"3","MESSAGE":"I/O error, dev sdc, sector 1"}`))
	case proto.OpHiddenScan:
		result = []proto.HiddenResult{{Mountpoint: "/mnt/drivepool", Parent: "/", ParentSource: "/dev/mapper/pve-root", Files: 22, Bytes: 78000430137,
			Samples: []proto.HiddenSample{{Name: "downloads", Bytes: 78000430137}}}}
	case proto.OpStatus:
		result = proto.StatusResult{Version: "t", WritesEnabled: f.writes}
	default:
		result = map[string]any{}
	}
	b, _ := json.Marshal(result)
	resp.Result = b
	if out != nil {
		json.Unmarshal(b, out)
	}
	return resp, nil
}

func newTest(t *testing.T, writes bool) (*Server, http.Handler, *fakeHelper) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword("admin", "supersecret1", true); err != nil {
		t.Fatal(err)
	}
	fh := &fakeHelper{t: t, writes: writes}
	s := New(Options{Version: "t", Allow: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("100.64.0.0/10")}}, st, fh)
	return s, s.Handler(), fh
}

func do(h http.Handler, method, path, body, cookie string, csrf bool, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if remote == "" {
		remote = "192.168.1.50:5555"
	}
	r.RemoteAddr = remote
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	if csrf {
		r.Header.Set("X-FSView-Request", "1")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, h http.Handler) string {
	w := do(h, "POST", "/api/login", `{"username":"admin","password":"supersecret1"}`, "", true, "")
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("cookie flags")
			}
			return c.Value
		}
	}
	t.Fatal("no cookie")
	return ""
}

func TestAccessControl(t *testing.T) {
	_, h, _ := newTest(t, false)
	if w := do(h, "GET", "/api/me", "", "", false, "8.8.8.8:1"); w.Code != 403 {
		t.Fatalf("outside IP: %d", w.Code)
	}
	if w := do(h, "GET", "/", "", "", false, "10.0.0.1:1"); w.Code != 403 {
		t.Fatalf("outside IP static: %d", w.Code)
	}
	if w := do(h, "GET", "/api/me", "", "", false, "100.90.1.2:1"); w.Code != 401 {
		t.Fatalf("tailscale IP unauthenticated should be 401, got %d", w.Code)
	}
	if w := do(h, "POST", "/api/login", `{"username":"admin","password":"supersecret1"}`, "", false, ""); w.Code != 403 {
		t.Fatalf("login without csrf header: %d", w.Code)
	}
	for i := 0; i < 5; i++ {
		do(h, "POST", "/api/login", `{"username":"admin","password":"wrong"}`, "", true, "192.168.1.66:1")
	}
	if w := do(h, "POST", "/api/login", `{"username":"admin","password":"supersecret1"}`, "", true, "192.168.1.66:1"); w.Code != 429 {
		t.Fatalf("rate limit: %d", w.Code)
	}
	tok := login(t, h)
	if w := do(h, "GET", "/api/me", "", tok, false, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "admin") {
		t.Fatalf("me: %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r.RemoteAddr = "192.168.1.50:1"
	r.Header.Set("X-FSView-Request", "1")
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-origin post: %d", w.Code)
	}
	if w := do(h, "POST", "/api/logout", "", tok, true, ""); w.Code != 200 {
		t.Fatal("logout")
	}
	if w := do(h, "GET", "/api/me", "", tok, false, ""); w.Code != 401 {
		t.Fatal("session survived logout")
	}
	if w := do(h, "GET", "/", "", "", false, ""); w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func TestOverviewAndSmart(t *testing.T) {
	s, h, _ := newTest(t, false)
	tok := login(t, h)
	s.refreshSmart(context.Background(), "sdc", false)
	s.refreshSmart(context.Background(), "sdb", false)
	w := do(h, "GET", "/api/overview", "", tok, false, "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var ov struct {
		Disks   []DiskView     `json:"disks"`
		Summary map[string]int `json:"summary"`
	}
	json.Unmarshal(w.Body.Bytes(), &ov)
	by := map[string]DiskView{}
	for _, d := range ov.Disks {
		by[d.Name] = d
	}
	if by["sdc"].Health == nil || by["sdc"].Health.Status != "crit" {
		t.Fatalf("sdc health %+v", by["sdc"].Health)
	}
	if by["sdb"].DisplayTransport != "SATA via SAS" || by["sdb"].DisplayModel != "ST6000DM003-2CY186" {
		t.Fatalf("sdb view %q %q", by["sdb"].DisplayTransport, by["sdb"].DisplayModel)
	}
	if !by["nvme0n1"].Protected || ov.Summary["protected"] != 1 || ov.Summary["crit"] != 1 {
		t.Fatalf("summary %+v", ov.Summary)
	}
	if w := do(h, "GET", "/api/disks/sdc?raw=1", "", tok, false, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Failed in segment") || !strings.Contains(w.Body.String(), `"raw"`) {
		t.Fatalf("disk detail %d", w.Code)
	}
	if w := do(h, "GET", "/api/disks/..%2fetc", "", tok, false, ""); w.Code == 200 {
		t.Fatal("bad name accepted")
	}
}

func TestSelfTestAndSettings(t *testing.T) {
	_, h, fh := newTest(t, false)
	tok := login(t, h)
	if w := do(h, "POST", "/api/disks/sdb/selftest", `{"test":"short","confirmed":true}`, tok, true, ""); w.Code != 403 || !strings.Contains(w.Body.String(), "writes_disabled") {
		t.Fatalf("writes off: %d %s", w.Code, w.Body)
	}
	fh.writes = true
	w := do(h, "POST", "/api/disks/sdb/selftest", `{"test":"short","dry_run":true}`, tok, true, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "smartctl -d sat -t short /dev/sdb") {
		t.Fatalf("dry run: %d %s", w.Code, w.Body)
	}
	last := fh.reqs[len(fh.reqs)-1]
	if last.Actor != "admin" || last.ClientIP != "192.168.1.50" || !last.DryRun {
		t.Fatalf("request fields %+v", last)
	}

	if w := do(h, "PUT", "/api/settings", `{"thresholds":{"temp_warn_c":70,"temp_crit_c":60}}`, tok, true, ""); w.Code != 400 {
		t.Fatalf("invalid settings accepted: %d", w.Code)
	}
	good := store.DefaultSettings()
	good.Thresholds.TempWarnC = 45
	b, _ := json.Marshal(good)
	if w := do(h, "PUT", "/api/settings", string(b), tok, true, ""); w.Code != 200 {
		t.Fatalf("settings: %d %s", w.Code, w.Body)
	}
}

func TestJournalPollAndEvents(t *testing.T) {
	s, h, _ := newTest(t, false)
	tok := login(t, h)
	s.pollJournal(context.Background())
	s.pollJournal(context.Background()) // duplicate cursor must not duplicate
	w := do(h, "GET", "/api/events?severity=error", "", tok, false, "")
	var evs []events.Event
	json.Unmarshal(w.Body.Bytes(), &evs)
	if len(evs) != 1 || evs[0].Device != "sdc" || evs[0].Category != events.CatIOError {
		t.Fatalf("events %+v", evs)
	}
	if s.store.JournalCursor() != "c1" {
		t.Fatal("cursor not saved")
	}
	// Persisted across restart.
	es := NewEventStore(s.store.Dir(), 100)
	if len(es.List(EventFilter{})) != 1 {
		t.Fatal("events not persisted")
	}
}

func TestHiddenScan(t *testing.T) {
	_, h, fh := newTest(t, false)
	tok := login(t, h)
	if w := do(h, "POST", "/api/hidden/scan?all=1", "", tok, true, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"files":22`) || !strings.Contains(w.Body.String(), `"all":true`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var p proto.HiddenScanParams
	json.Unmarshal(fh.reqs[len(fh.reqs)-1].Params, &p)
	if !p.All {
		t.Fatal("all flag not passed to helper")
	}
	if w := do(h, "GET", "/api/overview", "", tok, false, ""); !strings.Contains(w.Body.String(), "/mnt/drivepool") {
		t.Fatal("overview missing hidden data")
	}
}
