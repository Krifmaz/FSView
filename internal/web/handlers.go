package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/krifmaz/fsview/internal/bootcheck"
	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/smart"
	"github.com/krifmaz/fsview/internal/store"
)

//go:embed all:dist
var distFS embed.FS

const cookieName = "fsview_session"

type ctxKey int

const userKey ctxKey = 1

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "code": errCode})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userOf(r *http.Request) string {
	if u, ok := r.Context().Value(userKey).(string); ok {
		return u
	}
	return ""
}

// Handler builds the full HTTP handler chain.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("POST /api/login", s.handleLogin)
	api.HandleFunc("POST /api/logout", s.handleLogout)
	api.Handle("GET /api/me", s.authed(s.handleMe))
	api.Handle("POST /api/me/password", s.authed(s.handlePassword))
	api.Handle("GET /api/status", s.authed(s.handleStatus))
	api.Handle("GET /api/overview", s.authed(s.handleOverview))
	api.Handle("GET /api/disks/{name}", s.authed(s.handleDisk))
	api.Handle("POST /api/disks/{name}/smart/refresh", s.authed(s.handleSmartRefresh))
	api.Handle("POST /api/disks/{name}/selftest", s.authed(s.handleSelfTest))
	api.Handle("GET /api/events", s.authed(s.handleEvents))
	api.Handle("GET /api/events/stream", s.authed(s.handleEventStream))
	api.Handle("GET /api/bootcheck", s.authed(s.handleBootCheck))
	api.Handle("GET /api/audit", s.authed(s.handleAudit))
	api.Handle("GET /api/settings", s.authed(s.handleGetSettings))
	api.Handle("PUT /api/settings", s.authed(s.handlePutSettings))
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such endpoint")
	})

	root := http.NewServeMux()
	root.Handle("/api/", s.csrf(api))
	root.Handle("/", staticHandler())
	return s.ipFilter(securityHeaders(root))
}

// ipFilter is defence in depth behind the filtered listener.
func (s *Server) ipFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.opt.Allow) > 0 && !remoteAllowed(r.RemoteAddr, s.opt.Allow) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// csrf requires a custom header on state-changing requests (browsers
// cannot send it cross-origin without a CORS preflight, which we never
// allow) and rejects mismatched Origin headers.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-FSView-Request") != "1" {
				writeErr(w, http.StatusForbidden, "csrf", "missing X-FSView-Request header")
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					writeErr(w, http.StatusForbidden, "csrf", "cross-origin request rejected")
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authed(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		sess, ok := s.store.Session(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "session expired")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), userKey, sess.User)))
	})
}

// ---- login ----

type loginLimiter struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{fail: map[string][]time.Time{}} }

const (
	loginWindow   = 15 * time.Minute
	loginMaxFails = 5
)

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var keep []time.Time
	for _, t := range l.fail[ip] {
		if time.Since(t) < loginWindow {
			keep = append(keep, t)
		}
	}
	l.fail[ip] = keep
	return len(keep) >= loginMaxFails
}

func (l *loginLimiter) failed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail[ip] = append(l.fail[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, ip)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: maxAge,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.login.blocked(ip) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many failed logins; try again in 15 minutes")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body")
		return
	}
	if !s.store.CheckPassword(body.Username, body.Password) {
		s.login.failed(ip)
		s.logger.Printf("failed login for %q from %s", body.Username, ip)
		writeErr(w, http.StatusUnauthorized, "bad_credentials", "invalid username or password")
		return
	}
	s.login.reset(ip)
	tok, err := s.store.CreateSession(body.Username, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	s.setCookie(w, r, tok, int(store.SessionAbsolute.Seconds()))
	s.logger.Printf("login %q from %s", body.Username, ip)
	writeJSON(w, http.StatusOK, map[string]string{"user": body.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.store.DeleteSession(c.Value)
	}
	s.setCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"user": userOf(r)})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body")
		return
	}
	u := userOf(r)
	if !s.store.CheckPassword(u, body.Current) {
		writeErr(w, http.StatusForbidden, "bad_credentials", "current password is wrong")
		return
	}
	if err := s.store.SetPassword(u, body.New, false); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	tok, err := s.store.CreateSession(u, clientIP(r))
	if err == nil {
		s.setCookie(w, r, tok, int(store.SessionAbsolute.Seconds()))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- data ----

func helperErr(w http.ResponseWriter, err error) {
	var he *helperclient.Error
	if errors.As(err, &he) {
		status := http.StatusBadGateway
		switch he.Code {
		case proto.CodeBadRequest:
			status = http.StatusBadRequest
		case proto.CodeWritesOff, proto.CodeProtected, proto.CodeNotPermitted:
			status = http.StatusForbidden
		case proto.CodeNeedConfirm:
			status = http.StatusPreconditionRequired
		}
		writeJSON(w, status, map[string]any{"error": he.Msg, "code": he.Code, "plan": he.Plan})
		return
	}
	writeErr(w, http.StatusBadGateway, "helper_unavailable", err.Error())
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var st proto.StatusResult
	resp := map[string]any{
		"version": s.opt.Version,
		"listen":  s.opt.Listen,
		"allow":   s.opt.Allow,
		"user":    userOf(r),
		"tls":     s.opt.TLSCert != "",
	}
	if _, err := s.helper.Call(r.Context(), &proto.Request{Op: proto.OpStatus}, &st); err != nil {
		resp["helper_error"] = err.Error()
	} else {
		resp["helper"] = st
	}
	writeJSON(w, http.StatusOK, resp)
}

// HealthView is the SMART summary attached to a disk in API responses.
type HealthView struct {
	Status       string          `json:"status"`
	Findings     []smart.Finding `json:"findings,omitempty"`
	TemperatureC *int            `json:"temperature_c,omitempty"`
	PowerOnHours *int64          `json:"power_on_hours,omitempty"`
	Protocol     string          `json:"protocol,omitempty"`
	DevType      string          `json:"devtype,omitempty"`
	Model        string          `json:"model,omitempty"`
	Standby      bool            `json:"standby"`
	Running      *smart.Running  `json:"self_test_running,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
	CheckedAt    time.Time       `json:"checked_at"`
	Error        string          `json:"error,omitempty"`
}

type DiskView struct {
	inventory.Disk
	DisplayModel     string      `json:"display_model"`
	DisplayTransport string      `json:"display_transport"`
	Health           *HealthView `json:"health,omitempty"`
}

func (s *Server) diskView(d inventory.Disk) DiskView {
	v := DiskView{Disk: d, DisplayModel: d.Model, DisplayTransport: strings.ToUpper(d.Transport)}
	if v.DisplayTransport == "" {
		v.DisplayTransport = "?"
	}
	if e := s.smartFor(d.Name); e != nil {
		h := &HealthView{Status: e.Assessment.Status, Findings: e.Assessment.Findings, Standby: e.Standby, UpdatedAt: e.UpdatedAt, CheckedAt: e.CheckedAt, Error: e.Error}
		if rep := e.Report; rep != nil {
			h.TemperatureC, h.PowerOnHours, h.Protocol, h.DevType, h.Model, h.Running = rep.TemperatureC, rep.PowerOnHours, rep.Protocol, rep.DevType, rep.Model, rep.Running
			if rep.Model != "" && rep.Protocol == "ATA" {
				v.DisplayModel = rep.Model
			}
			if rep.Protocol == "ATA" && d.Transport == "sas" {
				v.DisplayTransport = "SATA via SAS"
			}
		}
		v.Health = h
	}
	return v
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	inv, err := s.inventory(r.Context(), r.URL.Query().Get("fresh") == "1")
	if err != nil {
		helperErr(w, err)
		return
	}
	views := make([]DiskView, 0, len(inv.Disks))
	sum := map[string]int{"disks": len(inv.Disks), "crit": 0, "warn": 0, "ok": 0, "unknown": 0, "protected": 0}
	for _, d := range inv.Disks {
		v := s.diskView(d)
		st := smart.StatusUnknown
		if v.Health != nil {
			st = v.Health.Status
		}
		sum[st]++
		if d.Protected {
			sum["protected"]++
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hostname":     inv.Hostname,
		"collected_at": inv.CollectedAt,
		"disks":        views,
		"hbas":         inv.HBAs,
		"enclosures":   inv.Enclosures,
		"warnings":     inv.Warnings,
		"summary":      sum,
		"events_24h":   s.events.Counts(time.Now().Add(-24 * time.Hour)),
	})
}

var reName = regexp.MustCompile(`^[a-z0-9]{2,16}$`)

func (s *Server) diskByName(w http.ResponseWriter, r *http.Request) (*inventory.Disk, bool) {
	name := r.PathValue("name")
	if !reName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid disk name")
		return nil, false
	}
	inv, err := s.inventory(r.Context(), false)
	if err != nil {
		helperErr(w, err)
		return nil, false
	}
	d := inv.FindDisk(name)
	if d == nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such disk")
		return nil, false
	}
	return d, true
}

func (s *Server) handleDisk(w http.ResponseWriter, r *http.Request) {
	d, ok := s.diskByName(w, r)
	if !ok {
		return
	}
	e := s.smartFor(d.Name)
	if e == nil {
		e = s.refreshSmart(r.Context(), d.Name, false)
	}
	resp := map[string]any{"disk": s.diskView(*d), "smart": e}
	if r.URL.Query().Get("raw") == "1" && e != nil && len(e.raw) > 0 {
		resp["raw"] = json.RawMessage(e.raw)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSmartRefresh(w http.ResponseWriter, r *http.Request) {
	d, ok := s.diskByName(w, r)
	if !ok {
		return
	}
	e := s.refreshSmart(r.Context(), d.Name, r.URL.Query().Get("wake") == "1")
	writeJSON(w, http.StatusOK, map[string]any{"disk": s.diskView(*d), "smart": e})
}

func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	d, ok := s.diskByName(w, r)
	if !ok {
		return
	}
	var body struct {
		Test      string `json:"test"`
		DryRun    bool   `json:"dry_run"`
		Confirmed bool   `json:"confirmed"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body")
		return
	}
	req := &proto.Request{
		Op: proto.OpSmartSelfTest, Actor: userOf(r), ClientIP: clientIP(r),
		DryRun: body.DryRun, Confirmed: body.Confirmed,
		Params: mustJSON(proto.SmartSelfTestParams{Device: d.Name, Test: body.Test}),
	}
	var res map[string]string
	resp, err := s.helper.Call(r.Context(), req, &res)
	if err != nil {
		helperErr(w, err)
		return
	}
	if !resp.DryRun {
		go func() {
			time.Sleep(5 * time.Second)
			select {
			case s.smartKick <- d.Name:
			default:
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dry_run": resp.DryRun, "plan": resp.Plan, "result": res})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{Severity: q.Get("severity"), Category: q.Get("category"), Device: q.Get("device"), Query: q.Get("q")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if h, err := strconv.Atoi(q.Get("hours")); err == nil && h > 0 {
		f.Since = time.Now().Add(-time.Duration(h) * time.Hour)
	}
	writeJSON(w, http.StatusOK, s.events.List(f))
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "streaming unsupported")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := s.events.Subscribe()
	defer s.events.Unsubscribe(ch)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	hb := time.NewTicker(25 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case e := <-ch:
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: disk\ndata: %s\n\n", b)
			fl.Flush()
		}
	}
}

func (s *Server) handleBootCheck(w http.ResponseWriter, r *http.Request) {
	s.bootMu.Lock()
	defer s.bootMu.Unlock()
	if s.bootRep != nil && time.Since(s.bootTime) < 30*time.Second && r.URL.Query().Get("fresh") != "1" {
		writeJSON(w, http.StatusOK, s.bootRep)
		return
	}
	var data bootcheck.Data
	if _, err := s.helper.Call(r.Context(), &proto.Request{Op: proto.OpBootCollect}, &data); err != nil {
		helperErr(w, err)
		return
	}
	inv, _ := s.inventory(r.Context(), false)
	rep := bootcheck.Analyze(&data, inv)
	s.bootRep, s.bootTime = rep, time.Now()
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var recs json.RawMessage
	if _, err := s.helper.Call(r.Context(), &proto.Request{Op: proto.OpAuditList, Params: mustJSON(proto.AuditListParams{Limit: limit})}, &recs); err != nil {
		helperErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(recs)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var v store.Settings
	if err := decodeBody(r, &v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body: "+err.Error())
		return
	}
	t := v.Thresholds
	switch {
	case t.TempWarnC < 20 || t.TempWarnC > 100 || t.TempCritC < t.TempWarnC || t.TempCritC > 110:
		writeErr(w, http.StatusBadRequest, "bad_request", "temperature thresholds must satisfy 20 ≤ warn ≤ crit ≤ 110")
		return
	case t.TripMarginC < 0 || t.TripMarginC > 30:
		writeErr(w, http.StatusBadRequest, "bad_request", "trip margin must be 0-30")
		return
	case t.ReallocatedWarn < 0 || t.ReallocatedCrit < 0 || t.PendingWarn < 0 || t.PendingCrit < 0 || t.UncorrWarn < 0 || t.CRCWarn < 0:
		writeErr(w, http.StatusBadRequest, "bad_request", "counters must not be negative")
		return
	case t.NVMeUsedWarn < 1 || t.NVMeUsedCrit < t.NVMeUsedWarn:
		writeErr(w, http.StatusBadRequest, "bad_request", "NVMe wear thresholds must satisfy 1 ≤ warn ≤ crit")
		return
	case v.LateDeviceSec < 5 || v.LateDeviceSec > 3600:
		writeErr(w, http.StatusBadRequest, "bad_request", "late device threshold must be 5-3600 seconds")
		return
	case v.EventRetention < 100 || v.EventRetention > 200000:
		writeErr(w, http.StatusBadRequest, "bad_request", "event retention must be 100-200000")
		return
	}
	if err := s.store.SetSettings(v); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ---- static UI ----

func staticHandler() http.Handler {
	sub, _ := fs.Sub(distFS, "dist")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := sub.Open(p); err == nil {
			f.Close()
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
			return
		}
		// SPA fallback.
		idx, err := sub.Open("index.html")
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "FSView UI is not built into this binary. Run `make ui` and rebuild.\n")
			return
		}
		defer idx.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		io.Copy(w, idx)
	})
}
