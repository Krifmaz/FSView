// Package web is the unprivileged HTTP server: login, sessions, the JSON
// API and the embedded React UI. Everything that needs root goes through
// the helper socket.
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/krifmaz/fsview/internal/events"
	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/smart"
	"github.com/krifmaz/fsview/internal/store"
)

// Helper is the subset of helperclient.Client the server uses.
type Helper interface {
	Call(ctx context.Context, req *proto.Request, out any) (*proto.Response, error)
}

type Options struct {
	Version     string
	Allow       []netip.Prefix
	Listen      []string
	TLSCert     string
	TLSKey      string
	SmartPoll   time.Duration
	JournalPoll time.Duration
}

type Server struct {
	opt    Options
	store  *store.Store
	helper Helper
	events *EventStore
	logger *log.Logger
	login  *loginLimiter

	invMu   sync.Mutex
	inv     *inventory.Inventory
	invTime time.Time

	smartMu sync.Mutex
	smart   map[string]*smartEntry

	bootMu   sync.Mutex
	bootRep  any
	bootTime time.Time

	smartKick chan string

	hiddenMu   sync.Mutex
	hidden     []proto.HiddenResult
	hiddenAll  bool
	hiddenTime time.Time
	hiddenErr  string
}

type smartEntry struct {
	Report     *smart.Report    `json:"report,omitempty"`
	Assessment smart.Assessment `json:"assessment"`
	UpdatedAt  time.Time        `json:"updated_at"`
	CheckedAt  time.Time        `json:"checked_at"`
	Standby    bool             `json:"standby"`
	Error      string           `json:"error,omitempty"`
	raw        []byte
}

func New(opt Options, st *store.Store, h Helper) *Server {
	if opt.SmartPoll <= 0 {
		opt.SmartPoll = 30 * time.Minute
	}
	if opt.JournalPoll <= 0 {
		opt.JournalPoll = 3 * time.Second
	}
	return &Server{
		opt:       opt,
		store:     st,
		helper:    h,
		events:    NewEventStore(st.Dir(), st.Settings().EventRetention),
		logger:    log.New(os.Stderr, "fsview: ", log.LstdFlags),
		login:     newLoginLimiter(),
		smart:     map[string]*smartEntry{},
		smartKick: make(chan string, 64),
	}
}

// filteredListener drops connections from outside the allow-list before
// any HTTP is spoken.
type filteredListener struct {
	net.Listener
	allow  []netip.Prefix
	logger *log.Logger
	last   time.Time
}

func (l *filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if remoteAllowed(c.RemoteAddr().String(), l.allow) {
			return c, nil
		}
		if time.Since(l.last) > 10*time.Second {
			l.logger.Printf("rejected connection from %s (not in allow-list)", c.RemoteAddr())
			l.last = time.Now()
		}
		c.Close()
	}
}

func remoteAllowed(remote string, allow []netip.Prefix) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if len(s.opt.Listen) == 0 {
		return errors.New("no listen addresses")
	}
	handler := s.Handler()
	var tlsCfg *tls.Config
	if s.opt.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(s.opt.TLSCert, s.opt.TLSKey)
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	go s.journalLoop(ctx)
	go s.smartLoop(ctx)
	go s.hiddenLoop(ctx)

	errc := make(chan error, len(s.opt.Listen))
	var servers []*http.Server
	for _, addr := range s.opt.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		var l net.Listener = &filteredListener{Listener: ln, allow: s.opt.Allow, logger: s.logger}
		if tlsCfg != nil {
			l = tls.NewListener(l, tlsCfg)
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
		servers = append(servers, srv)
		scheme := "http"
		if tlsCfg != nil {
			scheme = "https"
		}
		s.logger.Printf("listening on %s://%s (allowed: %v)", scheme, addr, s.opt.Allow)
		go func() { errc <- srv.Serve(l) }()
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(sctx)
	}
	return nil
}

// ---- background loops ----

func (s *Server) journalLoop(ctx context.Context) {
	t := time.NewTicker(s.opt.JournalPoll)
	defer t.Stop()
	for {
		s.pollJournal(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) pollJournal(ctx context.Context) {
	cur := s.store.JournalCursor()
	p := proto.JournalParams{AfterCursor: cur, Lines: 2000}
	if cur == "" {
		p.CurrentBoot = true
		p.Lines = 20000
	}
	var entries []events.Entry
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := s.helper.Call(cctx, &proto.Request{Op: proto.OpJournalKernel, Params: mustJSON(p)}, &entries); err != nil {
		return
	}
	if len(entries) == 0 {
		return
	}
	late := float64(s.store.Settings().LateDeviceSec)
	var evs []events.Event
	for _, e := range entries {
		if ev, ok := events.Classify(e, late); ok {
			evs = append(evs, ev)
		}
	}
	sortEvents(evs)
	s.events.Add(evs)
	if last := entries[len(entries)-1].Cursor; last != "" {
		_ = s.store.SetJournalCursor(last)
	}
}

func (s *Server) smartLoop(ctx context.Context) {
	t := time.NewTicker(s.opt.SmartPoll)
	defer t.Stop()
	s.refreshAllSmart(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshAllSmart(ctx)
		case dev := <-s.smartKick:
			s.refreshSmart(ctx, dev, false)
		}
	}
}

func (s *Server) refreshAllSmart(ctx context.Context) {
	inv, err := s.inventory(ctx, true)
	if err != nil {
		return
	}
	for _, d := range inv.Disks {
		if ctx.Err() != nil {
			return
		}
		s.refreshSmart(ctx, d.Name, false)
	}
}

func (s *Server) refreshSmart(ctx context.Context, dev string, wake bool) *smartEntry {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var res proto.SmartGetResult
	_, err := s.helper.Call(cctx, &proto.Request{Op: proto.OpSmartGet, Params: mustJSON(proto.SmartGetParams{Device: dev, Wake: wake})}, &res)
	now := time.Now().UTC()
	s.smartMu.Lock()
	defer s.smartMu.Unlock()
	prev := s.smart[dev]
	e := &smartEntry{CheckedAt: now}
	if prev != nil {
		*e = *prev
		e.CheckedAt = now
	}
	switch {
	case err != nil:
		e.Error = err.Error()
	case res.Standby:
		e.Standby = true
		e.Error = ""
	default:
		rep, perr := smart.Parse(res.Raw, res.DevType)
		if perr != nil {
			e.Error = perr.Error()
			break
		}
		e.Report = rep
		e.raw = res.Raw
		e.Standby = false
		e.Error = ""
		e.UpdatedAt = now
	}
	if e.Report != nil {
		e.Assessment = smart.Evaluate(e.Report, s.store.Settings().Thresholds)
	} else {
		e.Assessment = smart.Assessment{Status: smart.StatusUnknown}
	}
	s.smart[dev] = e
	c := *e
	return &c
}

func (s *Server) smartFor(dev string) *smartEntry {
	s.smartMu.Lock()
	defer s.smartMu.Unlock()
	if e := s.smart[dev]; e != nil {
		c := *e
		if c.Report != nil {
			// Thresholds may have changed since the last poll.
			c.Assessment = smart.Evaluate(c.Report, s.store.Settings().Thresholds)
		}
		return &c
	}
	return nil
}

func (s *Server) inventory(ctx context.Context, fresh bool) (*inventory.Inventory, error) {
	s.invMu.Lock()
	defer s.invMu.Unlock()
	if !fresh && s.inv != nil && time.Since(s.invTime) < 15*time.Second {
		return s.inv, nil
	}
	var inv inventory.Inventory
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := s.helper.Call(cctx, &proto.Request{Op: proto.OpInventory}, &inv); err != nil {
		if s.inv != nil {
			return s.inv, nil
		}
		return nil, err
	}
	s.inv, s.invTime = &inv, time.Now()
	return s.inv, nil
}

// hiddenLoop checks the root filesystem for data hidden under mountpoints
// shortly after start and then every 6 hours. Full scans (all
// filesystems, which may wake sleeping disks) only run on request.
func (s *Server) hiddenLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		s.scanHidden(ctx, false)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) scanHidden(ctx context.Context, all bool) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var res []proto.HiddenResult
	_, err := s.helper.Call(cctx, &proto.Request{Op: proto.OpHiddenScan, Params: mustJSON(proto.HiddenScanParams{All: all})}, &res)
	s.hiddenMu.Lock()
	defer s.hiddenMu.Unlock()
	if err != nil {
		s.hiddenErr = err.Error()
		return
	}
	if res == nil {
		res = []proto.HiddenResult{}
	}
	s.hidden, s.hiddenAll, s.hiddenTime, s.hiddenErr = res, all, time.Now().UTC(), ""
}

type hiddenView struct {
	Results   []proto.HiddenResult `json:"results"`
	All       bool                 `json:"all"`
	CheckedAt time.Time            `json:"checked_at"`
	Error     string               `json:"error,omitempty"`
}

func (s *Server) hiddenSnapshot() hiddenView {
	s.hiddenMu.Lock()
	defer s.hiddenMu.Unlock()
	r := s.hidden
	if r == nil {
		r = []proto.HiddenResult{}
	}
	return hiddenView{Results: r, All: s.hiddenAll, CheckedAt: s.hiddenTime, Error: s.hiddenErr}
}
