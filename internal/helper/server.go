// Package helper is the root-privileged half of FSView. It listens on a
// Unix socket, accepts only connections from the fsview user (checked with
// SO_PEERCRED), and executes a fixed allow-list of typed operations.
// Safety rules (writes switch, confirmations, protected disks, audit log)
// are enforced here regardless of what the web process sends.
package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/krifmaz/fsview/internal/inventory"
	"github.com/krifmaz/fsview/internal/proto"
	"github.com/krifmaz/fsview/internal/runner"
)

type Config struct {
	Socket        string
	AllowedUIDs   []int // peers allowed to connect
	SocketGID     int   // group owner of the socket (-1 to leave)
	WritesEnabled bool
	IncludeLoop   bool
	FstabPath     string
	SysRoot       string // default /sys
	Version       string
}

type Server struct {
	cfg    Config
	run    runner.Runner
	audit  *AuditLog
	inv    *inventory.Collector
	logger *log.Logger

	mu         sync.Mutex
	smartTypes map[string]smartChoice // device -> verified -d type
}

func New(cfg Config, r runner.Runner, audit *AuditLog) *Server {
	if cfg.FstabPath == "" {
		cfg.FstabPath = "/etc/fstab"
	}
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/sys"
	}
	inv := inventory.NewCollector(r, cfg.IncludeLoop)
	return &Server{
		cfg:        cfg,
		run:        r,
		audit:      audit,
		inv:        inv,
		logger:     log.New(os.Stderr, "fsview-helper: ", log.LstdFlags),
		smartTypes: map[string]smartChoice{},
	}
}

// Listen creates the socket with mode 0660 and the configured group.
func (s *Server) Listen() (*net.UnixListener, error) {
	if err := os.Remove(s.cfg.Socket); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	old := unix.Umask(0o117)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.cfg.Socket, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.cfg.Socket, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	if s.cfg.SocketGID >= 0 && os.Geteuid() == 0 {
		if err := os.Chown(s.cfg.Socket, 0, s.cfg.SocketGID); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handleConn(ctx, c)
	}
}

func peerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	return cred, cerr
}

func (s *Server) allowed(uid int) bool {
	for _, u := range s.cfg.AllowedUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

func (s *Server) handleConn(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	cred, err := peerCred(c)
	if err != nil || !s.allowed(int(cred.Uid)) {
		uid := -1
		if cred != nil {
			uid = int(cred.Uid)
		}
		s.logger.Printf("rejected connection from uid %d", uid)
		writeResp(c, &proto.Response{Code: proto.CodeNotPermitted, Error: "peer not permitted"})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(io.LimitReader(c, proto.MaxMessage))
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req proto.Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResp(c, &proto.Response{Code: proto.CodeBadRequest, Error: "invalid request json"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	octx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	resp := s.Handle(octx, &req, int(cred.Uid))
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	writeResp(c, resp)
}

func writeResp(w io.Writer, r *proto.Response) {
	b, err := json.Marshal(r)
	if err != nil {
		b = []byte(`{"ok":false,"code":"internal","error":"marshal failed"}`)
	}
	_, _ = w.Write(append(b, '\n'))
}

func errResp(code string, format string, args ...any) *proto.Response {
	return &proto.Response{Code: code, Error: fmt.Sprintf(format, args...)}
}

func okResp(v any) *proto.Response {
	b, err := json.Marshal(v)
	if err != nil {
		return errResp(proto.CodeInternal, "marshal result: %v", err)
	}
	return &proto.Response{OK: true, Result: b}
}
