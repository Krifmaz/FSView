package helper

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditRecord is one line in the audit log.
type AuditRecord struct {
	Time     time.Time       `json:"time"`
	Actor    string          `json:"actor"`
	ClientIP string          `json:"client_ip,omitempty"`
	PeerUID  int             `json:"peer_uid"`
	Op       string          `json:"op"`
	Targets  []string        `json:"targets,omitempty"`
	Params   json.RawMessage `json:"params,omitempty"`
	DryRun   bool            `json:"dry_run"`
	Commands []string        `json:"commands,omitempty"`
	Result   string          `json:"result"` // ok | error | rejected | dry-run
	Error    string          `json:"error,omitempty"`
	Output   string          `json:"output,omitempty"`
}

// AuditLog appends JSON lines to a root-owned file.
type AuditLog struct {
	mu   sync.Mutex
	path string
	gid  int
}

func NewAuditLog(path string, gid int) (*AuditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	f.Close()
	if gid >= 0 && os.Geteuid() == 0 {
		_ = os.Chown(path, 0, gid)
		_ = os.Chown(filepath.Dir(path), 0, gid)
	}
	return &AuditLog{path: path, gid: gid}, nil
}

func (a *AuditLog) Write(rec AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	if len(rec.Output) > 4096 {
		rec.Output = rec.Output[:4096] + "…(truncated)"
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Tail returns the newest `limit` records, newest first.
func (a *AuditLog) Tail(limit int) ([]AuditRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var all []AuditRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var r AuditRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			all = append(all, r)
		}
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, sc.Err()
}
