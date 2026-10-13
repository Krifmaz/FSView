package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/krifmaz/fsview/internal/proto"
)

// Hidden data: files stored in a directory on a parent filesystem that
// another filesystem is now mounted over. They use space but are invisible.
// This typically happens when a disk failed to mount and services wrote
// into the empty mountpoint (filling the root disk).
//
// The scan runs on a dedicated OS thread inside a private mount namespace:
// the parent filesystem is bind-mounted read-only (non-recursively, so
// child mounts are not carried over) into a temporary directory. The bind
// mount is never visible on the host and disappears with the thread.

// realFS are filesystems worth scanning as parents.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true, "reiserfs": true,
}

type fmNode struct {
	Target   string   `json:"target"`
	Source   string   `json:"source"`
	FSType   string   `json:"fstype"`
	Children []fmNode `json:"children"`
}

type scanJob struct {
	parent   fmNode
	children []string // child mount targets directly on parent
}

// planHiddenScan lists parents and the child mountpoints that sit on them.
// rootOnly limits the scan to the root filesystem.
func planHiddenScan(findmntJSON []byte, rootOnly bool) ([]scanJob, error) {
	var doc struct {
		Filesystems []fmNode `json:"filesystems"`
	}
	if err := json.Unmarshal(findmntJSON, &doc); err != nil {
		return nil, err
	}
	var jobs []scanJob
	var walk func(n fmNode)
	walk = func(n fmNode) {
		if realFS[n.FSType] && (!rootOnly || n.Target == "/") && len(n.Children) > 0 {
			j := scanJob{parent: n}
			for _, c := range n.Children {
				// A mount stacked on the same path hides the parent entirely.
				if c.Target != n.Target {
					j.children = append(j.children, c.Target)
				}
			}
			if len(j.children) > 0 {
				jobs = append(jobs, j)
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, f := range doc.Filesystems {
		walk(f)
	}
	return jobs, nil
}

const (
	hiddenMaxFiles = 200000
	hiddenMaxTime  = 60 * time.Second
	hiddenSamples  = 10
)

// measure walks dir and returns file count, bytes and the largest entries.
func measure(dir string, deadline time.Time) (files int, bytes int64, samples []proto.HiddenSample, truncated bool, err error) {
	sizes := map[string]int64{} // top-level entry -> bytes
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if p == dir {
			return nil
		}
		if files >= hiddenMaxFiles || time.Now().After(deadline) {
			truncated = true
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(dir, p)
		top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		if _, ok := sizes[top]; !ok {
			sizes[top] = 0
		}
		if d.Type().IsRegular() {
			files++
			if fi, err := d.Info(); err == nil {
				bytes += fi.Size()
				sizes[top] += fi.Size()
			}
		}
		return nil
	})
	for name, sz := range sizes {
		samples = append(samples, proto.HiddenSample{Name: name, Bytes: sz})
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Bytes > samples[j].Bytes })
	if len(samples) > hiddenSamples {
		samples = samples[:hiddenSamples]
	}
	return files, bytes, samples, truncated, err
}

// scanHidden performs the scan in a private mount namespace.
func (s *Server) scanHidden(ctx context.Context, rootOnly bool) ([]proto.HiddenResult, error) {
	res, err := s.run.Run(ctx, "findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE")
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("findmnt failed: %v", err)
	}
	jobs, err := planHiddenScan(res.Stdout, rootOnly)
	if err != nil {
		return nil, err
	}
	type outcome struct {
		results []proto.HiddenResult
		err     error
	}
	ch := make(chan outcome, 1)
	go func() {
		// Never unlocked: the thread exits with the goroutine, taking the
		// private mount namespace (and its bind mounts) with it.
		runtime.LockOSThread()
		r, err := s.scanInNamespace(jobs)
		ch <- outcome{r, err}
	}()
	select {
	case o := <-ch:
		return o.results, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) scanInNamespace(jobs []scanJob) ([]proto.HiddenResult, error) {
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return nil, fmt.Errorf("unshare mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("make mounts private: %w", err)
	}
	base := s.cfg.ScratchDir
	if base == "" {
		base = os.TempDir()
	}
	tmp, err := os.MkdirTemp(base, "fsview-hidden-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	deadline := time.Now().Add(hiddenMaxTime)
	var out []proto.HiddenResult
	for _, j := range jobs {
		if err := unix.Mount(j.parent.Target, tmp, "", unix.MS_BIND, ""); err != nil {
			out = append(out, proto.HiddenResult{Parent: j.parent.Target, ParentSource: j.parent.Source, Error: "bind mount failed: " + err.Error()})
			continue
		}
		_ = unix.Mount("", tmp, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, "")
		for _, child := range j.children {
			rel := strings.TrimPrefix(child, strings.TrimSuffix(j.parent.Target, "/"))
			dir := filepath.Join(tmp, rel)
			r := proto.HiddenResult{Mountpoint: child, Parent: j.parent.Target, ParentSource: j.parent.Source}
			if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
				continue
			}
			r.Files, r.Bytes, r.Samples, r.Truncated, _ = measure(dir, deadline)
			if r.Files > 0 || len(r.Samples) > 0 {
				out = append(out, r)
			}
		}
		_ = unix.Unmount(tmp, unix.MNT_DETACH)
	}
	return out, nil
}

func opHiddenScan(ctx context.Context, s *Server, req *proto.Request) (any, error) {
	var p proto.HiddenScanParams
	if err := decode(req, &p); err != nil {
		return nil, err
	}
	r, err := s.scanHidden(ctx, !p.All)
	if r == nil {
		r = []proto.HiddenResult{}
	}
	return r, err
}
