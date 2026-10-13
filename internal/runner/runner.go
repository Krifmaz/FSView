// Package runner executes external tools with a fixed environment.
// Commands are always invoked directly (never through a shell).
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Result is the outcome of a command. A non-zero exit code is not an error:
// many tools (smartctl in particular) use exit bits to report status.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs a command and returns its output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// Exec runs real binaries.
type Exec struct{}

// SafeEnv is the environment given to every child process.
var SafeEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}

func (Exec) Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = SafeEnv
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, err
}

// CommandLine renders a command for display/audit purposes.
func CommandLine(name string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	for _, p := range append([]string{name}, args...) {
		if p == "" || strings.ContainsAny(p, " \t\"'\\$`") {
			p = fmt.Sprintf("%q", p)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

// Fake is a Runner for tests. Responses are keyed by the full command line
// (name and args joined with single spaces).
type Fake struct {
	mu        sync.Mutex
	Responses map[string]Result
	Calls     []string
}

func (f *Fake) Run(_ context.Context, name string, args ...string) (Result, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, key)
	if r, ok := f.Responses[key]; ok {
		return r, nil
	}
	return Result{}, &exec.Error{Name: name, Err: exec.ErrNotFound}
}
