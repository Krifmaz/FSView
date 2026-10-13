// Package helperclient talks to the root helper over its Unix socket.
package helperclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/krifmaz/fsview/internal/proto"
)

type Client struct {
	Socket string
}

// Error is a helper-side failure with its code.
type Error struct {
	Code string
	Msg  string
	Plan []string
}

func (e *Error) Error() string { return e.Msg }

// Call sends one request. If out is non-nil the result is decoded into it.
// The raw response is returned for callers that need Plan/DryRun.
func (c *Client) Call(ctx context.Context, req *proto.Request, out any) (*proto.Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("helper unavailable: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, proto.MaxMessage)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("helper read: %w", err)
	}
	var resp proto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("helper response: %w", err)
	}
	if !resp.OK {
		return &resp, &Error{Code: resp.Code, Msg: resp.Error, Plan: resp.Plan}
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return &resp, fmt.Errorf("decode result: %w", err)
		}
	}
	return &resp, nil
}

// Params marshals operation parameters.
func Params(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
