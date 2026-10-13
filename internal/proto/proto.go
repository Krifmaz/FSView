// Package proto defines the wire protocol between the unprivileged web
// server and the root helper. One JSON request per connection, one JSON
// response back, newline terminated.
package proto

import "encoding/json"

// Operation names. The helper rejects anything not in its registry.
const (
	OpStatus        = "status"
	OpInventory     = "inventory"
	OpSmartGet      = "smart.get"
	OpSmartSelfTest = "smart.selftest"
	OpJournalKernel = "journal.kernel"
	OpBootCollect   = "boot.collect"
	OpAuditList     = "audit.list"
)

// MaxMessage bounds request and response sizes on the socket.
const MaxMessage = 32 << 20

type Request struct {
	Op string `json:"op"`
	// Actor is the web user on whose behalf the request is made. The helper
	// records it in the audit log; it cannot verify it.
	Actor    string `json:"actor,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	// DryRun returns the plan without executing anything.
	DryRun bool `json:"dry_run,omitempty"`
	// Confirmed must be true for non-destructive write operations.
	Confirmed bool `json:"confirmed,omitempty"`
	// ConfirmText must equal the target disk's device name or label for
	// destructive operations.
	ConfirmText string          `json:"confirm_text,omitempty"`
	Params      json.RawMessage `json:"params,omitempty"`
}

// Error codes.
const (
	CodeBadRequest   = "bad_request"
	CodeUnknownOp    = "unknown_op"
	CodeWritesOff    = "writes_disabled"
	CodeNeedConfirm  = "confirmation_required"
	CodeProtected    = "protected_disk"
	CodeExecFailed   = "exec_failed"
	CodeInternal     = "internal"
	CodeNotPermitted = "not_permitted"
)

type Response struct {
	OK     bool            `json:"ok"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	// Plan lists the exact commands that will run (or ran).
	Plan   []string `json:"plan,omitempty"`
	DryRun bool     `json:"dry_run,omitempty"`
}

// Params and results for individual operations.

type SmartGetParams struct {
	Device string `json:"device"`
	// Wake allows querying a disk in standby (spinning it up).
	Wake bool `json:"wake,omitempty"`
}

type SmartGetResult struct {
	Device     string          `json:"device"`
	DevType    string          `json:"devtype"`
	ExitStatus int             `json:"exit_status"`
	Standby    bool            `json:"standby"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

type SmartSelfTestParams struct {
	Device string `json:"device"`
	Test   string `json:"test"` // short | long | abort
}

type JournalParams struct {
	AfterCursor string `json:"after_cursor,omitempty"`
	CurrentBoot bool   `json:"current_boot,omitempty"`
	Lines       int    `json:"lines,omitempty"`
}

type AuditListParams struct {
	Limit int `json:"limit,omitempty"`
}

type StatusResult struct {
	Version       string          `json:"version"`
	Hostname      string          `json:"hostname"`
	WritesEnabled bool            `json:"writes_enabled"`
	BootID        string          `json:"boot_id"`
	Tools         map[string]bool `json:"tools"`
}
