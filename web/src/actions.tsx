import { useState, type ReactNode } from "react";
import { api, ApiError } from "./api";
import { ConfirmDialog, type ConfirmSpec } from "./components";
import type { Disk, WriteResult } from "./types";

export interface ActionSpec {
  url: string;
  body: Record<string, unknown>;
  title: string;
  operation: string;
  disk?: Disk;
  destructive?: boolean;
  confirmWith?: string[];
  confirmLabel?: string;
  extra?: ReactNode;
  wide?: boolean;
  /** Message after success; defaults to the helper's summary. */
  done?: (r: WriteResult) => string;
  /** Runs after success (e.g. a follow-up step); its error is shown. */
  then?: (r: WriteResult) => Promise<string | void>;
  /** Show the command output (e.g. fsck) in the result message. */
  showOutput?: boolean;
}

export function explainError(e: unknown): string {
  const ae = e as ApiError;
  if (ae?.code === "writes_disabled") return "Write operations are disabled. Set writes_enabled = true in /etc/fsview/helper.conf and restart fsview-helper.";
  return ae?.message ?? String(e);
}

type Msg = { kind: "info" | "error" | "ok"; text: string; output?: string };

/**
 * Write action flow shared by every page: dry run (the dialog shows the
 * exact commands the helper will run), confirmation (typed for
 * destructive operations), execution, then a result message.
 */
export function useAction(onDone?: () => void) {
  const [spec, setSpec] = useState<(ConfirmSpec & { a: ActionSpec }) | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Msg | null>(null);

  const start = async (a: ActionSpec) => {
    setMsg(null);
    setBusy(true);
    try {
      const dry = await api.post<WriteResult>(a.url, { ...a.body, dry_run: true });
      setSpec({
        a,
        title: a.title,
        disk: a.disk,
        operation: a.operation,
        destructive: a.destructive,
        confirmWith: a.confirmWith,
        plan: dry.plan,
        confirmLabel: a.confirmLabel ?? "Confirm",
        extra: a.extra,
        wide: a.wide,
      });
    } catch (e) {
      setMsg({ kind: "error", text: explainError(e) });
    } finally {
      setBusy(false);
    }
  };

  const run = async (typed: string) => {
    if (!spec) return;
    const a = spec.a;
    setBusy(true);
    try {
      const r = await api.post<WriteResult>(a.url, { ...a.body, confirmed: true, confirm_text: a.destructive ? typed : undefined });
      let text = a.done ? a.done(r) : r.result?.summary ? `Done: ${r.result.summary}.` : "Done.";
      if (a.then) {
        try {
          const more = await a.then(r);
          if (more) text += ` ${more}`;
        } catch (e) {
          setMsg({ kind: "error", text: `${text} Follow-up step failed: ${explainError(e)}` });
          setSpec(null);
          onDone?.();
          return;
        }
      }
      setMsg({ kind: "ok", text, output: a.showOutput ? r.result?.output : undefined });
      onDone?.();
    } catch (e) {
      setMsg({ kind: "error", text: explainError(e) });
    } finally {
      setSpec(null);
      setBusy(false);
    }
  };

  const dialog = spec ? <ConfirmDialog spec={spec} busy={busy} onConfirm={run} onCancel={() => setSpec(null)} /> : null;
  const message = msg ? (
    <div className={`alert ${msg.kind === "error" ? "error" : msg.kind === "ok" ? "ok" : "info"}`} style={{ flexDirection: "column", whiteSpace: "pre-wrap" }}>
      <div className="between" style={{ width: "100%" }}>
        <span>{msg.text}</span>
        <button className="btn ghost sm" onClick={() => setMsg(null)} aria-label="Dismiss">
          ✕
        </button>
      </div>
      {msg.output && <pre className="raw" style={{ width: "100%", margin: 0 }}>{msg.output}</pre>}
    </div>
  ) : null;
  return { start, busy, dialog, message, setMsg };
}
