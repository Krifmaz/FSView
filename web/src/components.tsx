import { useState, type ReactNode } from "react";
import type { Disk, Status, Usage } from "./types";
import { fmtBytes } from "./util";

export function StatusBadge({ status, label }: { status?: Status | string; label?: string }) {
  const s = status ?? "unknown";
  const text = label ?? { ok: "Healthy", warn: "Warning", crit: "Critical", unknown: "Unknown" }[s] ?? s;
  return <span className={`badge ${s}`}>{text}</span>;
}

export function ProtectedBadge({ disk }: { disk: Disk }) {
  if (!disk.protected) return null;
  return (
    <span className="badge protected" title={(disk.protected_reasons ?? []).join("\n")}>
      🔒 Protected
    </span>
  );
}

export function UsageBar({ usage }: { usage?: Usage }) {
  if (!usage || !usage.size_bytes) return <span className="dim">–</span>;
  const pct = Math.min(100, (usage.used_bytes / usage.size_bytes) * 100);
  const cls = pct >= 95 ? "crit" : pct >= 85 ? "warn" : "";
  return (
    <div title={`${fmtBytes(usage.used_bytes)} used of ${fmtBytes(usage.size_bytes)}, ${fmtBytes(usage.avail_bytes)} free`}>
      <div className={`usage ${cls}`}>
        <div style={{ width: `${pct}%` }} />
      </div>
      <div className="small dim">
        {pct.toFixed(0)}% · {fmtBytes(usage.avail_bytes)} free
      </div>
    </div>
  );
}

export function Loading() {
  return (
    <div className="row dim">
      <span className="spinner" /> Loading…
    </div>
  );
}

export function ErrorBox({ error }: { error?: string | null }) {
  if (!error) return null;
  return <div className="alert error">{error}</div>;
}

export function Temp({ c, trip }: { c?: number; trip?: number }) {
  if (c === undefined || c === null) return <span className="dim">–</span>;
  const cls = trip && c >= trip - 5 ? "warn" : c >= 60 ? "crit" : c >= 50 ? "warn" : "";
  return <span className={cls ? `badge ${cls}` : ""}>{c}°C</span>;
}

export interface ConfirmSpec {
  title: string;
  disk?: Disk;
  operation: string;
  destructive?: boolean;
  /** Accepted confirmation strings for destructive operations. */
  confirmWith?: string[];
  plan?: string[];
  confirmLabel?: string;
  extra?: ReactNode;
}

/**
 * ConfirmDialog shows disk identity and the exact operation. Destructive
 * operations require typing the disk's label or device name.
 */
export function ConfirmDialog({ spec, busy, onConfirm, onCancel }: { spec: ConfirmSpec; busy?: boolean; onConfirm: (typed: string) => void; onCancel: () => void }) {
  const [typed, setTyped] = useState("");
  const d = spec.disk;
  const accepted = spec.confirmWith ?? (d ? [d.name, d.label ?? ""].filter(Boolean) : []);
  const ok = !spec.destructive || accepted.includes(typed.trim());
  return (
    <div className="modal-bg" role="dialog" aria-modal="true" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{spec.title}</h2>
        {d && (
          <dl className="kv" style={{ marginBottom: 12 }}>
            <dt>Device</dt>
            <dd className="mono">{d.path}</dd>
            <dt>Model</dt>
            <dd>{d.display_model || d.model || "–"}</dd>
            <dt>Serial</dt>
            <dd className="mono">{d.serial || "–"}</dd>
            <dt>Size</dt>
            <dd>{fmtBytes(d.size_bytes)}</dd>
            <dt>Label</dt>
            <dd>{d.label || (d.children ?? []).map((c) => c.label).filter(Boolean).join(", ") || "–"}</dd>
          </dl>
        )}
        <div className="small dim">Operation</div>
        <div style={{ marginBottom: 10 }}>{spec.operation}</div>
        {spec.plan && spec.plan.length > 0 && (
          <>
            <div className="small dim">Will run</div>
            <div className="plan" style={{ marginBottom: 10 }}>
              {spec.plan.join("\n")}
            </div>
          </>
        )}
        {spec.extra}
        {spec.destructive && (
          <label className="field" style={{ marginBottom: 12 }}>
            <span>
              Type{" "}
              {accepted.map((a, i) => (
                <span key={a}>
                  {i > 0 && " or "}
                  <b className="mono">{a}</b>
                </span>
              ))}{" "}
              to confirm
            </span>
            <input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} autoCapitalize="off" autoCorrect="off" spellCheck={false} />
          </label>
        )}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className={`btn ${spec.destructive ? "danger" : "primary"}`} disabled={!ok || busy} onClick={() => onConfirm(typed.trim())}>
            {busy && <span className="spinner" />} {spec.confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}
