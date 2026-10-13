import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api";
import { ConfirmDialog, ErrorBox, Loading, type ConfirmSpec } from "../components";
import type { DiffLine, FsEntry, FstabBackupView, FstabDevice, FstabDoc, FstabIssue, FstabLine, FstabPreview, FstabState, WriteResult } from "../types";
import { fmtBytes, fmtTime, useFetch } from "../util";

const FS_TYPES = ["ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs3", "fuse.mergerfs", "nfs", "nfs4", "cifs", "swap", "auto"];
const OPTION_HINTS = [
  "defaults,nofail,x-systemd.device-timeout=5min",
  "defaults,nofail",
  "defaults,nofail,noatime",
  "defaults,allow_other,use_ino,cache.files=partial,dropcacheonclose=true,category.create=mfs,nofail",
  "errors=remount-ro",
  "sw",
];
// Filesystems that are not mounted through fstab directly.
const NOT_MOUNTABLE = ["swap", "LVM2_member", "linux_raid_member", "zfs_member", "crypto_LUKS", "ddf_raid_member", "isw_raid_member"];

function DiffView({ diff, context = true }: { diff: DiffLine[]; context?: boolean }) {
  const lines = context ? diff : diff.filter((l) => l.op !== " ");
  if (!lines.some((l) => l.op !== " ")) return <div className="dim small">No differences.</div>;
  return (
    <div className="diff">
      {lines.map((l, i) => (
        <div key={i} className={l.op === "+" ? "add" : l.op === "-" ? "del" : "ctx"}>
          {l.op}
          {l.text}
        </div>
      ))}
    </div>
  );
}

function Issues({ issues }: { issues: FstabIssue[] }) {
  if (issues.length === 0) return null;
  return (
    <ul className="fs-issues">
      {issues.map((i, k) => (
        <li key={k} className={i.level}>
          {i.level === "error" ? "✖ " : "⚠ "}
          {i.message}
        </li>
      ))}
    </ul>
  );
}

function sameDoc(a: FstabDoc, b: FstabDoc) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Specs a user can pick for a device, best first. */
function specsFor(d: FstabDevice): string[] {
  const out: string[] = [];
  if (d.uuid) out.push(`UUID=${d.uuid}`);
  if (d.label && !/\s/.test(d.label)) out.push(`LABEL=${d.label}`);
  if (d.partuuid) out.push(`PARTUUID=${d.partuuid}`);
  return out;
}

function referencesDevice(doc: FstabDoc, d: FstabDevice) {
  const specs = specsFor(d).map((s) => s.toLowerCase());
  return doc.lines.some((l) => l.kind === "entry" && (specs.includes(l.entry.spec.toLowerCase()) || l.entry.spec === d.path));
}

function newEntryFor(d: FstabDevice): FsEntry {
  const name = (d.label || d.name).replace(/[^A-Za-z0-9._@+-]/g, "_");
  const fsck = ["ext2", "ext3", "ext4"].includes(d.fstype) ? 2 : 0;
  const slow = d.rotational || d.shelf;
  return {
    spec: specsFor(d)[0] ?? d.path,
    file: `/mnt/${name}`,
    vfstype: d.fstype,
    options: slow ? "defaults,nofail,x-systemd.device-timeout=5min" : "defaults,nofail",
    freq: 0,
    passno: fsck,
  };
}

export default function FstabPage() {
  const { data: state, error, loading, reload } = useFetch(() => api.get<FstabState>("/api/fstab"), []);
  const [doc, setDoc] = useState<FstabDoc | null>(null);
  const [preview, setPreview] = useState<FstabPreview | null>(null);
  const [checking, setChecking] = useState(false);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<(ConfirmSpec & { run: () => Promise<void> }) | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "info" | "error"; text: string } | null>(null);
  const [backupView, setBackupView] = useState<FstabBackupView | null>(null);
  const seq = useRef(0);

  // Load the file into the editor (also after a write).
  useEffect(() => {
    if (state) {
      setDoc(structuredClone(state.doc));
      setPreview(null);
    }
  }, [state]);

  const dirty = !!(state && doc && !sameDoc(state.doc, doc));

  // Live validation: preview (validation + findmnt --verify) after edits.
  useEffect(() => {
    if (!doc || !dirty) {
      setPreview(null);
      setPreviewErr(null);
      return;
    }
    const my = ++seq.current;
    const t = setTimeout(async () => {
      setChecking(true);
      try {
        const p = await api.post<FstabPreview>("/api/fstab/preview", { doc });
        if (my === seq.current) {
          setPreview(p);
          setPreviewErr(null);
        }
      } catch (e: any) {
        if (my === seq.current) setPreviewErr(e?.message ?? String(e));
      } finally {
        if (my === seq.current) setChecking(false);
      }
    }, 600);
    return () => clearTimeout(t);
  }, [doc, dirty]);

  const issues = preview?.issues ?? (dirty ? [] : state?.issues ?? []);
  const byLine = useMemo(() => {
    const m = new Map<number, FstabIssue[]>();
    for (const i of issues) if (i.line !== undefined) m.set(i.line, [...(m.get(i.line) ?? []), i]);
    return m;
  }, [issues]);
  const fileIssues = issues.filter((i) => i.line === undefined);

  const specOptions = useMemo(() => (state?.devices ?? []).flatMap((d) => specsFor(d).map((s) => ({ s, d }))), [state]);
  const addable = useMemo(
    () => (state && doc ? state.devices.filter((d) => !d.protected && !NOT_MOUNTABLE.includes(d.fstype) && !referencesDevice(doc, d)) : []),
    [state, doc],
  );

  if (loading && !state) return <Loading />;
  if (!state || !doc) return <ErrorBox error={error ?? "fstab not available"} />;

  const update = (i: number, f: (e: FsEntry) => FsEntry) => {
    setMsg(null);
    setDoc({
      lines: doc.lines.map((l, k) => (k === i && l.kind === "entry" ? { ...l, entry: f(l.entry) } : l)),
    });
  };
  const remove = (i: number) => setDoc({ lines: doc.lines.filter((_, k) => k !== i) });
  const add = (e: FsEntry) => setDoc({ lines: [...doc.lines, { kind: "entry", raw: "", entry: e }] });

  const fail = (e: unknown) => {
    const err = e as ApiError;
    setMsg({ kind: "error", text: err?.message ?? String(e) });
  };

  const apply = async () => {
    if (!preview) return;
    setMsg(null);
    try {
      const dry = await api.post<WriteResult>("/api/fstab/apply", { doc, base_sha256: state.sha256, dry_run: true });
      setConfirm({
        title: `Save ${state.path}`,
        operation: `Write the changes below to ${state.path}. The current file is backed up first and can be restored with one click.`,
        plan: dry.plan,
        confirmLabel: "Save fstab",
        wide: true,
        extra: (
          <>
            <div className="small dim">Changes</div>
            <DiffView diff={preview.diff} context={false} />
            <div style={{ height: 10 }} />
          </>
        ),
        run: async () => {
          const r = await api.post<WriteResult>("/api/fstab/apply", { doc, base_sha256: state.sha256, confirmed: true });
          setMsg({
            kind: "info",
            text: `Saved. ${r.plan.find((p) => p.startsWith("cp ")) ? "Backup created. " : ""}New entries mount at the next boot, or now with: mount -a`,
          });
          await reload();
        },
      });
    } catch (e) {
      fail(e);
    }
  };

  const viewBackup = async (name: string) => {
    try {
      setBackupView(await api.get<FstabBackupView>(`/api/fstab/backups/${encodeURIComponent(name)}`));
    } catch (e) {
      fail(e);
    }
  };

  const restore = async (name: string) => {
    setMsg(null);
    try {
      const view = await api.get<FstabBackupView>(`/api/fstab/backups/${encodeURIComponent(name)}`);
      const dry = await api.post<WriteResult>("/api/fstab/rollback", { name, base_sha256: view.base_sha256, dry_run: true });
      setConfirm({
        title: `Restore ${state.path}`,
        operation: `Replace ${state.path} with backup ${name}. The current file is backed up first.`,
        plan: dry.plan,
        confirmLabel: "Restore backup",
        wide: true,
        extra: (
          <>
            <div className="small dim">Changes</div>
            <DiffView diff={view.diff} context={false} />
            <div style={{ height: 10 }} />
          </>
        ),
        run: async () => {
          await api.post<WriteResult>("/api/fstab/rollback", { name, base_sha256: view.base_sha256, confirmed: true });
          setBackupView(null);
          setMsg({ kind: "info", text: `Restored ${name}.` });
          await reload();
        },
      });
    } catch (e) {
      fail(e);
    }
  };

  const errors = issues.filter((i) => i.level === "error").length + (preview?.verify.errors.length ?? 0);
  const canApply = state.writes_enabled && dirty && !!preview?.can_apply && !checking;

  return (
    <>
      <div className="between">
        <h1>fstab</h1>
        <div className="row">
          <button className="btn" onClick={() => reload()} disabled={busy}>
            ↻ Reload
          </button>
          <button className="btn ghost" disabled={!dirty} onClick={() => setDoc(structuredClone(state.doc))}>
            Discard changes
          </button>
          <button className="btn primary" disabled={!canApply} onClick={apply} title={state.writes_enabled ? "" : "Writes are disabled in the helper configuration"}>
            Review &amp; save
          </button>
        </div>
      </div>
      <p className="dim small">
        Edits <span className="mono">{state.path}</span>. Every change is validated, checked with <span className="mono">findmnt --verify</span>, backed up to{" "}
        <span className="mono">{state.backup_dir}</span> and written atomically by the root helper. Comments are kept.
      </p>
      {!state.writes_enabled && (
        <div className="alert warn">
          Read-only: writes are disabled. To allow saving, run on the host:
          <div className="plan" style={{ marginTop: 6 }}>
            sed -i 's/^writes_enabled = false/writes_enabled = true/' /etc/fsview/helper.conf{"\n"}systemctl restart fsview-helper
          </div>
        </div>
      )}
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <ErrorBox error={error} />

      <div className="stack">
        {doc.lines.map((l, i) => (
          <LineEditor
            key={i}
            line={l}
            issues={byLine.get(i) ?? []}
            specOptions={specOptions}
            onChange={(f) => update(i, f)}
            onRemove={() => remove(i)}
          />
        ))}
      </div>

      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn" onClick={() => add({ spec: "", file: "", vfstype: "ext4", options: "defaults,nofail", freq: 0, passno: 2 })}>
          + Add entry
        </button>
        {addable.length > 0 && (
          <select
            value=""
            onChange={(e) => {
              const d = addable.find((x) => x.path === e.target.value);
              if (d) add(newEntryFor(d));
            }}
          >
            <option value="">+ Add from disk…</option>
            {addable.map((d) => (
              <option key={d.path} value={d.path}>
                {d.name} · {d.fstype} · {d.label || "no label"} · {fmtBytes(d.size_bytes)}
              </option>
            ))}
          </select>
        )}
      </div>
      <datalist id="fs-specs">
        {specOptions.map((o) => (
          <option key={o.s} value={o.s}>
            {o.d.name} {o.d.label} {o.d.fstype}
          </option>
        ))}
      </datalist>
      <datalist id="fs-types">
        {FS_TYPES.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      <datalist id="fs-options">
        {OPTION_HINTS.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>

      {(dirty || fileIssues.length > 0) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="between">
            <h2 style={{ margin: 0 }}>Changes</h2>
            {checking ? (
              <span className="row small dim">
                <span className="spinner" /> checking…
              </span>
            ) : preview ? (
              <span className={`badge ${errors ? "crit" : "ok"}`}>{errors ? `${errors} error${errors > 1 ? "s" : ""}: fix before saving` : "valid"}</span>
            ) : null}
          </div>
          <ErrorBox error={previewErr} />
          <Issues issues={fileIssues} />
          {preview && (
            <>
              <div style={{ height: 8 }} />
              <DiffView diff={preview.diff} />
              {preview.create_dirs.length > 0 && (
                <div className="small" style={{ marginTop: 8 }}>
                  Will create mountpoint{preview.create_dirs.length > 1 ? "s" : ""}: <span className="mono">{preview.create_dirs.join(", ")}</span>
                </div>
              )}
              <div className="small" style={{ marginTop: 8 }}>
                <b>findmnt --verify:</b> {preview.verify.ok ? "no errors" : `${preview.verify.errors.length} error(s)`}
                {preview.verify.warnings.length > 0 && `, ${preview.verify.warnings.length} warning(s)`}
              </div>
              <ul className="fs-issues">
                {preview.verify.errors.map((e) => (
                  <li key={e} className="error">
                    ✖ {e}
                  </li>
                ))}
                {preview.verify.warnings.map((e) => (
                  <li key={e} className="warning">
                    ⚠ {e}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      <h2 style={{ marginTop: 24 }}>Backups</h2>
      {state.backups.length === 0 ? (
        <div className="dim small">No backups yet. One is made automatically before every change.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Backup</th>
                <th>Saved</th>
                <th>Size</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {state.backups.map((b) => (
                <tr key={b.name}>
                  <td className="mono">{b.name}</td>
                  <td>{fmtTime(b.time)}</td>
                  <td>{b.size} B</td>
                  <td>
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <button className="btn" onClick={() => viewBackup(b.name)}>
                        View
                      </button>
                      <button className="btn" disabled={!state.writes_enabled} onClick={() => restore(b.name)}>
                        Restore
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {backupView && (
        <div className="modal-bg" role="dialog" aria-modal="true" onClick={() => setBackupView(null)}>
          <div className="modal wide" onClick={(e) => e.stopPropagation()}>
            <h2>{backupView.name}</h2>
            <div className="small dim">Restoring it would change the current file like this:</div>
            <DiffView diff={backupView.diff} />
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
              <button className="btn ghost" onClick={() => setBackupView(null)}>
                Close
              </button>
              <button className="btn primary" disabled={!state.writes_enabled} onClick={() => restore(backupView.name)}>
                Restore…
              </button>
            </div>
          </div>
        </div>
      )}

      {confirm && (
        <ConfirmDialog
          spec={confirm}
          busy={busy}
          onCancel={() => setConfirm(null)}
          onConfirm={async () => {
            setBusy(true);
            try {
              await confirm.run();
            } catch (e) {
              fail(e);
            } finally {
              setBusy(false);
              setConfirm(null);
            }
          }}
        />
      )}
    </>
  );
}

function LineEditor({
  line,
  issues,
  specOptions,
  onChange,
  onRemove,
}: {
  line: FstabLine;
  issues: FstabIssue[];
  specOptions: { s: string; d: FstabDevice }[];
  onChange: (f: (e: FsEntry) => FsEntry) => void;
  onRemove: () => void;
}) {
  if (line.kind === "comment") {
    return line.text.trim() ? <div className="fs-comment">{line.text}</div> : null;
  }
  if (line.kind === "invalid") {
    return (
      <div className="card">
        <div className="between">
          <span className="mono small">{line.text}</span>
          <button className="btn ghost" onClick={onRemove}>
            ✕ Remove
          </button>
        </div>
        <Issues issues={issues} />
      </div>
    );
  }
  const e = line.entry;
  const cls = (field: string) => (issues.some((i) => i.field === field && i.level === "error") ? "bad" : issues.some((i) => i.field === field) ? "warnf" : "");
  const dev = specOptions.find((o) => o.s.toLowerCase() === e.spec.toLowerCase())?.d;
  return (
    <div className="card">
      <div className="fs-entry">
        <label className="field wide">
          <span>Device {dev && <span className="dim">· {dev.name}{dev.label ? ` (${dev.label})` : ""}, {fmtBytes(dev.size_bytes)}</span>}</span>
          <input className={`mono ${cls("spec")}`} list="fs-specs" value={e.spec} onChange={(v) => onChange((x) => ({ ...x, spec: v.target.value }))} spellCheck={false} />
        </label>
        <label className="field">
          <span>Mountpoint</span>
          <input className={`mono ${cls("file")}`} value={e.file} onChange={(v) => onChange((x) => ({ ...x, file: v.target.value }))} spellCheck={false} />
        </label>
        <label className="field">
          <span>Type</span>
          <input className={`mono ${cls("vfstype")}`} list="fs-types" value={e.vfstype} onChange={(v) => onChange((x) => ({ ...x, vfstype: v.target.value }))} spellCheck={false} />
        </label>
        <label className="field">
          <span>Dump</span>
          <input className={cls("freq")} type="number" min={0} max={1} value={e.freq} onChange={(v) => onChange((x) => ({ ...x, freq: Math.max(0, Number(v.target.value) || 0) }))} />
        </label>
        <label className="field">
          <span>Pass</span>
          <input className={cls("passno")} type="number" min={0} max={2} value={e.passno} onChange={(v) => onChange((x) => ({ ...x, passno: Math.max(0, Number(v.target.value) || 0) }))} />
        </label>
        <button className="btn ghost" title="Remove entry" onClick={onRemove}>
          ✕
        </button>
        <label className="field opts">
          <span>Options</span>
          <input className={`mono ${cls("options")}`} list="fs-options" value={e.options} onChange={(v) => onChange((x) => ({ ...x, options: v.target.value }))} spellCheck={false} />
        </label>
      </div>
      <Issues issues={issues} />
    </div>
  );
}
