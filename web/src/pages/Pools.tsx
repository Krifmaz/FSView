import { useMemo, useState } from "react";
import { Layers, Plus } from "lucide-react";
import { api } from "../api";
import { useAction, explainError } from "../actions";
import { ErrorBox, Loading, UsageBar } from "../components";
import type { FsEntry, FstabDoc, FstabPreview, FstabState, Pool, PoolHealth, StorageEntry, StorageView, WriteResult } from "../types";
import { fmtBytes, useFetch } from "../util";
import { DiffView } from "./Fstab";
import { HealthBadge, useHealthMap } from "../life";
import PoolHealthPanel from "./PoolHealth";

const POLICIES: [string, string][] = [
  ["mfs", "Most free space: new files go to the disk with the most free space (recommended)"],
  ["epmfs", "Existing path, most free space: keeps folders together on the disks that already have them"],
  ["lfs", "Least free space: fills one disk before the next"],
  ["pfrd", "Weighted random by free space"],
  ["rand", "Random"],
  ["ff", "First found: always the first branch with room"],
];
const CACHE: [string, string][] = [
  ["off", "off (safest, works with all apps)"],
  ["partial", "partial (faster reads, needed for some apps that mmap files)"],
  ["auto-full", "auto-full"],
];
// Options the form manages; everything else is kept as "extra".
const MANAGED = ["category.create", "minfreespace", "cache.files", "moveonenospc", "dropcacheonclose", "x-systemd.requires-mounts-for", "x-systemd.wants-mounts-for", "nofail", "fsname", "allow_other", "defaults"];
// Dropped when a pool is saved: device-timeout means nothing for a FUSE
// mount (there is no device), and use_ino is ignored by current mergerfs.
const OBSOLETE = ["x-systemd.device-timeout", "use_ino"];

interface Form {
  original?: string;
  mountpoint: string;
  branches: string[];
  /** Branch path -> mergerfs mode (NC, RO); missing means read-write. */
  modes: Record<string, string>;
  policy: string;
  minfree: string;
  cache: string;
  moveonenospc: boolean;
  extra: string;
  mountNow: boolean;
}

function parseOptions(o: string): [string, string | undefined][] {
  return o
    .split(",")
    .filter(Boolean)
    .map((s) => {
      const i = s.indexOf("=");
      return i < 0 ? [s, undefined] : [s.slice(0, i), s.slice(i + 1)];
    });
}

function formFromPool(p: Pool): Form {
  const opts = parseOptions(p.options);
  const get = (k: string) => opts.find(([x]) => x === k)?.[1];
  return {
    original: p.file,
    mountpoint: p.file,
    branches: p.branches.map((b) => b.path),
    modes: Object.fromEntries(p.branches.filter((b) => b.mode && b.mode !== "RW").map((b) => [b.path, b.mode as string])),
    policy: get("category.create") ?? "epmfs",
    minfree: get("minfreespace") ?? "",
    cache: get("cache.files") ?? "off",
    moveonenospc: (get("moveonenospc") ?? "false") !== "false",
    extra: opts
      .filter(([k]) => !MANAGED.includes(k) && !OBSOLETE.includes(k))
      .map(([k, v]) => (v === undefined ? k : `${k}=${v}`))
      .join(","),
    mountNow: true,
  };
}

/** The data filesystem a branch path lives on (longest fstab mountpoint prefix). */
function ownerOf(path: string, entries: StorageEntry[], self: string): string | undefined {
  return entries
    .filter((e) => !e.pool && e.file !== "/" && e.file !== self && e.vfstype !== "swap")
    .filter((e) => path === e.file || path.startsWith(e.file + "/"))
    .sort((a, b) => b.file.length - a.file.length)[0]?.file;
}

function buildEntry(f: Form, entries: StorageEntry[]): FsEntry {
  const name = f.mountpoint.split("/").filter(Boolean).pop() ?? "pool";
  const req = [...new Set(f.branches.map((b) => ownerOf(b, entries, f.mountpoint)).filter((x): x is string => !!x))];
  const opts = [
    "defaults",
    "allow_other",
    `cache.files=${f.cache}`,
    "dropcacheonclose=true",
    `category.create=${f.policy}`,
    ...(f.moveonenospc ? ["moveonenospc=true"] : []),
    ...(f.minfree.trim() ? [`minfreespace=${f.minfree.trim()}`] : []),
    `fsname=mergerfs-${name}`,
    ...f.extra.split(",").map((s) => s.trim()).filter(Boolean),
    "nofail",
    ...req.map((m) => `x-systemd.wants-mounts-for=${m}`),
  ];
  const spec = f.branches.map((b) => (f.modes[b] ? `${b}=${f.modes[b]}` : b)).join(":");
  return { spec, file: f.mountpoint, vfstype: "fuse.mergerfs", options: [...new Set(opts)].join(","), freq: 0, passno: 0 };
}

function withEntry(doc: FstabDoc, original: string | undefined, e: FsEntry | null): FstabDoc {
  const lines = [...doc.lines];
  const i = original ? lines.findIndex((l) => l.kind === "entry" && l.entry.file === original) : -1;
  if (i >= 0) {
    if (e) lines[i] = { kind: "entry", raw: "", entry: e };
    else lines.splice(i, 1);
  } else if (e) {
    lines.push({ kind: "entry", raw: "", entry: e });
  }
  return { lines };
}

function PoolEditor({ form, data, onClose, onSaved }: { form: Form; data: StorageView; onClose: () => void; onSaved: (msg: string) => void }) {
  const [f, setF] = useState<Form>(form);
  const [custom, setCustom] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ pv: FstabPreview; doc: FstabDoc; sha: string; plan: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const candidates = data.entries.filter((e) => !e.pool && !e.system && e.vfstype !== "swap" && e.file.startsWith("/"));
  const editing = !!form.original;
  const wasMounted = editing && data.pools.find((p) => p.file === form.original)?.mounted;
  // Same mountpoint: the running pool takes the new settings live (no unmount).
  const live = wasMounted && f.mountpoint === form.original;

  const toggle = (p: string) => setF({ ...f, branches: f.branches.includes(p) ? f.branches.filter((b) => b !== p) : [...f.branches, p] });
  const move = (i: number, d: number) => {
    const b = [...f.branches];
    const j = i + d;
    if (j < 0 || j >= b.length) return;
    [b[i], b[j]] = [b[j], b[i]];
    setF({ ...f, branches: b });
  };

  const review = async () => {
    setErr(null);
    if (!f.mountpoint.startsWith("/mnt/") && !f.mountpoint.startsWith("/srv/") && !f.mountpoint.startsWith("/media/") && !f.mountpoint.startsWith("/storage")) {
      setErr("Use a mountpoint under /mnt, /srv, /media or /storage.");
      return;
    }
    if (f.branches.length === 0) {
      setErr("Pick at least one branch.");
      return;
    }
    setBusy(true);
    try {
      const st = await api.get<FstabState>("/api/fstab");
      const doc = withEntry(st.doc, f.original, buildEntry(f, data.entries));
      const pv = await api.post<FstabPreview>("/api/fstab/preview", { doc });
      let plan: string[] = [];
      if (pv.can_apply) plan = (await api.post<WriteResult>("/api/fstab/apply", { doc, base_sha256: st.sha256, dry_run: true })).plan;
      setPreview({ pv, doc, sha: st.sha256, plan });
    } catch (e) {
      setErr(explainError(e));
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (!preview) return;
    setBusy(true);
    setErr(null);
    try {
      await api.post("/api/fstab/apply", { doc: preview.doc, base_sha256: preview.sha, confirmed: true });
      let msg = `Pool ${f.mountpoint} saved to fstab (backup made).`;
      if (f.mountNow) {
        try {
          if (wasMounted && !live) {
            await api.post("/api/mounts/umount", { target: f.original, confirmed: true });
          }
          await api.post("/api/mounts/mount", { target: f.mountpoint, confirmed: true });
          msg += live ? " Applied to the running pool." : wasMounted ? " Remounted with the new settings." : " Mounted.";
        } catch (e) {
          msg += ` Not ${wasMounted ? "remounted" : "mounted"}: ${explainError(e)}`;
        }
      }
      onSaved(msg);
    } catch (e) {
      setErr(explainError(e));
      setBusy(false);
    }
  };

  const errors = preview ? preview.pv.issues.filter((i) => i.level === "error").map((i) => i.message).concat(preview.pv.verify.errors) : [];
  const warnings = preview ? preview.pv.issues.filter((i) => i.level === "warning" && (i.line === undefined || preview.doc.lines[i.line]?.kind === "entry" && (preview.doc.lines[i.line] as { entry: FsEntry }).entry.file === f.mountpoint)).map((i) => i.message) : [];

  return (
    <div className="modal-bg" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <h2>{editing ? `Edit pool ${form.original}` : "New mergerfs pool"}</h2>
        {!preview ? (
          <div className="stack">
            <label className="field">
              <span>Mountpoint</span>
              <input className="mono" value={f.mountpoint} onChange={(e) => setF({ ...f, mountpoint: e.target.value })} placeholder="/mnt/pool" />
            </label>
            <div className="field">
              <span>Branches (disks in the pool, in order)</span>
              <div className="stack" style={{ gap: 6 }}>
                {candidates.map((c) => {
                  const on = f.branches.filter((b) => b === c.file || b.startsWith(c.file + "/"));
                  return (
                    <label key={c.file} className="check card" style={{ padding: "8px 12px" }}>
                      <input type="checkbox" checked={on.length > 0} onChange={() => (on.length ? setF({ ...f, branches: f.branches.filter((b) => !on.includes(b)) }) : toggle(c.file))} />
                      <span className="mono">{c.file}</span>
                      <span className="small dim">
                        {c.device ? `${c.device.name}${c.device.label ? ` (${c.device.label})` : ""} · ${fmtBytes(c.device.size_bytes)}` : c.spec}
                        {c.usage && ` · ${fmtBytes(c.usage.avail_bytes)} free`}
                        {!c.mounted && " · not mounted"}
                      </span>
                    </label>
                  );
                })}
                <div className="row">
                  <input className="mono grow" placeholder="or a path, e.g. /mnt/media1/data" value={custom} onChange={(e) => setCustom(e.target.value)} />
                  <button
                    className="btn"
                    disabled={!custom.startsWith("/")}
                    onClick={() => {
                      if (!f.branches.includes(custom)) setF({ ...f, branches: [...f.branches, custom.replace(/\/+$/, "")] });
                      setCustom("");
                    }}
                  >
                    Add path
                  </button>
                </div>
              </div>
            </div>
            {f.branches.length > 0 && (
              <div className="card" style={{ padding: 12 }}>
                <div className="small dim" style={{ marginBottom: 6 }}>
                  Branch order (matters for the "ff" policy)
                </div>
                {f.branches.map((b, i) => (
                  <div key={b} className="between" style={{ padding: "2px 0" }}>
                    <span className="mono small">
                      {i + 1}. {b}
                      {!ownerOf(b, data.entries, f.mountpoint) && <span style={{ color: "var(--warn)" }}> · not on a disk in fstab</span>}
                    </span>
                    <span className="row" style={{ gap: 4 }}>
                      <select
                        className="sm"
                        value={f.modes[b] ?? ""}
                        title="Normal: read and write. No new files: existing files stay readable and editable, new files go elsewhere. Read-only: nothing is written."
                        onChange={(e) => {
                          const modes = { ...f.modes };
                          if (e.target.value) modes[b] = e.target.value;
                          else delete modes[b];
                          setF({ ...f, modes });
                        }}
                      >
                        <option value="">Normal</option>
                        <option value="NC">No new files</option>
                        <option value="RO">Read-only</option>
                      </select>
                      <button className="btn ghost sm" onClick={() => move(i, -1)} disabled={i === 0}>
                        ↑
                      </button>
                      <button className="btn ghost sm" onClick={() => move(i, 1)} disabled={i === f.branches.length - 1}>
                        ↓
                      </button>
                      <button className="btn ghost sm" onClick={() => setF({ ...f, branches: f.branches.filter((x) => x !== b) })}>
                        ✕
                      </button>
                    </span>
                  </div>
                ))}
              </div>
            )}
            <div className="grid2">
              <label className="field">
                <span>Where new files go</span>
                <select value={f.policy} onChange={(e) => setF({ ...f, policy: e.target.value })}>
                  {POLICIES.map(([k, d]) => (
                    <option key={k} value={k}>
                      {k}: {d}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Keep free on each disk</span>
                <input className="mono" value={f.minfree} onChange={(e) => setF({ ...f, minfree: e.target.value })} placeholder="20G" />
              </label>
              <label className="field">
                <span>File caching</span>
                <select value={f.cache} onChange={(e) => setF({ ...f, cache: e.target.value })}>
                  {CACHE.map(([k, d]) => (
                    <option key={k} value={k}>
                      {d}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Other mergerfs options</span>
                <input className="mono" value={f.extra} onChange={(e) => setF({ ...f, extra: e.target.value })} placeholder="e.g. func.getattr=newest" />
              </label>
            </div>
            <label className="check">
              <input type="checkbox" checked={f.moveonenospc} onChange={(e) => setF({ ...f, moveonenospc: e.target.checked })} />
              If a disk fills up during a write, move the file to another disk (moveonenospc)
            </label>
            <label className="check">
              <input type="checkbox" checked={f.mountNow} onChange={(e) => setF({ ...f, mountNow: e.target.checked })} />
              {live ? "Apply the changes to the running pool now (no unmount)" : wasMounted ? "Remount now so the changes take effect" : "Mount the pool now"}
            </label>
            <div className="small dim">
              FSView adds <span className="mono">nofail</span> and <span className="mono">x-systemd.wants-mounts-for</span> for every disk, so the pool mounts after its disks without
              being unmounted when one of them is. Use <b>Protect mountpoints</b> so a missing disk can never be replaced by the system disk underneath.
            </div>
            <ErrorBox error={err} />
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn ghost" onClick={onClose}>
                Cancel
              </button>
              <button className="btn primary" disabled={busy} onClick={review}>
                {busy && <span className="spinner" />} Review
              </button>
            </div>
          </div>
        ) : (
          <div className="stack">
            <div className="small dim">Changes to /etc/fstab</div>
            <DiffView diff={preview.pv.diff} context={false} />
            {errors.length > 0 && (
              <div className="alert error" style={{ flexDirection: "column" }}>
                {errors.map((e) => (
                  <div key={e}>✖ {e}</div>
                ))}
              </div>
            )}
            {warnings.length > 0 && (
              <div className="alert warn" style={{ flexDirection: "column" }}>
                {warnings.map((e) => (
                  <div key={e}>⚠ {e}</div>
                ))}
              </div>
            )}
            {preview.plan.length > 0 && (
              <>
                <div className="small dim">Will run</div>
                <div className="plan">
                  {[...preview.plan, ...(f.mountNow ? (live ? [`apply branches and policy to the running ${f.mountpoint} (setfattr, no unmount)`] : [...(wasMounted ? [`umount ${form.original}`] : []), `mount ${f.mountpoint}`]) : [])].join("\n")}
                </div>
              </>
            )}
            <ErrorBox error={err} />
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn ghost" onClick={() => setPreview(null)} disabled={busy}>
                Back
              </button>
              <button className="btn primary" disabled={busy || errors.length > 0 || !preview.pv.changed} onClick={save}>
                {busy && <span className="spinner" />} Save pool
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function PoolsPage() {
  const { data, error, loading, reload } = useFetch(() => api.get<StorageView>("/api/storage"), [], 30000);
  const poolHealth = useFetch(() => api.get<PoolHealth[]>("/api/pools/health"), [], 300000);
  const act = useAction(() => {
    reload();
    poolHealth.reload();
  });
  const health = useHealthMap();
  const [editor, setEditor] = useState<Form | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const newForm = useMemo<Form>(() => ({ mountpoint: "/mnt/pool", branches: [], modes: {}, policy: "mfs", minfree: "20G", cache: "off", moveonenospc: true, extra: "", mountNow: true }), []);
  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBox error={error} />;

  const mount = (p: Pool) =>
    act.start({ url: "/api/mounts/mount", body: { target: p.file }, title: `Mount pool ${p.file}`, operation: `Mount the mergerfs pool ${p.file}. FSView first checks that every branch disk is mounted.`, confirmLabel: "Mount", done: () => `${p.file} is mounted.` });
  const umount = (p: Pool) =>
    act.start({ url: "/api/mounts/umount", body: { target: p.file }, title: `Unmount pool ${p.file}`, operation: `Unmount the pool ${p.file}. The disks stay mounted and no data is touched.`, confirmLabel: "Unmount", done: () => `${p.file} is unmounted.` });
  const remove = async (p: Pool) => {
    try {
      const st = await api.get<FstabState>("/api/fstab");
      const doc = withEntry(st.doc, p.file, null);
      const pv = await api.post<FstabPreview>("/api/fstab/preview", { doc });
      act.start({
        url: "/api/fstab/apply",
        body: { doc, base_sha256: st.sha256 },
        title: `Remove pool ${p.file}`,
        operation: `Remove the pool from /etc/fstab (a backup is made). Files stay on the individual disks; only the combined view goes away.`,
        confirmLabel: "Remove pool",
        wide: true,
        extra: (
          <>
            <div className="small dim">Changes</div>
            <DiffView diff={pv.diff} context={false} />
            <div style={{ height: 10 }} />
          </>
        ),
        done: () => `Pool ${p.file} removed from fstab.`,
      });
    } catch (e) {
      act.setMsg({ kind: "error", text: explainError(e) });
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Pools</h1>
          <p className="sub small">mergerfs combines several disks into one folder. Each file lives whole on one disk, so a failed disk only loses its own files.</p>
        </div>
        <div className="row">
          <button
            className="btn"
            disabled={!data.writes_enabled}
            title="Makes the empty folders under your disk mounts read-only, so if a disk drops out nothing can be written onto the system disk in its place"
            onClick={() =>
              act.start({
                url: "/api/mounts/protect",
                body: {},
                title: "Protect mountpoints",
                operation:
                  "Make the empty directories underneath every data mount in fstab immutable (chattr +i). Disks still mount on top of them as usual. If a disk is missing or unmounted, pools and apps get an error instead of silently filling the system disk.",
                confirmLabel: "Protect",
              })
            }
          >
            Protect mountpoints
          </button>
          <button className="btn primary" disabled={!data.writes_enabled || data.mergerfs_installed === false} onClick={() => setEditor(newForm)}>
            <Plus size={16} /> New pool
          </button>
        </div>
      </div>
      {data.mergerfs_installed === false && (
        <div className="alert warn" style={{ flexDirection: "column" }}>
          mergerfs is not installed. On the host run:
          <div className="plan">apt install mergerfs</div>
        </div>
      )}
      {!data.writes_enabled && <div className="alert warn">Read-only: creating and changing pools needs writes_enabled = true in /etc/fsview/helper.conf.</div>}
      {saved && <div className="alert ok">{saved}</div>}
      {act.message}
      <ErrorBox error={error} />
      {data.pools.length === 0 && (
        <div className="card" style={{ textAlign: "center", padding: 40 }}>
          <Layers size={28} className="dim" />
          <h2 style={{ margin: "10px 0 4px" }}>No pools yet</h2>
          <div className="dim small">Create one to combine your data disks into a single folder.</div>
        </div>
      )}
      <div className="stack">
        {data.pools.map((p) => {
          const missing = p.branches.filter((b) => !b.mounted);
          const disks = p.branches.map((b) => data.entries.find((e) => e.file === b.mount)?.device?.disk).filter((x): x is string => !!x);
          const worst = disks.map((d) => health.get(d)?.status).find((s) => s === "crit") ?? disks.map((d) => health.get(d)?.status).find((s) => s === "warn");
          const unguarded = p.branches.filter((b) => b.mount && !b.required);
          return (
            <div key={p.file} className="card">
              <div className="between">
                <div className="row">
                  <Layers size={18} className="dim" />
                  <h2 style={{ margin: 0 }} className="mono">
                    {p.file}
                  </h2>
                  {p.mounted ? <span className="badge ok">mounted</span> : <span className="badge neutral">not mounted</span>}
                  {missing.length > 0 && <span className="badge crit">{missing.length} disk{missing.length > 1 ? "s" : ""} missing</span>}
                  {worst && (
                    <span className={`badge ${worst}`} title="Health of the disks in this pool">
                      {worst === "crit" ? "a disk is failing" : "a disk has warnings"}
                    </span>
                  )}
                  <span className="badge info">policy {p.policy}</span>
                </div>
                <div className="row">
                  {p.mounted ? (
                    <button className="btn sm" disabled={act.busy || !data.writes_enabled} onClick={() => umount(p)}>
                      Unmount
                    </button>
                  ) : (
                    <button className="btn sm primary" disabled={act.busy || !data.writes_enabled || missing.length > 0} title={missing.length ? "Mount the missing disks first" : ""} onClick={() => mount(p)}>
                      Mount
                    </button>
                  )}
                  <button className="btn sm" disabled={!data.writes_enabled} onClick={() => setEditor(formFromPool(p))}>
                    Edit
                  </button>
                  <button className="btn sm ghost" disabled={!data.writes_enabled || p.mounted} title={p.mounted ? "Unmount the pool first" : ""} onClick={() => remove(p)}>
                    Remove
                  </button>
                </div>
              </div>
              {p.usage && (
                <div style={{ maxWidth: 420, marginTop: 10 }}>
                  <UsageBar usage={p.usage} />
                </div>
              )}
              {unguarded.length > 0 && (
                <div className="alert warn" style={{ marginTop: 12 }}>
                  {unguarded.map((b) => b.mount).join(", ")} {unguarded.length > 1 ? "are" : "is"} not required by the pool, so it can mount without{" "}
                  {unguarded.length > 1 ? "them" : "it"} and write onto the system disk. Click Edit and save to fix this.
                </div>
              )}
              <div className="table-wrap" style={{ marginTop: 12, boxShadow: "none" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Branch</th>
                      <th>Disk</th>
                      <th>Status</th>
                      <th style={{ minWidth: 160 }}>Usage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.branches.map((b) => {
                      const owner = data.entries.find((e) => e.file === b.mount);
                      return (
                        <tr key={b.path}>
                          <td className="mono">
                            {b.path}
                            {b.mode && b.mode !== "RW" && <span className="badge neutral" style={{ marginLeft: 6 }}>{b.mode === "NC" ? "no new files" : b.mode === "RO" ? "read-only" : b.mode}</span>}
                          </td>
                          <td className="small">
                            {owner?.device ? (
                              <span className="row" style={{ gap: 6 }}>
                                <a href={`#/disk/${owner.device.disk}`}>
                                  {owner.device.name} {owner.device.label && <b>{owner.device.label}</b>}
                                </a>
                                <HealthBadge disk={owner.device.disk} health={health.get(owner.device.disk)} />
                              </span>
                            ) : (
                              <span className="dim">{b.mount ?? "–"}</span>
                            )}
                          </td>
                          <td>{b.mounted ? <span className="badge ok">ok</span> : <span className="badge crit">not mounted</span>}</td>
                          <td>{b.usage ? <UsageBar usage={b.usage} /> : <span className="dim">–</span>}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {p.mounted && poolHealth.data?.find((h) => h.mountpoint === p.file) && (
                <PoolHealthPanel
                  health={poolHealth.data.find((h) => h.mountpoint === p.file)!}
                  labels={Object.fromEntries(data.entries.filter((e) => e.device?.label).map((e) => [e.file, e.device!.label!]))}
                  writes={data.writes_enabled}
                  act={act}
                />
              )}
              {p.mounted && poolHealth.error && <div className="alert warn small" style={{ marginTop: 10 }}>Pool health: {poolHealth.error}</div>}
            </div>
          );
        })}
      </div>
      {editor && (
        <PoolEditor
          form={editor}
          data={data}
          onClose={() => setEditor(null)}
          onSaved={(m) => {
            setEditor(null);
            setSaved(m);
            reload();
          }}
        />
      )}
      {act.dialog}
    </>
  );
}
