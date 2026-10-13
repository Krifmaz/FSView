import { useState } from "react";
import { HardDrive, Layers, Pencil, Plus } from "lucide-react";
import { api } from "../api";
import { explainError, useAction } from "../actions";
import { ErrorBox, Loading, UsageBar } from "../components";
import type { FsEntry, FstabDevice, FstabDoc, FstabState, StorageEntry, StorageView, WriteResult } from "../types";
import { fmtBytes, useFetch } from "../util";

const MOUNTABLE = ["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "ntfs3"];
const MP_RE = /^\/(mnt|media|srv|data|storage|pool|tank)(\/[A-Za-z0-9._@+-]+)+$/;

function Status({ e }: { e: StorageEntry }) {
  if (e.mounted) return <span className="badge ok">mounted</span>;
  if (!e.present) return <span className="badge crit">disk missing</span>;
  return <span className="badge neutral">not mounted</span>;
}

function sum(xs: (StorageEntry | undefined)[]) {
  const t = { size_bytes: 0, used_bytes: 0, avail_bytes: 0 };
  for (const x of xs) {
    if (!x?.usage) continue;
    t.size_bytes += x.usage.size_bytes;
    t.used_bytes += x.usage.used_bytes;
    t.avail_bytes += x.usage.avail_bytes;
  }
  return t;
}

/** Moves a mountpoint in fstab, including pool branches that live on it. */
function moveMountpoint(doc: FstabDoc, from: string, to: string): FstabDoc {
  const sw = (p: string) => (p === from ? to : p.startsWith(from + "/") ? to + p.slice(from.length) : p);
  return {
    lines: doc.lines.map((l) => {
      if (l.kind !== "entry") return l;
      const e = l.entry;
      const pool = e.vfstype === "fuse.mergerfs";
      const next: FsEntry = {
        ...e,
        file: e.file === from ? to : e.file,
        spec: pool ? e.spec.split(":").map((b) => { const [p, mode] = b.split("="); return sw(p) + (mode ? `=${mode}` : ""); }).join(":") : e.spec,
        options: e.options
          .split(",")
          .map((o) => (o.startsWith("x-systemd.requires-mounts-for=") ? `x-systemd.requires-mounts-for=${sw(o.split("=")[1])}` : o))
          .join(","),
      };
      return JSON.stringify(next) === JSON.stringify(e) ? l : { kind: "entry" as const, raw: "", entry: next };
    }),
  };
}

function RenameDialog({ e, onClose, onStart }: { e: StorageEntry; onClose: () => void; onStart: (label: string, mountpoint: string) => void }) {
  const [label, setLabel] = useState(e.device?.label ?? "");
  const [mp, setMp] = useState(e.file);
  const canLabel = !!e.device && ["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat"].includes(e.device.fstype);
  const changed = (canLabel && label !== (e.device?.label ?? "")) || mp !== e.file;
  const mpOk = mp === e.file || MP_RE.test(mp);
  return (
    <div className="modal-bg" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="modal" onClick={(x) => x.stopPropagation()}>
        <h2>Rename {e.file}</h2>
        <div className="stack">
          {canLabel ? (
            <label className="field">
              <span>Disk label (the name the disk carries; shown in FSView, file managers and /dev/disk/by-label)</span>
              <input className="mono" value={label} maxLength={16} onChange={(x) => setLabel(x.target.value.replace(/[^A-Za-z0-9._-]/g, ""))} />
            </label>
          ) : (
            <div className="small dim">This filesystem's label cannot be changed here.</div>
          )}
          <label className="field">
            <span>Mountpoint (the folder it appears in)</span>
            <input className="mono" value={mp} onChange={(x) => setMp(x.target.value.trim())} />
          </label>
          {!mpOk && <div className="small" style={{ color: "var(--warn)" }}>Use a folder under /mnt, /media, /srv, /data, /storage, /pool or /tank.</div>}
          {mp !== e.file && (
            <div className="alert info small">
              Programs that use {e.file} (Plex libraries, Docker volumes, LXC bind mounts, SMB shares) must be pointed at {mp} afterwards. Pools that use this disk are updated automatically.
            </div>
          )}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="btn ghost" onClick={onClose}>
              Cancel
            </button>
            <button className="btn primary" disabled={!changed || !mpOk || (canLabel && !label)} onClick={() => onStart(label, mp)}>
              Continue
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AddMountDialog({ devices, onClose, onStart }: { devices: FstabDevice[]; onClose: () => void; onStart: (d: FstabDevice, mp: string, mountNow: boolean) => void }) {
  const [sel, setSel] = useState(devices[0]?.path ?? "");
  const d = devices.find((x) => x.path === sel);
  const [mp, setMp] = useState(d ? `/mnt/${d.label || d.name}` : "/mnt/data");
  const [now, setNow] = useState(true);
  return (
    <div className="modal-bg" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="modal" onClick={(x) => x.stopPropagation()}>
        <h2>Mount a disk</h2>
        {devices.length === 0 ? (
          <div className="stack">
            <div className="dim">Every filesystem on this host is already in fstab. To use a new or empty disk, format it from its disk page first.</div>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        ) : (
          <div className="stack">
            <label className="field">
              <span>Filesystem</span>
              <select
                value={sel}
                onChange={(x) => {
                  setSel(x.target.value);
                  const n = devices.find((y) => y.path === x.target.value);
                  if (n) setMp(`/mnt/${(n.label || n.name).replace(/[^A-Za-z0-9._@+-]/g, "_")}`);
                }}
              >
                {devices.map((x) => (
                  <option key={x.path} value={x.path}>
                    {x.name} · {x.fstype} · {x.label || "no label"} · {fmtBytes(x.size_bytes)}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Mountpoint</span>
              <input className="mono" value={mp} onChange={(x) => setMp(x.target.value.trim())} />
            </label>
            {!MP_RE.test(mp) && <div className="small" style={{ color: "var(--warn)" }}>Use a folder under /mnt, /media, /srv, /data, /storage, /pool or /tank.</div>}
            <label className="check">
              <input type="checkbox" checked={now} onChange={(x) => setNow(x.target.checked)} />
              Mount it now
            </label>
            <div className="small dim">
              FSView adds it to <span className="mono">/etc/fstab</span> by UUID with <span className="mono">nofail</span> (and a 5-minute wait for spinning or shelf disks), so it comes back after every reboot and a missing disk never
              blocks boot.
            </div>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn ghost" onClick={onClose}>
                Cancel
              </button>
              <button className="btn primary" disabled={!d || !MP_RE.test(mp)} onClick={() => d && onStart(d, mp, now)}>
                Continue
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function MountsPage() {
  const { data, error, loading, reload } = useFetch(() => api.get<StorageView>("/api/storage"), [], 30000);
  const act = useAction(reload);
  const [rename, setRename] = useState<StorageEntry | null>(null);
  const [adding, setAdding] = useState(false);
  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBox error={error} />;

  const mount = (e: StorageEntry) =>
    act.start({
      url: "/api/mounts/mount",
      body: { target: e.file },
      title: `Mount ${e.file}`,
      operation: `Mount ${e.spec} (${e.vfstype}) at ${e.file} using its fstab entry.`,
      confirmLabel: "Mount",
      done: () => `${e.file} is mounted.`,
    });
  const umount = (e: { file: string; source?: string | null }) =>
    act.start({
      url: "/api/mounts/umount",
      body: { target: e.file },
      title: `Unmount ${e.file}`,
      operation: `Unmount ${e.file}${e.source ? ` (${e.source})` : ""}. Programs using it must be stopped first; FSView checks this before running.`,
      confirmLabel: "Unmount",
      done: () => `${e.file} is unmounted.`,
    });

  const startRename = async (e: StorageEntry, label: string, mp: string) => {
    setRename(null);
    const relabel = !!e.device && label !== (e.device.label ?? "");
    const label_req = () =>
      api.post<WriteResult>(`/api/disks/${e.device!.disk}/label`, { device: e.device!.name, label, confirmed: true });
    try {
      if (mp === e.file) {
        act.start({
          url: `/api/disks/${e.device!.disk}/label`,
          body: { device: e.device!.name, label },
          title: `Rename disk ${e.device!.name}`,
          operation: `Change the label of ${e.device!.name} from "${e.device!.label || "(none)"}" to "${label}". Data is not touched.`,
          confirmLabel: "Rename",
          done: () => `${e.device!.name} is now labelled ${label}.`,
        });
        return;
      }
      if (e.mounted) {
        // Fails early (busy, used by a mounted pool) before fstab changes.
        await api.post<WriteResult>("/api/mounts/umount", { target: e.file, dry_run: true });
      }
      const st = await api.get<FstabState>("/api/fstab");
      const doc = moveMountpoint(st.doc, e.file, mp);
      act.start({
        url: "/api/fstab/apply",
        body: { doc, base_sha256: st.sha256 },
        title: `Move ${e.file} to ${mp}`,
        operation:
          `Change the mountpoint in /etc/fstab (backup made)${relabel ? ` and rename the disk to "${label}"` : ""}.` +
          (e.mounted ? ` Then unmount ${e.file} and mount it at ${mp}.` : ""),
        confirmLabel: "Rename",
        morePlan: [
          ...(relabel ? [`relabel ${e.device!.name} as ${label}`] : []),
          ...(e.mounted ? [`umount ${e.file}`, `mount ${mp}`] : []),
        ],
        done: () => `${e.file} is now ${mp}.`,
        then: async () => {
          const notes: string[] = [];
          if (relabel) {
            await label_req();
            notes.push(`Label is now ${label}.`);
          }
          if (e.mounted) {
            await api.post<WriteResult>("/api/mounts/umount", { target: e.file, confirmed: true });
            await api.post<WriteResult>("/api/mounts/mount", { target: mp, confirmed: true });
            notes.push(`Mounted at ${mp}.`);
          }
          return notes.join(" ");
        },
      });
    } catch (x) {
      act.setMsg({ kind: "error", text: explainError(x) });
    }
  };

  const startAdd = async (d: FstabDevice, mp: string, now: boolean) => {
    setAdding(false);
    try {
      const st = await api.get<FstabState>("/api/fstab");
      const slow = d.rotational || d.shelf;
      const entry: FsEntry = {
        spec: d.uuid ? `UUID=${d.uuid}` : d.path,
        file: mp,
        vfstype: d.fstype === "ntfs" ? "ntfs3" : d.fstype,
        options: slow ? "defaults,nofail,x-systemd.device-timeout=5min" : "defaults,nofail",
        freq: 0,
        passno: ["ext2", "ext3", "ext4", "xfs"].includes(d.fstype) ? 2 : 0,
      };
      const doc = { lines: [...st.doc.lines, { kind: "entry" as const, raw: "", entry }] };
      act.start({
        url: "/api/fstab/apply",
        body: { doc, base_sha256: st.sha256 },
        title: `Mount ${d.name} at ${mp}`,
        operation: `Add ${d.name} (${d.fstype}${d.label ? `, ${d.label}` : ""}) to /etc/fstab at ${mp}${now ? " and mount it" : ""}. A backup of fstab is made first.`,
        confirmLabel: now ? "Add and mount" : "Add to fstab",
        morePlan: now ? [`mount ${mp}`] : [],
        done: () => `${d.name} added to fstab at ${mp}.`,
        then: now
          ? async () => {
              await api.post<WriteResult>("/api/mounts/mount", { target: mp, confirmed: true });
              return "Mounted.";
            }
          : undefined,
      });
    } catch (x) {
      act.setMsg({ kind: "error", text: explainError(x) });
    }
  };

  const entries = data.entries;
  const disks = entries.filter((e) => !e.pool && !e.system);
  const dataTotal = sum(disks.filter((e) => e.mounted));
  const poolTotal = sum(entries.filter((e) => e.pool && e.mounted));
  const used = new Set(entries.map((e) => e.spec.toLowerCase()));
  const unmountedDevices = data.devices.filter(
    (d) => !d.protected && MOUNTABLE.includes(d.fstype) && !(d.mountpoints ?? []).length && !used.has(`uuid=${(d.uuid ?? "").toLowerCase()}`) && !used.has(`label=${(d.label ?? "").toLowerCase()}`) && !used.has(d.path.toLowerCase()),
  );

  const actions = (e: StorageEntry) => (
    <div className="row" style={{ justifyContent: "flex-end", gap: 6, flexWrap: "nowrap" }}>
      {e.system ? (
        <span className="small dim">system</span>
      ) : (
        <>
          {e.mounted ? (
            <button className="btn sm" disabled={act.busy || !data.writes_enabled} onClick={() => umount(e)}>
              Unmount
            </button>
          ) : (
            <button className="btn sm primary" disabled={act.busy || !data.writes_enabled || !e.present} onClick={() => mount(e)}>
              Mount
            </button>
          )}
          {e.pool ? (
            <a className="btn sm ghost" href="#/pools">
              <Pencil size={14} /> Edit
            </a>
          ) : (
            <button className="btn sm ghost" disabled={act.busy || !data.writes_enabled} onClick={() => setRename(e)}>
              <Pencil size={14} /> Rename
            </button>
          )}
        </>
      )}
    </div>
  );
  const device = (e: StorageEntry) =>
    e.device ? (
      <a href={`#/disk/${e.device.disk}`}>
        <span className="mono">{e.device.name}</span>
        {e.device.label && <b> {e.device.label}</b>}
        <span className="dim"> · {fmtBytes(e.device.size_bytes)}</span>
      </a>
    ) : e.pool ? (
      <a href="#/pools">mergerfs pool</a>
    ) : (
      <span className="mono dim">{e.spec}</span>
    );

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Mounts</h1>
          <p className="sub small">
            Every filesystem in <span className="mono">/etc/fstab</span> and whether it is mounted right now. Raw entries are on the <a href="#/fstab">fstab</a> page; pools on <a href="#/pools">Pools</a>.
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => reload()}>
            ↻ Refresh
          </button>
          <button className="btn primary" disabled={!data.writes_enabled} onClick={() => setAdding(true)}>
            <Plus size={16} /> Mount a disk
          </button>
        </div>
      </div>
      {!data.writes_enabled && <div className="alert warn">Read-only: mounting and renaming need writes_enabled = true in /etc/fsview/helper.conf.</div>}
      <ErrorBox error={error} />
      {act.message}

      <div className="cards">
        <div className="card stat">
          <div className="label">
            <HardDrive size={14} /> Data disks ({disks.filter((e) => e.mounted).length} mounted)
          </div>
          <div className="value">{fmtBytes(dataTotal.size_bytes)}</div>
          <div className="small dim">
            {fmtBytes(dataTotal.used_bytes)} used · {fmtBytes(dataTotal.avail_bytes)} free
          </div>
        </div>
        {poolTotal.size_bytes > 0 && (
          <div className="card stat">
            <div className="label">
              <Layers size={14} /> Pools
            </div>
            <div className="value">{fmtBytes(poolTotal.size_bytes)}</div>
            <div className="small dim">
              {fmtBytes(poolTotal.used_bytes)} used · {fmtBytes(poolTotal.avail_bytes)} free
            </div>
          </div>
        )}
      </div>

      <div className="table-wrap disktable">
        <table>
          <thead>
            <tr>
              <th>Mountpoint</th>
              <th>Disk</th>
              <th>Type</th>
              <th>Status</th>
              <th style={{ minWidth: 220 }}>Space</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.line}>
                <td>
                  <div className="row" style={{ gap: 8 }}>
                    {e.pool ? <Layers size={16} className="dim" /> : <HardDrive size={16} className="dim" />}
                    <b className="mono">{e.file}</b>
                  </div>
                  {!e.nofail && !e.system && <div className="small" style={{ color: "var(--warn)" }}>no nofail: boot stops if this is missing</div>}
                </td>
                <td className="small">{device(e)}</td>
                <td className="small mono">{e.vfstype}</td>
                <td>
                  <Status e={e} />
                </td>
                <td>{e.usage ? <UsageBar usage={e.usage} /> : <span className="dim">–</span>}</td>
                <td>{actions(e)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="diskcards">
        {entries.map((e) => (
          <div key={e.line} className="card">
            <div className="between">
              <div className="row" style={{ gap: 8 }}>
                {e.pool ? <Layers size={16} className="dim" /> : <HardDrive size={16} className="dim" />}
                <b className="mono">{e.file}</b>
              </div>
              <Status e={e} />
            </div>
            <div className="small" style={{ margin: "6px 0" }}>
              {device(e)} <span className="dim mono">· {e.vfstype}</span>
            </div>
            {e.usage && <UsageBar usage={e.usage} />}
            <div style={{ marginTop: 10 }}>{actions(e)}</div>
          </div>
        ))}
      </div>

      {data.other_mounts.length > 0 && (
        <>
          <h2>Mounted but not in fstab</h2>
          <p className="small dim">These were mounted by hand or by another tool and will not come back after a reboot.</p>
          <div className="stack">
            {data.other_mounts.map((m) => (
              <div key={m.target} className="card between">
                <div>
                  <b className="mono">{m.target}</b>
                  <div className="small dim mono">
                    {m.source} · {m.fstype}
                  </div>
                </div>
                <div style={{ minWidth: 200 }}>{m.usage ? <UsageBar usage={m.usage} /> : null}</div>
                <button className="btn sm" disabled={act.busy || !data.writes_enabled} onClick={() => umount({ file: m.target, source: m.source })}>
                  Unmount
                </button>
              </div>
            ))}
          </div>
        </>
      )}
      {rename && <RenameDialog e={rename} onClose={() => setRename(null)} onStart={(l, m) => startRename(rename, l, m)} />}
      {adding && <AddMountDialog devices={unmountedDevices} onClose={() => setAdding(false)} onStart={startAdd} />}
      {act.dialog}
    </>
  );
}
