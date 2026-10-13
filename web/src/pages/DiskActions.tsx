import { useState } from "react";
import { Eraser, Lightbulb, LightbulbOff, Stethoscope, Wrench } from "lucide-react";
import { api } from "../api";
import { useAction, explainError } from "../actions";
import type { Disk, FstabState, StorageView, WriteResult } from "../types";
import { fmtBytes, useFetch } from "../util";

const MEMBER = ["linux_raid_member", "LVM2_member", "zfs_member", "crypto_LUKS", "swap"];
const FS_TYPES: [string, string][] = [
  ["ext4", "ext4 (recommended for data disks and mergerfs)"],
  ["xfs", "XFS (large files, label max 12 characters)"],
  ["btrfs", "Btrfs (checksums, snapshots)"],
  ["exfat", "exFAT (move between Windows/Mac/Linux)"],
  ["vfat", "FAT32 (small USB sticks, label max 11 characters)"],
];

interface Fs {
  name: string;
  path: string;
  fstype: string;
  label: string;
  uuid: string;
  size: number;
  mounted: string[];
}

function filesystems(d: Disk): Fs[] {
  const out: Fs[] = [];
  if (d.fstype) out.push({ name: d.name, path: d.path, fstype: d.fstype, label: d.label ?? "", uuid: d.uuid ?? "", size: d.size_bytes, mounted: d.mountpoints ?? [] });
  const rec = (ns: Disk["children"]) =>
    (ns ?? []).forEach((n) => {
      if (n.type === "part") {
        out.push({ name: n.name, path: n.path, fstype: n.fstype ?? "", label: n.label ?? "", uuid: n.uuid ?? "", size: n.size_bytes, mounted: n.mountpoints ?? [] });
      }
      rec(n.children);
    });
  rec(d.children);
  return out;
}

function firstPartition(disk: string) {
  return /\d$/.test(disk) ? `${disk}p1` : `${disk}1`;
}

interface FormatForm {
  device: string;
  whole: boolean;
  fstype: string;
  label: string;
  partition: boolean;
  addFstab: boolean;
  mountpoint: string;
}

export default function DiskActions({ d, onChanged }: { d: Disk; onChanged: () => void }) {
  const storage = useFetch(() => api.get<StorageView>("/api/storage"), [d.name]);
  const act = useAction(() => {
    onChanged();
    storage.reload();
  });
  const [fmt, setFmt] = useState<FormatForm | null>(null);
  const fss = filesystems(d);
  const writes = storage.data?.writes_enabled ?? true;
  const tools = storage.data?.tools ?? {};
  const entryFor = (f: Fs) =>
    storage.data?.entries.find(
      (e) => (f.uuid && e.spec.toLowerCase() === `uuid=${f.uuid.toLowerCase()}`) || (f.label && e.spec === `LABEL=${f.label}`) || e.spec === f.path || (f.mounted.includes(e.file) && !e.pool),
    );

  const check = (f: Fs, repair: boolean) =>
    act.start({
      url: `/api/disks/${d.name}/check`,
      body: { device: f.name, repair },
      title: `${repair ? "Repair" : "Check"} ${f.fstype} on ${f.path}`,
      operation: repair
        ? `Repair the ${f.fstype} filesystem on ${f.path}${f.label ? ` (${f.label})` : ""}. Repairs change the filesystem; take a backup or image first if the data matters. A disk with failing sectors should be copied off, not repaired.`
        : `Read-only check of the ${f.fstype} filesystem on ${f.path}. Nothing is changed.`,
      disk: d,
      destructive: repair,
      confirmLabel: repair ? "Repair" : "Run check",
      showOutput: true,
      done: (r) => {
        const out = r.result?.output ?? "";
        const status = out.match(/\[(\S+) exit status (\d+)\]/);
        return repair ? "Repair finished." : status ? `Check finished: problems found (exit status ${status[2]}). Unmount and run Repair to fix them.` : "Check finished: no problems found.";
      },
    });

  const mount = (file: string) =>
    act.start({ url: "/api/mounts/mount", body: { target: file }, title: `Mount ${file}`, operation: `Mount ${file} using its fstab entry.`, confirmLabel: "Mount", done: () => `${file} is mounted.` });
  const umount = (file: string) =>
    act.start({ url: "/api/mounts/umount", body: { target: file }, title: `Unmount ${file}`, operation: `Unmount ${file}. Programs using it must be stopped first; FSView checks this before running.`, confirmLabel: "Unmount", done: () => `${file} is unmounted.` });
  const locate = (on: boolean) =>
    act.start({
      url: `/api/disks/${d.name}/locate`,
      body: { on },
      title: `Locate LED ${on ? "on" : "off"}`,
      operation: on ? `Blink the locate LED of the enclosure bay holding ${d.name} so you can find it.` : `Turn off the locate LED for ${d.name}.`,
      confirmLabel: on ? "Turn on" : "Turn off",
      done: () => `Locate LED ${on ? "on" : "off"}.`,
    });

  const startFormat = (f: FormatForm) => {
    const fsDev = f.whole && f.partition ? firstPartition(d.name) : f.device;
    const oldUuids = fss.filter((x) => (f.whole ? true : x.name === f.device)).map((x) => x.uuid).filter(Boolean);
    act.start({
      url: `/api/disks/${d.name}/format`,
      body: { device: f.device, fstype: f.fstype, label: f.label, partition: f.whole && f.partition },
      title: `Format ${f.whole ? "disk" : "partition"} ${f.device}`,
      operation:
        `ERASES EVERYTHING on /dev/${f.device}${f.whole ? " (the whole disk)" : ""} and creates an empty ${f.fstype} filesystem labelled "${f.label}"` +
        (f.whole && f.partition ? " on a new GPT partition table with one partition" : "") +
        "." +
        (f.addFstab ? ` Then adds it to /etc/fstab at ${f.mountpoint} (with backup) and mounts it.` : ""),
      disk: d,
      destructive: true,
      confirmLabel: "Erase and format",
      done: () => `/dev/${fsDev} formatted as ${f.fstype} (${f.label}).`,
      then: f.addFstab
        ? async () => {
            const st = await api.get<FstabState>("/api/fstab");
            const dev = st.devices.find((x) => x.path === `/dev/${fsDev}` || x.name === fsDev);
            const spec = dev?.uuid ? `UUID=${dev.uuid}` : `LABEL=${f.label}`;
            const slow = d.rotational || !!d.topology.expander || !!d.topology.enclosure;
            const entry = {
              spec,
              file: f.mountpoint,
              vfstype: f.fstype,
              options: slow ? "defaults,nofail,x-systemd.device-timeout=5min" : "defaults,nofail",
              freq: 0,
              passno: ["ext4", "xfs"].includes(f.fstype) ? 2 : 0,
            };
            // Replace entries of the old filesystem (same UUID) or the same mountpoint.
            const lines = st.doc.lines.filter(
              (l) => !(l.kind === "entry" && (l.entry.file === f.mountpoint || oldUuids.some((u) => l.entry.spec.toLowerCase() === `uuid=${u.toLowerCase()}`))),
            );
            lines.push({ kind: "entry", raw: "", entry });
            await api.post<WriteResult>("/api/fstab/apply", { doc: { lines }, base_sha256: st.sha256, confirmed: true });
            await api.post<WriteResult>("/api/mounts/mount", { target: f.mountpoint, confirmed: true });
            return `Added to fstab and mounted at ${f.mountpoint}.`;
          }
        : undefined,
    });
    setFmt(null);
  };

  const openFormat = (device: string, whole: boolean, label: string) =>
    setFmt({
      device,
      whole,
      fstype: "ext4",
      label: label || "data",
      partition: whole,
      addFstab: true,
      mountpoint: `/mnt/${label || "data"}`,
    });

  const anyMounted = fss.some((f) => f.mounted.length > 0);
  return (
    <>
      <div className="between">
        <h2>Actions</h2>
        {d.topology.enclosure && (
          <div className="row">
            <button className="btn sm" disabled={act.busy || !writes} onClick={() => locate(true)}>
              <Lightbulb size={15} /> Locate LED on
            </button>
            <button className="btn sm ghost" disabled={act.busy || !writes} onClick={() => locate(false)}>
              <LightbulbOff size={15} /> Off
            </button>
          </div>
        )}
      </div>
      {!writes && <div className="alert warn">Read-only: these actions need writes_enabled = true in /etc/fsview/helper.conf.</div>}
      {act.message}
      <div className="table-wrap">
        <table>
          <tbody>
            {fss.map((f) => {
              const e = entryFor(f);
              const member = MEMBER.includes(f.fstype);
              return (
                <tr key={f.name}>
                  <td>
                    <span className="mono">{f.name}</span> <span className="small dim">{fmtBytes(f.size)}</span>
                    <div className="small">
                      {f.fstype ? <b>{f.fstype}</b> : <span className="dim">no filesystem</span>} {f.label && <span>{f.label}</span>}
                    </div>
                  </td>
                  <td className="small">
                    {f.mounted.length ? (
                      <span className="badge ok">{f.mounted.join(", ")}</span>
                    ) : e ? (
                      <span className="dim">fstab: {e.file}</span>
                    ) : f.fstype && !member ? (
                      <a href="#/fstab">not in fstab</a>
                    ) : null}
                  </td>
                  <td>
                    <div className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                      {!d.protected && f.mounted.length > 0 && f.mounted[0] !== "[SWAP]" && (
                        <button className="btn sm" disabled={act.busy || !writes} onClick={() => umount(f.mounted[0])}>
                          Unmount
                        </button>
                      )}
                      {!f.mounted.length && e && (
                        <button className="btn sm primary" disabled={act.busy || !writes} onClick={() => mount(e.file)}>
                          Mount
                        </button>
                      )}
                      {f.fstype && !member && (
                        <>
                          <button className="btn sm" disabled={act.busy || !writes || f.mounted.length > 0} title={f.mounted.length ? "Unmount first" : "Read-only check"} onClick={() => check(f, false)}>
                            <Stethoscope size={14} /> Check
                          </button>
                          <button className="btn sm" disabled={act.busy || !writes || f.mounted.length > 0 || d.protected || f.fstype === "btrfs"} title={f.mounted.length ? "Unmount first" : ""} onClick={() => check(f, true)}>
                            <Wrench size={14} /> Repair
                          </button>
                        </>
                      )}
                      {f.name !== d.name && (
                        <button className="btn sm" disabled={act.busy || !writes || d.protected || f.mounted.length > 0 || member} onClick={() => openFormat(f.name, false, f.label)}>
                          <Eraser size={14} /> Format
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            <tr>
              <td colSpan={2}>
                <b>Whole disk</b>
                <div className="small dim">
                  {d.protected ? `Protected: ${(d.protected_reasons ?? []).join("; ")}` : "Erase the disk and create one filesystem, optionally with a fresh GPT partition table."}
                </div>
              </td>
              <td>
                <div className="row" style={{ justifyContent: "flex-end" }}>
                  <button className="btn sm danger" disabled={act.busy || !writes || d.protected || anyMounted} title={anyMounted ? "Unmount everything on this disk first" : ""} onClick={() => openFormat(d.name, true, d.label || fss[0]?.label || "")}>
                    <Eraser size={14} /> Erase &amp; format disk
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {fmt && (
        <div className="modal-bg" role="dialog" aria-modal="true" onClick={() => setFmt(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Format {fmt.whole ? `disk ${fmt.device}` : `partition ${fmt.device}`}</h2>
            <div className="stack">
              <label className="field">
                <span>Filesystem</span>
                <select value={fmt.fstype} onChange={(e) => setFmt({ ...fmt, fstype: e.target.value })}>
                  {FS_TYPES.map(([k, l]) => (
                    <option key={k} value={k} disabled={tools[`mkfs.${k}`] === false}>
                      {l}
                      {tools[`mkfs.${k}`] === false ? " (not installed)" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Label</span>
                <input
                  className="mono"
                  value={fmt.label}
                  maxLength={16}
                  onChange={(e) => {
                    const label = e.target.value.replace(/[^A-Za-z0-9._-]/g, "");
                    setFmt({ ...fmt, label, mountpoint: fmt.mountpoint === `/mnt/${fmt.label}` ? `/mnt/${label}` : fmt.mountpoint });
                  }}
                />
              </label>
              {fmt.whole && (
                <label className="check">
                  <input type="checkbox" checked={fmt.partition} onChange={(e) => setFmt({ ...fmt, partition: e.target.checked })} />
                  New GPT partition table with one partition (recommended)
                </label>
              )}
              <label className="check">
                <input type="checkbox" checked={fmt.addFstab} onChange={(e) => setFmt({ ...fmt, addFstab: e.target.checked })} />
                Add to fstab and mount it
              </label>
              {fmt.addFstab && (
                <label className="field">
                  <span>Mountpoint</span>
                  <input className="mono" value={fmt.mountpoint} onChange={(e) => setFmt({ ...fmt, mountpoint: e.target.value })} />
                </label>
              )}
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button className="btn ghost" onClick={() => setFmt(null)}>
                  Cancel
                </button>
                <button
                  className="btn danger"
                  disabled={!fmt.label || (fmt.addFstab && !/^\/(mnt|media|srv|data|storage|pool|tank)\/[A-Za-z0-9._@+-]+/.test(fmt.mountpoint))}
                  onClick={() => {
                    try {
                      startFormat(fmt);
                    } catch (e) {
                      act.setMsg({ kind: "error", text: explainError(e) });
                    }
                  }}
                >
                  Continue
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      {act.dialog}
    </>
  );
}
