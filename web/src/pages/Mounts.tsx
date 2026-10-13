import { HardDrive, Layers } from "lucide-react";
import { api } from "../api";
import { useAction } from "../actions";
import { ErrorBox, Loading, UsageBar } from "../components";
import type { StorageEntry, StorageView } from "../types";
import { useFetch } from "../util";

function Status({ e }: { e: StorageEntry }) {
  if (e.mounted) return <span className="badge ok">mounted</span>;
  if (!e.present) return <span className="badge crit">disk missing</span>;
  return <span className="badge neutral">not mounted</span>;
}

export default function MountsPage() {
  const { data, error, loading, reload } = useFetch(() => api.get<StorageView>("/api/storage"), [], 30000);
  const act = useAction(reload);
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

  const entries = data.entries;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Mounts</h1>
          <p className="sub small">
            Every filesystem in <span className="mono">/etc/fstab</span> and whether it is mounted right now. Add or change entries on the{" "}
            <a href="#/fstab">fstab</a> page; pools are on <a href="#/pools">Pools</a>.
          </p>
        </div>
        <button className="btn" onClick={() => reload()}>
          ↻ Refresh
        </button>
      </div>
      {!data.writes_enabled && <div className="alert warn">Read-only: mounting and unmounting need writes_enabled = true in /etc/fsview/helper.conf.</div>}
      <ErrorBox error={error} />
      {act.message}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Mountpoint</th>
              <th>Device</th>
              <th>Type</th>
              <th>Status</th>
              <th style={{ minWidth: 160 }}>Usage</th>
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
                <td className="small">
                  {e.device ? (
                    <a href={`#/disk/${e.device.disk}`}>
                      <span className="mono">{e.device.name}</span>
                      {e.device.label && <b> {e.device.label}</b>}
                    </a>
                  ) : e.pool ? (
                    <a href="#/pools">mergerfs pool</a>
                  ) : (
                    <span className="mono dim">{e.spec}</span>
                  )}
                </td>
                <td className="small mono">{e.vfstype}</td>
                <td>
                  <Status e={e} />
                </td>
                <td>{e.usage ? <UsageBar usage={e.usage} /> : <span className="dim">–</span>}</td>
                <td>
                  <div className="row" style={{ justifyContent: "flex-end" }}>
                    {e.system ? (
                      <span className="small dim">system</span>
                    ) : e.mounted ? (
                      <button className="btn sm" disabled={act.busy || !data.writes_enabled} onClick={() => umount(e)}>
                        Unmount
                      </button>
                    ) : (
                      <button className="btn sm primary" disabled={act.busy || !data.writes_enabled || !e.present} onClick={() => mount(e)}>
                        Mount
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.other_mounts.length > 0 && (
        <>
          <h2>Mounted but not in fstab</h2>
          <p className="small dim">These were mounted by hand or by another tool and will not come back after a reboot.</p>
          <div className="table-wrap">
            <table>
              <tbody>
                {data.other_mounts.map((m) => (
                  <tr key={m.target}>
                    <td className="mono">
                      <b>{m.target}</b>
                    </td>
                    <td className="small mono dim">{m.source}</td>
                    <td className="small mono">{m.fstype}</td>
                    <td style={{ minWidth: 160 }}>{m.usage ? <UsageBar usage={m.usage} /> : null}</td>
                    <td>
                      <div className="row" style={{ justifyContent: "flex-end" }}>
                        <button className="btn sm" disabled={act.busy || !data.writes_enabled} onClick={() => umount({ file: m.target, source: m.source })}>
                          Unmount
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {act.dialog}
    </>
  );
}
