import { api } from "../api";
import { ErrorBox, Loading } from "../components";
import { useState } from "react";
import type { BootReport, HiddenView } from "../types";
import { fmtBytes, fmtSec, fmtTime, timeAgo, useFetch } from "../util";

function HiddenData() {
  const { data, error, setData } = useFetch(() => api.get<HiddenView>("/api/hidden"), []);
  const [busy, setBusy] = useState(false);
  const scan = async (all: boolean) => {
    setBusy(true);
    try {
      setData(await api.post<HiddenView>(`/api/hidden/scan${all ? "?all=1" : ""}`));
    } finally {
      setBusy(false);
    }
  };
  const found = (data?.results ?? []).filter((r) => r.files > 0 || r.error);
  return (
    <>
      <div className="between">
        <h2>Hidden data under mountpoints</h2>
        <div className="row">
          <button className="btn" disabled={busy} onClick={() => scan(false)}>
            {busy && <span className="spinner" />} Scan root disk
          </button>
          <button className="btn" disabled={busy} onClick={() => scan(true)} title="Also scans data disks; may wake sleeping disks">
            Scan all disks
          </button>
        </div>
      </div>
      <p className="dim small">
        Files written into a mountpoint folder while its disk was not mounted stay on the disk underneath and become invisible once the mount
        returns. The root disk is checked automatically every 6 hours; scanning all disks may wake sleeping disks.
        {data?.checked_at && ` Last scan ${timeAgo(data.checked_at)} (${data.all ? "all disks" : "root disk"}).`}
      </p>
      {(error || data?.error) && <div className="alert error">{error ?? data?.error}</div>}
      {data?.checked_at && found.length === 0 && <div className="alert info">Nothing hidden under any mountpoint.</div>}
      {found.map((h) => (
        <div key={h.mountpoint + h.parent} className="card" style={{ marginBottom: 8 }}>
          {h.error ? (
            <div style={{ color: "var(--crit)" }}>
              {h.parent}: {h.error}
            </div>
          ) : (
            <>
              <div className="row">
                <span className="badge crit">{fmtBytes(h.bytes)}</span>
                <b className="mono">{h.mountpoint}</b>
                <span className="dim small">
                  {h.files.toLocaleString()} files on {h.parent} ({h.parent_source}){h.truncated && ", scan stopped early: at least this much"}
                </span>
              </div>
              <div className="small" style={{ marginTop: 4 }}>
                {(h.samples ?? []).map((x) => (
                  <span key={x.name} className="mono" style={{ marginRight: 12 }}>
                    {x.name} {fmtBytes(x.bytes)}
                  </span>
                ))}
              </div>
            </>
          )}
        </div>
      ))}
    </>
  );
}

export default function BootPage() {
  const { data, error, loading, reload, setData } = useFetch(() => api.get<BootReport>("/api/bootcheck"), []);
  if (loading && !data) return <Loading />;
  const refresh = () => api.get<BootReport>("/api/bootcheck?fresh=1").then(setData).catch(reload);
  const s = data?.summary;
  return (
    <>
      <div className="between">
        <h1>Boot check</h1>
        <button className="btn" onClick={refresh}>
          ↻ Re-check
        </button>
      </div>
      <ErrorBox error={error} />
      {data && (
        <>
          <p className="dim small">
            Current boot <span className="mono">{data.boot_id.slice(0, 12)}</span> · userspace started {fmtSec(data.userspace_start_sec)} · boot finished{" "}
            {fmtSec(data.boot_finished_sec)} · checked {fmtTime(data.collected_at)}
          </p>
          <div className="cards">
            <div className="card stat">
              <div className="label">Mounted OK</div>
              <div className="value">{s?.ok}</div>
            </div>
            <div className="card stat">
              <div className="label">Failed</div>
              <div className="value" style={{ color: s?.failed ? "var(--crit)" : undefined }}>{s?.failed}</div>
            </div>
            <div className="card stat">
              <div className="label">Late</div>
              <div className="value" style={{ color: s?.late ? "var(--warn)" : undefined }}>{s?.late}</div>
            </div>
            <div className="card stat">
              <div className="label">Skipped</div>
              <div className="value">{s?.skipped}</div>
            </div>
          </div>
          {(data.fstab_errors ?? []).map((e) => (
            <div key={e} className="alert error">
              /etc/fstab: {e}
            </div>
          ))}

          {data.late_devices && data.late_devices.length > 0 && (
            <>
              <h2>Disks that appeared late</h2>
              <div className="table-wrap" style={{ marginBottom: 16 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Disk</th>
                      <th>Appeared</th>
                      <th>Used by</th>
                      <th>Kernel message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.late_devices.map((l) => (
                      <tr key={l.device}>
                        <td>
                          <a className="mono" href={`#/disk/${l.device}`}>
                            {l.device}
                          </a>
                          {l.after_timeout && (
                            <div>
                              <span className="badge crit">after mount timeout</span>
                            </div>
                          )}
                        </td>
                        <td>{fmtSec(l.appeared_sec)}</td>
                        <td>{l.mountpoints?.join(", ") || <span className="dim">not in fstab</span>}</td>
                        <td className="mono small">{l.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <HiddenData />

          <h2>fstab entries</h2>
          <div className="stack">
            {data.entries.map((e) => (
              <div key={e.line} className="card">
                <div className="between">
                  <div className="row">
                    <span className={`badge ${e.status === "ok" ? "ok" : e.status}`}>{e.status}</span>
                    <b className="mono">{e.mountpoint}</b>
                    <span className="dim">{e.fstype}</span>
                    {e.disk && (
                      <a className="mono small" href={`#/disk/${e.disk}`}>
                        {e.device && e.device !== e.disk ? `${e.device} on ${e.disk}` : e.disk}
                      </a>
                    )}
                  </div>
                  <span className="small dim">line {e.line}</span>
                </div>
                <div className="mono small dim" style={{ marginTop: 4, wordBreak: "break-all" }}>
                  {e.spec} · {e.options}
                </div>
                <div className="row small" style={{ marginTop: 4 }}>
                  {e.device_appeared_sec !== undefined && <span>device appeared {fmtSec(e.device_appeared_sec)}</span>}
                  {e.mounted_sec !== undefined && <span>mounted {fmtSec(e.mounted_sec)}</span>}
                  {e.status !== "skipped" && <span className="dim">device timeout {e.device_timeout_sec}s</span>}
                  {e.nofail && <span className="badge neutral">nofail</span>}
                </div>
                {(e.problems ?? []).map((p) => (
                  <div key={p} className="small" style={{ color: e.status === "failed" ? "var(--crit)" : "var(--warn)", marginTop: 3 }}>
                    • {p}
                  </div>
                ))}
                {(e.hints ?? []).map((h) => (
                  <div key={h} className="small dim" style={{ marginTop: 3 }}>
                    {h}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}
