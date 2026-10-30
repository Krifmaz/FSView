import { useState } from "react";
import { api } from "../api";
import { ErrorBox, Loading, ProtectedBadge, StatusBadge, Temp, UsageBar } from "../components";
import { useSelfTest } from "../selftest";
import type { DiskDetail, Node, SmartReport } from "../types";
import { fmtBytes, fmtHours, fmtTime, slotLabel, timeAgo, useFetch } from "../util";
import DiskActions from "./DiskActions";
import { LifeCard } from "../life";

function Tree({ nodes }: { nodes?: Node[] }) {
  if (!nodes?.length) return null;
  return (
    <ul className="tree">
      {nodes.map((n, i) => (
        <li key={n.kname + i}>
          <div className="row">
            <span className="mono">{n.name}</span>
            <span className="badge neutral">{n.type}</span>
            <span>{fmtBytes(n.size_bytes)}</span>
            {n.fstype && <span className="dim">{n.fstype}</span>}
            {n.label && <b>{n.label}</b>}
            {n.mountpoints?.length ? <span>→ {n.mountpoints.join(", ")}</span> : null}
          </div>
          {(n.uuid || n.parttypename) && (
            <div className="small dim mono">
              {n.parttypename && <span>{n.parttypename} </span>}
              {n.uuid && <span>UUID={n.uuid}</span>}
            </div>
          )}
          {n.usage && (
            <div style={{ maxWidth: 260 }}>
              <UsageBar usage={n.usage} />
            </div>
          )}
          <Tree nodes={n.children} />
        </li>
      ))}
    </ul>
  );
}

function Metric({ label, value, bad }: { label: string; value: React.ReactNode; bad?: boolean }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value" style={{ fontSize: 18, color: bad ? "var(--crit)" : undefined }}>
        {value}
      </div>
    </div>
  );
}

function SmartMetrics({ r }: { r: SmartReport }) {
  const n = (v?: number) => (v === undefined || v === null ? "–" : v.toLocaleString());
  return (
    <div className="cards">
      <Metric label="Temperature" value={<Temp c={r.temperature_c} trip={r.temp_trip_c} />} />
      <Metric label="Power-on" value={fmtHours(r.power_on_hours)} />
      {r.protocol === "ATA" && (
        <>
          <Metric label="Reallocated" value={n(r.reallocated)} bad={!!r.reallocated} />
          <Metric label="Pending" value={n(r.pending)} bad={!!r.pending} />
          <Metric label="Offline uncorrectable" value={n(r.offline_uncorrectable)} bad={!!r.offline_uncorrectable} />
          <Metric label="CRC errors" value={n(r.crc_errors)} bad={!!r.crc_errors} />
          <Metric label="Reported uncorrectable" value={n(r.reported_uncorrectable)} bad={!!r.reported_uncorrectable} />
          <Metric label="Error log entries" value={n(r.ata_error_count)} bad={!!r.ata_error_count} />
        </>
      )}
      {r.protocol === "SCSI" && (
        <>
          <Metric label="Grown defects" value={n(r.grown_defects)} bad={!!r.grown_defects} />
          <Metric label="Uncorrected errors" value={n(r.uncorrected_errors)} bad={!!r.uncorrected_errors} />
        </>
      )}
      {r.protocol === "NVMe" && (
        <>
          <Metric label="Endurance used" value={r.nvme_percent_used !== undefined ? `${r.nvme_percent_used}%` : "–"} />
          <Metric label="Spare" value={r.nvme_available_spare !== undefined ? `${r.nvme_available_spare}%` : "–"} />
          <Metric label="Media errors" value={n(r.nvme_media_errors)} bad={!!r.nvme_media_errors} />
          <Metric label="Data written" value={r.nvme_data_written_tb !== undefined ? `${r.nvme_data_written_tb.toFixed(1)} TB` : "–"} />
          <Metric label="Unsafe shutdowns" value={n(r.nvme_unsafe_shutdowns)} />
        </>
      )}
      <Metric label="Power cycles" value={n(r.power_cycles)} />
    </div>
  );
}

export default function DiskPage({ name }: { name: string }) {
  const { data, error, loading, reload, setData } = useFetch(() => api.get<DiskDetail>(`/api/disks/${encodeURIComponent(name)}`), [name]);
  const st = useSelfTest(() => reload());
  const busy = st.busy;
  const [msg, setMsg] = useState<{ kind: "info" | "error"; text: string } | null>(null);
  const [raw, setRaw] = useState<unknown>(null);
  const [refreshing, setRefreshing] = useState(false);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBox error={error ?? "not found"} />;
  const d = data.disk;
  const sm = data.smart;
  const r = sm?.report;

  const refresh = async (wake: boolean) => {
    setRefreshing(true);
    try {
      const res = await api.post<DiskDetail>(`/api/disks/${d.name}/smart/refresh${wake ? "?wake=1" : ""}`);
      setData((prev) => ({ ...(prev as DiskDetail), ...res }));
    } catch (e: any) {
      setMsg({ kind: "error", text: e.message });
    } finally {
      setRefreshing(false);
    }
  };

  const acknowledge = async (on: boolean) => {
    setRefreshing(true);
    try {
      const res = await api.post<DiskDetail>(`/api/disks/${d.name}/acknowledge`, { acknowledge: on });
      setData((prev) => ({ ...(prev as DiskDetail), ...res }));
    } catch (e: any) {
      setMsg({ kind: "error", text: e.message });
    } finally {
      setRefreshing(false);
    }
  };

  const setSmr = async (mode: "auto" | "on" | "off") => {
    try {
      await api.post(`/api/disks/${d.name}/smr`, { mode });
      reload();
    } catch (e: any) {
      setMsg({ kind: "error", text: e.message });
    }
  };

  const startTest = (test: "short" | "long" | "abort") => st.start([d], test, test === "short" ? r?.short_test_minutes : test === "long" ? r?.long_test_minutes : undefined);

  const loadRaw = async () => {
    const res = await api.get<DiskDetail>(`/api/disks/${d.name}?raw=1`);
    setRaw(res.raw ?? "no raw data");
  };

  return (
    <>
      <div className="between">
        <h1>
          <a href="#/overview" className="dim">
            Disks
          </a>{" "}
          / <span className="mono">{d.name}</span>
        </h1>
        <div className="row">
          <ProtectedBadge disk={d} />
          <StatusBadge status={sm?.assessment.status} />
        </div>
      </div>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      {st.message}
      {d.protected && (
        <div className="alert info">
          <b>Protected system disk.</b> Destructive operations are blocked by the helper: {(d.protected_reasons ?? []).join("; ")}
        </div>
      )}

      <div className="grid2">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Identity</h3>
          <dl className="kv">
            <dt>Model</dt>
            <dd>{d.display_model || "–"}{r?.family && <div className="small dim">{r.family}</div>}</dd>
            <dt>Serial</dt>
            <dd className="mono">{d.serial || r?.serial || "–"}</dd>
            <dt>Firmware</dt>
            <dd>{r?.firmware || d.revision || "–"}</dd>
            <dt>Size</dt>
            <dd>
              {fmtBytes(d.size_bytes)} <span className="dim">({fmtBytes(d.size_bytes, false)})</span>
            </dd>
            <dt>Type</dt>
            <dd>
              {d.rotational ? `HDD${r?.rotation_rate ? `, ${r.rotation_rate} rpm` : ""}` : "SSD"}
              {d.removable && ", removable"}
            </dd>
            <dt>WWN</dt>
            <dd className="mono">{d.wwn || "–"}</dd>
            <dt>Partition table</dt>
            <dd>{d.pttype?.toUpperCase() || "none"}</dd>
            {d.rotational && d.smr && (
              <>
                <dt title="Shingled drives stall under long write bursts; FSView gives them queue depth 1, a 180 s timeout and small writeback batches">SMR</dt>
                <dd className="row" style={{ gap: 6 }}>
                  <select
                    value={d.smr.overridden === undefined ? "auto" : d.smr.overridden ? "on" : "off"}
                    onChange={(e) => setSmr(e.target.value as "auto" | "on" | "off")}
                  >
                    <option value="auto">Auto ({d.smr.known ? "known SMR model" : "not a known SMR model"})</option>
                    <option value="on">SMR: protect</option>
                    <option value="off">Not SMR</option>
                  </select>
                  {d.smr.protected ? <span className="badge info">protected</span> : null}
                </dd>
              </>
            )}
          </dl>
        </div>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Location</h3>
          <dl className="kv">
            <dt>Transport</dt>
            <dd>{d.display_transport}</dd>
            <dt>Controller</dt>
            <dd>
              {d.topology.hba_name || "–"}
              <div className="small dim mono">{[d.topology.hba, d.topology.hba_driver, d.topology.scsi_host].filter(Boolean).join(" · ")}</div>
            </dd>
            {d.topology.expander && (
              <>
                <dt>Expander</dt>
                <dd className="mono">{d.topology.expander}</dd>
              </>
            )}
            <dt>Slot</dt>
            <dd>
              {slotLabel(d) || "–"}
              {d.topology.enclosure && (
                <div className="small dim">
                  enclosure {d.topology.enclosure.enclosure} · {d.topology.enclosure.status}
                  {d.topology.enclosure.fault && " · FAULT"}
                  {d.topology.enclosure.locate && " · locate LED on"}
                </div>
              )}
            </dd>
            <dt>SCSI address</dt>
            <dd className="mono">{d.hctl || "–"}</dd>
            {d.topology.sas_address && (
              <>
                <dt>SAS address</dt>
                <dd className="mono">{d.topology.sas_address}</dd>
              </>
            )}
            <dt>Port</dt>
            <dd className="mono">{d.topology.end_device || d.topology.port || "–"}</dd>
          </dl>
        </div>
      </div>

      <h2>Partitions &amp; filesystems</h2>
      <div className="card">
        {d.fstype && (
          <div className="row" style={{ marginBottom: 6 }}>
            <span>Whole-disk filesystem:</span>
            <b>{d.fstype}</b>
            {d.label && <b>{d.label}</b>}
            <span className="mono small dim">UUID={d.uuid}</span>
            <span>{d.mountpoints?.length ? `→ ${d.mountpoints.join(", ")}` : <span className="dim">not mounted</span>}</span>
          </div>
        )}
        {d.usage && <UsageBar usage={d.usage} />}
        {d.children?.length ? <Tree nodes={d.children} /> : !d.fstype && <span className="dim">No partitions or filesystem.</span>}
      </div>

      <DiskActions d={d} onChanged={reload} />

      <div className="between">
        <h2>SMART</h2>
        <div className="row">
          {sm && <span className="small dim">checked {timeAgo(sm.checked_at)}{sm.updated_at && `, data from ${timeAgo(sm.updated_at)}`}</span>}
          <button className="btn" disabled={refreshing} onClick={() => refresh(false)}>
            {refreshing ? <span className="spinner" /> : "↻"} Refresh
          </button>
        </div>
      </div>
      {sm?.error && <div className="alert error">{sm.error}</div>}
      {sm?.standby && (
        <div className="alert info between">
          <span>The disk is in standby; FSView does not wake sleeping disks for routine polling.</span>
          <button className="btn" onClick={() => refresh(true)}>
            Wake &amp; read
          </button>
        </div>
      )}
      {!r && !sm?.standby && <div className="dim">No SMART data yet.</div>}
      {!r && (
        <div className="card between" style={{ marginBottom: 12 }}>
          <span className="small dim">Self-tests run inside the drive and do not need SMART data first.</span>
          <div className="row">
            <button className="btn" disabled={busy} onClick={() => startTest("short")}>
              Short test
            </button>
            <button className="btn" disabled={busy} onClick={() => startTest("long")}>
              Long test
            </button>
          </div>
        </div>
      )}
      {r && (
        <>
          {(sm?.assessment.findings ?? []).map((f) => (
            <div key={f.text} className={`alert ${f.level === "crit" ? "error" : f.level === "ok" ? "info" : "warn"}`}>
              <div className="between" style={{ width: "100%" }}>
                <span>{f.text}</span>
                {f.ackable && (
                  <button className="btn sm" disabled={refreshing} onClick={() => acknowledge(true)} title="Hide the errors already logged; new errors warn again">
                    Acknowledge
                  </button>
                )}
                {f.text.endsWith("(acknowledged)") && (
                  <button className="btn ghost sm" disabled={refreshing} onClick={() => acknowledge(false)}>
                    Undo
                  </button>
                )}
              </div>
            </div>
          ))}
          {(r.messages ?? [])
            .filter((m) => m.startsWith("FSView:"))
            .map((m) => (
              <div key={m} className="alert warn">
                {m.replace(/^FSView:\s*/, "")}
              </div>
            ))}
          {(r.notes ?? []).map((n) => (
            <div key={n} className="alert info small">
              {n}
            </div>
          ))}
          <div className="small dim" style={{ marginBottom: 8 }}>
            {r.protocol} via <span className="mono">{r.devtype || "auto"}</span> · overall health:{" "}
            {r.passed === undefined ? "n/a" : r.passed ? <span style={{ color: "var(--ok)" }}>PASSED</span> : <b style={{ color: "var(--crit)" }}>FAILED</b>}
          </div>
          <SmartMetrics r={r} />
          <LifeCard life={sm?.life} rotational={d.rotational} />

          <div className="card" style={{ marginBottom: 12 }}>
            <div className="between">
              <h3 style={{ margin: 0 }}>Self-tests</h3>
              <div className="row">
                {r.self_test_running ? (
                  <>
                    <span className="badge info">
                      running{r.self_test_running.remaining_percent !== undefined && `, ${r.self_test_running.remaining_percent}% left`}
                    </span>
                    <button className="btn" disabled={busy} onClick={() => startTest("abort")}>
                      Abort
                    </button>
                  </>
                ) : (
                  <>
                    <button className="btn" disabled={busy} onClick={() => startTest("short")}>
                      Short test{r.short_test_minutes ? ` (~${r.short_test_minutes} min)` : ""}
                    </button>
                    <button className="btn" disabled={busy} onClick={() => startTest("long")}>
                      Long test{r.long_test_minutes ? ` (~${r.long_test_minutes} min)` : ""}
                    </button>
                  </>
                )}
              </div>
            </div>
            {(r.self_tests ?? []).length === 0 ? (
              <div className="dim small" style={{ marginTop: 8 }}>
                No self-tests logged.
              </div>
            ) : (
              <div style={{ overflowX: "auto", marginTop: 8 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Result</th>
                      <th>At</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.self_tests!.map((t, i) => (
                      <tr key={i}>
                        <td>{t.type}</td>
                        <td>
                          <span className={`badge ${t.outcome === "passed" ? "ok" : t.outcome === "failed" ? "crit" : t.outcome === "aborted" ? "warn" : "neutral"}`}>{t.status}</span>
                        </td>
                        <td>{t.lifetime_hours !== undefined ? `${t.lifetime_hours.toLocaleString()} h` : "–"}</td>
                        <td className="small">
                          {t.detail}
                          {t.lba !== undefined && <span className="mono"> LBA {t.lba}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {r.attributes && r.attributes.length > 0 && (
            <div className="table-wrap" style={{ marginBottom: 12 }}>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Attribute</th>
                    <th>Value</th>
                    <th>Worst</th>
                    <th>Thresh</th>
                    <th>Raw</th>
                  </tr>
                </thead>
                <tbody>
                  {r.attributes.map((a) => {
                    const bad = a.when_failed === "now" || ([5, 197, 198, 187].includes(a.id) && a.raw > 0);
                    return (
                      <tr key={a.id}>
                        <td>{a.id}</td>
                        <td>
                          {a.name} {a.prefailure && <span className="small dim">pre-fail</span>}
                        </td>
                        <td>{a.value}</td>
                        <td>{a.worst}</td>
                        <td>{a.thresh}</td>
                        <td className="mono" style={{ color: bad ? "var(--crit)" : undefined }}>
                          {a.raw_string}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {(r.messages ?? []).some((m) => !m.startsWith("FSView:")) && (
            <div className="small dim">smartctl: {r.messages!.filter((m) => !m.startsWith("FSView:")).join(" · ")}</div>
          )}
          <details style={{ marginTop: 10 }} onToggle={(e) => (e.target as HTMLDetailsElement).open && !raw && loadRaw()}>
            <summary>Raw smartctl JSON</summary>
            <pre className="raw">{raw ? JSON.stringify(raw, null, 2) : "Loading…"}</pre>
          </details>
          <div className="small dim" style={{ marginTop: 6 }}>
            Last reading {fmtTime(sm?.updated_at)}
          </div>
        </>
      )}

      {st.dialog}
    </>
  );
}
