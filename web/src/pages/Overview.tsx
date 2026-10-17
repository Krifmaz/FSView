import { api } from "../api";
import { ErrorBox, Loading, ProtectedBadge, StatusBadge, Temp, UsageBar } from "../components";
import type { BootReport, Disk, Enclosure, Overview } from "../types";
import { diskFilesystems, diskNames, fmtBytes, slotLabel, timeAgo, useFetch } from "../util";

function go(d: Disk) {
  window.location.hash = `#/disk/${d.name}`;
}

function Filesystems({ d }: { d: Disk }) {
  const fss = diskFilesystems(d);
  if (fss.length === 0) return <span className="dim">{d.pttype ? `${d.pttype.toUpperCase()}, no filesystem` : "empty"}</span>;
  return (
    <div className="stack" style={{ gap: 6 }}>
      {fss.map((f) => (
        <div key={f.name} className="row" style={{ alignItems: "flex-start" }}>
          <div style={{ minWidth: 150 }}>
            <span className="mono">{f.name}</span> <span className="dim">{f.fstype}</span>
            {f.label && <b> {f.label}</b>}
            <div className="small">
              {f.mounts.length ? f.mounts.join(", ") : <span className="dim">not mounted</span>}
            </div>
          </div>
          {f.usage && (
            <div style={{ width: 140 }}>
              <UsageBar usage={f.usage} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

const SHORT: Record<string, string> = {
  "Power supply": "PSU",
  Cooling: "Fan",
  "Temperature sensor": "Temp",
  "Voltage sensor": "Volt",
  "Current sensor": "Current",
  "Enclosure services controller electronics": "IOM",
  Enclosure: "Enclosure",
};

function encName(e: Enclosure) {
  return [e.vendor, e.model].filter(Boolean).join(" ") || `Enclosure ${e.id}`;
}

function EnclosureHealth({ e }: { e: Enclosure }) {
  const els = (e.elements ?? []).filter((x) => x.level !== "absent");
  if (!els.length) return null;
  const groups = new Map<string, typeof els>();
  for (const x of els) groups.set(x.type, [...(groups.get(x.type) ?? []), x]);
  return (
    <div className="stack" style={{ gap: 4, marginTop: 6 }}>
      {[...groups.entries()].map(([type, xs]) => (
        <div key={type} className="row small">
          <span className="dim" style={{ minWidth: 70 }}>
            {SHORT[type] ?? type}
          </span>
          {xs.map((x) => (
            <span
              key={x.index}
              className={`badge ${x.level === "ok" || x.level === "ignored" ? "neutral" : x.level}`}
              style={x.level === "ignored" ? { opacity: 0.55 } : undefined}
              title={`${type} ${x.index}: ${x.status}${x.detail ? ` (${x.detail})` : ""}${x.level === "ignored" ? " (marked as expected)" : ""}`}
            >
              {x.index}
              {x.level === "ignored"
                ? ": expected"
                : x.detail && !x.detail.includes(",") && !x.detail.includes(";") && x.level === "ok"
                  ? `: ${x.detail}`
                  : x.level !== "ok"
                    ? `: ${x.status}`
                    : ""}
            </span>
          ))}
        </div>
      ))}
    </div>
  );
}

export default function OverviewPage() {
  const { data, error, loading, reload } = useFetch(() => api.get<Overview>("/api/overview"), [], 30000);
  const boot = useFetch(() => api.get<BootReport>("/api/bootcheck"), []);
  if (loading && !data) return <Loading />;
  const s = data?.summary ?? {};
  const ignoreElement = async (key: string, ignore: boolean, refresh = true) => {
    await api.post("/api/enclosures/ignore", { key, ignore });
    if (refresh) await reload();
  };
  return (
    <>
      <div className="between">
        <h1>Overview {data && <span className="dim small">· {data.hostname}</span>}</h1>
        <div className="row">
          {data && <span className="small dim">updated {timeAgo(data.collected_at)}</span>}
          <button className="btn" onClick={() => api.get<Overview>("/api/overview?fresh=1").then(reload)}>
            ↻ Refresh
          </button>
        </div>
      </div>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="cards">
            <div className="card stat">
              <div className="label">Disks</div>
              <div className="value">{s.disks ?? 0}</div>
            </div>
            <a className="card stat" href="#/health" style={{ color: "inherit" }}>
              <div className="label">Critical</div>
              <div className="value" style={{ color: s.crit ? "var(--crit)" : undefined }}>{s.crit ?? 0}</div>
            </a>
            <a className="card stat" href="#/health" style={{ color: "inherit" }}>
              <div className="label">Warnings</div>
              <div className="value" style={{ color: s.warn ? "var(--warn)" : undefined }}>{s.warn ?? 0}</div>
            </a>
            <div className="card stat">
              <div className="label">Protected (system)</div>
              <div className="value">{s.protected ?? 0}</div>
            </div>
            <a className="card stat" href="#/events" style={{ color: "inherit" }}>
              <div className="label">Disk errors (24 h)</div>
              <div className="value" style={{ color: data.events_24h?.error ? "var(--crit)" : undefined }}>{data.events_24h?.error ?? 0}</div>
            </a>
          </div>
          {(data.enclosures ?? []).flatMap((e) =>
            (e.elements ?? [])
              .filter((x) => x.level === "crit" || x.level === "warn")
              .map((x) => (
                <div key={`${e.id}-${x.type}-${x.index}`} className={`alert ${x.level === "crit" ? "error" : "warn"} between`}>
                  <span>
                    <b>{encName(e)}</b>: {x.type} {x.index} — {x.status}
                    {x.detail && ` (${x.detail})`}
                  </span>
                  {x.key && (
                    <button
                      className="btn ghost small"
                      title="For example an empty PSU bay. It stays visible on the enclosure card and can be restored there."
                      onClick={() => ignoreElement(x.key!, true)}
                    >
                      Mark as expected
                    </button>
                  )}
                </div>
              )),
          )}
          {(() => {
            const ign = (data.enclosures ?? []).flatMap((e) => (e.elements ?? []).filter((x) => x.level === "ignored"));
            if (!ign.length) return null;
            return (
              <div className="small dim" style={{ marginBottom: 12 }}>
                {ign.length} enclosure {ign.length === 1 ? "alert is" : "alerts are"} marked as expected ({ign.map((x) => `${SHORT[x.type] ?? x.type} ${x.index}`).join(", ")}).{" "}
                <a
                  href="#/overview"
                  onClick={(ev) => {
                    ev.preventDefault();
                    Promise.all(ign.map((x) => ignoreElement(x.key!, false, false))).then(reload);
                  }}
                >
                  Show them again
                </a>
              </div>
            );
          })()}
          {(data.hidden?.results ?? [])
            .filter((h) => h.files > 0)
            .map((h) => (
              <div key={h.mountpoint} className="alert error">
                <a href="#/boot">
                  <b>Hidden data:</b> {fmtBytes(h.bytes)} in {h.files.toLocaleString()} files
                </a>{" "}
                is stored on {h.parent} underneath the <span className="mono">{h.mountpoint}</span> mount. It uses space but can't be seen while the mount is active.
              </div>
            ))}
          {boot.data && boot.data.summary.failed > 0 && (
            <div className="alert error">
              <a href="#/boot">
                <b>Boot check:</b> {boot.data.summary.failed} fstab {boot.data.summary.failed === 1 ? "entry" : "entries"} failed
              </a>{" "}
              — {boot.data.entries.filter((x) => x.status === "failed").map((x) => x.mountpoint).join(", ")}
            </div>
          )}
          {(data.warnings ?? []).map((w) => (
            <div key={w} className="alert warn">
              {w}
            </div>
          ))}

          <div className="table-wrap disktable">
            <table>
              <thead>
                <tr>
                  <th>Health</th>
                  <th>Device</th>
                  <th>Model / serial</th>
                  <th>Size</th>
                  <th>Connection</th>
                  <th>Temp</th>
                  <th>Filesystems</th>
                </tr>
              </thead>
              <tbody>
                {data.disks.map((d) => (
                  <tr key={d.name} className="clickable" onClick={() => go(d)}>
                    <td>
                      <div className="stack" style={{ gap: 4, alignItems: "flex-start" }}>
                        <StatusBadge status={d.health?.status} />
                        {d.health?.standby && <span className="badge neutral">standby</span>}
                        {d.health?.self_test_running && <span className="badge info">testing</span>}
                      </div>
                    </td>
                    <td>
                      <a href={`#/disk/${d.name}`} className="mono" onClick={(e) => e.stopPropagation()}>
                        {d.name}
                      </a>
                      {diskNames(d).labels.length > 0 && <div><b>{diskNames(d).labels.join(", ")}</b></div>}
                      <div className="small dim">{slotLabel(d)}</div>
                      <ProtectedBadge disk={d} />
                    </td>
                    <td>
                      {d.display_model || "–"}
                      <div className="small dim mono">{d.serial}</div>
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {fmtBytes(d.size_bytes)}
                      <div className="small dim">{d.rotational ? "HDD" : "SSD"}</div>
                    </td>
                    <td>
                      {d.display_transport}
                      <div className="small dim">{d.topology.hba_name || d.topology.hba || ""}</div>
                    </td>
                    <td>
                      <Temp c={d.health?.temperature_c} />
                    </td>
                    <td>
                      <Filesystems d={d} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="diskcards">
            {data.disks.map((d) => (
              <a key={d.name} className="card diskcard" href={`#/disk/${d.name}`}>
                <div className="between">
                  <div className="row">
                    <b className="mono">{d.name}</b>
                    {diskNames(d).labels.length > 0 && <b>{diskNames(d).labels.join(", ")}</b>}
                    <span className="dim small">{slotLabel(d)}</span>
                  </div>
                  <div className="row">
                    <ProtectedBadge disk={d} />
                    <StatusBadge status={d.health?.status} />
                  </div>
                </div>
                <div className="small" style={{ margin: "4px 0 8px" }}>
                  {d.display_model} · {fmtBytes(d.size_bytes)} · {d.display_transport}
                  {d.health?.temperature_c !== undefined && ` · ${d.health.temperature_c}°C`}
                </div>
                <Filesystems d={d} />
              </a>
            ))}
          </div>

          {(data.hbas?.length || data.enclosures?.length) && (
            <div className="grid2" style={{ marginTop: 16 }}>
              {data.hbas && data.hbas.length > 0 && (
                <div className="card">
                  <h3 style={{ marginTop: 0 }}>Controllers</h3>
                  {data.hbas.map((h) => (
                    <div key={h.pci} style={{ marginBottom: 8 }}>
                      <div>{h.name || "Unknown controller"}</div>
                      <div className="small dim mono">
                        {h.pci} · {h.driver || "?"} {h.hosts?.length ? `· ${h.hosts.join(", ")}` : ""}
                      </div>
                      <div className="small">{h.disks?.length ? h.disks.join(" ") : <span className="dim">no disks</span>}</div>
                    </div>
                  ))}
                </div>
              )}
              {data.enclosures && data.enclosures.length > 0 && (
                <div className="card">
                  <h3 style={{ marginTop: 0 }}>Enclosures</h3>
                  {data.enclosures.map((e) => (
                    <div key={e.id} style={{ marginBottom: 10 }}>
                      <div className="row">
                        {encName(e)} <span className="dim mono small">{e.id}{e.sg_device ? ` · ${e.sg_device}` : ""}</span>
                        {e.status && <span className={`badge ${e.status}`}>{e.status === "ok" ? "OK" : e.status === "warn" ? "Warning" : "Critical"}</span>}
                      </div>
                      <div className="row small" style={{ marginTop: 4 }}>
                        {e.components.length === 0 && <span className="dim">no slot information exposed</span>}
                        {e.components.map((c) => (
                          <span
                            key={c.name}
                            className={`badge ${c.fault ? "crit" : c.disk ? "ok" : "neutral"}`}
                            title={`${c.name}: ${c.status ?? ""}${c.locate ? " (locate on)" : ""}`}
                          >
                            {c.slot ?? c.name}: {c.disk ?? "—"}
                          </span>
                        ))}
                      </div>
                      <EnclosureHealth e={e} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </>
  );
}
