import { api } from "../api";
import { ErrorBox, Loading, StatusBadge, Temp } from "../components";
import type { Overview } from "../types";
import { fmtBytes, fmtHours, slotLabel, timeAgo, useFetch } from "../util";
import { useSelfTest } from "../selftest";
import { LifeCell } from "../life";

const order: Record<string, number> = { crit: 0, warn: 1, unknown: 2, ok: 3 };

export default function HealthPage() {
  const { data, error, loading, reload } = useFetch(() => api.get<Overview>("/api/overview"), [], 60000);
  const st = useSelfTest(reload);
  if (loading && !data) return <Loading />;
  const disks = [...(data?.disks ?? [])].sort((a, b) => (order[a.health?.status ?? "unknown"] ?? 9) - (order[b.health?.status ?? "unknown"] ?? 9) || a.name.localeCompare(b.name));
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Health</h1>
          <p className="sub small">
            SMART is read every 30 minutes with <span className="mono">smartctl -n standby</span>, so sleeping disks are not woken. Thresholds are set under Settings.
          </p>
        </div>
        <div className="row">
          <button className="btn" disabled={st.busy || !disks.length} onClick={() => st.start(disks.filter((d) => !d.health?.self_test_running), "short", 2)}>
            Short test all disks
          </button>
          <button className="btn" disabled={st.busy || !disks.length} onClick={() => st.start(disks.filter((d) => !d.health?.self_test_running), "long")}>
            Long test all disks
          </button>
        </div>
      </div>
      <ErrorBox error={error} />
      {st.message}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Disk</th>
              <th>Temp</th>
              <th>Age / life left</th>
              <th>Findings</th>
              <th>Checked</th>
              <th>Self-test</th>
            </tr>
          </thead>
          <tbody>
            {disks.map((d) => (
              <tr key={d.name} className="clickable" onClick={() => (window.location.hash = `#/disk/${d.name}`)}>
                <td>
                  <StatusBadge status={d.health?.status} />
                </td>
                <td>
                  <span className="mono">{d.name}</span> <span className="dim small">{slotLabel(d)}</span>
                  <div className="small">
                    {d.display_model} · {fmtBytes(d.size_bytes)}
                  </div>
                  {d.health?.devtype && <div className="small dim">{d.health.protocol} via {d.health.devtype}</div>}
                </td>
                <td>
                  <Temp c={d.health?.temperature_c} />
                </td>
                <td style={{ minWidth: 150 }}>{d.health?.life ? <LifeCell life={d.health.life} /> : <span className="small">{fmtHours(d.health?.power_on_hours)}</span>}</td>
                <td className="small">
                  {d.health?.standby && <div className="dim">in standby (last data kept)</div>}
                  {d.health?.error && <div style={{ color: "var(--crit)" }}>{d.health.error}</div>}
                  {(d.health?.findings ?? []).map((f) => (
                    <div key={f.text} className={f.level === "ok" ? "dim" : undefined} style={f.level === "ok" ? undefined : { color: f.level === "crit" ? "var(--crit)" : "var(--warn)" }}>
                      {f.text}
                    </div>
                  ))}
                  {d.health?.status === "ok" && !d.health.findings?.length && <span className="dim">no issues</span>}
                </td>
                <td className="small dim">{timeAgo(d.health?.checked_at)}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  {d.health?.self_test_running ? (
                    <div className="row" style={{ gap: 6 }}>
                      <span className="badge info">
                        running{d.health.self_test_running.remaining_percent !== undefined && `, ${d.health.self_test_running.remaining_percent}% left`}
                      </span>
                      <button className="btn sm" disabled={st.busy} onClick={() => st.start([d], "abort")}>
                        Abort
                      </button>
                    </div>
                  ) : (
                    <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                      <button className="btn sm" disabled={st.busy} onClick={() => st.start([d], "short", 2)}>
                        Short
                      </button>
                      <button className="btn sm" disabled={st.busy} onClick={() => st.start([d], "long")}>
                        Long
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {st.dialog}
    </>
  );
}
