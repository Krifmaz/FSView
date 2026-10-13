import { api } from "../api";
import { ErrorBox, Loading, StatusBadge, Temp } from "../components";
import type { Overview } from "../types";
import { fmtBytes, fmtHours, slotLabel, timeAgo, useFetch } from "../util";

const order: Record<string, number> = { crit: 0, warn: 1, unknown: 2, ok: 3 };

export default function HealthPage() {
  const { data, error, loading } = useFetch(() => api.get<Overview>("/api/overview"), [], 60000);
  if (loading && !data) return <Loading />;
  const disks = [...(data?.disks ?? [])].sort((a, b) => (order[a.health?.status ?? "unknown"] ?? 9) - (order[b.health?.status ?? "unknown"] ?? 9) || a.name.localeCompare(b.name));
  return (
    <>
      <h1>Health</h1>
      <ErrorBox error={error} />
      <p className="dim small">
        SMART is read every 30 minutes with <span className="mono">smartctl -n standby</span>, so sleeping disks are not woken. Thresholds are set under Settings.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Disk</th>
              <th>Temp</th>
              <th>Power-on</th>
              <th>Findings</th>
              <th>Checked</th>
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
                <td className="small">{fmtHours(d.health?.power_on_hours)}</td>
                <td className="small">
                  {d.health?.standby && <div className="dim">in standby (last data kept)</div>}
                  {d.health?.error && <div style={{ color: "var(--crit)" }}>{d.health.error}</div>}
                  {(d.health?.findings ?? []).map((f) => (
                    <div key={f.text} style={{ color: f.level === "crit" ? "var(--crit)" : "var(--warn)" }}>
                      {f.text}
                    </div>
                  ))}
                  {d.health?.status === "ok" && !d.health.findings?.length && <span className="dim">no issues</span>}
                </td>
                <td className="small dim">{timeAgo(d.health?.checked_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
