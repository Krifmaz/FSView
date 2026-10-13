import { api } from "./api";
import type { HealthView, Life, Overview } from "./types";
import { fmtBytes, fmtDuration, useFetch } from "./util";

const levelBadge = { ok: "ok", warn: "warn", crit: "crit" } as const;

/** Compact life summary for tables. */
export function LifeCell({ life }: { life?: Life }) {
  if (!life) return <span className="dim">–</span>;
  return (
    <div className="small">
      <div>
        {life.age_hours !== undefined ? (
          <>
            <b>{fmtDuration(life.age_hours)}</b> <span className="dim">powered on</span>
          </>
        ) : (
          <span className="dim">age not reported</span>
        )}
      </div>
      {life.level !== "ok" && <div style={{ color: life.level === "crit" ? "var(--crit)" : "var(--warn)" }}>{life.verdict}</div>}
      {life.remaining_pct !== undefined && (
        <div className="row" style={{ gap: 6, marginTop: 3, flexWrap: "nowrap" }}>
          <div className={`usage ${life.level === "ok" ? "" : life.level}`} style={{ minWidth: 60, width: 60 }}>
            <div style={{ width: `${Math.max(2, life.remaining_pct)}%` }} />
          </div>
          <span className="dim">
            ~{life.remaining_pct}% left{life.remaining_hours ? ` · ${fmtDuration(life.remaining_hours)}` : ""}
          </span>
        </div>
      )}
      {life.written_bytes !== undefined && <div className="dim">{fmtBytes(life.written_bytes)} written</div>}
    </div>
  );
}

function Row({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>
        {value}
        {sub && <div className="small dim">{sub}</div>}
      </dd>
    </>
  );
}

/** Full lifespan card for the disk page. */
export function LifeCard({ life, rotational }: { life?: Life; rotational: boolean }) {
  if (!life) return null;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="between">
        <h3 style={{ margin: 0 }}>Lifespan</h3>
        <span className={`badge ${levelBadge[life.level]}`}>{life.verdict}</span>
      </div>
      {life.remaining_pct !== undefined && (
        <div style={{ margin: "14px 0 6px" }}>
          <div className={`usage ${life.level === "ok" ? "" : life.level}`} style={{ height: 10 }}>
            <div style={{ width: `${Math.max(1, life.remaining_pct)}%` }} />
          </div>
          <div className="small dim" style={{ marginTop: 4 }}>
            Estimated <b style={{ color: "var(--text)" }}>{life.remaining_pct}%</b> of life left
            {life.remaining_hours !== undefined && life.remaining_hours > 0 && <> · about {fmtDuration(life.remaining_hours)} of power-on time</>}
          </div>
        </div>
      )}
      <dl className="kv" style={{ marginTop: 12 }}>
        <Row
          label="Age (powered on)"
          value={life.age_hours !== undefined ? fmtDuration(life.age_hours) : "not reported"}
          sub={life.age_hours !== undefined ? `${life.age_hours.toLocaleString()} hours` : "This disk sits behind a SAS bridge that hides it; FSView retries with ATA pass-through when possible."}
        />
        {life.written_bytes !== undefined && <Row label="Data written" value={fmtBytes(life.written_bytes)} />}
        {life.read_bytes !== undefined && <Row label="Data read" value={fmtBytes(life.read_bytes)} />}
        {life.workload_bytes_per_year !== undefined && (
          <Row
            label="Workload"
            value={`${fmtBytes(life.workload_bytes_per_year)} per year`}
            sub={rotational ? "Reads + writes. Desktop disks are rated around 55 TB/year, NAS 180-300 TB/year, enterprise 550 TB/year." : "Reads + writes per year of power-on time."}
          />
        )}
        {life.wear_used_pct !== undefined && <Row label="Flash wear used" value={`${life.wear_used_pct}%`} sub="Share of the rated write endurance used up." />}
        {life.remaining_written_bytes !== undefined && <Row label="Writes left (estimate)" value={`≈ ${fmtBytes(life.remaining_written_bytes)}`} sub="At the same wear per byte as so far." />}
      </dl>
      <div className="small dim" style={{ marginTop: 10 }}>
        Estimate based on {life.basis}. Health findings (bad sectors, failed tests) override the age-based estimate.
      </div>
    </div>
  );
}

/** Disk name → health, for pages that show disks by mount. */
export function useHealthMap(): Map<string, HealthView> {
  const { data } = useFetch(() => api.get<Overview>("/api/overview"), [], 60000);
  const m = new Map<string, HealthView>();
  for (const d of data?.disks ?? []) if (d.health) m.set(d.name, d.health);
  return m;
}

/** Small health badge for a disk; links to its page. */
export function HealthBadge({ disk, health }: { disk?: string; health?: HealthView }) {
  if (!disk || !health) return null;
  const label = { ok: "Healthy", warn: "Warning", crit: "Critical", unknown: "Unknown" }[health.status] ?? health.status;
  const title = (health.findings ?? []).map((f) => f.text).join("\n") || health.life?.verdict || "";
  return (
    <a href={`#/disk/${disk}`} className={`badge ${health.status}`} title={title} style={{ textDecoration: "none" }}>
      {label}
    </a>
  );
}
