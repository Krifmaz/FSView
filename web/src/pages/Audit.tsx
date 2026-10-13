import { api } from "../api";
import { ErrorBox, Loading } from "../components";
import type { AuditRecord } from "../types";
import { fmtTime, useFetch } from "../util";

const cls: Record<string, string> = { ok: "ok", error: "crit", rejected: "warn", "dry-run": "info" };

export default function AuditPage() {
  const { data, error, loading } = useFetch(() => api.get<AuditRecord[]>("/api/audit?limit=500"), [], 30000);
  if (loading && !data) return <Loading />;
  return (
    <>
      <h1>Audit log</h1>
      <p className="dim small">
        Every write operation (including dry runs and rejected attempts), recorded by the root helper in <span className="mono">/var/log/fsview/audit.log</span>.
      </p>
      <ErrorBox error={error} />
      {data?.length === 0 && <div className="dim">No write operations yet.</div>}
      <div className="stack">
        {(data ?? []).map((r, i) => (
          <div key={i} className="card">
            <div className="between">
              <div className="row">
                <span className={`badge ${cls[r.result] ?? "neutral"}`}>{r.result}</span>
                <b>{r.op}</b>
                {r.targets?.map((t) => (
                  <a key={t} className="mono" href={`#/disk/${t}`}>
                    {t}
                  </a>
                ))}
              </div>
              <span className="small dim">{fmtTime(r.time)}</span>
            </div>
            <div className="small dim" style={{ marginTop: 4 }}>
              by <b>{r.actor || "?"}</b> from {r.client_ip || "?"}
            </div>
            {r.commands && r.commands.length > 0 && (
              <div className="plan" style={{ marginTop: 6 }}>
                {r.commands.join("\n")}
              </div>
            )}
            {r.error && (
              <div className="small" style={{ color: "var(--crit)", marginTop: 4 }}>
                {r.error}
              </div>
            )}
            {r.output && (
              <details style={{ marginTop: 4 }}>
                <summary className="small">output</summary>
                <pre className="raw">{r.output}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    </>
  );
}
