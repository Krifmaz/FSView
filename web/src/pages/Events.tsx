import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorBox, Loading } from "../components";
import type { DiskEvent } from "../types";
import { fmtSec, fmtTime, useFetch } from "../util";

const CATEGORIES = ["", "io_error", "medium_error", "reset", "link_down", "appeared", "removed", "filesystem"];

export default function EventsPage() {
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [device, setDevice] = useState("");
  const [q, setQ] = useState("");
  const [live, setLive] = useState(false);
  const qs = new URLSearchParams({ severity, category, device, q, limit: "500" }).toString();
  const { data, error, loading, setData } = useFetch(() => api.get<DiskEvent[]>(`/api/events?${qs}`), [qs]);

  useEffect(() => {
    const es = new EventSource("/api/events/stream");
    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false);
    es.addEventListener("disk", (m) => {
      const ev = JSON.parse((m as MessageEvent).data) as DiskEvent;
      if (severity && ev.severity !== severity) return;
      if (category && ev.category !== category) return;
      if (device && !ev.device?.startsWith(device)) return;
      if (q && !ev.message.toLowerCase().includes(q.toLowerCase())) return;
      setData((prev) => [ev, ...(prev ?? [])].slice(0, 1000));
    });
    return () => es.close();
  }, [severity, category, device, q, setData]);

  return (
    <>
      <div className="between">
        <h1>Events</h1>
        <span className="row small dim">
          <span className={`pulse ${live ? "" : "off"}`} /> {live ? "live" : "disconnected"}
        </span>
      </div>
      <p className="dim small">Kernel log filtered for disk events: I/O and medium errors, resets, link drops, disks appearing (late ones flagged) or disappearing, and filesystem errors.</p>
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="error">Errors</option>
          <option value="warn">Warnings</option>
          <option value="info">Info</option>
        </select>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c ? c.replace("_", " ") : "All categories"}
            </option>
          ))}
        </select>
        <input placeholder="device (sdc, nvme0…)" value={device} onChange={(e) => setDevice(e.target.value.trim())} style={{ width: 150 }} />
        <input placeholder="search text" value={q} onChange={(e) => setQ(e.target.value)} className="grow" />
      </div>
      <ErrorBox error={error} />
      {loading && !data ? (
        <Loading />
      ) : (
        <div className="card" style={{ padding: 0 }}>
          {data?.length === 0 && <div className="dim" style={{ padding: 14 }}>No matching events.</div>}
          <ul className="events">
            {(data ?? []).map((e) => (
              <li key={e.cursor}>
                <div className="row small">
                  <span className={`badge ${e.severity === "error" ? "crit" : e.severity}`}>{e.category.replace("_", " ")}</span>
                  {e.late && <span className="badge late">late after boot</span>}
                  {e.device && (
                    <a className="mono" href={/^(sd[a-z]+|nvme\d+n\d+)$/.test(e.device) ? `#/disk/${e.device}` : undefined}>
                      {e.device}
                    </a>
                  )}
                  <span className="dim">{fmtTime(e.time)}</span>
                  <span className="dim">boot {fmtSec(e.monotonic_sec)}</span>
                </div>
                <div className="msg">{e.message}</div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
