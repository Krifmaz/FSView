import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { ErrorBox, Loading } from "../components";
import type { Settings, StatusInfo, Thresholds } from "../types";
import { useFetch } from "../util";
import { setSkipConfirm } from "../actions";

const FIELDS: { key: keyof Thresholds; label: string; unit?: string }[] = [
  { key: "temp_warn_c", label: "Temperature warning", unit: "°C" },
  { key: "temp_crit_c", label: "Temperature critical", unit: "°C" },
  { key: "trip_margin_c", label: "Warn within X of drive trip point", unit: "°C" },
  { key: "reallocated_warn", label: "Reallocated / grown defects warning" },
  { key: "reallocated_crit", label: "Reallocated / grown defects critical" },
  { key: "pending_warn", label: "Pending sectors warning" },
  { key: "pending_crit", label: "Pending sectors critical" },
  { key: "uncorrectable_warn", label: "Uncorrectable errors warning" },
  { key: "crc_warn", label: "Interface CRC errors warning" },
  { key: "error_log_warn", label: "ATA error log entries warning" },
  { key: "nvme_used_warn", label: "NVMe endurance used warning", unit: "%" },
  { key: "nvme_used_crit", label: "NVMe endurance used critical", unit: "%" },
];

export default function SettingsPage({ user, onLogout }: { user: string; onLogout: () => void }) {
  const st = useFetch(() => api.get<StatusInfo>("/api/status"), []);
  const cfg = useFetch(() => api.get<Settings>("/api/settings"), []);
  const [form, setForm] = useState<Settings | null>(null);
  const [msg, setMsg] = useState<{ kind: string; text: string } | null>(null);
  const [pw, setPw] = useState({ current: "", next: "", repeat: "" });
  const [pwMsg, setPwMsg] = useState<{ kind: string; text: string } | null>(null);

  useEffect(() => {
    if (cfg.data) setForm(cfg.data);
  }, [cfg.data]);

  const toggleConfirm = async (skip: boolean) => {
    if (!form) return;
    try {
      const next = await api.put<Settings>("/api/settings", { ...form, skip_confirm: skip });
      setForm(next);
      setSkipConfirm(skip);
    } catch (err: any) {
      setMsg({ kind: "error", text: err.message });
    }
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!form) return;
    try {
      await api.put("/api/settings", form);
      setMsg({ kind: "info", text: "Saved." });
    } catch (err: any) {
      setMsg({ kind: "error", text: err.message });
    }
  };

  const changePw = async (e: FormEvent) => {
    e.preventDefault();
    if (pw.next !== pw.repeat) {
      setPwMsg({ kind: "error", text: "New passwords do not match." });
      return;
    }
    try {
      await api.post("/api/me/password", { current: pw.current, new: pw.next });
      setPwMsg({ kind: "info", text: "Password changed. Other sessions were signed out." });
      setPw({ current: "", next: "", repeat: "" });
    } catch (err: any) {
      setPwMsg({ kind: "error", text: err.message });
    }
  };

  const logout = async () => {
    await api.post("/api/logout").catch(() => {});
    onLogout();
  };

  const s = st.data;
  return (
    <>
      <h1>Settings</h1>
      <div className="grid2">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>System</h3>
          {st.loading && !s ? (
            <Loading />
          ) : (
            <dl className="kv">
              <dt>Version</dt>
              <dd>{s?.version}</dd>
              <dt>Listening on</dt>
              <dd className="mono">
                {s?.listen.join(", ")} {s?.tls ? "(HTTPS)" : "(HTTP)"}
              </dd>
              <dt>Allowed clients</dt>
              <dd className="mono">{s?.allow.join(", ")}</dd>
              <dt>Root helper</dt>
              <dd>{s?.helper ? `connected (${s.helper.version})` : <span style={{ color: "var(--crit)" }}>{s?.helper_error ?? "unavailable"}</span>}</dd>
              <dt>Write operations</dt>
              <dd>
                {s?.helper?.writes_enabled ? (
                  <span className="badge warn">enabled</span>
                ) : (
                  <span className="badge ok">disabled (read-only)</span>
                )}
                <div className="small dim">
                  Controlled only by root in <span className="mono">/etc/fsview/helper.conf</span> (<span className="mono">writes_enabled</span>), then{" "}
                  <span className="mono">systemctl restart fsview-helper</span>. The web UI cannot change it.
                </div>
              </dd>
              <dt>Tools</dt>
              <dd className="row small">
                {Object.entries(s?.helper?.tools ?? {}).map(([k, v]) => (
                  <span key={k} className={`badge ${v ? "ok" : "neutral"}`}>
                    {k}
                  </span>
                ))}
              </dd>
            </dl>
          )}
        </div>

        <div className="card stack">
          <h3 style={{ margin: 0 }}>Confirmations</h3>
          <label className="check" style={{ alignItems: "flex-start" }}>
            <input type="checkbox" checked={!form?.skip_confirm} disabled={!form} onChange={(e) => toggleConfirm(!e.target.checked)} />
            <span>
              Ask before mount, unmount, rename, self-tests and other non-destructive actions
              <div className="small dim">
                When off, they run right away (still recorded in the audit log). Format, wipe and repair always ask you to type the disk name; fstab and pool edits always show the diff.
              </div>
            </span>
          </label>
        </div>

        <div className="card stack">
          <h3 style={{ margin: 0 }}>Account</h3>
          <div className="between">
            <span>
              Signed in as <b>{user}</b>
            </span>
            <button className="btn" onClick={logout}>
              Sign out
            </button>
          </div>
          <form className="stack" onSubmit={changePw}>
            {pwMsg && <div className={`alert ${pwMsg.kind}`}>{pwMsg.text}</div>}
            <label className="field">
              Current password
              <input type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} required />
            </label>
            <label className="field">
              New password (min. 10 characters)
              <input type="password" autoComplete="new-password" minLength={10} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} required />
            </label>
            <label className="field">
              Repeat new password
              <input type="password" autoComplete="new-password" value={pw.repeat} onChange={(e) => setPw({ ...pw, repeat: e.target.value })} required />
            </label>
            <button className="btn" type="submit">
              Change password
            </button>
          </form>
        </div>
      </div>

      <h2>Alert thresholds</h2>
      <ErrorBox error={cfg.error} />
      {form && (
        <form className="card stack" onSubmit={save}>
          {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
          <div className="grid2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
            {FIELDS.map((f) => (
              <label key={f.key} className="field">
                {f.label} {f.unit && `(${f.unit})`}
                <input
                  type="number"
                  min={0}
                  value={form.thresholds[f.key]}
                  onChange={(e) => setForm({ ...form, thresholds: { ...form.thresholds, [f.key]: Number(e.target.value) } })}
                />
              </label>
            ))}
            <label className="field">
              Flag disks appearing later than (seconds after boot)
              <input type="number" min={5} value={form.late_device_sec} onChange={(e) => setForm({ ...form, late_device_sec: Number(e.target.value) })} />
            </label>
            <label className="field">
              Events kept
              <input type="number" min={100} value={form.event_retention} onChange={(e) => setForm({ ...form, event_retention: Number(e.target.value) })} />
            </label>
          </div>
          <div>
            <button className="btn primary" type="submit">
              Save thresholds
            </button>
          </div>
        </form>
      )}
    </>
  );
}
