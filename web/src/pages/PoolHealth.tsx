import { Fragment, useState } from "react";
import { HeartPulse, Search, Wrench } from "lucide-react";
import { api } from "../api";
import { explainError, type useAction } from "../actions";
import type { BranchHealth, HealthFlag, JournalLine, PoolHealth, PoolLocate } from "../types";

const FLAG_LABEL: Record<HealthFlag["kind"], string> = {
  branch_ro: "pool RO",
  branch_nc: "no new files",
  mount_ro: "mounted ro",
  emergency_ro: "emergency_ro",
  not_mounted: "disk not mounted",
  ext4_errors: "ext4 errors",
  io_errors: "I/O errors",
  smart_uncorrected: "SMART uncorrected",
  smart_reallocated: "SMART reallocated",
  smart_unknown: "SMART unknown",
};

const badgeClass = (s: HealthFlag["severity"]) => (s === "error" ? "crit" : s === "warn" ? "warn" : "neutral");

function time(l: JournalLine) {
  return new Date(l.realtime_us / 1000).toLocaleString();
}

function Lines({ lines }: { lines: JournalLine[] }) {
  return (
    <pre className="mono small" style={{ whiteSpace: "pre-wrap", margin: 0, maxHeight: 260, overflow: "auto" }}>
      {lines.map((l) => `${new Date(l.realtime_us / 1000).toLocaleTimeString()}  ${l.message.trim()}`).join("\n")}
    </pre>
  );
}

/** Kernel messages before the first ext4 error, and the latest errors. */
function BranchDetail({ b }: { b: BranchHealth }) {
  return (
    <div className="stack" style={{ gap: 10 }}>
      {b.flags.map((f) => (
        <div key={f.kind} className="small">
          <span className={`badge ${badgeClass(f.severity)}`}>{FLAG_LABEL[f.kind]}</span> {f.detail}
        </div>
      ))}
      {b.first_error && (
        <div>
          <div className="small">
            <b>Likely trigger</b>: kernel messages in the 10 minutes before the first ext4 error ({time(b.first_error)}). Look for resets, timeouts or a
            disk dropping off; they usually point at the cable, bay or controller rather than the filesystem.
          </div>
          {b.trigger.length ? <Lines lines={b.trigger} /> : <div className="dim small">No kernel messages in that window.</div>}
        </div>
      )}
      {b.io_errors.length > 0 && (
        <div>
          <div className="small">
            <b>Latest read/write errors</b> ({b.io_error_count} this boot). The disk could not read or write these blocks; while it does, creating files can fail
            on the whole pool. Take the branch out of the pool and copy its data off.
          </div>
          <Lines lines={b.io_errors} />
        </div>
      )}
      {b.ext4_errors.length > 0 && (
        <div>
          <div className="small">
            <b>Latest ext4 errors</b> ({b.ext4_error_count} this boot)
          </div>
          <Lines lines={b.ext4_errors} />
        </div>
      )}
    </div>
  );
}

/** "Which branch holds this file?" via user.mergerfs.fullpath. */
function LocateFile({ pool }: { pool: string }) {
  const [path, setPath] = useState("");
  const [res, setRes] = useState<PoolLocate | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const find = async () => {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      setRes(await api.get<PoolLocate>(`/api/pools/locate?${new URLSearchParams({ pool, path })}`));
    } catch (e) {
      setErr(explainError(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack" style={{ gap: 6 }}>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (path.trim()) find();
        }}
      >
        <input className="mono" style={{ flex: 1, minWidth: 200 }} placeholder={`${pool}/music/Artist/Album/01.flac`} value={path} onChange={(e) => setPath(e.target.value)} />
        <button className="btn sm" disabled={busy || !path.trim()}>
          <Search size={14} /> Which disk?
        </button>
      </form>
      {err && <div className="alert crit small">{err}</div>}
      {res && (
        <div className="small">
          <span className="mono">{res.path}</span> lives on branch <b className="mono">{res.branch || "?"}</b> as <span className="mono">{res.fullpath}</span>
          {res.allpaths && res.allpaths.length > 1 && (
            <div className="dim">
              Present on {res.allpaths.length} branches: <span className="mono">{res.allpaths.join(", ")}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Pool health for one mounted mergerfs pool: per-branch findings (RO/NC
 * mode, ro/emergency_ro mounts, ext4 journal errors with their trigger,
 * SMART), a file locator and the guided "Repair branch" action.
 */
export default function PoolHealthPanel({
  health,
  labels,
  writes,
  act,
}: {
  health: PoolHealth;
  labels: Record<string, string>;
  writes: boolean;
  act: ReturnType<typeof useAction>;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const problems = health.branches.filter((b) => b.flags.some((f) => f.severity !== "info"));

  const repair = (b: BranchHealth) => {
    const label = labels[b.mount_target];
    act.start({
      url: "/api/pools/repair",
      body: { pool: health.mountpoint, branch: b.path },
      title: `Repair branch ${b.path}`,
      operation:
        `Runs the configured stop commands, unmounts the pool ${health.mountpoint} and ${b.mount_target}, runs fsck.ext4 -f -y on ${b.device}, ` +
        `mounts both again and runs the configured post commands. The pool is offline meanwhile. If a step fails, the rest (including the post commands) ` +
        `is skipped and the pool stays unmounted for you to look at. Type the disk name${label ? " or label" : ""} to confirm.`,
      destructive: true,
      confirmWith: [b.disk, label].filter((x): x is string => !!x),
      confirmLabel: "Repair",
      wide: true,
      showOutput: true,
      extra: b.first_error ? (
        <div className="small" style={{ marginTop: 8 }}>
          <b>Kernel messages before the first ext4 error</b> (recorded in the audit log with the repair):
          <Lines lines={b.trigger} />
        </div>
      ) : undefined,
      done: () => `Branch ${b.path} repaired; ${health.mountpoint} is mounted again.`,
    });
  };

  return (
    <div className="stack" style={{ marginTop: 14, gap: 10 }}>
      <div className="row">
        <HeartPulse size={16} className="dim" />
        <b>Pool health</b>
        {health.error ? (
          <span className="badge crit">unknown</span>
        ) : problems.length ? (
          <span className="badge crit">
            {problems.length} branch{problems.length > 1 ? "es" : ""} need attention
          </span>
        ) : (
          <span className="badge ok">all branches healthy</span>
        )}
      </div>
      {health.error && <div className="alert warn small">{health.error}</div>}
      {health.branches.length > 0 && (
        <div className="table-wrap" style={{ boxShadow: "none" }}>
          <table>
            <thead>
              <tr>
                <th>Branch</th>
                <th>Filesystem</th>
                <th>Findings</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {health.branches.map((b) => (
                <Fragment key={b.path}>
                  <tr>
                    <td className="mono">
                      {b.path} <span className="dim">={b.mode}</span>
                    </td>
                    <td className="small">
                      {b.mount_target ? (
                        <>
                          <span className="mono">{b.device || b.mount_target}</span> {b.fstype}
                          {b.disk && (
                            <>
                              {" "}
                              on <a href={`#/disk/${b.disk}`}>{b.disk}</a>
                            </>
                          )}
                        </>
                      ) : (
                        <span className="dim">–</span>
                      )}
                    </td>
                    <td>
                      <div className="row" style={{ gap: 4, flexWrap: "wrap" }}>
                        {b.flags.length === 0 && <span className="badge ok">healthy</span>}
                        {b.flags.map((f) => (
                          <span key={f.kind} className={`badge ${badgeClass(f.severity)}`} title={f.detail}>
                            {FLAG_LABEL[f.kind]}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                      {b.flags.length > 0 && (
                        <button className="btn sm ghost" onClick={() => setOpen(open === b.path ? null : b.path)}>
                          {open === b.path ? "Hide" : "Details"}
                        </button>
                      )}
                      <button
                        className="btn sm"
                        disabled={act.busy || !writes || !!b.repair_blocker}
                        title={!writes ? "Writes are disabled in helper.conf" : b.repair_blocker || "Unmount, fsck and remount this branch"}
                        onClick={() => repair(b)}
                      >
                        <Wrench size={14} /> Repair branch
                      </button>
                    </td>
                  </tr>
                  {open === b.path && (
                    <tr>
                      <td colSpan={4}>
                        <BranchDetail b={b} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <LocateFile pool={health.mountpoint} />
    </div>
  );
}
