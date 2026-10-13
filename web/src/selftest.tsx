import { useState } from "react";
import { api, ApiError } from "./api";
import { ConfirmDialog, type ConfirmSpec } from "./components";
import { confirmSkipped } from "./actions";
import type { Disk } from "./types";

type Test = "short" | "long" | "abort";

function explain(e: unknown): string {
  const ae = e as ApiError;
  if (ae?.code === "writes_disabled") return "Write operations are disabled in /etc/fsview/helper.conf (writes_enabled = false).";
  return ae?.message ?? String(e);
}

/**
 * Starts SMART self-tests on one or more disks: a dry run first (so the
 * dialog shows the exact commands), then the confirmed run.
 */
export function useSelfTest(onDone?: () => void) {
  const [spec, setSpec] = useState<(ConfirmSpec & { disks: Disk[]; test: Test }) | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "info" | "error"; text: string } | null>(null);

  const start = async (disks: Disk[], test: Test, minutes?: number) => {
    setMsg(null);
    if (confirmSkipped()) {
      await run({ disks, test } as never);
      return;
    }
    setBusy(true);
    try {
      const plans: string[] = [];
      const ok: Disk[] = [];
      const skipped: string[] = [];
      for (const d of disks) {
        try {
          const dry = await api.post<{ plan: string[] }>(`/api/disks/${d.name}/selftest`, { test, dry_run: true });
          plans.push(...dry.plan);
          ok.push(d);
        } catch (e) {
          if ((e as ApiError).code === "writes_disabled") throw e;
          skipped.push(`${d.name}: ${explain(e)}`);
        }
      }
      if (!ok.length) throw new Error(skipped.join("\n") || "no disks");
      const many = ok.length > 1;
      setSpec({
        disks: ok,
        test,
        title: test === "abort" ? "Abort self-test" : `Run ${test} SMART self-test${many ? ` on ${ok.length} disks` : ""}`,
        disk: many ? undefined : ok[0],
        operation:
          test === "abort"
            ? "Abort the running self-test."
            : `Start a ${test} self-test. Disks stay usable; the test runs inside each drive's firmware${minutes ? ` (about ${minutes} min)` : ""}. Sleeping disks will spin up.` +
              (skipped.length ? `\n\nSkipped: ${skipped.join("; ")}` : ""),
        plan: plans,
        confirmLabel: test === "abort" ? "Abort test" : "Start test",
      });
    } catch (e) {
      setMsg({ kind: "error", text: explain(e) });
    } finally {
      setBusy(false);
    }
  };

  const run = async (direct?: { disks: Disk[]; test: Test }) => {
    const job = direct ?? spec;
    if (!job) return;
    setBusy(true);
    const failed: string[] = [];
    for (const d of job.disks) {
      try {
        await api.post(`/api/disks/${d.name}/selftest`, { test: job.test, confirmed: true });
      } catch (e) {
        failed.push(`${d.name}: ${explain(e)}`);
      }
    }
    const started = job.disks.length - failed.length;
    setMsg(
      failed.length
        ? { kind: "error", text: `${started} started, ${failed.length} failed:\n${failed.join("\n")}` }
        : {
            kind: "info",
            text:
              job.test === "abort"
                ? "Self-test aborted."
                : `${job.test === "short" ? "Short" : "Long"} self-test started on ${job.disks.map((d) => d.name).join(", ")}. Progress shows on each disk's page.`,
          },
    );
    setSpec(null);
    setBusy(false);
    if (onDone) setTimeout(onDone, 6000);
  };

  const dialog = spec ? <ConfirmDialog spec={spec} busy={busy} onConfirm={() => run()} onCancel={() => setSpec(null)} /> : null;
  const message = msg ? (
    <div className={`alert ${msg.kind}`} style={{ whiteSpace: "pre-wrap" }}>
      {msg.text}
    </div>
  ) : null;
  return { start, busy, dialog, message };
}
