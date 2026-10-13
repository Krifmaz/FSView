import { useCallback, useEffect, useRef, useState } from "react";
import type { Disk, Node } from "./types";

export function fmtBytes(n?: number | null, si = true): string {
  if (n === undefined || n === null || isNaN(n)) return "–";
  const base = si ? 1000 : 1024;
  const units = si ? ["B", "kB", "MB", "GB", "TB", "PB"] : ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = n;
  while (v >= base && i < units.length - 1) {
    v /= base;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function fmtHours(h?: number | null): string {
  if (h === undefined || h === null) return "–";
  const years = h / 8766;
  if (years >= 1) return `${h.toLocaleString()} h (${years.toFixed(1)} y)`;
  const days = h / 24;
  return days >= 1 ? `${h.toLocaleString()} h (${days.toFixed(0)} d)` : `${h} h`;
}

export function fmtSec(s?: number | null): string {
  if (s === undefined || s === null) return "–";
  if (s < 120) return `+${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  if (m < 120) return `+${m}m${Math.round(s % 60)}s`;
  return `+${Math.floor(m / 60)}h${m % 60}m`;
}

export function timeAgo(iso?: string): string {
  if (!iso || iso.startsWith("0001")) return "never";
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}

export function fmtTime(iso?: string): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

/** Collect every mountpoint and the most interesting filesystem rows of a disk. */
export function diskFilesystems(d: Disk): { name: string; fstype?: string; label?: string; mounts: string[]; usage?: Node["usage"]; uuid?: string }[] {
  const out: { name: string; fstype?: string; label?: string; mounts: string[]; usage?: Node["usage"]; uuid?: string }[] = [];
  if (d.fstype) out.push({ name: d.name, fstype: d.fstype, label: d.label, mounts: d.mountpoints ?? [], usage: d.usage, uuid: d.uuid });
  const walk = (ns?: Node[]) => {
    for (const n of ns ?? []) {
      if (n.fstype) out.push({ name: n.name, fstype: n.fstype, label: n.label, mounts: n.mountpoints ?? [], usage: n.usage, uuid: n.uuid });
      walk(n.children);
    }
  };
  walk(d.children);
  return out;
}

export function slotLabel(d: Disk): string {
  const e = d.topology.enclosure;
  if (e) return e.slot !== undefined ? `Slot ${e.slot}` : e.component;
  if (d.topology.bay_id !== undefined) return `Bay ${d.topology.bay_id}`;
  return "";
}

/** Fetch JSON with loading/error state and an optional refresh interval. */
export function useFetch<T>(load: () => Promise<T>, deps: unknown[], intervalMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;
  const reload = useCallback(async () => {
    try {
      const d = await loadRef.current();
      setData(d);
      setError(null);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    setLoading(true);
    reload();
    if (intervalMs > 0) {
      const t = setInterval(reload, intervalMs);
      return () => clearInterval(t);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload, setData };
}

export function useHashRoute(): string[] {
  const parse = () => (window.location.hash.replace(/^#\/?/, "") || "overview").split("/").map(decodeURIComponent);
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const h = () => setRoute(parse());
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return route;
}
