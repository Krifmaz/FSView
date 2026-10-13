import { api } from "./api";
import type { ActionSpec } from "./actions";
import type { WriteResult } from "./types";

/** Filesystems whose label FSView can change. */
export const LABEL_FS = ["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs"];
/** These must be unmounted while the label changes. */
const NEEDS_UNMOUNT = ["xfs", "ntfs"];
const MAX: Record<string, number> = { xfs: 12, vfat: 11, exfat: 15 };

export function labelProblem(fstype: string, label: string): string | null {
  if (!LABEL_FS.includes(fstype)) return `${fstype || "This"} filesystem labels can't be changed here.`;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/.test(label)) return "Use 1-16 letters, digits, '.', '_' or '-'.";
  if (MAX[fstype] && label.length > MAX[fstype]) return `${fstype} labels can be at most ${MAX[fstype]} characters.`;
  return null;
}

/**
 * Action that renames a filesystem. XFS and NTFS are unmounted for the
 * change and mounted again (via fstab) afterwards.
 */
export function relabelAction(disk: string, dev: { name: string; fstype: string; label?: string }, label: string, mountedAt?: string, inFstab?: boolean): ActionSpec {
  const req = () => api.post<WriteResult>(`/api/disks/${disk}/label`, { device: dev.name, label, confirmed: true });
  const op = `Rename ${dev.name} from "${dev.label || "(no label)"}" to "${label}". Data is not touched.`;
  if (mountedAt && NEEDS_UNMOUNT.includes(dev.fstype)) {
    return {
      url: "/api/mounts/umount",
      body: { target: mountedAt },
      title: `Rename disk ${dev.name}`,
      operation: `${op} ${dev.fstype.toUpperCase()} labels can only change while unmounted, so ${mountedAt} is unmounted first${inFstab ? " and mounted again afterwards" : ""}.`,
      confirmLabel: "Rename",
      morePlan: [`relabel ${dev.name} as ${label}`, ...(inFstab ? [`mount ${mountedAt}`] : [])],
      done: () => `${dev.name} is now labelled ${label}.`,
      then: async () => {
        await req();
        if (inFstab) {
          await api.post<WriteResult>("/api/mounts/mount", { target: mountedAt, confirmed: true });
          return `Mounted again at ${mountedAt}.`;
        }
      },
    };
  }
  return {
    url: `/api/disks/${disk}/label`,
    body: { device: dev.name, label },
    title: `Rename disk ${dev.name}`,
    operation: op,
    confirmLabel: "Rename",
    done: () => `${dev.name} is now labelled ${label}.`,
  };
}
