//! Mount/unmount, format, check/repair and enclosure locate LEDs.
//! Every operation is planned here from validated, typed parameters; the
//! generic write path in ops.rs enforces the writes switch, protected
//! disks, typed confirmation, dry run and the audit log.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use super::ops::{bad, decode, failed, tool_exists, Action, OpError, Plan};
use super::Server;
use crate::fstab::{self, FsEntry, Line};
use crate::inventory::{parse_findmnt, Disk, Inventory, Mount};
use crate::proto::*;

/// Mountpoints FSView never unmounts.
const SYSTEM_MOUNTS: [&str; 10] = [
    "/",
    "/boot",
    "/boot/efi",
    "/efi",
    "/usr",
    "/var",
    "/home",
    "/tmp",
    "/root",
    "/etc/pve",
];
const SYSTEM_PREFIXES: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];
/// Filesystems that belong to something else (RAID, LVM, ZFS, LUKS).
const MEMBER_TYPES: [&str; 6] = [
    "linux_raid_member",
    "LVM2_member",
    "zfs_member",
    "crypto_LUKS",
    "ddf_raid_member",
    "isw_raid_member",
];

fn part_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^(sd[a-z]{1,3}[0-9]{1,3}|vd[a-z]{1,3}[0-9]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}p[0-9]{1,3}|mmcblk[0-9]{1,3}p[0-9]{1,3}|loop[0-9]{1,4}p[0-9]{1,3})$").unwrap()
    })
}

fn label_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$").unwrap())
}

fn slot_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9:._ -]{1,64}$").unwrap())
}

/// A filesystem-capable block device resolved from the inventory.
#[derive(Debug, Clone)]
pub(super) struct BlockDev {
    /// Parent whole disk (the target for protection and confirmation).
    pub disk: String,
    pub name: String,
    pub path: String,
    pub is_disk: bool,
    pub fstype: String,
    /// Mountpoints of this device and everything below it.
    pub mounted: Vec<String>,
    /// Non-partition children (LVM, md, crypt) below it.
    pub holders: Vec<String>,
}

fn resolve(inv: &Inventory, name: &str) -> Option<BlockDev> {
    for d in &inv.disks {
        if d.name == name {
            let mut mounted = d.mountpoints.clone();
            let mut holders = vec![];
            d.walk(&mut |n| {
                mounted.extend(n.mountpoints.iter().cloned());
                if n.kind != "part" {
                    holders.push(format!("{} ({})", n.name, n.kind));
                } else if MEMBER_TYPES.contains(&n.fstype.as_str()) {
                    holders.push(format!("{} ({})", n.name, n.fstype));
                }
            });
            return Some(BlockDev {
                disk: d.name.clone(),
                name: d.name.clone(),
                path: d.path.clone(),
                is_disk: true,
                fstype: d.fstype.clone(),
                mounted,
                holders,
            });
        }
        let mut found = None;
        find_node(d, name, &mut found);
        if found.is_some() {
            return found;
        }
    }
    None
}

fn find_node(d: &Disk, name: &str, out: &mut Option<BlockDev>) {
    d.walk(&mut |n| {
        if out.is_none() && n.name == name && n.kind == "part" {
            let mut mounted = n.mountpoints.clone();
            let mut holders = vec![];
            fn rec(ns: &[crate::inventory::Node], m: &mut Vec<String>, h: &mut Vec<String>) {
                for c in ns {
                    m.extend(c.mountpoints.iter().cloned());
                    h.push(format!("{} ({})", c.name, c.kind));
                    rec(&c.children, m, h);
                }
            }
            rec(&n.children, &mut mounted, &mut holders);
            *out = Some(BlockDev {
                disk: d.name.clone(),
                name: n.name.clone(),
                path: n.path.clone(),
                is_disk: false,
                fstype: n.fstype.clone(),
                mounted,
                holders,
            });
        }
    });
}

fn label_of(inv: &Inventory, name: &str) -> String {
    for d in &inv.disks {
        if d.name == name {
            return d.label.clone();
        }
        let mut l = None;
        d.walk(&mut |n| {
            if n.name == name {
                l = Some(n.label.clone());
            }
        });
        if let Some(l) = l {
            return l;
        }
    }
    String::new()
}

/// `p` is `t` or inside it.
fn under(p: &str, t: &str) -> bool {
    p == t || p.starts_with(&format!("{t}/"))
}

/// Path of a mergerfs branch entry ("/mnt/a=RW" -> "/mnt/a").
fn branch_path(b: &str) -> &str {
    b.split('=').next().unwrap_or(b)
}

/// Replaces the branch list of a running pool.
fn set_branches(pool: &str, branches: &[String]) -> Action {
    Action::Run(vec![
        "setfattr".into(),
        "-n".into(),
        "user.mergerfs.branches".into(),
        "-v".into(),
        branches.join(":"),
        format!("{pool}/.mergerfs"),
    ])
}

/// First partition of a disk as the kernel will name it.
fn first_partition(disk: &str) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{disk}p1")
    } else {
        format!("{disk}1")
    }
}

fn mkfs_command(fstype: &str, label: &str, dev: &str) -> Result<Vec<String>, OpError> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let (max, cmd) = match fstype {
        "ext4" => (16, s(&["mkfs.ext4", "-F", "-L", label, dev])),
        "xfs" => (12, s(&["mkfs.xfs", "-f", "-L", label, dev])),
        "btrfs" => (16, s(&["mkfs.btrfs", "-f", "-L", label, dev])),
        "vfat" => (11, s(&["mkfs.vfat", "-F", "32", "-n", label, dev])),
        "exfat" => (15, s(&["mkfs.exfat", "-L", label, dev])),
        _ => return Err(bad("filesystem must be ext4, xfs, btrfs, vfat or exfat")),
    };
    if label.len() > max {
        return Err(bad(format!(
            "{fstype} labels can be at most {max} characters"
        )));
    }
    if !tool_exists(&cmd[0]) {
        let pkg = match fstype {
            "xfs" => "xfsprogs",
            "btrfs" => "btrfs-progs",
            "vfat" => "dosfstools",
            "exfat" => "exfatprogs",
            _ => "e2fsprogs",
        };
        return Err(bad(format!(
            "{} is not installed (apt install {pkg})",
            cmd[0]
        )));
    }
    Ok(cmd)
}

/// Read-only check and repair commands for a filesystem type.
fn fsck_commands(fstype: &str, dev: &str) -> Result<(Vec<String>, Vec<String>), OpError> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let (check, repair) = match fstype {
        "ext2" | "ext3" | "ext4" => (
            s(&["e2fsck", "-f", "-n", dev]),
            s(&["e2fsck", "-f", "-y", dev]),
        ),
        "xfs" => (s(&["xfs_repair", "-n", dev]), s(&["xfs_repair", dev])),
        "vfat" => (s(&["fsck.vfat", "-n", dev]), s(&["fsck.vfat", "-a", dev])),
        "exfat" => (s(&["fsck.exfat", "-n", dev]), s(&["fsck.exfat", "-y", dev])),
        "btrfs" => (s(&["btrfs", "check", "--readonly", dev]), vec![]),
        "" => return Err(bad("no filesystem on this device")),
        other => {
            return Err(bad(format!(
                "checking {other} filesystems is not supported"
            )))
        }
    };
    Ok((check, repair))
}

fn is_system_mount(t: &str) -> bool {
    SYSTEM_MOUNTS.contains(&t)
        || SYSTEM_PREFIXES
            .iter()
            .any(|p| t == *p || t.starts_with(&format!("{p}/")))
}

/// Branch paths of a mergerfs fstab entry ("a:b=RW:c" or "mergerfs#a:b").
pub fn mergerfs_branches(e: &FsEntry) -> Vec<String> {
    e.spec
        .trim_start_matches("mergerfs#")
        .split(':')
        .map(|b| b.split('=').next().unwrap_or("").to_string())
        .filter(|b| !b.is_empty())
        .collect()
}

pub fn is_mergerfs(e: &FsEntry) -> bool {
    e.vfstype == "fuse.mergerfs" || (e.vfstype == "fuse" && e.spec.starts_with("mergerfs#"))
}

impl Server {
    pub(super) fn mounts(&self) -> Result<Vec<Mount>, OpError> {
        let r = self
            .runner
            .run("findmnt", &["-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
            .map_err(|e| failed(format!("findmnt: {e}")))?;
        parse_findmnt(&r.stdout).map_err(failed)
    }

    /// Mounts of real and FUSE filesystems with usage. Network and
    /// virtual filesystems are skipped (statfs on a dead NFS server hangs).
    pub(super) fn mounts_list(&self) -> Result<Vec<MountInfo>, OpError> {
        let r = self
            .runner
            .run(
                "findmnt",
                &[
                    "-J",
                    "-b",
                    "-t",
                    "ext2,ext3,ext4,xfs,btrfs,vfat,exfat,ntfs,ntfs3,fuseblk,fuse.mergerfs,zfs,f2fs",
                    "-o",
                    "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL",
                ],
            )
            .map_err(|e| failed(format!("findmnt: {e}")))?;
        if r.stdout.iter().all(u8::is_ascii_whitespace) {
            return Ok(vec![]);
        }
        parse_mount_list(&r.stdout).map_err(failed)
    }

    fn fstab_entries(&self) -> Result<Vec<FsEntry>, OpError> {
        let text = std::fs::read_to_string(&self.cfg.fstab_path)
            .map_err(|e| failed(format!("{}: {e}", self.cfg.fstab_path.display())))?;
        Ok(fstab::parse(&text)
            .lines
            .into_iter()
            .filter_map(|l| match l {
                Line::Entry { entry, .. } => Some(entry),
                _ => None,
            })
            .collect())
    }

    fn block_dev(&self, inv: &Inventory, name: &str) -> Result<BlockDev, OpError> {
        if !super::ops::disk_re().is_match(name) && !part_re().is_match(name) {
            return Err(bad(format!("invalid device name {name:?}")));
        }
        if name.starts_with("loop") && !self.cfg.include_loop {
            return Err(bad("loop devices are not enabled"));
        }
        resolve(inv, name).ok_or_else(|| bad(format!("device {name} not found")))
    }

    pub(super) fn prep_mount(&self, req: &Request) -> Result<Plan, OpError> {
        let p: MountParams = decode(req)?;
        let t = p.target.trim_end_matches('/');
        let t = if t.is_empty() { "/" } else { t };
        let entries = self.fstab_entries()?;
        let e = entries.iter().find(|e| e.file == t).ok_or_else(|| {
            bad(format!(
                "{t} is not in {} (add it on the fstab page first)",
                self.cfg.fstab_path.display()
            ))
        })?;
        if e.vfstype == "swap" {
            return Err(bad("swap entries are not mounted here"));
        }
        let mounts = self.mounts()?;
        let reattach = self.reattach_actions(&entries, &mounts, t);
        if mounts.iter().any(|m| m.target == t) {
            if reattach.is_empty() {
                return Err(bad(format!("{t} is already mounted")));
            }
            return Ok(Plan {
                targets: vec![t.into()],
                actions: reattach,
                summary: format!("re-attach {t} to its pool"),
                detail: String::new(),
            });
        }
        if is_mergerfs(e) {
            if !tool_exists("mergerfs") {
                return Err(bad("mergerfs is not installed (apt install mergerfs)"));
            }
            // The pool must never mount on top of missing branches: writes
            // would land on the disk underneath.
            for b in mergerfs_branches(e) {
                let owner = entries
                    .iter()
                    .filter(|o| o.file != "/" && o.file != t && o.vfstype != "swap")
                    .filter(|o| b == o.file || b.starts_with(&format!("{}/", o.file)))
                    .max_by_key(|o| o.file.len());
                if let Some(o) = owner {
                    if !mounts.iter().any(|m| m.target == o.file) {
                        return Err(bad(format!(
                            "branch {b} is on {} which is not mounted; mount it first",
                            o.file
                        )));
                    }
                }
                if !b.contains('*') && !Path::new(&b).is_dir() {
                    return Err(bad(format!("branch {b} does not exist")));
                }
            }
        }
        let mut actions = vec![];
        if !Path::new(t).exists() {
            if !fstab::creatable_mountpoint(t) {
                return Err(bad(format!("mountpoint {t} does not exist")));
            }
            actions.push(Action::Mkdir(t.into()));
        }
        let cmd = if is_mergerfs(e) {
            // Started directly: older FUSE mount helpers pass fstab-only
            // options such as nofail through to mergerfs, which rejects them.
            let opts: Vec<&str> = e
                .options
                .split(',')
                .filter(|o| {
                    !o.is_empty()
                        && ![
                            "defaults", "nofail", "noauto", "auto", "_netdev", "user", "users",
                        ]
                        .contains(o)
                        && !o.starts_with("x-")
                        && !o.starts_with("comment=")
                })
                .collect();
            let mut c = vec!["mergerfs".to_string()];
            if !opts.is_empty() {
                c.extend(["-o".into(), opts.join(",")]);
            }
            c.extend([
                e.spec.trim_start_matches("mergerfs#").to_string(),
                t.to_string(),
            ]);
            c
        } else {
            let mut c = vec!["mount".to_string()];
            if self.cfg.fstab_path != Path::new("/etc/fstab") {
                c.extend(["-T".into(), self.cfg.fstab_path.display().to_string()]);
            }
            c.push(t.into());
            c
        };
        actions.push(Action::Run(cmd));
        let rejoin = !reattach.is_empty();
        actions.extend(reattach);
        Ok(Plan {
            targets: vec![t.into()],
            actions,
            summary: if rejoin {
                format!("mount {t} and re-attach it to its pool")
            } else {
                format!("mount {t}")
            },
            detail: String::new(),
        })
    }

    pub(super) fn prep_umount(&self, req: &Request) -> Result<Plan, OpError> {
        let p: MountParams = decode(req)?;
        if !p.target.starts_with('/') {
            return Err(bad("target must be an absolute mountpoint"));
        }
        let t = match p.target.trim_end_matches('/') {
            "" => "/",
            t => t,
        };
        if is_system_mount(t) {
            return Err(bad(format!(
                "{t} is a system mount and is never unmounted by FSView"
            )));
        }
        let mounts = self.mounts()?;
        let m = mounts
            .iter()
            .find(|m| m.target == t)
            .ok_or_else(|| bad(format!("{t} is not mounted")))?;
        let inv = self.inventory().map_err(failed)?;
        for d in inv.disks.iter().filter(|d| d.protected) {
            let mut on = d.mountpoints.iter().any(|x| x == t);
            d.walk(&mut |n| on |= n.mountpoints.iter().any(|x| x == t));
            if on {
                return Err(bad(format!("{t} is on protected system disk {}", d.name)));
            }
        }
        if let Some(n) = mounts
            .iter()
            .find(|o| o.target.starts_with(&format!("{t}/")))
        {
            return Err(bad(format!(
                "{} is mounted inside {t}; unmount it first",
                n.target
            )));
        }
        // A mounted pool with a branch here keeps running without it: the
        // branch is detached live first. A pool that would be left empty
        // has to be unmounted instead.
        let mut actions = vec![];
        let mut detached = vec![];
        for e in self.fstab_entries()?.iter().filter(|e| is_mergerfs(e)) {
            if e.file == t
                || !mounts.iter().any(|m| m.target == e.file)
                || !mergerfs_branches(e).iter().any(|b| under(b, t))
            {
                continue;
            }
            let Some(live) = self.live_branches(&e.file) else {
                return Err(bad(format!(
                    "pool {} uses {t}; unmount the pool first (install the attr package to let FSView detach disks from a running pool)",
                    e.file
                )));
            };
            let keep: Vec<String> = live
                .iter()
                .filter(|b| !under(branch_path(b), t))
                .cloned()
                .collect();
            if keep.is_empty() {
                return Err(bad(format!(
                    "{t} is the only disk in pool {}; unmount the pool first",
                    e.file
                )));
            }
            if keep.len() != live.len() {
                actions.push(set_branches(&e.file, &keep));
                detached.push(e.file.clone());
            }
        }
        if let Some(users) = self.mount_users(t) {
            return Err(bad(format!(
                "{t} is in use by {users}; stop those first (for containers or VMs, shut them down)"
            )));
        }
        actions.push(Action::Run(vec!["umount".into(), t.into()]));
        Ok(Plan {
            targets: vec![t.into()],
            actions,
            summary: if detached.is_empty() {
                format!("unmount {t} ({})", m.source)
            } else {
                format!(
                    "unmount {t} ({}); pool {} keeps running without it",
                    m.source,
                    detached.join(", ")
                )
            },
            detail: String::new(),
        })
    }

    /// Branches of a running mergerfs pool, as mergerfs reports them
    /// ("/mnt/a=RW", ...). None if they cannot be read.
    fn live_branches(&self, pool: &str) -> Option<Vec<String>> {
        if !tool_exists("getfattr") || !tool_exists("setfattr") {
            return None;
        }
        let ctl = format!("{pool}/.mergerfs");
        let r = self
            .runner
            .run(
                "getfattr",
                &["--only-values", "-n", "user.mergerfs.branches", &ctl],
            )
            .ok()?;
        if r.code != 0 {
            return None;
        }
        let v = String::from_utf8_lossy(&r.stdout);
        Some(
            v.trim()
                .split(':')
                .filter(|b| !b.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }

    /// After `t` is mounted (or while it is mounted but detached), puts
    /// its branches back into running pools, in fstab order.
    fn reattach_actions(&self, entries: &[FsEntry], mounts: &[Mount], t: &str) -> Vec<Action> {
        let mut out = vec![];
        for e in entries.iter().filter(|e| is_mergerfs(e)) {
            if e.file == t || !mounts.iter().any(|m| m.target == e.file) {
                continue;
            }
            let wanted: Vec<String> = e
                .spec
                .trim_start_matches("mergerfs#")
                .split(':')
                .filter(|b| !b.is_empty())
                .map(str::to_string)
                .collect();
            if !wanted.iter().any(|b| under(branch_path(b), t)) {
                continue;
            }
            let Some(live) = self.live_branches(&e.file) else {
                continue;
            };
            let live_paths: Vec<&str> = live.iter().map(|b| branch_path(b)).collect();
            let desired: Vec<String> = wanted
                .iter()
                .filter(|b| {
                    let p = branch_path(b);
                    under(p, t) || live_paths.contains(&p)
                })
                .cloned()
                .collect();
            let desired_paths: Vec<&str> = desired.iter().map(|b| branch_path(b)).collect();
            if desired_paths != live_paths {
                out.push(set_branches(&e.file, &desired));
            }
        }
        out
    }

    /// Processes using a mount, e.g. "plex (1234), smbd (99)".
    fn mount_users(&self, t: &str) -> Option<String> {
        if !tool_exists("fuser") {
            return None;
        }
        let r = self.runner.run("fuser", &["-m", t]).ok()?;
        let pids: Vec<u32> = String::from_utf8_lossy(&r.stdout)
            .split_whitespace()
            .filter_map(|p| {
                p.trim_end_matches(|c: char| c.is_ascii_alphabetic())
                    .parse()
                    .ok()
            })
            .collect();
        if pids.is_empty() {
            return None;
        }
        let mut names: Vec<String> = pids
            .iter()
            .take(12)
            .map(|p| {
                let comm = std::fs::read_to_string(format!("/proc/{p}/comm")).unwrap_or_default();
                format!("{} ({p})", comm.trim())
            })
            .collect();
        if pids.len() > 12 {
            names.push(format!("and {} more", pids.len() - 12));
        }
        Some(names.join(", "))
    }

    /// Rejects devices that are mounted or in use by another layer.
    fn ensure_idle(dev: &BlockDev) -> Result<(), OpError> {
        if let Some(m) = dev.mounted.first() {
            return Err(bad(format!(
                "{} is in use ({}); unmount it first",
                dev.name,
                if m == "[SWAP]" { "active swap" } else { m }
            )));
        }
        if !dev.holders.is_empty()
            && !(dev.is_disk && dev.holders.iter().all(|h| h.ends_with("(part)")))
        {
            return Err(bad(format!(
                "{} is used by {}; remove that first",
                dev.name,
                dev.holders.join(", ")
            )));
        }
        if MEMBER_TYPES.contains(&dev.fstype.as_str()) {
            return Err(bad(format!(
                "{} is a {} (part of an array, volume group, pool or encrypted volume); remove it from there first",
                dev.name, dev.fstype
            )));
        }
        Ok(())
    }

    pub(super) fn prep_format(&self, req: &Request) -> Result<Plan, OpError> {
        let p: FormatParams = decode(req)?;
        if !label_re().is_match(&p.label) {
            return Err(bad(
                "label: 1-16 letters, digits, '.', '_' or '-', starting with a letter or digit",
            ));
        }
        let inv = self.inventory().map_err(failed)?;
        let dev = self.block_dev(&inv, &p.device)?;
        if p.partition && !dev.is_disk {
            return Err(bad(
                "a new partition table can only be created on a whole disk",
            ));
        }
        let disk = resolve(&inv, &dev.disk).expect("parent exists");
        // Formatting a whole disk (with or without a new partition table)
        // destroys every partition on it.
        Self::ensure_idle(if dev.is_disk { &disk } else { &dev })?;
        if dev.is_disk && !p.partition && disk.holders.iter().any(|h| h.ends_with("(part)")) {
            return Err(bad(format!(
                "{} has partitions; format a partition, or choose \"new partition table\"",
                dev.name
            )));
        }
        let mut actions = vec![Action::Run(vec![
            "wipefs".into(),
            "-a".into(),
            dev.path.clone(),
        ])];
        let fs_dev = if p.partition {
            if !tool_exists("sgdisk") {
                return Err(bad("sgdisk is not installed (apt install gdisk)"));
            }
            let part = format!("/dev/{}", first_partition(&dev.name));
            actions.push(Action::Run(vec![
                "sgdisk".into(),
                "--zap-all".into(),
                dev.path.clone(),
            ]));
            actions.push(Action::Run(vec![
                "sgdisk".into(),
                "-n".into(),
                "1:0:0".into(),
                "-t".into(),
                "1:8300".into(),
                "-c".into(),
                format!("1:{}", p.label),
                dev.path.clone(),
            ]));
            actions.push(Action::Run(vec![
                "partx".into(),
                "-u".into(),
                dev.path.clone(),
            ]));
            actions.extend(settle());
            actions.push(Action::WaitDevice(part.clone().into()));
            part
        } else {
            dev.path.clone()
        };
        actions.push(Action::Run(mkfs_command(&p.fstype, &p.label, &fs_dev)?));
        actions.extend(settle());
        Ok(Plan {
            targets: vec![dev.disk.clone()],
            actions,
            summary: format!(
                "format {fs_dev} as {} labelled {}{}",
                p.fstype,
                p.label,
                if p.partition {
                    " (new GPT partition table)"
                } else {
                    ""
                }
            ),
            detail: String::new(),
        })
    }

    pub(super) fn prep_fs_check(&self, req: &Request, repair: bool) -> Result<Plan, OpError> {
        let p: FsCheckParams = decode(req)?;
        let inv = self.inventory().map_err(failed)?;
        let dev = self.block_dev(&inv, &p.device)?;
        if !dev.mounted.is_empty() {
            return Err(bad(format!(
                "{} is mounted at {}; unmount it first (a check of a mounted filesystem is not reliable)",
                dev.name,
                dev.mounted.join(", ")
            )));
        }
        let (check, fix) = fsck_commands(&dev.fstype, &dev.path)?;
        let cmd = if repair { fix } else { check };
        if cmd.is_empty() {
            return Err(bad(format!(
                "FSView does not repair {} (btrfs check --repair can make things worse); mount it and run a scrub instead",
                dev.fstype
            )));
        }
        if !tool_exists(&cmd[0]) {
            return Err(bad(format!("{} is not installed", cmd[0])));
        }
        Ok(Plan {
            targets: vec![dev.disk.clone()],
            actions: vec![Action::Run(cmd)],
            summary: format!(
                "{} {} filesystem on {}",
                if repair { "repair" } else { "check" },
                dev.fstype,
                dev.path
            ),
            detail: String::new(),
        })
    }

    /// Changes a filesystem label. Refused when fstab mounts it by its
    /// current label (the entry would stop matching at the next boot).
    pub(super) fn prep_label(&self, req: &Request) -> Result<Plan, OpError> {
        let p: LabelParams = decode(req)?;
        if !label_re().is_match(&p.label) {
            return Err(bad(
                "label: 1-16 letters, digits, '.', '_' or '-', starting with a letter or digit",
            ));
        }
        let inv = self.inventory().map_err(failed)?;
        let dev = self.block_dev(&inv, &p.device)?;
        if inv.find_disk(&dev.disk).is_some_and(|d| d.protected) {
            return Err(bad(format!("{} is on a protected system disk", dev.name)));
        }
        let old = label_of(&inv, &dev.name);
        if !old.is_empty() {
            if let Some(e) = self.fstab_entries()?.iter().find(|e| {
                e.spec == format!("LABEL={old}") || e.spec == format!("/dev/disk/by-label/{old}")
            }) {
                return Err(bad(format!(
                    "fstab mounts {} by its label ({}); change that entry to UUID= on the fstab page first",
                    e.file, e.spec
                )));
            }
        }
        let mounted = dev.mounted.first().cloned();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let (max, cmd) = match dev.fstype.as_str() {
            "ext2" | "ext3" | "ext4" => (16, s(&["e2label", &dev.path, &p.label])),
            "xfs" => {
                if mounted.is_some() {
                    return Err(bad(
                        "XFS labels can only be changed while unmounted; unmount it first",
                    ));
                }
                (12, s(&["xfs_admin", "-L", &p.label, &dev.path]))
            }
            "btrfs" => (
                255,
                s(&[
                    "btrfs",
                    "filesystem",
                    "label",
                    mounted.as_deref().unwrap_or(&dev.path),
                    &p.label,
                ]),
            ),
            "vfat" => (11, s(&["fatlabel", &dev.path, &p.label.to_uppercase()])),
            "exfat" => (15, s(&["exfatlabel", &dev.path, &p.label])),
            "ntfs" => {
                if mounted.is_some() {
                    return Err(bad(
                        "NTFS labels can only be changed while unmounted; unmount it first",
                    ));
                }
                (32, s(&["ntfslabel", &dev.path, &p.label]))
            }
            "" => return Err(bad("no filesystem on this device")),
            other => {
                return Err(bad(format!(
                    "renaming {other} filesystems is not supported"
                )))
            }
        };
        if p.label.len() > max {
            return Err(bad(format!(
                "{} labels can be at most {max} characters",
                dev.fstype
            )));
        }
        if !tool_exists(&cmd[0]) {
            let pkg = match cmd[0].as_str() {
                "ntfslabel" => " (apt install ntfs-3g)",
                "fatlabel" => " (apt install dosfstools)",
                "exfatlabel" => " (apt install exfatprogs)",
                "xfs_admin" => " (apt install xfsprogs)",
                _ => "",
            };
            return Err(bad(format!("{} is not installed{pkg}", cmd[0])));
        }
        let mut actions = vec![Action::Run(cmd)];
        // Label tools write the disk directly; udev (and so lsblk and
        // /dev/disk/by-label) only notices after a change event.
        if tool_exists("udevadm") {
            actions.push(Action::Run(vec![
                "udevadm".into(),
                "trigger".into(),
                "--action=change".into(),
                dev.path.clone(),
            ]));
        }
        actions.extend(settle());
        Ok(Plan {
            targets: vec![dev.disk.clone()],
            actions,
            summary: format!(
                "rename {} from {} to {}",
                dev.path,
                if old.is_empty() { "(no label)" } else { &old },
                p.label
            ),
            detail: String::new(),
        })
    }

    pub(super) fn prep_locate(&self, req: &Request) -> Result<Plan, OpError> {
        let p: LocateParams = decode(req)?;
        self.valid_disk(&p.device)?;
        let inv = self.inventory().map_err(failed)?;
        let d = inv
            .find_disk(&p.device)
            .ok_or_else(|| bad(format!("{} not found", p.device)))?;
        let slot = d.topology.enclosure.as_ref().ok_or_else(|| {
            bad(format!(
                "{} is not in an enclosure slot the kernel knows",
                p.device
            ))
        })?;
        if !slot_re().is_match(&slot.enclosure) || !slot_re().is_match(&slot.component) {
            return Err(bad("unexpected enclosure name"));
        }
        let path: PathBuf = self
            .cfg
            .sys_root
            .join("class/enclosure")
            .join(&slot.enclosure)
            .join(&slot.component)
            .join("locate");
        if !path.exists() {
            return Err(bad("this enclosure has no locate LED control"));
        }
        Ok(Plan {
            targets: vec![d.name.clone()],
            actions: vec![Action::WriteSysfs {
                path,
                value: if p.on { "1" } else { "0" }.into(),
            }],
            summary: format!(
                "locate LED {} for {} (slot {})",
                if p.on { "on" } else { "off" },
                d.name,
                slot.component
            ),
            detail: String::new(),
        })
    }
}

/// Parses `findmnt -J -b` with size columns (numbers or strings).
pub fn parse_mount_list(data: &[u8]) -> Result<Vec<MountInfo>, String> {
    use serde_json::Value;
    let doc: Value = serde_json::from_slice(data).map_err(|e| format!("parse findmnt: {e}"))?;
    let mut out = Vec::new();
    fn num(v: Option<&Value>) -> u64 {
        match v {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            _ => 0,
        }
    }
    fn rec(v: &Value, out: &mut Vec<MountInfo>) {
        if let Value::Array(a) = v {
            for f in a {
                let g = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                out.push(MountInfo {
                    target: g("target"),
                    source: g("source"),
                    fstype: g("fstype"),
                    options: g("options"),
                    size_bytes: num(f.get("size")),
                    used_bytes: num(f.get("used")),
                    avail_bytes: num(f.get("avail")),
                });
                if let Some(c) = f.get("children") {
                    rec(c, out);
                }
            }
        }
    }
    rec(doc.get("filesystems").unwrap_or(&Value::Null), &mut out);
    Ok(out)
}

fn settle() -> Option<Action> {
    tool_exists("udevadm").then(|| {
        Action::Run(vec![
            "udevadm".into(),
            "settle".into(),
            "--timeout=30".into(),
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_names() {
        assert_eq!(first_partition("sdb"), "sdb1");
        assert_eq!(first_partition("nvme0n1"), "nvme0n1p1");
        assert_eq!(first_partition("loop3"), "loop3p1");
    }

    #[test]
    fn system_mounts() {
        for t in [
            "/",
            "/boot/efi",
            "/proc",
            "/sys/fs/cgroup",
            "/run/user/0",
            "/etc/pve",
        ] {
            assert!(is_system_mount(t), "{t}");
        }
        for t in ["/mnt/media1", "/srv/data", "/running"] {
            assert!(!is_system_mount(t), "{t}");
        }
    }

    #[test]
    fn branches() {
        let e = FsEntry {
            spec: "/mnt/a:/mnt/b=RO:/mnt/c/data".into(),
            vfstype: "fuse.mergerfs".into(),
            ..Default::default()
        };
        assert!(is_mergerfs(&e));
        assert_eq!(
            mergerfs_branches(&e),
            vec!["/mnt/a", "/mnt/b", "/mnt/c/data"]
        );
    }

    #[test]
    fn mount_list() {
        let m = parse_mount_list(br#"{"filesystems":[{"target":"/mnt/a","source":"/dev/sdb1","fstype":"ext4","options":"rw","size":1000,"used":"400","avail":600,"children":[{"target":"/mnt/a/b","source":"a:b","fstype":"fuse.mergerfs","options":"rw","size":5,"used":1,"avail":4}]}]}"#).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].size_bytes, m[0].used_bytes), (1000, 400));
        assert_eq!(m[1].fstype, "fuse.mergerfs");
    }

    #[test]
    fn labels() {
        assert!(label_re().is_match("media7"));
        for l in ["", "-x", "a b", "x;rm", "averyveryverylonglabel"] {
            assert!(!label_re().is_match(l), "{l}");
        }
        assert!(mkfs_command("xfs", "thirteenchars", "/dev/x").is_err());
        assert!(mkfs_command("ntfs", "x", "/dev/x").is_err());
    }
}
