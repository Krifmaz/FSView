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

/// Branch paths with their mergerfs mode suffix (e.g. "NC" from
/// "/mnt/disk=NC"), empty when none is set.
pub fn mergerfs_branch_modes(e: &FsEntry) -> Vec<(String, String)> {
    e.spec
        .trim_start_matches("mergerfs#")
        .split(':')
        .filter_map(|b| {
            let (p, m) = b.split_once('=').unwrap_or((b, ""));
            (!p.is_empty()).then(|| (p.to_string(), m.to_string()))
        })
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

    pub(super) fn fstab_entries(&self) -> Result<Vec<FsEntry>, OpError> {
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
            if reattach.is_empty() && is_mergerfs(e) {
                return self.apply_pool_live(e, &entries, &mounts);
            }
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
            check_branches(e, &entries, &mounts)?;
        }
        let mut actions = vec![];
        if !Path::new(t).exists() {
            if !fstab::creatable_mountpoint(t) {
                return Err(bad(format!("mountpoint {t} does not exist")));
            }
            actions.push(Action::Mkdir(t.into()));
        }
        let cmd = self.mount_command(e);
        actions.push(Action::Run(own_scope(cmd)));
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
        // The now-empty mountpoint must not take writes meant for the disk
        // (e.g. from a pool or a container still pointing at it).
        if fstab::creatable_mountpoint(t) && tool_exists("chattr") {
            actions.push(Action::Run(vec!["chattr".into(), "+i".into(), t.into()]));
        }
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
    pub(super) fn mount_users(&self, t: &str) -> Option<String> {
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

impl Server {
    /// Sets the immutable flag on the directories underneath every data
    /// mount in fstab (seen through a bind mount of / without submounts),
    /// so a disk that drops out or is unmounted can't have its files
    /// written onto the system disk instead. Mounting over an immutable
    /// directory works as before.
    pub(super) fn prep_protect_mountpoints(&self) -> Result<Plan, OpError> {
        if !tool_exists("chattr") {
            return Err(bad("chattr is not installed (apt install e2fsprogs)"));
        }
        let entries = self.fstab_entries()?;
        let targets: Vec<String> = entries
            .iter()
            .filter(|e| e.vfstype != "swap" && fstab::creatable_mountpoint(&e.file))
            .map(|e| e.file.clone())
            .collect();
        if targets.is_empty() {
            return Err(bad("no data mountpoints in fstab"));
        }
        let view = self.cfg.scratch_dir.join("rootview");
        let v = view.display().to_string();
        let mut actions = vec![
            Action::Mkdir(view.clone()),
            Action::Run(vec!["mount".into(), "--bind".into(), "/".into(), v.clone()]),
        ];
        for t in &targets {
            actions.push(Action::Run(vec![
                "chattr".into(),
                "+i".into(),
                format!("{v}{t}"),
            ]));
        }
        actions.push(Action::Run(vec!["umount".into(), v]));
        Ok(Plan {
            targets: targets.clone(),
            actions,
            summary: format!(
                "protect {} mountpoint(s) against writes while unmounted",
                targets.len()
            ),
            detail: String::new(),
        })
    }
}

/// Every branch of a pool must exist and sit on a mounted filesystem;
/// otherwise writes would land on the disk underneath the mountpoint.
fn check_branches(e: &FsEntry, entries: &[FsEntry], mounts: &[Mount]) -> Result<(), OpError> {
    for b in mergerfs_branches(e) {
        let owner = entries
            .iter()
            .filter(|o| o.file != "/" && o.file != e.file && o.vfstype != "swap")
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
    Ok(())
}

impl Server {
    /// Applies a mounted pool's fstab settings (branches with their modes,
    /// create policy, minfreespace, moveonenospc) to the running mergerfs
    /// without unmounting it, so programs using the pool keep working.
    fn apply_pool_live(
        &self,
        e: &FsEntry,
        entries: &[FsEntry],
        mounts: &[Mount],
    ) -> Result<Plan, OpError> {
        if !tool_exists("setfattr") {
            return Err(bad("setfattr is not installed (apt install attr)"));
        }
        check_branches(e, entries, mounts)?;
        let t = e.file.as_str();
        let branches: Vec<String> = e
            .spec
            .trim_start_matches("mergerfs#")
            .split(':')
            .filter(|b| !b.is_empty())
            .map(str::to_string)
            .collect();
        let mut actions = vec![set_branches(t, &branches)];
        for opt in e.options.split(',') {
            let (k, v) = opt.split_once('=').unwrap_or((opt, "true"));
            if ["category.create", "minfreespace", "moveonenospc"].contains(&k) {
                actions.push(Action::Run(vec![
                    "setfattr".into(),
                    "-n".into(),
                    format!("user.mergerfs.{k}"),
                    "-v".into(),
                    v.into(),
                    format!("{t}/.mergerfs"),
                ]));
            }
        }
        Ok(Plan {
            targets: vec![t.into()],
            actions,
            summary: format!("apply the fstab settings to the running pool {t}"),
            detail: String::new(),
        })
    }
}

/// Where a pool branch's filesystem stands right now.
#[derive(Debug, Clone, PartialEq)]
enum Owner {
    /// Not on a separate fstab mount.
    Root,
    /// Mounted; `ro` when mounted read-only.
    Up { ro: bool },
    /// Still mounted, but its disk dropped out (the device node is gone
    /// or now belongs to a newer attach), so every access fails.
    Stale(String),
    /// The fstab mountpoint is not mounted.
    Down(String),
}

#[derive(Debug, Clone)]
struct HealBranch {
    path: String,
    /// Mode from fstab ("" means RW), possibly with extra ",..." settings.
    mode: String,
    /// Mode the running pool has for it, None if it is not in the pool.
    live: Option<String>,
    owner: Owner,
}

fn mode_word(m: &str) -> String {
    match m.split(',').next().unwrap_or("") {
        "" => "RW".into(),
        w => w.to_ascii_uppercase(),
    }
}

/// Works out the branch list a running pool should have and the
/// mountpoints to remount first. `blocker` says why a branch's disk must
/// not be trusted with writes again (None when it is fine); it is only
/// asked about branches that would change, so healthy pools never touch
/// their disks.
fn heal_branches(
    bs: &[HealBranch],
    blocker: &mut dyn FnMut(&HealBranch) -> Option<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut desired, mut remount, mut notes) = (vec![], vec![], vec![]);
    let keep = |b: &HealBranch, out: &mut Vec<String>| {
        if let Some(l) = &b.live {
            out.push(format!("{}={l}", b.path));
        }
    };
    let want = |b: &HealBranch| {
        if b.mode.is_empty() {
            format!("{}=RW", b.path)
        } else {
            format!("{}={}", b.path, b.mode)
        }
    };
    for b in bs {
        let upgrade = b
            .live
            .as_ref()
            .is_some_and(|l| mode_word(l) != mode_word(&b.mode));
        match &b.owner {
            Owner::Up { ro: true } => desired.push(format!("{}=RO", b.path)),
            Owner::Root | Owner::Up { .. } => {
                if upgrade {
                    if let Some(why) = blocker(b) {
                        notes.push(format!(
                            "{} stays {}: {why}",
                            b.path,
                            mode_word(b.live.as_deref().unwrap_or(""))
                        ));
                        keep(b, &mut desired);
                        continue;
                    }
                }
                desired.push(want(b));
            }
            Owner::Down(t) | Owner::Stale(t) => {
                // Only branches that dropped out are brought back; one that
                // was detached on purpose (FSView unmount) is not in the pool.
                if b.live.is_none() {
                    continue;
                }
                if !remount.contains(t) {
                    if let Some(why) = blocker(b) {
                        notes.push(format!("{t} not remounted: {why}"));
                        if matches!(b.owner, Owner::Stale(_)) {
                            // A dead mount still looks like free space, so
                            // new files would keep failing on it.
                            desired.push(format!("{}=RO", b.path));
                        } else {
                            keep(b, &mut desired);
                        }
                        continue;
                    }
                    remount.push(t.clone());
                }
                desired.push(want(b));
            }
        }
    }
    (desired, remount, notes)
}

/// A block filesystem whose disk dropped out while mounted: its device
/// node is gone, or the name now belongs to a fresh attach of the disk.
/// `dev_dir` stands in for `/dev` (tests point it elsewhere).
fn device_lost(m: &Mount, dev_dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(rest) = m.source.strip_prefix("/dev/") else {
        return false;
    };
    let Ok(dev) = std::fs::metadata(dev_dir.join(rest)) else {
        return true;
    };
    // Only filesystems whose st_dev is the block device itself.
    if ![
        "ext2", "ext3", "ext4", "xfs", "vfat", "exfat", "ntfs3", "f2fs",
    ]
    .contains(&m.fstype.as_str())
    {
        return false;
    }
    std::fs::metadata(&m.target).is_ok_and(|t| t.dev() != dev.rdev())
}

/// Device node an fstab spec refers to, if it is a local block device.
fn spec_device(spec: &str) -> Option<PathBuf> {
    for (tag, dir) in [
        ("UUID=", "by-uuid"),
        ("LABEL=", "by-label"),
        ("PARTUUID=", "by-partuuid"),
        ("PARTLABEL=", "by-partlabel"),
    ] {
        if let Some(v) = spec.strip_prefix(tag) {
            return Some(PathBuf::from(format!(
                "/dev/disk/{dir}/{}",
                v.trim_matches('"')
            )));
        }
    }
    spec.starts_with("/dev/").then(|| PathBuf::from(spec))
}

impl Server {
    /// Brings running mergerfs pools back to their fstab state after a
    /// disk dropped out: remounts branch disks that are back (and not
    /// failing or carrying filesystem errors) and restores branches
    /// mergerfs switched to read-only. An empty plan means nothing to do.
    pub(super) fn prep_pool_heal(&self, req: &Request) -> Result<Plan, OpError> {
        let p: PoolHealParams = decode(req)?;
        let entries = self.fstab_entries()?;
        let mounts = self.mounts()?;
        let inv = self.inventory().ok();
        let mut plan = Plan {
            targets: vec![],
            actions: vec![],
            summary: String::new(),
            detail: String::new(),
        };
        let mut done = vec![];
        let mut notes = vec![];
        let mut kernel_log: Option<Vec<crate::events::Entry>> = None;
        for pool in entries.iter().filter(|e| is_mergerfs(e)) {
            if pool.spec.contains('*') || !mounts.iter().any(|m| m.target == pool.file) {
                continue;
            }
            let Some(live) = self.live_branches(&pool.file) else {
                continue;
            };
            let bs: Vec<HealBranch> = mergerfs_branch_modes(pool)
                .into_iter()
                .map(|(path, mode)| {
                    let live = live
                        .iter()
                        .find(|l| branch_path(l) == path)
                        .map(|l| l.split_once('=').map(|x| x.1).unwrap_or("RW").to_string());
                    let owner = match branch_owner(&path, pool, &entries) {
                        None => Owner::Root,
                        Some(o) => match mounts.iter().find(|m| m.target == o.file) {
                            Some(m) if device_lost(m, &self.cfg.dev_dir) => {
                                Owner::Stale(o.file.clone())
                            }
                            Some(m) => Owner::Up {
                                ro: m.options.split(',').any(|x| x == "ro"),
                            },
                            None => Owner::Down(o.file.clone()),
                        },
                    };
                    HealBranch {
                        path,
                        mode,
                        live,
                        owner,
                    }
                })
                .collect();
            let mut blocker = |b: &HealBranch| -> Option<String> {
                let (dev, fstype) = match &b.owner {
                    Owner::Root => return None,
                    Owner::Down(t) | Owner::Stale(t) => {
                        let e = entries.iter().find(|e| &e.file == t)?;
                        let Some(d) = spec_device(&e.spec) else {
                            return Some("not a local disk".into());
                        };
                        if !d.exists() {
                            return Some("its disk is not connected".into());
                        }
                        (d, e.vfstype.clone())
                    }
                    _ => {
                        let o = branch_owner(&b.path, pool, &entries)?;
                        let m = mounts.iter().find(|m| m.target == o.file)?;
                        (PathBuf::from(&m.source), m.fstype.clone())
                    }
                };
                let dev = std::fs::canonicalize(&dev)
                    .unwrap_or(dev)
                    .display()
                    .to_string();
                if let Some(inv) = &inv {
                    for d in &inv.disks {
                        let mut on = d.path == dev;
                        d.walk(&mut |n| on |= n.path == dev);
                        if on && p.skip_disks.contains(&d.name) {
                            return Some(format!("{} is failing (SMART)", d.name));
                        }
                    }
                }
                if fstype.starts_with("ext") && tool_exists("dumpe2fs") {
                    if let Ok(r) = self.runner.run("dumpe2fs", &["-h", &dev]) {
                        let out = String::from_utf8_lossy(&r.stdout);
                        if r.code != 0 {
                            return Some(format!("cannot read the filesystem on {dev}"));
                        }
                        if out
                            .lines()
                            .any(|l| l.starts_with("Filesystem state:") && l.contains("error"))
                        {
                            return Some(format!(
                                "the filesystem on {dev} has recorded errors; check it first"
                            ));
                        }
                    }
                }
                None
            };
            let (mut desired, remount, n) = heal_branches(&bs, &mut blocker);
            notes.extend(n);

            // Filesystems under the branches that need fsck: recorded ext
            // errors, or shut down / remounted read-only by the kernel.
            let mut repairing: Vec<String> = vec![];
            let mut broken: Vec<String> = vec![];
            for b in &bs {
                let Owner::Up { .. } = b.owner else { continue };
                let Some(o) = branch_owner(&b.path, pool, &entries) else {
                    continue;
                };
                let Some(m) = mounts.iter().rev().find(|m| m.target == o.file) else {
                    continue;
                };
                let Some(why) = self.needs_fsck(m, o) else {
                    continue;
                };
                broken.push(b.path.clone());
                let dev = super::poolhealth::canonical(&m.source);
                let verdict = if !p.repair {
                    Err("automatic repair is off".to_string())
                } else if done.contains(&o.file) {
                    Err("already handled for another pool".to_string())
                } else {
                    self.auto_repair_check(
                        &o.file,
                        &dev,
                        inv.as_ref(),
                        &p.skip_disks,
                        &mut kernel_log,
                    )
                };
                match verdict {
                    Err(e) => notes.push(format!(
                        "{}: {why}; not repaired automatically: {e}",
                        o.file
                    )),
                    Ok(()) => {
                        let keep: Vec<String> = live
                            .iter()
                            .filter(|l| branch_path(l) != b.path)
                            .cloned()
                            .collect();
                        if keep.is_empty() {
                            notes.push(format!(
                                "{}: {why}; not repaired automatically: it is the only disk in {}",
                                o.file, pool.file
                            ));
                            continue;
                        }
                        // Unmount first: if something still uses the disk
                        // this fails before anything changed. Then detach
                        // it from the pool, check it, mount it again.
                        plan.actions
                            .push(Action::Run(vec!["umount".into(), o.file.clone()]));
                        plan.actions.push(set_branches(&pool.file, &keep));
                        plan.actions.push(Action::Run(vec![
                            "fsck.ext4".into(),
                            "-f".into(),
                            "-y".into(),
                            dev.clone(),
                        ]));
                        plan.actions
                            .push(Action::Run(own_scope(self.mount_command(o))));
                        plan.targets.push(o.file.clone());
                        notes.push(format!("{}: {why}; repairing it (fsck {dev})", o.file));
                        if !req.dry_run {
                            self.repairs
                                .lock()
                                .unwrap()
                                .entry(o.file.clone())
                                .or_default()
                                .push(std::time::SystemTime::now());
                        }
                        repairing.push(b.path.clone());
                        done.push(o.file.clone());
                    }
                }
            }
            // A broken filesystem that is not being repaired only serves
            // reads; one being repaired goes back with its fstab mode.
            for d in desired.iter_mut() {
                let path = branch_path(d).to_string();
                if repairing.contains(&path) {
                    if let Some(b) = bs.iter().find(|b| b.path == path) {
                        *d = if b.mode.is_empty() {
                            format!("{path}=RW")
                        } else {
                            format!("{path}={}", b.mode)
                        };
                    }
                } else if broken.contains(&path) {
                    *d = format!("{path}=RO");
                }
            }
            for t in remount {
                if done.contains(&t) {
                    continue;
                }
                if mounts.iter().any(|m| m.target == t) {
                    // The dead mount of a disk that dropped out and came
                    // back; whatever is still open on it is already lost.
                    plan.actions
                        .push(Action::Run(vec!["umount".into(), "-l".into(), t.clone()]));
                }
                let mut c = vec!["mount".to_string()];
                if self.cfg.fstab_path != Path::new("/etc/fstab") {
                    c.extend(["-T".into(), self.cfg.fstab_path.display().to_string()]);
                }
                c.push(t.clone());
                plan.actions.push(Action::Run(own_scope(c)));
                plan.targets.push(t.clone());
                done.push(t);
            }
            let norm = |v: &[String]| -> Vec<String> {
                v.iter()
                    .map(|b| {
                        let (p, m) = b.split_once('=').unwrap_or((b, ""));
                        format!("{p}={}", mode_word(m))
                    })
                    .collect()
            };
            if !desired.is_empty() && (!repairing.is_empty() || norm(&desired) != norm(&live)) {
                plan.actions.push(set_branches(&pool.file, &desired));
                plan.targets.push(pool.file.clone());
            }
        }
        plan.summary = if plan.actions.is_empty() {
            "pools are healthy".into()
        } else {
            format!("heal {}", plan.targets.join(", "))
        };
        plan.detail = notes.join("\n");
        if !plan.detail.is_empty() {
            plan.detail.push('\n');
        }
        Ok(plan)
    }
}

/// Most automatic repairs of one filesystem per day; after that it waits
/// for a person.
const MAX_AUTO_REPAIRS_PER_DAY: usize = 3;

impl Server {
    /// Why an ext filesystem under a branch needs fsck, or None: the kernel
    /// shut it down (`emergency_ro`), remounted it read-only although fstab
    /// mounts it read-write, or it has recorded errors
    /// (`/sys/fs/ext4/<dev>/errors_count`, read without touching the disk).
    fn needs_fsck(&self, m: &Mount, e: &FsEntry) -> Option<String> {
        if !m.fstype.starts_with("ext") {
            return None;
        }
        let opts: Vec<&str> = m.options.split(',').collect();
        if opts.contains(&"emergency_ro") {
            return Some("the kernel shut the filesystem down (emergency_ro)".into());
        }
        if opts.contains(&"ro") && !e.options.split(',').any(|o| o == "ro") {
            return Some("the kernel remounted it read-only after an error".into());
        }
        let dev = super::poolhealth::canonical(&m.source);
        let kname = crate::poolhealth::kernel_name(&dev);
        let n: u64 = std::fs::read_to_string(
            self.cfg
                .sys_root
                .join("fs/ext4")
                .join(kname)
                .join("errors_count"),
        )
        .ok()?
        .trim()
        .parse()
        .ok()?;
        (n > 0).then(|| format!("its filesystem recorded {n} error(s)"))
    }

    /// Whether the filesystem mounted at `target` (device `dev`) may be
    /// repaired automatically. Refused when fsck.ext4 is missing, after
    /// [`MAX_AUTO_REPAIRS_PER_DAY`] repairs in 24 hours, while something
    /// uses the filesystem (it is retried on the next check), when SMART
    /// rates the disk failing, cannot be read or shows uncorrected errors,
    /// or when the disk had read errors in the last 6 hours: a disk that
    /// cannot return its data needs copying off, not fsck.
    fn auto_repair_check(
        &self,
        target: &str,
        dev: &str,
        inv: Option<&crate::inventory::Inventory>,
        skip_disks: &[String],
        kernel_log: &mut Option<Vec<crate::events::Entry>>,
    ) -> Result<(), String> {
        if !tool_exists("fsck.ext4") {
            return Err("fsck.ext4 is not installed".into());
        }
        let day = std::time::Duration::from_secs(86_400);
        let recent = self
            .repairs
            .lock()
            .unwrap()
            .get(target)
            .map(|v| {
                v.iter()
                    .filter(|t| t.elapsed().is_ok_and(|e| e < day))
                    .count()
            })
            .unwrap_or(0);
        if recent >= MAX_AUTO_REPAIRS_PER_DAY {
            return Err(format!(
                "repaired {recent} times in the last 24 hours; it keeps failing, so it needs a look"
            ));
        }
        let disk = inv
            .and_then(|i| super::poolhealth::disk_of(i, dev))
            .ok_or_else(|| format!("cannot find the disk holding {dev}"))?;
        if skip_disks.contains(&disk) {
            return Err(format!("SMART rates {disk} as failing"));
        }
        if let Some(users) = self.mount_users(target) {
            return Err(format!("in use by {users}; will retry"));
        }
        let log = kernel_log.get_or_insert_with(|| {
            self.runner
                .run(
                    "journalctl",
                    &["-k", "--since", "-6h", "-o", "json", "--no-pager"],
                )
                .map(|r| crate::events::parse_json_lines(&r.stdout))
                .unwrap_or_default()
        });
        let kname = crate::poolhealth::kernel_name(dev);
        let reads = log
            .iter()
            .filter(|e| crate::poolhealth::is_read_error(&e.message, &[kname, &disk]))
            .count();
        if reads > 0 {
            return Err(format!(
                "{disk} had {reads} read error(s) in the last 6 hours; copy its data off instead"
            ));
        }
        let st = self.smart_state(&disk, true);
        let Some(c) = st.counts.filter(|c| !c.is_empty()) else {
            return Err(format!("SMART of {disk} could not be read"));
        };
        if c.uncorrected() > 0 {
            return Err(format!("{disk} has uncorrected errors ({})", c.describe()));
        }
        Ok(())
    }
}

/// The fstab mount a pool branch lives on (deepest match), if any.
fn branch_owner<'a>(b: &str, pool: &FsEntry, entries: &'a [FsEntry]) -> Option<&'a FsEntry> {
    entries
        .iter()
        .filter(|o| o.file != "/" && o.file != pool.file && o.vfstype != "swap")
        .filter(|o| under(b, &o.file))
        .max_by_key(|o| o.file.len())
}

impl Server {
    /// The command that mounts fstab entry `e`, before [`own_scope`].
    /// mergerfs pools are started directly: older FUSE mount helpers pass
    /// fstab-only options such as nofail through to mergerfs, which rejects
    /// them. Everything else goes through `mount <target>` so the fstab
    /// options apply.
    pub(super) fn mount_command(&self, e: &FsEntry) -> Vec<String> {
        if is_mergerfs(e) {
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
                e.file.clone(),
            ]);
            c
        } else {
            let mut c = vec!["mount".to_string()];
            if self.cfg.fstab_path != Path::new("/etc/fstab") {
                c.extend(["-T".into(), self.cfg.fstab_path.display().to_string()]);
            }
            c.push(e.file.clone());
            c
        }
    }
}

/// Runs a mount command in its own transient systemd scope. FUSE
/// filesystems (mergerfs, ntfs-3g) leave a daemon running; started from
/// the helper it would sit in fsview-helper's cgroup and be killed when the
/// helper restarts, e.g. on an FSView upgrade, taking the mount down.
pub(super) fn own_scope(cmd: Vec<String>) -> Vec<String> {
    if !Path::new("/run/systemd/system").exists() || !tool_exists("systemd-run") {
        return cmd;
    }
    let mut c: Vec<String> = ["systemd-run", "--scope", "--quiet", "--collect", "--"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    c.extend(cmd);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heal_plan() {
        let b = |path: &str, mode: &str, live: Option<&str>, owner: Owner| HealBranch {
            path: path.into(),
            mode: mode.into(),
            live: live.map(str::to_string),
            owner,
        };
        let bs = vec![
            // dropped out, back again: remount and restore RW
            b("/mnt/a", "", Some("RO"), Owner::Down("/mnt/a".into())),
            // marked RO by mergerfs while mounted fine: back to RW
            b("/mnt/b", "", Some("RO"), Owner::Up { ro: false }),
            // NC stays NC
            b("/mnt/c", "NC", Some("NC"), Owner::Up { ro: false }),
            // unmounted on purpose (detached): left out
            b("/mnt/d", "", None, Owner::Down("/mnt/d".into())),
            // disk dropped out while mounted and is back: remount
            b("/mnt/e", "", Some("RW"), Owner::Stale("/mnt/e".into())),
            // filesystem remounted read-only: stays RO
            b("/mnt/f", "", Some("RW"), Owner::Up { ro: true }),
        ];
        let (d, r, n) = heal_branches(&bs, &mut |_| None);
        assert_eq!(
            d,
            [
                "/mnt/a=RW",
                "/mnt/b=RW",
                "/mnt/c=NC",
                "/mnt/e=RW",
                "/mnt/f=RO"
            ]
        );
        assert_eq!(r, ["/mnt/a", "/mnt/e"]);
        assert!(n.is_empty());

        // a failing disk is neither remounted nor made writable
        let (d, r, n) = heal_branches(&bs, &mut |b| {
            (b.path != "/mnt/c").then(|| "failing".to_string())
        });
        assert_eq!(
            d,
            [
                "/mnt/a=RO",
                "/mnt/b=RO",
                "/mnt/c=NC",
                "/mnt/e=RO",
                "/mnt/f=RO"
            ]
        );
        assert!(r.is_empty());
        // the dead mount is made read-only so new files go elsewhere
        assert_eq!(n.len(), 3);

        // healthy pools never ask about their disks
        let ok = vec![b("/mnt/a", "", Some("RW"), Owner::Up { ro: false })];
        let (d, _, _) = heal_branches(&ok, &mut |_| panic!("disk touched"));
        assert_eq!(d, ["/mnt/a=RW"]);
    }

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
