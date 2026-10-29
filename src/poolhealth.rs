//! Pool health for mergerfs pools.
//!
//! A mergerfs pool keeps serving even when one of its disks is in trouble:
//! mergerfs marks a branch `=RO` after write errors, the kernel remounts an
//! ext4 branch read-only (`emergency_ro` on newer kernels) when its journal
//! aborts, and a disk can keep running with unreadable sectors. From the
//! outside all of this shows up as "Read-only file system" or "Input/output
//! error" in some program much later. This module turns the raw sources into
//! one verdict per branch:
//!
//! * the pool and its mount table entry come from `/proc/mounts`
//!   ([`parse_proc_mounts`], [`mergerfs_pools`]);
//! * the branch list and modes come from the `user.mergerfs.branches`
//!   extended attribute on `<pool>/.mergerfs` ([`parse_branches`]);
//! * the filesystem under each branch is the deepest mount containing it
//!   ([`owner_mount`]);
//! * ext4 journal trouble is found in the kernel log ([`ext4_errors`]), and
//!   the messages leading up to the first one are kept as the likely trigger
//!   ([`trigger_context`]);
//! * SMART counters decide whether the disk itself is losing data
//!   ([`SmartCounts`]).
//!
//! Everything here is pure (no I/O) so it can be tested with captured
//! output; the root helper gathers the inputs and the web server only shows
//! the result.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::events::Entry;
use crate::smart::Report;

/// Filesystem type mergerfs pools report in `/proc/mounts`.
pub const MERGERFS_FSTYPE: &str = "fuse.mergerfs";

/// How far back before the first ext4 error kernel messages are kept as the
/// likely trigger (a link reset, a timeout, a disk dropping off the bus).
pub const TRIGGER_WINDOW_SECS: i64 = 600;

/// Most recent ext4 error lines kept per branch.
pub const MAX_ERROR_LINES: usize = 20;

/// Most trigger lines kept per branch (newest ones, closest to the error).
pub const MAX_TRIGGER_LINES: usize = 200;

/// One line of `/proc/mounts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcMount {
    /// Mount source: a device path for block filesystems, the `fsname` for
    /// mergerfs.
    pub source: String,
    /// Mountpoint.
    pub target: String,
    /// Filesystem type, e.g. `ext4` or `fuse.mergerfs`.
    pub fstype: String,
    /// Mount options, split at commas.
    pub options: Vec<String>,
}

impl ProcMount {
    /// True when the filesystem is mounted read-only, either normally
    /// (`ro`) or because the kernel shut it down after an error
    /// (`emergency_ro`).
    pub fn read_only(&self) -> bool {
        self.options
            .iter()
            .any(|o| o == "ro" || o == "emergency_ro")
    }
}

/// Decodes the octal escapes `/proc/mounts` uses for spaces, tabs, newlines
/// and backslashes in paths (`\040`, `\011`, `\012`, `\134`).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            let oct = &b[i + 1..i + 4];
            if oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                let v = oct.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
                if let Ok(v) = u8::try_from(v) {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `/proc/mounts` (or `/proc/self/mounts`). Malformed lines are
/// skipped. The order is kept: when mounts are stacked on one mountpoint the
/// later line is the one that is visible.
pub fn parse_proc_mounts(text: &str) -> Vec<ProcMount> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let source = unescape(f.next()?);
            let target = unescape(f.next()?);
            let fstype = f.next()?.to_string();
            let options = f.next()?.split(',').map(str::to_string).collect();
            Some(ProcMount {
                source,
                target,
                fstype,
                options,
            })
        })
        .collect()
}

/// The mergerfs pools in a mount table, each mountpoint once (the visible,
/// last-mounted instance).
pub fn mergerfs_pools(mounts: &[ProcMount]) -> Vec<&ProcMount> {
    let mut out: Vec<&ProcMount> = Vec::new();
    for m in mounts.iter().filter(|m| m.fstype == MERGERFS_FSTYPE) {
        out.retain(|o| o.target != m.target);
        out.push(m);
    }
    out
}

/// A pool branch as mergerfs reports it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Branch {
    /// Branch directory.
    pub path: String,
    /// `RW`, `RO` or `NC` (no create). Per-branch settings such as a
    /// branch minfreespace (`=RW,10G`) are dropped.
    pub mode: String,
}

/// Parses the value of `user.mergerfs.branches`, e.g.
/// `/mnt/a=RW:/mnt/b=NC`. A branch without a mode is `RW`.
pub fn parse_branches(value: &str) -> Vec<Branch> {
    value
        .trim()
        .trim_end_matches('\0')
        .split(':')
        .filter(|b| !b.is_empty())
        .map(|b| {
            let (path, mode) = b.split_once('=').unwrap_or((b, "RW"));
            let mode = mode.split(',').next().unwrap_or("").to_ascii_uppercase();
            Branch {
                path: path.to_string(),
                mode: if mode.is_empty() { "RW".into() } else { mode },
            }
        })
        .collect()
}

/// `p` is `dir` or lies inside it.
pub fn is_under(p: &str, dir: &str) -> bool {
    dir == "/" || p == dir || p.starts_with(&format!("{}/", dir.trim_end_matches('/')))
}

/// The filesystem a branch directory lives on: the deepest mount whose
/// mountpoint contains it. Other mergerfs pools are ignored (a branch is
/// never meant to sit on another pool). Among stacked mounts the visible
/// (last) one wins.
pub fn owner_mount<'a>(path: &str, mounts: &'a [ProcMount]) -> Option<&'a ProcMount> {
    let mut best: Option<&ProcMount> = None;
    for m in mounts.iter().filter(|m| m.fstype != MERGERFS_FSTYPE) {
        if !is_under(path, &m.target) {
            continue;
        }
        if best.is_none_or(|b| m.target.len() >= b.target.len()) {
            best = Some(m);
        }
    }
    best
}

/// Kernel device name of a device path (`/dev/sdc1` -> `sdc1`).
pub fn kernel_name(dev: &str) -> &str {
    dev.rsplit('/').next().unwrap_or(dev)
}

struct Patterns {
    trouble: Regex,
    io: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        trouble: Regex::new(
            r"(?i)(EXT4-fs error|journal has aborted|detected aborted journal|Remounting filesystem read-only)",
        )
        .expect("valid regex"),
        io: Regex::new(
            r"(?i)(I/O error|error -5\b|Medium Error|Internal target failure|Unrecovered read error)",
        )
        .expect("valid regex"),
    })
}

/// True when a kernel message is ext4 journal trouble on device `kname`:
/// an `EXT4-fs error`, an aborted journal or a forced read-only remount.
/// The device must appear as a whole word (`sdc1` does not match `sdc10`),
/// as ext4 prints it (`(device sdc1)`, `EXT4-fs (sdc1)`) or as the journal
/// thread (`jbd2/sdc1-8`).
pub fn is_ext4_error(msg: &str, kname: &str) -> bool {
    !kname.is_empty() && patterns().trouble.is_match(msg) && mentions(msg, kname)
}

/// True when `name` appears in `msg` as a whole word (`sdc1` does not
/// match `sdc10`).
fn mentions(msg: &str, name: &str) -> bool {
    msg.match_indices(name).any(|(i, _)| {
        let before = msg[..i].chars().next_back();
        let after = msg[i + name.len()..].chars().next();
        let edge = |c: Option<char>| c.is_none_or(|c| !c.is_ascii_alphanumeric());
        edge(before) && edge(after)
    })
}

/// True when a kernel message is a read or write failure on one of `names`
/// (the filesystem's device and its disk): block layer `I/O error, dev
/// sdh`, `Buffer I/O error`, SCSI medium errors and target failures, or a
/// filesystem reporting `error -5` (EIO). These are often logged only as
/// ext4 *warnings*, so [`is_ext4_error`] alone misses a disk that cannot
/// read one of its directories.
pub fn is_io_error(msg: &str, names: &[&str]) -> bool {
    patterns().io.is_match(msg) && names.iter().any(|n| !n.is_empty() && mentions(msg, n))
}

/// The kernel messages that are ext4 journal trouble on `kname`, oldest
/// first.
pub fn ext4_errors<'a>(entries: &'a [Entry], kname: &str) -> Vec<&'a Entry> {
    entries
        .iter()
        .filter(|e| is_ext4_error(&e.message, kname))
        .collect()
}

/// Every kernel message in the `window_secs` before `first` (exclusive),
/// oldest first, at most [`MAX_TRIGGER_LINES`] (the ones closest to the
/// error). Messages about any device are kept: the cause is often a reset
/// on the controller or enclosure, logged under a different name.
pub fn trigger_context(entries: &[Entry], first: &Entry, window_secs: i64) -> Vec<Entry> {
    let from = first.realtime_us - window_secs * 1_000_000;
    let mut out: Vec<Entry> = entries
        .iter()
        .filter(|e| {
            e.realtime_us >= from && e.realtime_us < first.realtime_us && e.cursor != first.cursor
        })
        .cloned()
        .collect();
    if out.len() > MAX_TRIGGER_LINES {
        out.drain(..out.len() - MAX_TRIGGER_LINES);
    }
    out
}

/// SMART counters that tell whether a disk is losing data.
///
/// ATA disks report sectors (attributes 5, 187, 197 and 198); SAS disks
/// report errors in their error counter log (`total uncorrected errors` for
/// reads, writes and verifies, summed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SmartCounts {
    /// ATA 5: sectors already remapped to spares (data was rescued).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reallocated: Option<i64>,
    /// ATA 197: sectors waiting to be remapped because they could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    /// ATA 198: sectors the offline scan could not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_uncorrectable: Option<i64>,
    /// ATA 187: errors the disk could not correct with ECC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_uncorrectable: Option<i64>,
    /// SAS: total uncorrected errors from the error counter log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas_uncorrected: Option<i64>,
}

impl SmartCounts {
    /// Takes the counters from a parsed smartctl report.
    pub fn from_report(r: &Report) -> SmartCounts {
        SmartCounts {
            reallocated: r.reallocated,
            pending: r.pending,
            offline_uncorrectable: r.offline_uncorrectable,
            reported_uncorrectable: r.reported_uncorrectable,
            sas_uncorrected: r.uncorrected_errors,
        }
    }

    /// Errors the disk could not correct: pending, offline uncorrectable,
    /// reported uncorrectable and SAS uncorrected. Reallocated sectors are
    /// not counted: their data was moved before it was lost.
    pub fn uncorrected(&self) -> i64 {
        [
            self.pending,
            self.offline_uncorrectable,
            self.reported_uncorrectable,
            self.sas_uncorrected,
        ]
        .iter()
        .flatten()
        .map(|v| (*v).max(0))
        .sum()
    }

    /// True when no counter could be read (e.g. a bridge hides SMART).
    pub fn is_empty(&self) -> bool {
        *self == SmartCounts::default()
    }

    /// Human-readable list of the non-zero counters.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = [
            ("reallocated", self.reallocated),
            ("pending", self.pending),
            ("offline uncorrectable", self.offline_uncorrectable),
            ("reported uncorrectable", self.reported_uncorrectable),
            ("SAS uncorrected", self.sas_uncorrected),
        ]
        .iter()
        .filter_map(|(n, v)| v.filter(|v| *v > 0).map(|v| format!("{v} {n}")))
        .collect();
        if parts.is_empty() {
            "no errors".into()
        } else {
            parts.join(", ")
        }
    }
}

/// Kind of problem found on a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    /// mergerfs marked the branch read-only (`=RO`).
    BranchRo,
    /// The branch takes no new files (`=NC`), set by hand or by FSView.
    BranchNc,
    /// The filesystem under the branch is mounted `ro`.
    MountRo,
    /// The kernel shut the filesystem down after an error (`emergency_ro`).
    EmergencyRo,
    /// The branch directory is not on its own mount (its disk is missing
    /// and the empty mountpoint on the system disk shows instead).
    NotMounted,
    /// ext4 journal errors in the kernel log for this boot.
    Ext4Errors,
    /// Reads or writes on the branch's disk failed this boot (block layer
    /// I/O errors, medium errors, EIO from the filesystem). One unreadable
    /// directory on one branch makes file creation fail on the whole pool.
    IoErrors,
    /// The disk reports errors it could not correct.
    SmartUncorrected,
    /// The disk has remapped sectors (early wear sign, data intact).
    SmartReallocated,
    /// SMART could not be read (asleep, unsupported or behind a bridge).
    SmartUnknown,
}

/// One finding on a branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flag {
    pub kind: FlagKind,
    /// `error`, `warn` or `info`.
    pub severity: String,
    /// What was seen, in words.
    pub detail: String,
}

fn flag(kind: FlagKind, severity: &str, detail: impl Into<String>) -> Flag {
    Flag {
        kind,
        severity: severity.into(),
        detail: detail.into(),
    }
}

/// Health of one pool branch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BranchHealth {
    /// Branch directory.
    pub path: String,
    /// Mode mergerfs has for it: `RW`, `RO` or `NC`.
    pub mode: String,
    /// Mountpoint of the filesystem under the branch.
    pub mount_target: String,
    /// Device of that filesystem (canonical path, e.g. `/dev/sdc1`).
    pub device: String,
    /// Disk the device is on (e.g. `sdc`), empty when unknown.
    pub disk: String,
    /// Filesystem type.
    pub fstype: String,
    /// Mount options.
    pub mount_options: Vec<String>,
    /// Everything found, most severe first.
    pub flags: Vec<Flag>,
    /// Number of ext4 error messages this boot.
    pub ext4_error_count: usize,
    /// The latest ext4 error messages (at most [`MAX_ERROR_LINES`]).
    pub ext4_errors: Vec<Entry>,
    /// Number of read/write failures on the device or its disk this boot.
    pub io_error_count: usize,
    /// The latest of them (at most [`MAX_ERROR_LINES`]).
    pub io_errors: Vec<Entry>,
    /// The first ext4 error this boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error: Option<Entry>,
    /// Kernel messages in the [`TRIGGER_WINDOW_SECS`] before the first
    /// error: what probably set it off.
    pub trigger: Vec<Entry>,
    /// SMART counters, when they could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smart: Option<SmartCounts>,
    /// Why "Repair branch" is not offered (empty when it is).
    pub repair_blocker: String,
}

impl BranchHealth {
    /// True when the branch cannot take writes: mergerfs set it `RO`, or
    /// its filesystem is mounted read-only (including `emergency_ro`).
    pub fn read_only(&self) -> bool {
        self.flags.iter().any(|f| {
            matches!(
                f.kind,
                FlagKind::BranchRo | FlagKind::MountRo | FlagKind::EmergencyRo
            )
        })
    }

    /// Short reasons for [`read_only`](Self::read_only), e.g.
    /// "mergerfs marked it RO, mounted emergency_ro".
    pub fn read_only_reasons(&self) -> String {
        self.flags
            .iter()
            .filter_map(|f| match f.kind {
                FlagKind::BranchRo => Some("mergerfs marked it RO"),
                FlagKind::MountRo => Some("mounted read-only"),
                FlagKind::EmergencyRo => Some("mounted emergency_ro"),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Health of one mergerfs pool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PoolHealth {
    /// Pool mountpoint.
    pub mountpoint: String,
    /// The pool's `fsname` (mount source).
    pub source: String,
    /// Branches in mergerfs order.
    pub branches: Vec<BranchHealth>,
    /// Set when the branch list could not be read (e.g. `getfattr` missing).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl PoolHealth {
    /// True when any branch has an `error` flag.
    pub fn has_errors(&self) -> bool {
        self.branches
            .iter()
            .any(|b| b.flags.iter().any(|f| f.severity == "error"))
    }
}

/// What the helper gathered for one branch; [`assess_branch`] turns it into
/// a [`BranchHealth`].
#[derive(Debug, Clone, Default)]
pub struct BranchInput<'a> {
    pub branch: Branch,
    /// The filesystem under the branch.
    pub owner: Option<&'a ProcMount>,
    /// Canonical device path (empty for non-block sources).
    pub device: String,
    /// Disk holding the device.
    pub disk: String,
    /// Kernel log of the current boot, oldest first.
    pub journal: &'a [Entry],
    /// SMART counters, None when they could not be read.
    pub smart: Option<SmartCounts>,
    /// SMART was not read because the disk is asleep.
    pub smart_standby: bool,
}

/// Turns gathered facts into a verdict. Flags are ordered errors first.
pub fn assess_branch(i: BranchInput<'_>) -> BranchHealth {
    let mut h = BranchHealth {
        path: i.branch.path.clone(),
        mode: i.branch.mode.clone(),
        device: i.device.clone(),
        disk: i.disk.clone(),
        ..Default::default()
    };
    let mut flags = vec![];
    match i.branch.mode.as_str() {
        "RO" => flags.push(flag(
            FlagKind::BranchRo,
            "error",
            "mergerfs marked this branch read-only (=RO); new files and changes to files on it fail",
        )),
        "NC" => flags.push(flag(
            FlagKind::BranchNc,
            "info",
            "no new files are created here (=NC); existing files can still change",
        )),
        _ => {}
    }
    match i.owner {
        Some(m) if m.target == "/" && i.branch.path != "/" => flags.push(flag(
            FlagKind::NotMounted,
            "error",
            "the branch is on the system disk: its own disk is not mounted",
        )),
        Some(m) => {
            h.mount_target = m.target.clone();
            h.fstype = m.fstype.clone();
            h.mount_options = m.options.clone();
            if m.options.iter().any(|o| o == "emergency_ro") {
                flags.push(flag(
                    FlagKind::EmergencyRo,
                    "error",
                    format!(
                        "the kernel shut {} down after an error (emergency_ro)",
                        m.target
                    ),
                ));
            } else if m.options.iter().any(|o| o == "ro") {
                flags.push(flag(
                    FlagKind::MountRo,
                    "error",
                    format!("{} is mounted read-only", m.target),
                ));
            }
        }
        None => flags.push(flag(
            FlagKind::NotMounted,
            "error",
            "no mounted filesystem holds this branch",
        )),
    }
    let kname = kernel_name(&i.device);
    let errs = if i.device.is_empty() {
        vec![]
    } else {
        ext4_errors(i.journal, kname)
    };
    h.ext4_error_count = errs.len();
    if let Some(first) = errs.first() {
        h.first_error = Some((*first).clone());
        h.trigger = trigger_context(i.journal, first, TRIGGER_WINDOW_SECS);
        h.ext4_errors = errs
            .iter()
            .skip(errs.len().saturating_sub(MAX_ERROR_LINES))
            .map(|e| (*e).clone())
            .collect();
        flags.push(flag(
            FlagKind::Ext4Errors,
            "error",
            format!(
                "{} ext4 journal error message(s) for {kname} this boot, first at {}",
                errs.len(),
                first.time().format("%Y-%m-%d %H:%M:%S UTC")
            ),
        ));
    }
    let names = [kname, i.disk.as_str()];
    let io: Vec<&Entry> = if i.device.is_empty() {
        vec![]
    } else {
        i.journal
            .iter()
            .filter(|e| is_io_error(&e.message, &names))
            .collect()
    };
    h.io_error_count = io.len();
    if let (Some(first), Some(last)) = (io.first(), io.last()) {
        h.io_errors = io
            .iter()
            .skip(io.len().saturating_sub(MAX_ERROR_LINES))
            .map(|e| (*e).clone())
            .collect();
        flags.push(flag(
            FlagKind::IoErrors,
            "error",
            format!(
                "{} read/write error message(s) for {} this boot, {} to {}",
                io.len(),
                if i.disk.is_empty() { kname } else { &i.disk },
                first.time().format("%Y-%m-%d %H:%M"),
                last.time().format("%Y-%m-%d %H:%M UTC")
            ),
        ));
    }
    match &i.smart {
        Some(s) if s.uncorrected() > 0 => flags.push(flag(
            FlagKind::SmartUncorrected,
            "error",
            format!(
                "the disk reports errors it could not correct: {}",
                s.describe()
            ),
        )),
        Some(s) if s.reallocated.is_some_and(|v| v > 0) => flags.push(flag(
            FlagKind::SmartReallocated,
            "warn",
            format!(
                "{} sectors were remapped (data intact; watch for growth)",
                s.reallocated.unwrap_or(0)
            ),
        )),
        Some(s) if s.is_empty() => flags.push(flag(
            FlagKind::SmartUnknown,
            "info",
            "SMART has none of the error counters",
        )),
        Some(_) => {}
        None if !i.disk.is_empty() => flags.push(flag(
            FlagKind::SmartUnknown,
            "info",
            if i.smart_standby {
                "SMART not read: the disk is asleep"
            } else {
                "SMART could not be read"
            },
        )),
        None => {}
    }
    let rank = |s: &str| match s {
        "error" => 0,
        "warn" => 1,
        _ => 2,
    };
    flags.sort_by_key(|f| rank(&f.severity));
    h.flags = flags;
    h.smart = i.smart;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = "\
/dev/nvme0n1p2 / ext4 rw,relatime 0 0
/dev/sdd1 /mnt/media7 ext4 rw,relatime 0 0
/dev/sde1 /mnt/media8 ext4 rw,relatime 0 0
/dev/sdh /mnt/media2 ext4 rw,relatime 0 0
/dev/sdc1 /mnt/media5 ext4 ro,relatime,emergency_ro 0 0
/dev/sdb1 /mnt/my\\040disk ext4 ro,relatime 0 0
mergerfs-drivepool /mnt/drivepool fuse.mergerfs rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other 0 0
";

    fn entry(t: i64, cursor: &str, msg: &str) -> Entry {
        Entry {
            cursor: cursor.into(),
            realtime_us: t * 1_000_000,
            message: msg.into(),
            ..Default::default()
        }
    }

    #[test]
    fn mounts_and_pools() {
        let m = parse_proc_mounts(MOUNTS);
        assert_eq!(m.len(), 7);
        assert_eq!(m[5].target, "/mnt/my disk");
        assert!(m[4].read_only() && m[5].read_only() && !m[1].read_only());
        let pools = mergerfs_pools(&m);
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].target, "/mnt/drivepool");
        // stacked pool instances: the later one is reported once
        let twice = format!("{MOUNTS}mergerfs-new /mnt/drivepool fuse.mergerfs rw 0 0\n");
        let m2 = parse_proc_mounts(&twice);
        let p2 = mergerfs_pools(&m2);
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].source, "mergerfs-new");
    }

    #[test]
    fn branches_and_owners() {
        let b = parse_branches(
            "/mnt/media7=RW:/mnt/media8=rw:/mnt/media2=NC:/mnt/media5=RO,10G:/mnt/x\n",
        );
        assert_eq!(
            b.iter()
                .map(|b| (b.path.as_str(), b.mode.as_str()))
                .collect::<Vec<_>>(),
            [
                ("/mnt/media7", "RW"),
                ("/mnt/media8", "RW"),
                ("/mnt/media2", "NC"),
                ("/mnt/media5", "RO"),
                ("/mnt/x", "RW"),
            ]
        );
        let m = parse_proc_mounts(MOUNTS);
        assert_eq!(owner_mount("/mnt/media5", &m).unwrap().source, "/dev/sdc1");
        assert_eq!(
            owner_mount("/mnt/media5/data", &m).unwrap().source,
            "/dev/sdc1"
        );
        // /mnt/media55 is not inside /mnt/media5
        assert_eq!(owner_mount("/mnt/media55", &m).unwrap().target, "/");
        // the pool itself is never an owner
        assert_eq!(owner_mount("/mnt/drivepool/x", &m).unwrap().target, "/");
    }

    #[test]
    fn ext4_matching_and_trigger() {
        let j = vec![
            entry(1000, "a", "sd 2:0:9:0: [sdc] tag#3 timing out command, waited 180s"),
            entry(1300, "b", "mpt2sas_cm0: log_info(0x31110d00): originator(PL)"),
            entry(1500, "c", "EXT4-fs error (device sdc10): ext4_find_entry: reading lblock 0"),
            entry(1580, "d", "EXT4-fs error (device sdc1): ext4_journal_check_start:86: comm kworker: Detected aborted journal"),
            entry(1590, "e", "EXT4-fs (sdc1): Remounting filesystem read-only"),
            entry(1595, "f", "Aborting journal on device sdc1-8."),
            entry(1600, "g", "EXT4-fs (sdd1): mounted filesystem"),
        ];
        assert!(
            !is_ext4_error(&j[2].message, "sdc1"),
            "sdc10 is a different device"
        );
        let errs = ext4_errors(&j, "sdc1");
        assert_eq!(
            errs.iter().map(|e| e.cursor.as_str()).collect::<Vec<_>>(),
            ["d", "e"]
        );
        // 10 minutes before 1580: from 980 on, the error itself excluded
        let t = trigger_context(&j, errs[0], TRIGGER_WINDOW_SECS);
        assert_eq!(
            t.iter().map(|e| e.cursor.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
        // a 100 s window keeps only the message at 1500
        let t = trigger_context(&j, errs[0], 100);
        assert_eq!(
            t.iter().map(|e| e.cursor.as_str()).collect::<Vec<_>>(),
            ["c"]
        );
        let t = trigger_context(&j, errs[0], 10);
        assert!(t.is_empty());
    }

    #[test]
    fn io_errors() {
        let n = ["sdh", "sdh"];
        for m in [
            "I/O error, dev sdh, sector 9906979072 op 0x0:(READ) flags 0x803000",
            "EXT4-fs warning (device sdh): dx_probe:791: inode #154796033: lblock 0: comm fuse.read: error -5 reading directory block",
            "Buffer I/O error on dev sdh, logical block 1465130624, async page read",
            "sd 2:0:18:0: [sdh] tag#1005 Add. Sense: Internal target failure",
        ] {
            assert!(is_io_error(m, &n), "{m}");
        }
        assert!(!is_io_error("I/O error, dev sdhx, sector 1", &n));
        assert!(!is_io_error("EXT4-fs (sdh): mounted filesystem", &n));
        // partition filesystem, errors logged against the disk
        assert!(is_io_error(
            "I/O error, dev sdc, sector 5",
            &["sdc1", "sdc"]
        ));
    }

    #[test]
    fn smart_counts() {
        let ata = SmartCounts {
            reallocated: Some(8),
            pending: Some(0),
            offline_uncorrectable: Some(0),
            reported_uncorrectable: Some(0),
            sas_uncorrected: None,
        };
        assert_eq!(ata.uncorrected(), 0, "reallocated alone is not uncorrected");
        let sas = SmartCounts {
            sas_uncorrected: Some(3),
            ..Default::default()
        };
        assert_eq!(sas.uncorrected(), 3);
        assert_eq!(sas.describe(), "3 SAS uncorrected");
        assert!(SmartCounts::default().is_empty());
    }

    #[test]
    fn assess() {
        let m = parse_proc_mounts(MOUNTS);
        let j = vec![
            entry(1000, "a", "sd 2:0:9:0: [sdc] attempting task abort"),
            entry(1100, "b", "EXT4-fs (sdc1): Remounting filesystem read-only"),
        ];
        let h = assess_branch(BranchInput {
            branch: Branch {
                path: "/mnt/media5".into(),
                mode: "RO".into(),
            },
            owner: owner_mount("/mnt/media5", &m),
            device: "/dev/sdc1".into(),
            disk: "sdc".into(),
            journal: &j,
            smart: Some(SmartCounts {
                reallocated: Some(0),
                pending: Some(2),
                ..Default::default()
            }),
            smart_standby: false,
        });
        let kinds: Vec<FlagKind> = h.flags.iter().map(|f| f.kind).collect();
        for k in [
            FlagKind::BranchRo,
            FlagKind::EmergencyRo,
            FlagKind::Ext4Errors,
            FlagKind::SmartUncorrected,
        ] {
            assert!(kinds.contains(&k), "{k:?} missing from {kinds:?}");
        }
        assert!(h.read_only());
        assert_eq!(
            h.read_only_reasons(),
            "mergerfs marked it RO, mounted emergency_ro"
        );
        assert_eq!(h.trigger.len(), 1);
        assert_eq!(h.mount_target, "/mnt/media5");

        // a healthy branch has no flags
        let ok = assess_branch(BranchInput {
            branch: Branch {
                path: "/mnt/media7".into(),
                mode: "RW".into(),
            },
            owner: owner_mount("/mnt/media7", &m),
            device: "/dev/sdd1".into(),
            disk: "sdd".into(),
            journal: &j,
            smart: Some(SmartCounts {
                reallocated: Some(0),
                pending: Some(0),
                ..Default::default()
            }),
            smart_standby: false,
        });
        assert!(ok.flags.is_empty(), "{:?}", ok.flags);
        assert!(!ok.read_only());

        // a branch whose disk is missing resolves to the root filesystem
        let gone = assess_branch(BranchInput {
            branch: Branch {
                path: "/mnt/media9".into(),
                mode: "RW".into(),
            },
            owner: owner_mount("/mnt/media9", &m),
            journal: &j,
            ..Default::default()
        });
        assert_eq!(gone.flags[0].kind, FlagKind::NotMounted);
    }
}
