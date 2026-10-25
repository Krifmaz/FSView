//! Root side of pool health: gathers mount table, branch list, kernel log
//! and SMART for every mounted mergerfs pool, answers "which branch holds
//! this file", and plans the guided branch repair.
//!
//! The verdicts themselves come from [`crate::poolhealth`], which has no
//! I/O; this module only collects its inputs.

use std::collections::HashMap;
use std::path::{Component, Path};

use super::ops::{bad, decode, failed, tool_exists, Action, OpError, Plan};
use super::storage::{is_mergerfs, mergerfs_branches, own_scope};
use super::Server;
use crate::events::{self, Entry};
use crate::inventory::Inventory;
use crate::poolhealth::{
    self as ph, assess_branch, BranchHealth, BranchInput, PoolHealth, ProcMount, SmartCounts,
};
use crate::proto::*;
use crate::smart;

/// Filesystems the guided repair can check (`fsck.ext4` handles all three).
const REPAIRABLE_FS: [&str; 3] = ["ext2", "ext3", "ext4"];

/// Most kernel log entries read for one health check (one boot).
const JOURNAL_LINES: &str = "200000";

/// SMART of one disk as the health check sees it.
#[derive(Clone, Default)]
struct SmartState {
    counts: Option<SmartCounts>,
    standby: bool,
}

impl Server {
    /// The mount table from [`super::Config::mounts_file`].
    fn proc_mounts(&self) -> Result<Vec<ProcMount>, OpError> {
        let text = std::fs::read_to_string(&self.cfg.mounts_file)
            .map_err(|e| failed(format!("{}: {e}", self.cfg.mounts_file.display())))?;
        Ok(ph::parse_proc_mounts(&text))
    }

    /// True when device path `dev` (`/dev/...`) exists under
    /// [`super::Config::dev_dir`].
    fn dev_exists(&self, dev: &str) -> bool {
        dev.strip_prefix("/dev/")
            .is_some_and(|rest| self.cfg.dev_dir.join(rest).exists())
    }

    /// Reads one extended attribute with `getfattr --only-values`. None when
    /// the attribute or the file does not exist, or getfattr is missing.
    fn xattr(&self, path: &str, name: &str) -> Option<Vec<u8>> {
        let r = self
            .runner
            .run("getfattr", &["--only-values", "-n", name, path])
            .ok()?;
        (r.code == 0).then_some(r.stdout)
    }

    /// Branches of a running pool from `user.mergerfs.branches` on its
    /// control file.
    fn pool_branches(&self, pool: &str) -> Result<Vec<ph::Branch>, String> {
        let ctl = format!("{}/.mergerfs", pool.trim_end_matches('/'));
        let v = self.xattr(&ctl, "user.mergerfs.branches").ok_or_else(|| {
            format!("cannot read user.mergerfs.branches on {ctl} (is the attr package installed?)")
        })?;
        Ok(ph::parse_branches(&String::from_utf8_lossy(&v)))
    }

    /// Kernel messages of the current boot, oldest first. Empty when the
    /// journal cannot be read.
    fn boot_kernel_log(&self) -> Vec<Entry> {
        match self.runner.run(
            "journalctl",
            &["-k", "-b", "-o", "json", "--no-pager", "-n", JOURNAL_LINES],
        ) {
            Ok(r) => events::parse_json_lines(&r.stdout),
            Err(_) => vec![],
        }
    }

    /// SMART counters of `disk`. With `wake` false a sleeping disk is left
    /// alone and reported as standby.
    fn smart_state(&self, disk: &str, wake: bool) -> SmartState {
        let Ok(res) = self.smart_get(disk, wake) else {
            return SmartState::default();
        };
        if res.standby {
            return SmartState {
                counts: None,
                standby: true,
            };
        }
        let raw = serde_json::to_vec(&res.raw).unwrap_or_default();
        SmartState {
            counts: smart::parse(&raw, &res.devtype)
                .ok()
                .map(|r| SmartCounts::from_report(&r)),
            standby: false,
        }
    }

    /// Health of every mounted mergerfs pool.
    pub(super) fn pool_health(&self, p: &PoolHealthParams) -> Result<Vec<PoolHealth>, OpError> {
        let mounts = self.proc_mounts()?;
        let inv = self.inventory().ok();
        let journal = self.boot_kernel_log();
        let entries = self.fstab_entries().unwrap_or_default();
        let mut smart_cache: HashMap<String, SmartState> = HashMap::new();
        let mut out = vec![];
        for pool in ph::mergerfs_pools(&mounts) {
            let mut ph_out = PoolHealth {
                mountpoint: pool.target.clone(),
                source: pool.source.clone(),
                ..Default::default()
            };
            let branches = match self.pool_branches(&pool.target) {
                Ok(b) => b,
                Err(e) => {
                    ph_out.error = e;
                    out.push(ph_out);
                    continue;
                }
            };
            for b in branches {
                let owner = ph::owner_mount(&b.path, &mounts);
                let device = owner
                    .filter(|m| m.source.starts_with("/dev/"))
                    .map(|m| canonical(&m.source))
                    .unwrap_or_default();
                let disk = inv
                    .as_ref()
                    .and_then(|i| disk_of(i, &device))
                    .unwrap_or_default();
                let st = if p.skip_smart || disk.is_empty() {
                    SmartState::default()
                } else {
                    smart_cache
                        .entry(disk.clone())
                        .or_insert_with(|| self.smart_state(&disk, false))
                        .clone()
                };
                let mut h = assess_branch(BranchInput {
                    branch: b,
                    owner,
                    device,
                    disk,
                    journal: &journal,
                    smart: st.counts,
                    smart_standby: st.standby,
                });
                h.repair_blocker =
                    repair_blocker(&h, &pool.target, &entries, |d| self.dev_exists(d));
                ph_out.branches.push(h);
            }
            out.push(ph_out);
        }
        Ok(out)
    }

    /// Which branch holds a file: reads `user.mergerfs.fullpath` (and
    /// `user.mergerfs.allpaths`) through the pool.
    pub(super) fn pool_locate(&self, p: &PoolLocateParams) -> Result<PoolLocateResult, OpError> {
        let mounts = self.proc_mounts()?;
        let pool = ph::mergerfs_pools(&mounts)
            .into_iter()
            .find(|m| m.target == p.pool.trim_end_matches('/'))
            .ok_or_else(|| bad(format!("{} is not a mounted mergerfs pool", p.pool)))?;
        let rel = relative_in_pool(&pool.target, &p.path)?;
        let full = format!("{}/{rel}", pool.target.trim_end_matches('/'));
        let fullpath = self
            .xattr(&full, "user.mergerfs.fullpath")
            .map(|v| {
                String::from_utf8_lossy(&v)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .ok_or_else(|| bad(format!("{full} was not found in the pool")))?;
        let branches = self.pool_branches(&pool.target).map_err(failed)?;
        let branch = branches
            .iter()
            .filter(|b| ph::is_under(&fullpath, &b.path))
            .max_by_key(|b| b.path.len())
            .map(|b| b.path.clone())
            .unwrap_or_default();
        let allpaths: Vec<String> = self
            .xattr(&full, "user.mergerfs.allpaths")
            .map(|v| {
                v.split(|c| *c == 0 || *c == b'\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        Ok(PoolLocateResult {
            path: full,
            fullpath,
            branch,
            allpaths: if allpaths.len() > 1 { allpaths } else { vec![] },
        })
    }

    /// Plans the guided repair of one branch.
    ///
    /// Refuses when the branch is not a separate ext2/3/4 mount listed in
    /// fstab, when another pool also uses that filesystem, when the pool
    /// itself is not in fstab (it could not be started again), or when SMART
    /// shows uncorrected errors or cannot be read (fsck on a disk that is
    /// losing sectors makes recovery harder; copy it off instead).
    ///
    /// The plan, executed in order and stopping at the first failure:
    /// 1. the configured stop commands (failures ignored),
    /// 2. `umount <pool>`, 3. `umount <branch mount>`,
    /// 4. `fsck.ext4 -f -y <device>` (exit 1 and 2 are success),
    /// 5. mount the branch, 6. start the pool, both from fstab,
    /// 7. the configured post commands (failures ignored).
    ///
    /// If a step fails, later steps (including the post commands) do not
    /// run, so nothing is restarted on top of a half-repaired pool. The
    /// kernel messages leading up to the first ext4 error are written to
    /// the plan detail, so the audit log records what triggered the repair.
    pub(super) fn prep_pool_repair(&self, req: &Request) -> Result<Plan, OpError> {
        let p: PoolRepairParams = decode(req)?;
        let pool = p.pool.trim_end_matches('/').to_string();
        let mounts = self.proc_mounts()?;
        if !ph::mergerfs_pools(&mounts).iter().any(|m| m.target == pool) {
            return Err(bad(format!("{pool} is not a mounted mergerfs pool")));
        }
        let branches = self.pool_branches(&pool).map_err(failed)?;
        let b = branches
            .iter()
            .find(|b| b.path == p.branch)
            .cloned()
            .ok_or_else(|| bad(format!("{} is not a branch of {pool}", p.branch)))?;
        let owner = ph::owner_mount(&b.path, &mounts)
            .cloned()
            .ok_or_else(|| bad(format!("no mounted filesystem holds {}", b.path)))?;
        if owner.target == "/" {
            return Err(bad(format!(
                "{} is on the system disk (its own disk is not mounted); mount it first",
                b.path
            )));
        }
        if !REPAIRABLE_FS.contains(&owner.fstype.as_str()) {
            return Err(bad(format!(
                "{} is {}; the guided repair only handles ext2/3/4",
                owner.target, owner.fstype
            )));
        }
        let device = canonical(&owner.source);
        if !self.dev_exists(&device) {
            return Err(bad(format!(
                "the device of {} ({}) is gone; reconnect the disk first",
                owner.target, owner.source
            )));
        }
        let entries = self.fstab_entries()?;
        let pool_entry = entries
            .iter()
            .find(|e| e.file == pool && is_mergerfs(e))
            .ok_or_else(|| {
                bad(format!(
                    "{pool} is not in fstab, so FSView could not start it again after the repair"
                ))
            })?;
        let branch_entry = entries
            .iter()
            .find(|e| e.file == owner.target)
            .ok_or_else(|| {
                bad(format!(
                    "{} is not in fstab, so FSView could not mount it again after the repair",
                    owner.target
                ))
            })?;
        for other in ph::mergerfs_pools(&mounts)
            .into_iter()
            .filter(|m| m.target != pool)
        {
            let shared = match self.pool_branches(&other.target) {
                Ok(bs) => bs.iter().any(|x| ph::is_under(&x.path, &owner.target)),
                Err(_) => entries
                    .iter()
                    .filter(|e| e.file == other.target && is_mergerfs(e))
                    .any(|e| {
                        mergerfs_branches(e)
                            .iter()
                            .any(|x| ph::is_under(x, &owner.target))
                    }),
            };
            if shared {
                return Err(bad(format!(
                    "pool {} also uses {}; unmount that pool first",
                    other.target, owner.target
                )));
            }
        }
        if !tool_exists("fsck.ext4") {
            return Err(bad("fsck.ext4 is not installed (apt install e2fsprogs)"));
        }
        let inv = self.inventory().map_err(failed)?;
        let disk = disk_of(&inv, &device)
            .ok_or_else(|| bad(format!("cannot find the disk holding {device}")))?;
        let st = self.smart_state(&disk, true);
        let Some(counts) = st.counts.filter(|c| !c.is_empty()) else {
            return Err(bad(format!(
                "SMART of {disk} could not be read, so FSView cannot rule out a failing disk; check it on the Health page first"
            )));
        };
        if counts.uncorrected() > 0 {
            return Err(bad(format!(
                "{disk} reports errors it could not correct ({}); fsck on a failing disk can make recovery harder. Copy the data off (e.g. ddrescue) instead of repairing it in place",
                counts.describe()
            )));
        }

        let mut actions = vec![];
        for c in &self.cfg.repair_stop {
            actions.push(Action::RunBestEffort(c.clone()));
        }
        actions.push(Action::Run(vec!["umount".into(), pool.clone()]));
        actions.push(Action::Run(vec!["umount".into(), owner.target.clone()]));
        actions.push(Action::Run(vec![
            "fsck.ext4".into(),
            "-f".into(),
            "-y".into(),
            device.clone(),
        ]));
        actions.push(Action::Run(own_scope(self.mount_command(branch_entry))));
        actions.push(Action::Run(own_scope(self.mount_command(pool_entry))));
        for c in &self.cfg.repair_post {
            actions.push(Action::RunBestEffort(c.clone()));
        }

        let journal = self.boot_kernel_log();
        let errors = ph::ext4_errors(&journal, ph::kernel_name(&device));
        let mut detail = format!(
            "Repairing branch {} of {pool}: {} ({device}, disk {disk}, SMART: {}).\n",
            b.path,
            owner.target,
            counts.describe()
        );
        if self.cfg.repair_stop.is_empty() {
            detail.push_str("No stop commands are configured (repair_stop in helper.conf); programs using the pool must be stopped by hand or the unmount fails.\n");
        }
        if let Some(first) = errors.first() {
            detail.push_str(&format!(
                "First ext4 error this boot ({}): {}\nKernel messages in the {} minutes before it (likely trigger):\n",
                first.time().format("%Y-%m-%d %H:%M:%S UTC"),
                first.message.trim(),
                ph::TRIGGER_WINDOW_SECS / 60
            ));
            let ctx = ph::trigger_context(&journal, first, ph::TRIGGER_WINDOW_SECS);
            if ctx.is_empty() {
                detail.push_str("  (none)\n");
            }
            for e in ctx {
                detail.push_str(&format!(
                    "  {} {}\n",
                    e.time().format("%H:%M:%S"),
                    e.message.trim()
                ));
            }
        } else {
            detail.push_str("No ext4 errors for this device in the kernel log of this boot.\n");
        }
        Ok(Plan {
            targets: vec![disk],
            actions,
            summary: format!(
                "repair branch {} of {pool} (fsck {device}) and start the pool again",
                b.path
            ),
            detail,
        })
    }
}

/// Resolves symlinks such as `/dev/disk/by-uuid/...`; returns the input
/// when it cannot be resolved.
fn canonical(p: &str) -> String {
    std::fs::canonicalize(p)
        .map(|c| c.display().to_string())
        .unwrap_or_else(|_| p.to_string())
}

/// Name of the disk holding device path `dev` (the disk itself or one of
/// its partitions or layers).
fn disk_of(inv: &Inventory, dev: &str) -> Option<String> {
    if dev.is_empty() {
        return None;
    }
    inv.disks.iter().find_map(|d| {
        let mut on = d.path == dev;
        d.walk(&mut |n| on |= n.path == dev);
        on.then(|| d.name.clone())
    })
}

/// Why the guided repair is not offered for a branch, or empty. The helper
/// re-checks everything (SMART with the disk awake, other pools sharing the
/// filesystem) when the repair is actually requested; this is only for the
/// UI.
fn repair_blocker(
    h: &BranchHealth,
    pool: &str,
    entries: &[crate::fstab::FsEntry],
    dev_exists: impl Fn(&str) -> bool,
) -> String {
    if h.mount_target.is_empty() || h.mount_target == "/" {
        return "the branch's own disk is not mounted".into();
    }
    if !REPAIRABLE_FS.contains(&h.fstype.as_str()) {
        return format!("{} is not ext2/3/4", h.fstype);
    }
    if !dev_exists(&h.device) {
        return "its device is gone; reconnect the disk".into();
    }
    if !entries.iter().any(|e| e.file == pool && is_mergerfs(e)) {
        return format!("{pool} is not in fstab");
    }
    if !entries.iter().any(|e| e.file == h.mount_target) {
        return format!("{} is not in fstab", h.mount_target);
    }
    if h.smart.as_ref().is_some_and(|s| s.uncorrected() > 0) {
        return "SMART shows uncorrected errors: copy the data off instead".into();
    }
    String::new()
}

/// Turns the path asked about into a path relative to the pool root.
/// Absolute paths must lie inside the pool; `..` and NUL are refused.
fn relative_in_pool(pool: &str, path: &str) -> Result<String, OpError> {
    if path.contains('\0') {
        return Err(bad("invalid path"));
    }
    let rel = if path.starts_with('/') {
        let root = pool.trim_end_matches('/');
        if path == root {
            ""
        } else {
            path.strip_prefix(&format!("{root}/"))
                .ok_or_else(|| bad(format!("{path} is not inside {pool}")))?
        }
    } else {
        path
    };
    let mut parts = vec![];
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return Err(bad("the path must not contain '..'")),
        }
    }
    if parts.is_empty() {
        return Err(bad("give a file or directory inside the pool"));
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths() {
        let r = |p| relative_in_pool("/mnt/pool", p);
        assert_eq!(r("/mnt/pool/music/a.flac").unwrap(), "music/a.flac");
        assert_eq!(r("music/./a.flac").unwrap(), "music/a.flac");
        assert!(r("/mnt/pool").is_err());
        assert!(r("/mnt/poolx/a").is_err());
        assert!(r("music/../../etc/shadow").is_err());
        assert!(r("/etc/passwd").is_err());
    }
}
