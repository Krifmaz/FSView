//! SMR protection on the root side: plans the sysfs and sysctl writes that
//! [`crate::smr`] describes, only where the current value differs.

use std::path::{Path, PathBuf};

use super::ops::{bad, decode, disk_re, Action, OpError, Plan};
use super::Server;
use crate::proto::*;
use crate::smr;

/// Current value of a sysfs/procfs file, trimmed. None when unreadable.
fn read_num(p: &Path) -> Option<u64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

impl Server {
    /// Plans SMR protection: for each disk in `smr_disks`, queue depth
    /// [`smr::QUEUE_DEPTH`] and a command timeout of at least
    /// [`smr::TIMEOUT_SECS`]; with `writeback`, `vm.dirty_bytes` and
    /// `vm.dirty_background_bytes` capped to [`smr::DIRTY_BYTES`] and
    /// [`smr::DIRTY_BACKGROUND_BYTES`]. Values already in place are left
    /// alone, so a repeated call plans nothing. Timeouts are only raised,
    /// never lowered (a longer timeout set by hand stays). Settings a device
    /// rejected once are skipped until the helper restarts.
    pub(super) fn prep_disk_tune(&self, req: &Request) -> Result<Plan, OpError> {
        let p: DiskTuneParams = decode(req)?;
        let failed = self.tune_failed.lock().unwrap().clone();
        let mut actions = vec![];
        let mut targets = vec![];
        let mut want = |path: PathBuf, value: u64, ok: &dyn Fn(u64) -> bool| -> bool {
            if failed.contains(&path) || read_num(&path).is_some_and(ok) {
                return false;
            }
            if !path.exists() {
                return false;
            }
            actions.push(Action::TrySysfs {
                path,
                value: value.to_string(),
            });
            true
        };
        for d in &p.smr_disks {
            if !disk_re().is_match(d) {
                return Err(bad(format!("invalid disk name {d:?}")));
            }
            let dev = self.cfg.sys_root.join("block").join(d).join("device");
            let a = want(dev.join("queue_depth"), u64::from(smr::QUEUE_DEPTH), &|v| {
                v == u64::from(smr::QUEUE_DEPTH)
            });
            let b = want(dev.join("timeout"), u64::from(smr::TIMEOUT_SECS), &|v| {
                v >= u64::from(smr::TIMEOUT_SECS)
            });
            if a || b {
                targets.push(d.clone());
            }
        }
        if p.writeback {
            let vm = self.cfg.proc_sys.join("vm");
            let a = want(vm.join("dirty_bytes"), smr::DIRTY_BYTES, &|v| {
                v != 0 && v <= smr::DIRTY_BYTES
            });
            let b = want(
                vm.join("dirty_background_bytes"),
                smr::DIRTY_BACKGROUND_BYTES,
                &|v| v != 0 && v <= smr::DIRTY_BACKGROUND_BYTES,
            );
            if a || b {
                targets.push("writeback".into());
            }
        }
        Ok(Plan {
            summary: if actions.is_empty() {
                "SMR protection already applied".into()
            } else {
                format!("SMR protection for {}", targets.join(", "))
            },
            targets,
            actions,
            detail: String::new(),
        })
    }
}
