//! Hidden data: files stored in a directory on a parent filesystem that
//! another filesystem is now mounted over. They use space but are
//! invisible. This happens when a disk failed to mount and services wrote
//! into the empty mountpoint (78 GB filled spiritlab's root disk this way).
//!
//! The scan runs on a dedicated OS thread inside a private mount namespace:
//! each parent filesystem is bind-mounted read-only and non-recursively
//! (child mounts are not carried over) into a temporary directory. The
//! bind mount is never visible on the host and disappears with the thread.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use serde_json::Value;

use super::Server;
use crate::proto::{HiddenResult, HiddenSample};

/// Filesystems worth scanning as parents.
const REAL_FS: [&str; 14] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3",
    "fuseblk", "jfs", "reiserfs",
];

const MAX_FILES: u64 = 200_000;
const MAX_TIME: Duration = Duration::from_secs(60);
const SAMPLES: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct ScanJob {
    pub parent: String,
    pub parent_source: String,
    /// Child mount targets sitting directly on the parent.
    pub children: Vec<String>,
}

/// Parents (from the findmnt tree) and the child mountpoints on them.
/// `root_only` limits the scan to the root filesystem.
pub fn plan_hidden_scan(findmnt_json: &[u8], root_only: bool) -> Result<Vec<ScanJob>, String> {
    let doc: Value = serde_json::from_slice(findmnt_json).map_err(|e| e.to_string())?;
    let mut jobs = Vec::new();
    fn walk(n: &Value, root_only: bool, jobs: &mut Vec<ScanJob>) {
        let s = |k: &str| n.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let children: &[Value] = n
            .get("children")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let target = s("target");
        if REAL_FS.contains(&s("fstype").as_str()) && (!root_only || target == "/") {
            let kids: Vec<String> = children
                .iter()
                .filter_map(|c| c.get("target").and_then(Value::as_str))
                // A mount stacked on the same path hides the parent entirely.
                .filter(|t| *t != target)
                .map(String::from)
                .collect();
            if !kids.is_empty() {
                jobs.push(ScanJob {
                    parent: target.clone(),
                    parent_source: s("source"),
                    children: kids,
                });
            }
        }
        for c in children {
            walk(c, root_only, jobs);
        }
    }
    for f in doc
        .get("filesystems")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(f, root_only, &mut jobs);
    }
    Ok(jobs)
}

struct Measure {
    files: u64,
    bytes: u64,
    truncated: bool,
    samples: Vec<HiddenSample>,
}

/// Counts regular files below `dir` (symlinks are not followed) and the
/// largest top-level entries.
fn measure(dir: &Path, deadline: Instant) -> Measure {
    let mut m = Measure {
        files: 0,
        bytes: 0,
        truncated: false,
        samples: vec![],
    };
    let mut tops: BTreeMap<String, u64> = BTreeMap::new();
    let mut stack: Vec<(PathBuf, String)> = Vec::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        tops.insert(name.clone(), 0);
        stack.push((e.path(), name));
    }
    while let Some((p, top)) = stack.pop() {
        if m.files >= MAX_FILES || Instant::now() > deadline {
            m.truncated = true;
            break;
        }
        let Ok(md) = fs::symlink_metadata(&p) else {
            continue;
        };
        if md.is_file() {
            m.files += 1;
            m.bytes += md.len();
            *tops.entry(top).or_default() += md.len();
        } else if md.is_dir() {
            for e in fs::read_dir(&p).into_iter().flatten().flatten() {
                stack.push((e.path(), top.clone()));
            }
        }
    }
    m.samples = tops
        .into_iter()
        .map(|(name, bytes)| HiddenSample { name, bytes })
        .collect();
    m.samples.sort_by_key(|s| std::cmp::Reverse(s.bytes));
    m.samples.truncate(SAMPLES);
    m
}

fn scan_in_namespace(jobs: Vec<ScanJob>, scratch: PathBuf) -> Result<Vec<HiddenResult>, String> {
    unshare(CloneFlags::CLONE_NEWNS).map_err(|e| format!("unshare mount namespace: {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make mounts private: {e}"))?;
    let tmp = scratch.join(format!(
        "fsview-hidden-{}",
        hex::encode(crate::auth::random_bytes::<6>())
    ));
    fs::create_dir(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let deadline = Instant::now() + MAX_TIME;
    let mut out = Vec::new();
    for j in jobs {
        if let Err(e) = mount(
            Some(j.parent.as_str()),
            &tmp,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            out.push(HiddenResult {
                parent: j.parent.clone(),
                parent_source: j.parent_source.clone(),
                error: format!("bind mount failed: {e}"),
                ..Default::default()
            });
            continue;
        }
        let _ = mount(
            None::<&str>,
            &tmp,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        );
        let base = j.parent.trim_end_matches('/');
        for child in &j.children {
            let rel = child
                .strip_prefix(base)
                .unwrap_or(child)
                .trim_start_matches('/');
            let dir = tmp.join(rel);
            if !fs::symlink_metadata(&dir)
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                continue;
            }
            let m = measure(&dir, deadline);
            if m.files > 0 || !m.samples.is_empty() {
                out.push(HiddenResult {
                    mountpoint: child.clone(),
                    parent: j.parent.clone(),
                    parent_source: j.parent_source.clone(),
                    files: m.files,
                    bytes: m.bytes,
                    truncated: m.truncated,
                    samples: m.samples,
                    error: String::new(),
                });
            }
        }
        let _ = umount2(&tmp, MntFlags::MNT_DETACH);
    }
    let _ = fs::remove_dir(&tmp);
    Ok(out)
}

impl Server {
    pub(super) fn scan_hidden(&self, root_only: bool) -> Result<Vec<HiddenResult>, String> {
        let out = self
            .runner
            .run("findmnt", &["-J", "-o", "TARGET,SOURCE,FSTYPE"])
            .map_err(|e| format!("findmnt: {e}"))?;
        if out.code != 0 {
            return Err(format!("findmnt exited {}", out.code));
        }
        let jobs = plan_hidden_scan(&out.stdout, root_only)?;
        let scratch = self.cfg.scratch_dir.clone();
        // A fresh OS thread: its private mount namespace dies with it.
        std::thread::Builder::new()
            .name("fsview-hidden-scan".into())
            .spawn(move || scan_in_namespace(jobs, scratch))
            .map_err(|e| e.to_string())?
            .join()
            .map_err(|_| "hidden-data scan panicked".to_string())?
    }
}
