//! Reports fstab entries that failed to mount or mounted late during the
//! current boot, and disks that appeared after the mount timeout.

mod fstab;

pub use fstab::{escape_path, parse_fstab, parse_systemd_duration, Entry};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::{self, attached_device};
use crate::inventory::{parse_findmnt, Inventory, Mount};
use crate::runner::Runner;

/// Raw material the helper collects (read-only).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Data {
    pub boot_id: String,
    pub collected_at: DateTime<Utc>,
    pub fstab: String,
    pub units: BTreeMap<String, BTreeMap<String, String>>,
    pub manager: BTreeMap<String, String>,
    pub kernel: Vec<events::Entry>,
    pub systemd: Vec<events::Entry>,
    pub mounts: Vec<Mount>,
}

const UNIT_PROPS: &str = "Id,LoadState,ActiveState,SubState,Result,ActiveEnterTimestampMonotonic,InactiveExitTimestampMonotonic";

pub fn read_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().replace('-', ""))
        .unwrap_or_default()
}

/// Gathers Data. It only reads.
pub fn collect(r: &dyn Runner, fstab_path: &Path) -> Result<Data, String> {
    let fstab = std::fs::read_to_string(fstab_path)
        .map_err(|e| format!("{}: {e}", fstab_path.display()))?;
    let mut d = Data {
        fstab,
        collected_at: Utc::now(),
        boot_id: read_boot_id(),
        ..Default::default()
    };
    let (entries, _) = parse_fstab(&d.fstab);
    let mut units = Vec::new();
    for e in &entries {
        let mu = e.mount_unit();
        if !mu.is_empty() && !e.is_virtual() {
            units.push(mu);
        }
        if let Some(du) = e.device_unit() {
            units.push(du);
        }
    }
    if !units.is_empty() {
        let mut args = vec!["show", "--no-pager", "-p", UNIT_PROPS, "--"];
        args.extend(units.iter().map(String::as_str));
        if let Ok(res) = r.run("systemctl", &args) {
            for blk in parse_show(&String::from_utf8_lossy(&res.stdout)) {
                if let Some(id) = blk.get("Id").cloned().filter(|s| !s.is_empty()) {
                    d.units.insert(id, blk);
                }
            }
        }
    }
    if let Ok(res) = r.run(
        "systemctl",
        &[
            "show",
            "--no-pager",
            "-p",
            "UserspaceTimestampMonotonic,FinishTimestampMonotonic,KernelTimestamp",
        ],
    ) {
        if let Some(b) = parse_show(&String::from_utf8_lossy(&res.stdout))
            .into_iter()
            .next()
        {
            d.manager = b;
        }
    }
    if let Ok(res) = r.run("journalctl", &["-k", "-b", "-o", "json", "--no-pager"]) {
        d.kernel = events::parse_json_lines(&res.stdout)
            .into_iter()
            .filter(|e| attached_device(&e.message).is_some())
            .collect();
    }
    if let Ok(res) = r.run("journalctl", &["-b", "_PID=1", "-o", "json", "--no-pager"]) {
        d.systemd = events::parse_json_lines(&res.stdout)
            .into_iter()
            .filter(|e| systemd_interesting(&e.message))
            .collect();
    }
    if let Ok(res) = r.run("findmnt", &["-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]) {
        d.mounts = parse_findmnt(&res.stdout).unwrap_or_default();
    }
    Ok(d)
}

fn systemd_interesting(msg: &str) -> bool {
    [
        "Timed out waiting for device",
        "Dependency failed for",
        "Failed to mount",
        "Mounted ",
        "Activated swap",
        "Failed to activate swap",
        "Job dev-",
    ]
    .iter()
    .any(|k| msg.contains(k))
}

/// Parses `systemctl show` output (blank-line separated blocks).
pub fn parse_show(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut out = Vec::new();
    let mut cur = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.insert(k.to_string(), v.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub boot_id: String,
    pub collected_at: DateTime<Utc>,
    #[serde(rename = "userspace_start_sec")]
    pub userspace_sec: f64,
    #[serde(rename = "boot_finished_sec")]
    pub finished_sec: f64,
    pub entries: Vec<EntryResult>,
    pub late_devices: Vec<LateDevice>,
    pub summary: Summary,
    #[serde(
        rename = "fstab_errors",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub fstab_parse_errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub ok: u32,
    pub failed: u32,
    pub late: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryResult {
    pub line: usize,
    pub spec: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: String,
    /// ok | failed | late | skipped
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disk: String,
    pub mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounted_sec: Option<f64>,
    #[serde(
        rename = "device_appeared_sec",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub device_sec: Option<f64>,
    pub device_timeout_sec: f64,
    pub nofail: bool,
    pub noauto: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LateDevice {
    pub device: String,
    pub appeared_sec: f64,
    pub after_timeout: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mountpoints: Vec<String>,
    pub message: String,
}

fn usec_prop(m: Option<&BTreeMap<String, String>>, k: &str) -> f64 {
    m.and_then(|m| m.get(k))
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0) as f64
        / 1e6
}

/// Finds the lsblk node and whole disk for an fstab spec.
fn resolve_spec(spec: &str, inv: Option<&Inventory>) -> (String, String) {
    let Some(inv) = inv else {
        return Default::default();
    };
    let mut key = "";
    let mut val = String::new();
    for p in ["UUID=", "LABEL=", "PARTUUID=", "PARTLABEL="] {
        if let Some(v) = spec.strip_prefix(p) {
            key = p;
            val = v.trim_matches('"').to_string();
        }
    }
    for (prefix, k) in [
        ("/dev/disk/by-uuid/", "UUID="),
        ("/dev/disk/by-label/", "LABEL="),
        ("/dev/disk/by-partuuid/", "PARTUUID="),
        ("/dev/disk/by-partlabel/", "PARTLABEL="),
    ] {
        if let Some(v) = spec.strip_prefix(prefix) {
            key = k;
            val = v.to_string();
        }
    }
    // /dev/VG/LV -> device-mapper name VG-LV (dashes doubled).
    let mut lv_name = String::new();
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() == 4
        && parts[0].is_empty()
        && parts[1] == "dev"
        && parts[2] != "mapper"
        && parts[2] != "disk"
    {
        lv_name = format!(
            "{}-{}",
            parts[2].replace('-', "--"),
            parts[3].replace('-', "--")
        );
    }
    let matches = |name: &str,
                   path: &str,
                   uuid: &str,
                   label: &str,
                   partuuid: &str,
                   partlabel: &str| match key {
        "UUID=" => uuid.eq_ignore_ascii_case(&val),
        "LABEL=" => label == val,
        "PARTUUID=" => partuuid.eq_ignore_ascii_case(&val),
        "PARTLABEL=" => partlabel == val,
        _ => {
            path == spec
                || format!("/dev/{name}") == spec
                || (!lv_name.is_empty() && name == lv_name)
        }
    };
    for d in &inv.disks {
        if matches(&d.name, &d.path, &d.uuid, &d.label, "", "") {
            return (d.name.clone(), d.name.clone());
        }
        let mut found = String::new();
        d.walk(&mut |n| {
            if found.is_empty()
                && matches(
                    &n.name,
                    &n.path,
                    &n.uuid,
                    &n.label,
                    &n.partuuid,
                    &n.partlabel,
                )
            {
                found = n.name.clone();
            }
        });
        if !found.is_empty() {
            return (found, d.name.clone());
        }
    }
    Default::default()
}

fn fmt_sec(s: f64) -> String {
    let tenths = (s * 10.0).round() as i64;
    let (h, rem) = (tenths / 36000, tenths % 36000);
    let (m, t) = (rem / 600, rem % 600);
    let secs = format!("{}.{}s", t / 10, t % 10);
    let secs = secs.replace(".0s", "s");
    match (h, m) {
        (0, 0) => secs,
        (0, m) => format!("{m}m{secs}"),
        (h, m) => format!("{h}h{m}m{secs}"),
    }
}

/// Turns collected data into a report.
pub fn analyze(d: &Data, inv: Option<&Inventory>) -> Report {
    let mut rep = Report {
        boot_id: d.boot_id.clone(),
        collected_at: d.collected_at,
        userspace_sec: usec_prop(Some(&d.manager), "UserspaceTimestampMonotonic"),
        finished_sec: usec_prop(Some(&d.manager), "FinishTimestampMonotonic"),
        ..Default::default()
    };
    let (entries, perrs) = parse_fstab(&d.fstab);
    rep.fstab_parse_errors = perrs;
    let mounted: HashSet<&str> = d.mounts.iter().map(|m| m.target.as_str()).collect();
    let mut attached: HashMap<String, &events::Entry> = HashMap::new();
    for k in &d.kernel {
        if let Some(dev) = attached_device(&k.message) {
            attached.entry(dev).or_insert(k);
        }
    }

    let mut results: Vec<EntryResult> = Vec::new();
    let mut min_timeout = 0f64;
    for e in &entries {
        let mut r = EntryResult {
            line: e.line,
            spec: e.spec.clone(),
            mountpoint: e.file.clone(),
            fstype: e.vfstype.clone(),
            options: e.options.join(","),
            nofail: e.has("nofail"),
            noauto: e.has("noauto"),
            device_timeout_sec: e.device_timeout().as_secs_f64(),
            ..Default::default()
        };
        if e.is_virtual() {
            r.status = "skipped".into();
            r.hints.push("virtual filesystem".into());
            results.push(r);
            continue;
        }
        (r.device, r.disk) = resolve_spec(&e.spec, inv);
        let mu = d.units.get(&e.mount_unit());
        r.mounted = if e.is_swap() {
            mu.and_then(|m| m.get("ActiveState")).map(String::as_str) == Some("active")
        } else {
            mounted.contains(e.file.as_str())
        };
        let t = usec_prop(mu, "ActiveEnterTimestampMonotonic");
        if t > 0.0 && r.mounted {
            r.mounted_sec = Some(t);
        }
        let du = e.device_unit();
        if let Some(du) = &du {
            let t = usec_prop(d.units.get(du), "ActiveEnterTimestampMonotonic");
            if t > 0.0 {
                r.device_sec = Some(t);
            }
            if !r.noauto
                && r.device_timeout_sec > 0.0
                && (min_timeout == 0.0 || r.device_timeout_sec < min_timeout)
            {
                min_timeout = r.device_timeout_sec;
            }
        }
        if r.device_sec.is_none() && !r.disk.is_empty() {
            if let Some(k) = attached.get(&r.disk) {
                r.device_sec = Some(k.monotonic_sec());
            }
        }
        if du.is_some() && r.device.is_empty() {
            r.problems
                .push("device not found on this host (missing disk or wrong UUID/LABEL)".into());
        }
        if let Some(res) = mu
            .and_then(|m| m.get("Result"))
            .filter(|s| !s.is_empty() && *s != "success")
        {
            r.problems.push(format!("systemd unit result: {res}"));
        }
        let mount_unit = e.mount_unit();
        for s in &d.systemd {
            let msg = s.message.trim();
            let mentions = (!mount_unit.is_empty() && msg.contains(&mount_unit))
                || msg.ends_with(&format!(" {}.", e.file))
                || du.as_ref().is_some_and(|du| msg.contains(du.as_str()));
            if !mentions {
                continue;
            }
            if msg.contains("Timed out waiting for device") {
                r.problems.push(format!(
                    "systemd timed out waiting for the device after {}s (at +{:.1}s)",
                    r.device_timeout_sec,
                    s.monotonic_sec()
                ));
            } else if msg.contains("Dependency failed for") {
                r.problems.push(format!(
                    "mount skipped: dependency failed (at +{:.1}s)",
                    s.monotonic_sec()
                ));
            } else if msg.contains("Failed to mount") {
                r.problems
                    .push(format!("mount failed (at +{:.1}s)", s.monotonic_sec()));
            }
        }
        if e.is_mergerfs() {
            r.depends_on = e.mergerfs_branches();
        }
        results.push(r);
    }

    // Dependencies: mergerfs branches.
    let snapshot: Vec<(String, bool, bool)> = results
        .iter()
        .map(|r| (r.mountpoint.clone(), r.mounted, r.noauto))
        .collect();
    let mut dep_failed = vec![false; results.len()];
    for (i, r) in results.iter_mut().enumerate() {
        for b in r.depends_on.clone() {
            let Some((dep_mp, _, _)) =
                owning_mount(&b, &snapshot, &r.mountpoint).filter(|(_, m, na)| !*m && !*na)
            else {
                continue;
            };
            dep_failed[i] = true;
            if r.mounted {
                r.problems.push(format!("branch {b} is not mounted, but this pool is: files written to the pool land in the empty {dep_mp} directory on the filesystem underneath (usually the root disk)"));
                r.hints.push(format!("Use a subdirectory that only exists on the mounted disk as the branch (e.g. {}/data) or protect the mountpoints (FSView Pools → Protect mountpoints), and add x-systemd.wants-mounts-for={dep_mp} to this entry.", dep_mp.trim_end_matches('/')));
            } else {
                r.problems
                    .push(format!("depends on {dep_mp}, which is not mounted"));
            }
        }
    }

    for (i, r) in results.iter_mut().enumerate() {
        if r.status == "skipped" {
            rep.summary.skipped += 1;
            continue;
        }
        let mut late = false;
        if let Some(ds) = r.device_sec {
            if r.device_timeout_sec > 0.0
                && rep.userspace_sec > 0.0
                && ds > rep.userspace_sec + r.device_timeout_sec
            {
                late = true;
                let who = if r.disk.is_empty() {
                    r.device.clone()
                } else {
                    r.disk.clone()
                };
                r.problems.push(format!(
                    "device {who} appeared at +{}, {} after userspace start; its device timeout is {}s",
                    fmt_sec(ds),
                    fmt_sec(ds - rep.userspace_sec),
                    r.device_timeout_sec
                ));
                r.hints.push("The disk is enumerated too late for this timeout. Check spin-up/staggered start on the HBA or shelf, or raise x-systemd.device-timeout.".into());
            }
        }
        if let Some(ms) = r.mounted_sec {
            if rep.finished_sec > 0.0 && ms > rep.finished_sec + 1.0 {
                late = true;
                r.problems.push(format!(
                    "mounted at +{}, after boot finished at +{} (manual mount or late retry)",
                    fmt_sec(ms),
                    fmt_sec(rep.finished_sec)
                ));
            }
        }
        if dep_failed[i] {
            r.status = "failed".into();
            if !r.mounted {
                r.problems.insert(0, "not mounted".into());
            }
            rep.summary.failed += 1;
        } else if r.noauto && !r.mounted {
            r.status = "skipped".into();
            r.hints.push("noauto: not mounted at boot by design".into());
            rep.summary.skipped += 1;
        } else if !r.mounted {
            r.status = "failed".into();
            r.problems.insert(0, "not mounted".into());
            rep.summary.failed += 1;
        } else if late {
            r.status = "late".into();
            rep.summary.late += 1;
        } else {
            r.status = "ok".into();
            rep.summary.ok += 1;
        }
    }

    // Disks that appeared after the shortest device-timeout window.
    if rep.userspace_sec > 0.0 {
        let window = if min_timeout == 0.0 {
            90.0
        } else {
            min_timeout
        };
        for (dev, k) in &attached {
            let t = k.monotonic_sec();
            let mut mps = Vec::new();
            let mut after = false;
            for r in results.iter().filter(|r| &r.disk == dev) {
                mps.push(r.mountpoint.clone());
                if r.device_timeout_sec > 0.0 && t > rep.userspace_sec + r.device_timeout_sec {
                    after = true;
                }
            }
            if t > rep.userspace_sec + window || after {
                rep.late_devices.push(LateDevice {
                    device: dev.clone(),
                    appeared_sec: t,
                    after_timeout: after,
                    mountpoints: mps,
                    message: k.message.clone(),
                });
            }
        }
        rep.late_devices
            .sort_by(|a, b| a.appeared_sec.total_cmp(&b.appeared_sec));
    }
    rep.entries = results;
    rep
}

/// The fstab entry whose mountpoint contains `path` (never "/").
fn owning_mount<'a>(
    path: &str,
    all: &'a [(String, bool, bool)],
    this: &str,
) -> Option<&'a (String, bool, bool)> {
    all.iter()
        .filter(|(mp, _, _)| mp != this && mp != "none" && mp.starts_with('/'))
        .filter(|(mp, _, _)| {
            path == mp || path.starts_with(&format!("{}/", mp.trim_end_matches('/')))
        })
        .max_by_key(|(mp, _, _)| mp.len())
        .filter(|(mp, _, _)| mp != "/")
}

#[cfg(test)]
mod tests;
