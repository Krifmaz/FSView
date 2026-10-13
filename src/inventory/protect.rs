use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Disk;

/// Mountpoints whose backing disks are protected.
pub const SYSTEM_MOUNTPOINTS: [&str; 6] = ["/", "/boot", "/boot/efi", "/efi", "/usr", "/var"];

/// One entry from findmnt.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Mount {
    pub target: String,
    pub source: String,
    pub fstype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub options: String,
}

/// Flattens `findmnt -J` output.
pub fn parse_findmnt(data: &[u8]) -> Result<Vec<Mount>, String> {
    let doc: Value = serde_json::from_slice(data).map_err(|e| format!("parse findmnt: {e}"))?;
    let mut out = Vec::new();
    fn rec(v: &Value, out: &mut Vec<Mount>) {
        if let Value::Array(a) = v {
            for f in a {
                let g = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                out.push(Mount {
                    target: g("target"),
                    source: g("source"),
                    fstype: g("fstype"),
                    options: g("options"),
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

/// Everything needed to decide which disks hold the system.
#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub mounts: Vec<Mount>,
    /// Block devices (paths) in use as swap.
    pub swap_devices: Vec<String>,
    /// Other device paths holding the system (root VG PVs, root pool
    /// vdevs), with the reason.
    pub extra_system_devices: BTreeMap<String, String>,
}

/// Resolves a device path (possibly a symlink) to its kernel name.
pub type Resolver<'a> = &'a dyn Fn(&str) -> String;

pub fn real_resolver(path: &str) -> String {
    let p = std::fs::canonicalize(path).unwrap_or_else(|_| Path::new(path).to_path_buf());
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Strips a btrfs subvolume suffix like "/dev/sda2[/@]".
fn source_device(src: &str) -> &str {
    match src.find('[') {
        Some(i) if i > 0 => &src[..i],
        _ => src,
    }
}

/// Flags every disk that holds a system mountpoint, active swap, or one of
/// the extra system devices.
pub fn mark_protected(disks: &mut [Disk], sys: &SystemInfo, resolve: Resolver) {
    struct Want {
        path: String,
        kname: String,
        reason: String,
    }
    let mut wants: Vec<Want> = Vec::new();
    let mut add = |dev: &str, reason: String| {
        if dev.starts_with("/dev/") {
            wants.push(Want {
                path: dev.to_string(),
                kname: resolve(dev),
                reason,
            });
        }
    };
    for mp in SYSTEM_MOUNTPOINTS {
        for m in sys.mounts.iter().filter(|m| m.target == mp) {
            add(source_device(&m.source), format!("holds {mp}"));
        }
    }
    for s in &sys.swap_devices {
        add(s, "active swap".into());
    }
    for (dev, reason) in &sys.extra_system_devices {
        add(dev, reason.clone());
    }

    for d in disks.iter_mut() {
        let mut reasons = BTreeSet::new();
        let mut check = |path: &str, kname: &str, mounts: &[String], name: &str| {
            for w in &wants {
                if (!w.path.is_empty() && w.path == path)
                    || (!w.kname.is_empty() && w.kname == kname)
                {
                    reasons.insert(format!("{} ({name})", w.reason));
                }
            }
            for m in mounts {
                if SYSTEM_MOUNTPOINTS.contains(&m.as_str()) {
                    reasons.insert(format!("holds {m} ({name})"));
                }
                if m == "[SWAP]" {
                    reasons.insert(format!("active swap ({name})"));
                }
            }
        };
        check(&d.path, &d.name, &d.mountpoints, &d.name);
        d.walk(&mut |n| check(&n.path, &n.kname, &n.mountpoints, &n.name));
        if !reasons.is_empty() {
            d.protected = true;
            d.protected_reasons = reasons.into_iter().collect();
        }
    }
}

/// Block devices from /proc/swaps (swap files live on a system mount anyway).
pub fn parse_proc_swaps(data: &str) -> Vec<String> {
    data.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 2 && f[1] == "partition").then(|| f[0].replace("\\040", " "))
        })
        .collect()
}

/// Rows of `lvs/pvs --reportformat json` for `kind` ("lv" or "pv").
pub fn parse_lvm_report(data: &[u8], kind: &str) -> Result<Vec<BTreeMap<String, String>>, String> {
    let doc: Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for r in doc
        .get("report")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for row in r.get(kind).and_then(Value::as_array).into_iter().flatten() {
            if let Value::Object(o) = row {
                rows.push(
                    o.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect(),
                );
            }
        }
    }
    Ok(rows)
}

/// Device paths from `zpool list -v -H -P`.
pub fn parse_zpool_vdevs(data: &str) -> Vec<String> {
    data.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|f| f.starts_with("/dev/"))
        .map(String::from)
        .collect()
}
