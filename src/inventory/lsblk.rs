use serde_json::Value;

use super::{Disk, Node, Usage};

/// Columns requested from lsblk (with -b for byte sizes).
pub const LSBLK_COLUMNS: &str = "NAME,KNAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,VENDOR,REV,TRAN,HCTL,WWN,ROTA,RM,RO,STATE,\
PTTYPE,FSTYPE,FSVER,LABEL,UUID,PARTUUID,PARTLABEL,PARTTYPENAME,PARTN,MOUNTPOINTS,FSSIZE,FSUSED,FSAVAIL";

pub const LSBLK_ARGS: [&str; 4] = ["-J", "-b", "-o", LSBLK_COLUMNS];

// lsblk's JSON types vary between versions (numbers vs. strings, bools vs.
// "0"/"1"), so fields are read leniently.

pub(crate) fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

pub(crate) fn n(v: &Value, k: &str) -> Option<u64> {
    match v.get(k) {
        Some(Value::Number(x)) => x.as_u64(),
        Some(Value::String(x)) => x.trim().parse().ok(),
        _ => None,
    }
}

fn b(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(x)) => *x,
        Some(Value::Number(x)) => x.as_u64() == Some(1),
        Some(Value::String(x)) => x.trim() == "1" || x.trim() == "true",
        _ => false,
    }
}

fn mounts(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |m: &Value| {
        if let Value::String(x) = m {
            if !x.is_empty() && !out.contains(x) {
                out.push(x.clone());
            }
        }
    };
    if let Some(Value::Array(a)) = v.get("mountpoints") {
        a.iter().for_each(&mut add);
    }
    if let Some(m) = v.get("mountpoint") {
        add(m);
    }
    out
}

fn usage(v: &Value) -> Option<Usage> {
    let size = n(v, "fssize")?;
    Some(Usage {
        size_bytes: size,
        used_bytes: n(v, "fsused").unwrap_or(0),
        avail_bytes: n(v, "fsavail").unwrap_or(0),
    })
}

fn children(v: &Value) -> Vec<Node> {
    match v.get("children") {
        Some(Value::Array(a)) => a.iter().map(to_node).collect(),
        _ => Vec::new(),
    }
}

fn to_node(v: &Value) -> Node {
    let name = s(v, "name");
    let mut kname = s(v, "kname");
    if kname.is_empty() {
        kname = name.clone();
    }
    let mut path = s(v, "path");
    if path.is_empty() {
        path = format!("/dev/{name}");
    }
    Node {
        kname,
        path,
        kind: s(v, "type"),
        size_bytes: n(v, "size").unwrap_or(0),
        fstype: s(v, "fstype"),
        fsver: s(v, "fsver"),
        label: s(v, "label"),
        uuid: s(v, "uuid"),
        partuuid: s(v, "partuuid"),
        partlabel: s(v, "partlabel"),
        parttypename: s(v, "parttypename"),
        partn: n(v, "partn").map(|x| x as u32),
        read_only: b(v, "ro"),
        mountpoints: mounts(v),
        usage: usage(v),
        children: children(v),
        name,
    }
}

/// Converts `lsblk -J` output into disks. Only whole disks (and loop
/// devices when `include_loop` is set) become top-level entries.
pub fn parse_lsblk(data: &[u8], include_loop: bool) -> Result<Vec<Disk>, String> {
    let doc: Value = serde_json::from_slice(data).map_err(|e| format!("parse lsblk: {e}"))?;
    let mut disks = Vec::new();
    let Some(Value::Array(devs)) = doc.get("blockdevices") else {
        return Err("parse lsblk: no blockdevices".into());
    };
    for d in devs {
        let typ = s(d, "type");
        let name = s(d, "name");
        let size = n(d, "size").unwrap_or(0);
        let keep = (typ == "disk" && !name.starts_with("zram"))
            || (typ == "loop" && include_loop && size > 0);
        if !keep {
            continue;
        }
        let mut path = s(d, "path");
        if path.is_empty() {
            path = format!("/dev/{name}");
        }
        let mut transport = s(d, "tran");
        if typ == "loop" {
            transport = "loop".into();
        }
        disks.push(Disk {
            name,
            path,
            model: display_model(&s(d, "vendor"), &s(d, "model")),
            vendor: s(d, "vendor"),
            serial: s(d, "serial"),
            wwn: s(d, "wwn"),
            revision: s(d, "rev"),
            size_bytes: size,
            transport,
            hctl: s(d, "hctl"),
            rotational: b(d, "rota"),
            removable: b(d, "rm"),
            read_only: b(d, "ro"),
            state: s(d, "state"),
            pttype: s(d, "pttype"),
            fstype: s(d, "fstype"),
            fsver: s(d, "fsver"),
            label: s(d, "label"),
            uuid: s(d, "uuid"),
            mountpoints: mounts(d),
            usage: usage(d),
            children: children(d),
            kind: typ,
            ..Default::default()
        });
    }
    Ok(disks)
}

/// Vendor + model the way people read it; generic vendors are dropped.
pub fn display_model(vendor: &str, model: &str) -> String {
    let vendor = vendor.trim();
    let model = model.trim();
    match vendor.to_uppercase().as_str() {
        "" | "ATA" | "NVME" => return model.to_string(),
        _ => {}
    }
    if model.to_uppercase().starts_with(&vendor.to_uppercase()) {
        return model.to_string();
    }
    format!("{vendor} {model}")
}
