//! fstab document model for the editor: parsing that preserves comments and
//! untouched lines, rendering, validation, risk warnings and line diffs.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::bootcheck::parse_systemd_duration;
use crate::inventory::Inventory;

/// One fstab entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FsEntry {
    pub spec: String,
    pub file: String,
    pub vfstype: String,
    /// Comma-separated, as in fstab.
    pub options: String,
    #[serde(default)]
    pub freq: u32,
    #[serde(default)]
    pub passno: u32,
}

/// A line of /etc/fstab. Comments and unparsable lines are kept verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Line {
    Comment {
        text: String,
    },
    Invalid {
        text: String,
    },
    Entry {
        /// Original text; kept when the entry is unchanged so the diff
        /// shows only real edits.
        #[serde(default)]
        raw: String,
        entry: FsEntry,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    pub lines: Vec<Line>,
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(n);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("\\040"),
            '\t' => out.push_str("\\011"),
            '\n' => out.push_str("\\012"),
            '\\' => out.push_str("\\134"),
            '#' if out.is_empty() => out.push_str("\\043"),
            _ => out.push(c),
        }
    }
    out
}

/// Parses one entry line, or None if it is not an entry.
pub fn parse_entry(line: &str) -> Option<FsEntry> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let f: Vec<&str> = t.split_whitespace().collect();
    if f.len() < 3 || f.len() > 6 {
        return None;
    }
    Some(FsEntry {
        spec: unescape(f[0]),
        file: unescape(f[1]),
        vfstype: f[2].to_string(),
        options: f
            .get(3)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "defaults".into()),
        freq: f.get(4).and_then(|x| x.parse().ok()).unwrap_or(0),
        passno: f.get(5).and_then(|x| x.parse().ok()).unwrap_or(0),
    })
}

pub fn parse(text: &str) -> Doc {
    let lines = text
        .lines()
        .map(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                Line::Comment {
                    text: l.to_string(),
                }
            } else if let Some(entry) = parse_entry(l) {
                Line::Entry {
                    raw: l.to_string(),
                    entry,
                }
            } else {
                Line::Invalid {
                    text: l.to_string(),
                }
            }
        })
        .collect();
    Doc { lines }
}

pub fn format_entry(e: &FsEntry) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        escape(e.spec.trim()),
        escape(e.file.trim()),
        e.vfstype.trim(),
        if e.options.trim().is_empty() {
            "defaults"
        } else {
            e.options.trim()
        },
        e.freq,
        e.passno
    )
}

/// Renders a document; unchanged entries keep their original text.
pub fn render(doc: &Doc) -> String {
    let mut out = String::new();
    for l in &doc.lines {
        match l {
            Line::Comment { text } | Line::Invalid { text } => out.push_str(text),
            Line::Entry { raw, entry } => {
                if !raw.is_empty() && parse_entry(raw).as_ref() == Some(entry) {
                    out.push_str(raw)
                } else {
                    out.push_str(&format_entry(entry))
                }
            }
        }
        out.push('\n');
    }
    out
}

pub fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(text.as_bytes()))
}

// ---- diff ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffLine {
    /// " " unchanged, "+" added, "-" removed
    pub op: String,
    pub text: String,
}

/// Line diff (LCS); fstab files are small.
pub fn diff(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    let line = |op: &str, t: &str| DiffLine {
        op: op.into(),
        text: t.into(),
    };
    while i < n && j < m {
        if a[i] == b[j] {
            out.push(line(" ", a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(line("-", a[i]));
            i += 1;
        } else {
            out.push(line("+", b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|t| line("-", t)));
    out.extend(b[j..].iter().map(|t| line("+", t)));
    out
}

pub fn diff_text(d: &[DiffLine]) -> String {
    d.iter()
        .filter(|l| l.op != " ")
        .map(|l| format!("{}{}\n", l.op, l.text))
        .collect()
}

// ---- validation ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issue {
    /// error | warning
    pub level: String,
    /// Index into Doc.lines (None = whole file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field: String,
    pub message: String,
}

/// A filesystem the host has, for resolving specs and suggesting entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub path: String,
    pub name: String,
    pub disk: String,
    pub fstype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub partuuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub partlabel: String,
    pub size_bytes: u64,
    pub rotational: bool,
    /// Behind a SAS expander or in an enclosure (shelf).
    pub shelf: bool,
    pub protected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mountpoints: Vec<String>,
}

/// Filesystems from inventory.
pub fn devices(inv: &Inventory) -> Vec<Device> {
    let mut out = Vec::new();
    for d in &inv.disks {
        let shelf = !d.topology.expander.is_empty() || d.topology.enclosure.is_some();
        let base = Device {
            disk: d.name.clone(),
            rotational: d.rotational,
            shelf,
            protected: d.protected,
            ..Default::default()
        };
        if !d.fstype.is_empty() {
            out.push(Device {
                path: d.path.clone(),
                name: d.name.clone(),
                fstype: d.fstype.clone(),
                uuid: d.uuid.clone(),
                label: d.label.clone(),
                size_bytes: d.size_bytes,
                mountpoints: d.mountpoints.clone(),
                ..base.clone()
            });
        }
        d.walk(&mut |n| {
            if !n.fstype.is_empty() {
                out.push(Device {
                    path: n.path.clone(),
                    name: n.name.clone(),
                    fstype: n.fstype.clone(),
                    uuid: n.uuid.clone(),
                    label: n.label.clone(),
                    partuuid: n.partuuid.clone(),
                    partlabel: n.partlabel.clone(),
                    size_bytes: n.size_bytes,
                    mountpoints: n.mountpoints.clone(),
                    ..base.clone()
                });
            }
        });
    }
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// What validation needs to know about the host.
pub struct Context<'a> {
    pub devices: &'a [Device],
    /// Filesystem types the kernel knows (/proc/filesystems).
    pub kernel_fs: &'a [String],
    pub path_exists: &'a dyn Fn(&str) -> bool,
}

const SYSTEM_TARGETS: [&str; 6] = ["/", "/boot", "/boot/efi", "/efi", "/usr", "/var"];
const VIRTUAL: [&str; 12] = [
    "proc",
    "sysfs",
    "tmpfs",
    "devpts",
    "devtmpfs",
    "cgroup",
    "cgroup2",
    "debugfs",
    "securityfs",
    "efivarfs",
    "hugetlbfs",
    "mqueue",
];
const COMMON_FS: [&str; 18] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "ntfs3", "ntfs-3g", "zfs",
    "swap", "nfs", "nfs4", "cifs", "f2fs", "iso9660", "none",
];

/// Paths under which FSView may create a missing mountpoint directory.
pub fn creatable_mountpoint(p: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(r"^/(mnt|media|srv|data|storage|pool|tank)(/[A-Za-z0-9._@+-]+)+$").unwrap()
    });
    re.is_match(p) && !p.split('/').any(|c| c == ".." || c == ".")
}

fn opt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9_.:@+\-]+(=[^,\s]*)?$").unwrap())
}

pub fn split_options(o: &str) -> Vec<(String, Option<String>)> {
    o.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| match s.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (s.to_string(), None),
        })
        .collect()
}

fn find_device<'a>(spec: &str, devs: &'a [Device]) -> Option<&'a Device> {
    let (key, val) = if let Some(v) = spec.strip_prefix("UUID=") {
        ("uuid", v)
    } else if let Some(v) = spec.strip_prefix("LABEL=") {
        ("label", v)
    } else if let Some(v) = spec.strip_prefix("PARTUUID=") {
        ("partuuid", v)
    } else if let Some(v) = spec.strip_prefix("PARTLABEL=") {
        ("partlabel", v)
    } else if let Some(v) = spec.strip_prefix("/dev/disk/by-uuid/") {
        ("uuid", v)
    } else if let Some(v) = spec.strip_prefix("/dev/disk/by-label/") {
        ("label", v)
    } else {
        ("path", spec)
    };
    let val = val.trim_matches('"');
    devs.iter().find(|d| match key {
        "uuid" => d.uuid.eq_ignore_ascii_case(val),
        "label" => d.label == val,
        "partuuid" => d.partuuid.eq_ignore_ascii_case(val),
        "partlabel" => d.partlabel == val,
        _ => d.path == val || format!("/dev/{}", d.name) == val,
    })
}

/// Validates a document. Errors block saving; warnings are advice.
pub fn validate(doc: &Doc, ctx: &Context) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut targets: HashMap<String, usize> = HashMap::new();
    let entries: Vec<(usize, &FsEntry)> = doc
        .lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| match l {
            Line::Entry { entry, .. } => Some((i, entry)),
            _ => None,
        })
        .collect();
    let mountpoints: BTreeMap<&str, &FsEntry> =
        entries.iter().map(|(_, e)| (e.file.as_str(), *e)).collect();

    for (i, l) in doc.lines.iter().enumerate() {
        if let Line::Invalid { text } = l {
            out.push(Issue {
                level: "error".into(),
                line: Some(i),
                field: String::new(),
                message: format!("not a valid fstab line: {:?}", text.trim()),
            });
        }
    }

    for (i, e) in &entries {
        let i = *i;
        let mut err = |field: &str, m: String| {
            out.push(Issue {
                level: "error".into(),
                line: Some(i),
                field: field.into(),
                message: m,
            })
        };
        let spec = e.spec.trim();
        let file = e.file.trim();
        let vfs = e.vfstype.trim();
        if spec.is_empty() {
            err("spec", "device is required".into());
        }
        if vfs.is_empty() {
            err("vfstype", "filesystem type is required".into());
        } else if vfs.chars().any(char::is_whitespace) {
            err("vfstype", "filesystem type must not contain spaces".into());
        }
        let is_swap = vfs == "swap";
        if is_swap {
            if file != "none" && file != "swap" {
                err("file", "swap entries use \"none\" as mountpoint".into());
            }
        } else if !file.starts_with('/') {
            err("file", "mountpoint must be an absolute path".into());
        } else if file.split('/').any(|c| c == ".." || c == ".")
            || (file.len() > 1 && file.ends_with('/'))
        {
            err(
                "file",
                "mountpoint must be a normalized path (no '.', '..' or trailing '/')".into(),
            );
        } else if let Some(prev) = targets.insert(file.to_string(), i) {
            err(
                "file",
                format!(
                    "mountpoint {file} is used twice (also on line {})",
                    prev + 1
                ),
            );
        }
        if e.options.chars().any(char::is_whitespace) {
            err("options", "options must not contain spaces".into());
        }
        for (k, v) in split_options(&e.options) {
            let whole = match &v {
                Some(v) => format!("{k}={v}"),
                None => k.clone(),
            };
            if !opt_re().is_match(&whole) {
                err("options", format!("invalid option {whole:?}"));
            }
            if (k == "x-systemd.device-timeout"
                || k == "x-systemd.mount-timeout"
                || k == "x-systemd.idle-timeout")
                && v.as_deref().and_then(parse_systemd_duration).is_none()
            {
                err(
                    "options",
                    format!("{k} has an invalid duration {:?}", v.unwrap_or_default()),
                );
            }
        }
        if e.freq > 1 {
            err("freq", "dump must be 0 or 1".into());
        }
        if e.passno > 2 {
            err("passno", "fsck pass must be 0, 1 or 2".into());
        }

        // ---- warnings ----
        let mut issue = |level: &str, field: &str, m: String| {
            out.push(Issue {
                level: level.into(),
                line: Some(i),
                field: field.into(),
                message: m,
            })
        };
        macro_rules! warn {
            ($f:expr, $m:expr $(,)?) => {
                issue("warning", $f, $m)
            };
        }
        let opts = split_options(&e.options);
        let has = |k: &str| opts.iter().any(|(o, _)| o == k);
        let virt = VIRTUAL.contains(&vfs);
        let fuse = vfs.starts_with("fuse");
        let network = ["nfs", "nfs4", "cifs", "smb3", "sshfs"].contains(&vfs) || has("_netdev");
        let system = SYSTEM_TARGETS.contains(&file) || is_swap;
        let dev = find_device(spec, ctx.devices);

        if !vfs.is_empty()
            && !virt
            && !fuse
            && !COMMON_FS.contains(&vfs)
            && !ctx.kernel_fs.iter().any(|k| k == vfs)
        {
            warn!(
                "vfstype",
                format!("filesystem type {vfs:?} is not known to this kernel"),
            );
        }
        let names_device = spec.starts_with("UUID=")
            || spec.starts_with("LABEL=")
            || spec.starts_with("PARTUUID=")
            || spec.starts_with("PARTLABEL=")
            || spec.starts_with("/dev/");
        if names_device
            && !virt
            && !network
            && !fuse
            && dev.is_none()
            && !spec.starts_with("/dev/mapper/")
            && !is_lv_path(spec)
        {
            let m = format!("no filesystem matching {spec} on this host");
            if has("nofail") || has("noauto") {
                warn!("spec", format!("{m}; it will be skipped at boot"));
            } else {
                issue(
                    "error",
                    "spec",
                    format!("{m} (add nofail if the disk is often absent)"),
                );
            }
        }
        if let Some(d) = dev {
            if !d.fstype.is_empty()
                && !vfs.is_empty()
                && vfs != "auto"
                && !fs_matches(vfs, &d.fstype)
            {
                warn!(
                    "vfstype",
                    format!("{spec} contains {} but the entry says {vfs}", d.fstype),
                );
            }
        }
        if static_sd_re().is_match(spec) {
            warn!(
                "spec",
                "/dev/sdX names change between boots (they did on spiritlab); use UUID= or LABEL="
                    .into(),
            );
        }
        if !system && !virt && !has("nofail") && !has("noauto") {
            warn!(
                "options",
                "without nofail a missing or slow disk drops the host into emergency mode at boot"
                    .into(),
            );
        }
        let timeout = opts
            .iter()
            .find(|(k, _)| k == "x-systemd.device-timeout")
            .and_then(|(_, v)| v.as_deref().and_then(parse_systemd_duration));
        if let (Some(t), Some(d)) = (timeout, dev) {
            if (d.rotational || d.shelf) && t.as_secs() < 60 {
                warn!(
                    "options",
                    format!(
                        "x-systemd.device-timeout={}s is short for a {} disk; spin-up and expander enumeration can take minutes (sdi appeared after 21 min on spiritlab). Use 5min.",
                        t.as_secs(),
                        if d.shelf { "shelf" } else { "spinning" }
                    ),
                );
            }
        }
        if !is_swap && !virt && file.starts_with('/') && !(ctx.path_exists)(file) {
            if creatable_mountpoint(file) {
                warn!(
                    "file",
                    format!("mountpoint {file} does not exist; it will be created"),
                );
            } else {
                issue("error", "file", format!("mountpoint {file} does not exist (FSView only creates mountpoints under /mnt, /media, /srv, /data, /storage, /pool, /tank)"));
            }
        }
        if vfs == "fuse.mergerfs" || (vfs == "fuse" && spec.starts_with("mergerfs#")) {
            let branches: Vec<String> = spec
                .trim_start_matches("mergerfs#")
                .split(':')
                .map(|b| b.split('=').next().unwrap_or("").to_string())
                .filter(|b| !b.is_empty())
                .collect();
            let requires: Vec<String> = opts
                .iter()
                .filter(|(k, _)| {
                    k == "x-systemd.requires-mounts-for" || k == "x-systemd.wants-mounts-for"
                })
                .filter_map(|(_, v)| v.clone())
                .collect();
            for b in &branches {
                if let Some((mp, _)) = mountpoints
                    .iter()
                    .filter(|(mp, _)| {
                        *mp != &file && (b == *mp || b.starts_with(&format!("{mp}/")))
                    })
                    .max_by_key(|(mp, _)| mp.len())
                {
                    if *mp == "/" {
                        continue;
                    }
                    if !requires.iter().any(|r| r == mp) {
                        warn!("options", format!("branch {b} lives on {mp}; add x-systemd.wants-mounts-for={mp} so the pool mounts after it"));
                    }
                    if b == *mp {
                        warn!("spec", format!("branch {b} is the mountpoint itself; if {mp} fails to mount, writes land on the disk underneath. Use a subdirectory such as {mp}/data, or protect the mountpoint (Pools → Protect mountpoints)"));
                    }
                }
            }
            if opts
                .iter()
                .any(|(k, _)| k == "x-systemd.requires-mounts-for")
            {
                warn!("options", "x-systemd.requires-mounts-for makes systemd unmount the whole pool when one of its disks is unmounted; use x-systemd.wants-mounts-for and protect the mountpoints instead".to_string());
            }
        }
    }

    // Root/system entries changed or missing.
    if !entries.iter().any(|(_, e)| e.file == "/") {
        out.push(Issue {
            level: "warning".into(),
            line: None,
            field: String::new(),
            message: "there is no entry for / (normal on some setups, but double-check)".into(),
        });
    }
    out
}

fn fs_matches(entry: &str, actual: &str) -> bool {
    fn norm(s: &str) -> &str {
        match s {
            "ntfs-3g" | "ntfs3" | "fuseblk" => "ntfs",
            "vfat" | "fat" | "msdos" => "vfat",
            x => x,
        }
    }
    norm(entry) == norm(actual)
}

fn is_lv_path(spec: &str) -> bool {
    let p: Vec<&str> = spec.split('/').collect();
    p.len() == 4
        && p[1] == "dev"
        && p[2] != "disk"
        && !p[2].starts_with("sd")
        && !p[2].starts_with("nvme")
}

fn static_sd_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^/dev/(sd[a-z]+|vd[a-z]+|hd[a-z])\d*$").unwrap())
}

// ---- findmnt --verify ----

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Verify {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Messages FSView filtered out as known noise (e.g. for mergerfs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
}

/// Interprets `findmnt --verify --verbose --tab-file` output. Known noise
/// for FUSE pools and for mountpoints FSView will create is ignored.
pub fn parse_verify(stdout: &str, stderr: &str, doc: &Doc, will_create: &[String]) -> Verify {
    let types: HashMap<&str, &str> = doc
        .lines
        .iter()
        .filter_map(|l| match l {
            Line::Entry { entry, .. } => Some((entry.file.as_str(), entry.vfstype.as_str())),
            _ => None,
        })
        .collect();
    let mut v = Verify::default();
    // stderr carries "findmnt: <file>: parse error at line N -- ignored"
    // and (on newer util-linux) the summary line.
    for l in stderr.lines().filter(|l| l.contains("parse error at")) {
        v.errors
            .push(l.trim().trim_start_matches("findmnt: ").to_string());
    }
    let mut target = String::new();
    for line in stdout.lines() {
        if line.is_empty() || summary_re().is_match(line) {
            continue;
        }
        if !line.starts_with(' ') {
            target = line.trim().to_string();
            continue;
        }
        let t = line.trim();
        let (is_err, msg) = if let Some(m) = t.strip_prefix("[E] ") {
            (true, m)
        } else if let Some(m) = t.strip_prefix("[W] ") {
            (false, m)
        } else {
            continue;
        };
        let fuse = types
            .get(target.as_str())
            .is_some_and(|t| t.starts_with("fuse"));
        let noise = msg.contains("systemd still uses the old version")
            || (fuse
                && (msg.contains("seems unsupported by the current kernel")
                    || msg.contains("non-bind mount source")
                    || msg.contains("cannot detect on-disk filesystem type")
                    // mergerfs branch modes ("/mnt/disk=NC") look like a
                    // LABEL=/UUID= tag to findmnt.
                    || msg.contains("unsupported source tag")))
            || (will_create.iter().any(|w| w == &target)
                && msg.starts_with("unreachable on boot required target"));
        let full = format!("{target}: {msg}");
        if noise {
            v.ignored.push(full);
        } else if is_err {
            v.errors.push(full);
        } else {
            v.warnings.push(full);
        }
    }
    v.ok = v.errors.is_empty();
    v
}

fn summary_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\d+ parse errors?, \d+ errors?, \d+ warnings?$").unwrap())
}

/// Mountpoints of the document that do not exist and may be created.
pub fn mountpoints_to_create(doc: &Doc, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out: Vec<String> = doc
        .lines
        .iter()
        .filter_map(|l| match l {
            Line::Entry { entry, .. }
                if entry.vfstype != "swap"
                    && creatable_mountpoint(&entry.file)
                    && !exists(&entry.file) =>
            {
                Some(entry.file.clone())
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/spiritlab")
                .join(n),
        )
        .unwrap()
    }

    fn spiritlab_devices() -> Vec<Device> {
        let disks = crate::inventory::parse_lsblk(fx("lsblk.json").as_bytes(), false).unwrap();
        let mut inv = Inventory {
            disks,
            ..Default::default()
        };
        for d in inv.disks.iter_mut().filter(|d| d.transport == "sas") {
            d.topology.expander = "expander-2:0".into();
        }
        devices(&inv)
    }

    fn check(text: &str) -> Vec<Issue> {
        let devs = spiritlab_devices();
        let kernel = vec![
            "ext4".to_string(),
            "vfat".to_string(),
            "fuseblk".to_string(),
        ];
        let exists = |p: &str| {
            [
                "/",
                "/boot/efi",
                "/mnt/media1",
                "/mnt/cache",
                "/mnt/drivepool",
                "/proc",
            ]
            .contains(&p)
        };
        validate(
            &parse(text),
            &Context {
                devices: &devs,
                kernel_fs: &kernel,
                path_exists: &exists,
            },
        )
    }

    #[test]
    fn roundtrip_preserves_text() {
        let t = fx("fstab");
        let d = parse(&t);
        assert_eq!(render(&d), t);
        assert!(diff(&t, &render(&d)).iter().all(|l| l.op == " "));
        // JSON round trip (what the UI sends back).
        let back: Doc = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(render(&back), t);
    }

    #[test]
    fn edit_renders_and_diffs_one_line() {
        let t = fx("fstab");
        let mut d = parse(&t);
        for l in d.lines.iter_mut() {
            if let Line::Entry { entry, .. } = l {
                if entry.file == "/mnt/media1" {
                    entry.options = "defaults,nofail,x-systemd.device-timeout=5min".into();
                }
            }
        }
        let new = render(&d);
        let changes: Vec<_> = diff(&t, &new).into_iter().filter(|l| l.op != " ").collect();
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(
            changes[1].text.contains("x-systemd.device-timeout=5min")
                && changes[1].text.contains('\t')
        );
    }

    #[test]
    fn escaping() {
        let e = FsEntry {
            spec: "LABEL=my disk".into(),
            file: "/mnt/my disk".into(),
            vfstype: "ext4".into(),
            options: "defaults".into(),
            freq: 0,
            passno: 2,
        };
        let line = format_entry(&e);
        assert!(line.starts_with("LABEL=my\\040disk\t/mnt/my\\040disk\t"));
        assert_eq!(parse_entry(&line), Some(e));
    }

    #[test]
    fn spiritlab_original_warnings() {
        let issues = check(&fx("fstab"));
        let errors: Vec<_> = issues.iter().filter(|i| i.level == "error").collect();
        assert!(errors.is_empty(), "{errors:?}");
        let all: String = issues.iter().map(|i| i.message.clone() + "\n").collect();
        for frag in [
            "x-systemd.device-timeout=10s is short for a shelf disk",
            "add x-systemd.wants-mounts-for=/mnt/media1",
            "branch /mnt/media1 is the mountpoint itself",
        ] {
            assert!(all.contains(frag), "missing {frag:?} in\n{all}");
        }
    }

    #[test]
    fn errors() {
        let t = "UUID=00000000-dead /mnt/x ext4 defaults 0 2\nUUID=c69cfb3b-4f39-449a-bb21-cd2e4ba23d49 relative ext4 defaults 0 2\n/dev/sdb /mnt/cache ext4 bad option 0 2\nUUID=df81e242-df1f-41a9-87ea-b441da0ee820 /mnt/cache ext4 x-systemd.device-timeout=soon 0 7\nbroken\n/dev/sdb /mnt/cache ext4 defaults 0 2\n";
        let issues = check(t);
        let msgs: String = issues
            .iter()
            .filter(|i| i.level == "error")
            .map(|i| i.message.clone() + "\n")
            .collect();
        for frag in [
            "no filesystem matching UUID=00000000-dead",
            "absolute path",
            "invalid duration",
            "fsck pass",
            "not a valid fstab line",
            "used twice",
        ] {
            assert!(msgs.contains(frag), "missing {frag:?} in\n{msgs}");
        }
        assert!(issues
            .iter()
            .any(|i| i.level == "warning" && i.message.contains("/dev/sdX names change")));
    }

    #[test]
    fn missing_disk_with_nofail_is_warning() {
        let issues = check("UUID=00000000-dead /mnt/new ext4 defaults,nofail 0 2\n");
        assert!(issues.iter().all(|i| i.level == "warning"), "{issues:?}");
        assert!(issues.iter().any(|i| i.message.contains("will be created")));
    }

    #[test]
    fn verify_parsing() {
        let doc = parse("UUID=x /mnt/x ext4 defaults,nofail 0 2\n/mnt/a /mnt/pool fuse.mergerfs allow_other 0 0\n");
        let out = "/mnt/x\n   [E] unreachable on boot required target: No such file or directory\n   [ ] userspace options: nofail\n   [E] unreachable on boot required source: UUID=x\n/mnt/pool\n   [W] unreachable source: /mnt/a: No such file or directory\n   [W] fuse.mergerfs seems unsupported by the current kernel\n   [W] cannot detect on-disk filesystem type (No such file or directory)\n   [E] unsupported source tag: /mnt/a:/mnt/b=NC\n\n0 parse errors, 0 errors, 1 warning\n";
        let v = parse_verify(
            out,
            "findmnt: f: parse error at line 3 -- ignored\n1 parse error, 2 errors, 3 warnings\n",
            &doc,
            &["/mnt/x".to_string()],
        );
        assert_eq!(
            v.errors,
            vec![
                "f: parse error at line 3 -- ignored",
                "/mnt/x: unreachable on boot required source: UUID=x"
            ]
        );
        assert_eq!(
            v.warnings,
            vec!["/mnt/pool: unreachable source: /mnt/a: No such file or directory"]
        );
        assert_eq!(v.ignored.len(), 4);
        assert!(!v.ok);
        assert!(
            creatable_mountpoint("/mnt/media7")
                && !creatable_mountpoint("/etc/x")
                && !creatable_mountpoint("/mnt/../etc")
        );
    }
}
