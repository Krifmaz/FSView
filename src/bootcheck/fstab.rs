use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// One fstab line.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub line: usize,
    pub spec: String,
    pub file: String,
    pub vfstype: String,
    pub options: Vec<String>,
    pub freq: i64,
    pub pass: i64,
}

fn unescape_octal(s: &str) -> String {
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

/// Parses fstab text. Malformed lines are reported but do not stop parsing.
pub fn parse_fstab(text: &str) -> (Vec<Entry>, Vec<String>) {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = t.split_whitespace().collect();
        if f.len() < 3 {
            errs.push(format!("line {}: expected at least 3 fields", i + 1));
            continue;
        }
        out.push(Entry {
            line: i + 1,
            spec: unescape_octal(f[0]),
            file: unescape_octal(f[1]),
            vfstype: f[2].to_string(),
            options: f
                .get(3)
                .map(|o| o.split(',').map(String::from).collect())
                .unwrap_or_else(|| vec!["defaults".into()]),
            freq: f.get(4).and_then(|x| x.parse().ok()).unwrap_or(0),
            pass: f.get(5).and_then(|x| x.parse().ok()).unwrap_or(0),
        });
    }
    (out, errs)
}

const VIRTUAL: [&str; 19] = [
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
    "configfs",
    "fusectl",
    "binfmt_misc",
    "pstore",
    "bpf",
    "tracefs",
    "ramfs",
];
const NETWORK: [&str; 10] = [
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "sshfs",
    "fuse.sshfs",
    "glusterfs",
    "ceph",
    "9p",
    "virtiofs",
];

impl Entry {
    /// Value of an option ("" if it has none), if present.
    pub fn opt(&self, name: &str) -> Option<&str> {
        self.options.iter().find_map(|o| {
            let (k, v) = o.split_once('=').unwrap_or((o.as_str(), ""));
            (k == name).then_some(v)
        })
    }
    pub fn has(&self, name: &str) -> bool {
        self.opt(name).is_some()
    }
    pub fn is_virtual(&self) -> bool {
        VIRTUAL.contains(&self.vfstype.as_str())
    }
    pub fn is_swap(&self) -> bool {
        self.vfstype == "swap"
    }
    pub fn is_network(&self) -> bool {
        NETWORK.contains(&self.vfstype.as_str()) || self.has("_netdev")
    }
    pub fn is_mergerfs(&self) -> bool {
        self.vfstype == "fuse.mergerfs"
            || self.vfstype == "mergerfs"
            || (self.vfstype == "fuse" && self.spec.starts_with("mergerfs#"))
    }
    pub fn is_bind(&self) -> bool {
        self.has("bind") || self.has("rbind")
    }

    /// x-systemd.device-timeout (systemd's default is 90s).
    pub fn device_timeout(&self) -> Duration {
        self.opt("x-systemd.device-timeout")
            .and_then(parse_systemd_duration)
            .unwrap_or(Duration::from_secs(90))
    }

    /// Branch paths of a mergerfs spec like "/mnt/a:/mnt/b=RO".
    pub fn mergerfs_branches(&self) -> Vec<String> {
        self.spec
            .trim_start_matches("mergerfs#")
            .split(':')
            .map(|b| b.split('=').next().unwrap_or("").trim().to_string())
            .filter(|b| !b.is_empty())
            .collect()
    }

    pub fn mount_unit(&self) -> String {
        if self.is_swap() {
            return self
                .device_path()
                .map(|d| format!("{}.swap", escape_path(&d)))
                .unwrap_or_default();
        }
        format!("{}.mount", escape_path(&self.file))
    }

    /// The fs_spec as a /dev path, if it names a block device.
    pub fn device_path(&self) -> Option<String> {
        for (prefix, dir) in [
            ("UUID=", "by-uuid"),
            ("LABEL=", "by-label"),
            ("PARTUUID=", "by-partuuid"),
            ("PARTLABEL=", "by-partlabel"),
        ] {
            if let Some(v) = self.spec.strip_prefix(prefix) {
                return Some(format!("/dev/disk/{dir}/{}", v.trim_matches('"')));
            }
        }
        self.spec.starts_with("/dev/").then(|| self.spec.clone())
    }

    /// The systemd device unit the mount waits for, if any.
    pub fn device_unit(&self) -> Option<String> {
        if self.is_virtual() || self.is_network() || self.is_bind() || self.is_mergerfs() {
            return None;
        }
        self.device_path()
            .map(|d| format!("{}.device", escape_path(&d)))
    }
}

/// Parses systemd time spans: "10s", "1min 30s", "90" (seconds), "infinity".
pub fn parse_systemd_duration(s: &str) -> Option<Duration> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(\d+(?:\.\d+)?)\s*(usec|us|msec|ms|seconds|second|sec|s|minutes|minute|min|m|hours|hour|hr|h|days|day|d)?").unwrap()
    });
    let s = s.trim();
    if s == "infinity" || s == "0" {
        return Some(Duration::ZERO);
    }
    if s.is_empty() || !re.replace_all(s, "").trim().is_empty() {
        return None;
    }
    let mut total = 0f64;
    for c in re.captures_iter(s) {
        let n: f64 = c[1].parse().ok()?;
        let unit = match c.get(2).map(|m| m.as_str()) {
            Some("us" | "usec") => 1e-6,
            Some("ms" | "msec") => 1e-3,
            Some("m" | "min" | "minute" | "minutes") => 60.0,
            Some("h" | "hr" | "hour" | "hours") => 3600.0,
            Some("d" | "day" | "days") => 86400.0,
            _ => 1.0,
        };
        total += n * unit;
    }
    Some(Duration::from_secs_f64(total))
}

/// `systemd-escape --path`.
pub fn escape_path(p: &str) -> String {
    let joined = p
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return "-".into();
    }
    let mut out = String::new();
    for (i, c) in joined.bytes().enumerate() {
        match c {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str(&format!("\\x{c:02x}")),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out
}
