//! journald JSON parsing and classification of disk-related kernel messages.

use std::sync::OnceLock;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Minimal journal entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub cursor: String,
    pub realtime_us: i64,
    pub monotonic_us: i64,
    pub boot_id: String,
    pub priority: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identifier: String,
    pub message: String,
}

impl Entry {
    pub fn time(&self) -> DateTime<Utc> {
        Utc.timestamp_micros(self.realtime_us)
            .single()
            .unwrap_or_default()
    }
    /// Seconds since boot.
    pub fn monotonic_sec(&self) -> f64 {
        self.monotonic_us as f64 / 1e6
    }
}

/// journald encodes MESSAGE as a string, or as a byte array when it is not
/// valid UTF-8.
fn message(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => {
            let bytes: Vec<u8> = a
                .iter()
                .filter_map(|x| x.as_u64())
                .map(|x| x as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

/// Parses `journalctl -o json` output (one object per line).
pub fn parse_json_lines(data: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in data.split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.first() != Some(&b'{') {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let st = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let num = |k: &str| st(k).parse::<i64>().unwrap_or(0);
        out.push(Entry {
            cursor: st("__CURSOR"),
            realtime_us: num("__REALTIME_TIMESTAMP"),
            monotonic_us: num("__MONOTONIC_TIMESTAMP"),
            boot_id: st("_BOOT_ID"),
            priority: st("PRIORITY").parse().unwrap_or(6),
            identifier: st("SYSLOG_IDENTIFIER"),
            message: message(v.get("MESSAGE")),
        });
    }
    out
}

/// A classified disk-related kernel message.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub cursor: String,
    pub time: DateTime<Utc>,
    pub boot_id: String,
    pub monotonic_sec: f64,
    pub category: String,
    /// error | warn | info
    pub severity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    pub message: String,
    /// "Device appeared" well after boot.
    #[serde(default, skip_serializing_if = "crate::proto::is_false")]
    pub late: bool,
}

pub const CAT_IO_ERROR: &str = "io_error";
pub const CAT_RESET: &str = "reset";
pub const CAT_LINK_DOWN: &str = "link_down";
pub const CAT_APPEARED: &str = "appeared";
pub const CAT_REMOVED: &str = "removed";
pub const CAT_FS: &str = "filesystem";
pub const CAT_MEDIUM: &str = "medium_error";

struct Rules {
    rules: Vec<(Regex, &'static str, &'static str)>,
    devices: Vec<Regex>,
    attach: Regex,
    nvme_part: Regex,
}

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| {
        let r = |s: &str| Regex::new(s).unwrap();
        Rules {
            rules: vec![
                (r(r"(?i)(Medium Error|Unrecovered read error|critical medium error|Sense Key : Medium Error)"), CAT_MEDIUM, "error"),
                (r(r"(?i)(I/O error|blk_update_request|Buffer I/O error|end_request: I/O error|failed command: (READ|WRITE)|UNC\b)"), CAT_IO_ERROR, "error"),
                (r(r"(?i)(EXT4-fs error|EXT4-fs warning|XFS \(.*\): (Corruption|metadata I/O error|Filesystem has been shut down)|BTRFS (error|critical|warning)|ntfs3?.*error|FAT-fs .*error|remounting filesystem read-only)"), CAT_FS, "error"),
                (r(r"(?i)(SATA link down|link is down|phy.* link down|detected link down|ata\d+: (link|SATA) .*down)"), CAT_LINK_DOWN, "warn"),
                (r(r"(?i)(hard resetting link|soft resetting link|attempting task abort|task abort|device_reset|target reset|host reset|bus reset|resetting controller|nvme.*reset|controller is down|timeout, (aborting|resetting)|log_info\(0x31)"), CAT_RESET, "warn"),
                (r(r"(Attached SCSI (removable )?disk|nvme\d+n\d+: p\d|nvme nvme\d+: \d+/\d+/\d+ default/read/poll queues)"), CAT_APPEARED, "info"),
                (r(r"(?i)(removing handle|Synchronizing SCSI cache|device offlined|rejecting I/O to offline device|nvme.*removing)"), CAT_REMOVED, "warn"),
                (r(r"(EXT4-fs \(.*\): mounted filesystem|XFS \(.*\): Mounting|BTRFS info .*: (disk space caching|use .* compression)|EXT4-fs \(.*\): unmounting)"), CAT_FS, "info"),
            ],
            devices: vec![
                r(r"\[(sd[a-z]+)\]"),
                r(r"\b(nvme\d+n\d+(?:p\d+)?)\b"),
                r(r"\b(nvme\d+)\b"),
                r(r"dev (sd[a-z]+\d*)\b"),
                r(r"\((sd[a-z]+\d*|dm-\d+|md\d+|nvme\d+n\d+p?\d*)\)"),
                r(r"\b(sd \d+:\d+:\d+:\d+)\b"),
                r(r"\b(ata\d+(?:\.\d+)?)\b"),
                r(r"\b(sd[a-z]+)\b"),
            ],
            attach: r(r"\[(sd[a-z]+)\] Attached SCSI"),
            nvme_part: r(r"^\s*(nvme\d+n\d+): p\d"),
        }
    })
}

/// Classifies disk-related kernel messages. "Appeared" events later than
/// `late_after_sec` (0 disables) are flagged late.
pub fn classify(e: &Entry, late_after_sec: f64) -> Option<Event> {
    let r = rules();
    let (_, cat, sev) = r.rules.iter().find(|(re, _, _)| re.is_match(&e.message))?;
    let mut ev = Event {
        cursor: e.cursor.clone(),
        time: e.time(),
        boot_id: e.boot_id.clone(),
        monotonic_sec: e.monotonic_sec(),
        category: cat.to_string(),
        severity: sev.to_string(),
        device: r
            .devices
            .iter()
            .find_map(|d| d.captures(&e.message).map(|c| c[1].to_string()))
            .unwrap_or_default(),
        message: e.message.trim().to_string(),
        late: false,
    };
    if ev.category == CAT_APPEARED && late_after_sec > 0.0 && ev.monotonic_sec > late_after_sec {
        ev.late = true;
        ev.severity = "warn".into();
    }
    Some(ev)
}

/// Disk name if the message announces a newly attached disk.
pub fn attached_device(msg: &str) -> Option<String> {
    let r = rules();
    r.attach
        .captures(msg)
        .or_else(|| r.nvme_part.captures(msg))
        .map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"__CURSOR":"s=a;i=1","__REALTIME_TIMESTAMP":"1791850000000000","__MONOTONIC_TIMESTAMP":"7500000","_BOOT_ID":"b1","PRIORITY":"5","MESSAGE":"sd 2:0:1:0: [sda] Attached SCSI disk"}
{"__CURSOR":"s=a;i=2","__REALTIME_TIMESTAMP":"1791851100000000","__MONOTONIC_TIMESTAMP":"1260000000","_BOOT_ID":"b1","PRIORITY":"5","MESSAGE":"sd 2:0:9:0: [sdi] Attached SCSI disk"}
{"__CURSOR":"s=a;i=3","__REALTIME_TIMESTAMP":"1791851200000000","__MONOTONIC_TIMESTAMP":"1270000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"I/O error, dev sdc, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2"}
{"__CURSOR":"s=a;i=4","__REALTIME_TIMESTAMP":"1791851300000000","__MONOTONIC_TIMESTAMP":"1280000000","_BOOT_ID":"b1","PRIORITY":"4","MESSAGE":"sd 2:0:3:0: attempting task abort!scmd(0x000000001)"}
{"__CURSOR":"s=a;i=5","__REALTIME_TIMESTAMP":"1791851400000000","__MONOTONIC_TIMESTAMP":"1290000000","_BOOT_ID":"b1","PRIORITY":"6","MESSAGE":[104,105,255]}
{"__CURSOR":"s=a;i=6","__REALTIME_TIMESTAMP":"1791851500000000","__MONOTONIC_TIMESTAMP":"1300000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"sd 2:0:3:0: [sdc] tag#12 Sense Key : Medium Error [current]"}
{"__CURSOR":"s=a;i=7","__REALTIME_TIMESTAMP":"1791851600000000","__MONOTONIC_TIMESTAMP":"1310000000","_BOOT_ID":"b1","PRIORITY":"3","MESSAGE":"EXT4-fs error (device sdi): ext4_find_entry:1234: inode #2: comm ls: reading directory lblock 0"}
{"__CURSOR":"s=a;i=8","__REALTIME_TIMESTAMP":"1791851700000000","__MONOTONIC_TIMESTAMP":"1320000000","_BOOT_ID":"b1","PRIORITY":"6","MESSAGE":"usb 1-1: new high-speed USB device number 2 using xhci_hcd"}
"#;

    #[test]
    fn parse_and_classify() {
        let es = parse_json_lines(SAMPLE.as_bytes());
        assert_eq!(es.len(), 8);
        assert_eq!(es[4].message, "hi\u{FFFD}");
        let want: [(&str, &str, &str, bool); 8] = [
            (CAT_APPEARED, "sda", "info", false),
            (CAT_APPEARED, "sdi", "warn", true),
            (CAT_IO_ERROR, "sdc", "error", false),
            (CAT_RESET, "sd 2:0:3:0", "warn", false),
            ("", "", "", false),
            (CAT_MEDIUM, "sdc", "error", false),
            (CAT_FS, "sdi", "error", false),
            ("", "", "", false),
        ];
        for (e, w) in es.iter().zip(want) {
            let ev = classify(e, 60.0);
            if w.0.is_empty() {
                assert!(ev.is_none(), "unexpected {ev:?}");
                continue;
            }
            let ev = ev.unwrap();
            assert_eq!(
                (
                    ev.category.as_str(),
                    ev.device.as_str(),
                    ev.severity.as_str(),
                    ev.late
                ),
                w,
                "{}",
                e.message
            );
        }
        assert_eq!(attached_device(&es[1].message).as_deref(), Some("sdi"));
        assert_eq!(
            attached_device("nvme0n1: p1 p2 p3").as_deref(),
            Some("nvme0n1")
        );
    }
}
