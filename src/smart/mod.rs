//! Normalizes `smartctl -j -a` output for ATA, SCSI and NVMe devices and
//! evaluates it against alert thresholds.

mod eval;

pub use eval::{
    evaluate, lifespan, worse, Assessment, Finding, Life, Thresholds, CRIT, HDD_DESIGN_HOURS, OK,
    UNKNOWN, WARN,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Attribute {
    pub id: i64,
    pub name: String,
    pub value: i64,
    pub worst: i64,
    pub thresh: i64,
    pub raw: i64,
    pub raw_string: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub when_failed: String,
    pub prefailure: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SelfTest {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    /// passed | failed | aborted | running | unknown
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_hours: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lba: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Running {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_percent: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub device: String,
    pub devtype: String,
    /// ATA | SCSI | NVMe
    pub protocol: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family: String,
    pub serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firmware: String,
    pub capacity_bytes: u64,
    pub rotation_rate: i64,

    pub smart_available: bool,
    pub smart_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,
    pub standby: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature_c: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_trip_c: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_on_hours: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_cycles: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reallocated: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_uncorrectable: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_uncorrectable: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crc_errors: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grown_defects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncorrected_errors: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ata_error_count: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ata_last_error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ata_last_error_hours: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_critical_warning: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_percent_used: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_available_spare: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_spare_threshold: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_media_errors: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_unsafe_shutdowns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvme_data_written_tb: Option<f64>,

    /// Lifetime host writes/reads in bytes, when the drive reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_bytes: Option<u64>,
    /// Flash endurance used (0-100+), from NVMe percentage_used, SAS SSD
    /// endurance indicator or an ATA SSD wear attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wear_used_pct: Option<i64>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<Attribute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub self_tests: Vec<SelfTest>,
    #[serde(
        default,
        rename = "self_test_running",
        skip_serializing_if = "Option::is_none"
    )]
    pub running: Option<Running>,
    #[serde(
        default,
        rename = "short_test_minutes",
        skip_serializing_if = "is_zero"
    )]
    pub short_minutes: i64,
    #[serde(default, rename = "long_test_minutes", skip_serializing_if = "is_zero")]
    pub long_minutes: i64,

    pub exit_status: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

// JSON path helpers.
fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |cur, k| cur.get(k))
}
fn int(v: &Value, path: &[&str]) -> Option<i64> {
    at(v, path).and_then(Value::as_i64)
}
fn uint(v: &Value, path: &[&str]) -> Option<u64> {
    at(v, path).and_then(Value::as_u64)
}
fn string(v: &Value, path: &[&str]) -> String {
    at(v, path)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}
fn boolean(v: &Value, path: &[&str]) -> Option<bool> {
    at(v, path).and_then(Value::as_bool)
}

/// Normalizes smartctl JSON. `devtype` is the -d type used ("" = default).
pub fn parse(data: &[u8], devtype: &str) -> Result<Report, String> {
    let r: Value = serde_json::from_slice(data).map_err(|e| format!("parse smartctl json: {e}"))?;
    let mut rep = Report {
        device: string(&r, &["device", "name"]),
        devtype: if devtype.is_empty() {
            string(&r, &["device", "type"])
        } else {
            devtype.to_string()
        },
        protocol: string(&r, &["device", "protocol"]),
        model: string(&r, &["model_name"])
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        family: string(&r, &["model_family"]),
        serial: string(&r, &["serial_number"]),
        firmware: string(&r, &["firmware_version"]),
        capacity_bytes: uint(&r, &["user_capacity", "bytes"]).unwrap_or(0),
        rotation_rate: int(&r, &["rotation_rate"]).unwrap_or(0),
        smart_available: boolean(&r, &["smart_support", "available"]).unwrap_or(false),
        smart_enabled: boolean(&r, &["smart_support", "enabled"]).unwrap_or(false),
        passed: boolean(&r, &["smart_status", "passed"]),
        exit_status: int(&r, &["smartctl", "exit_status"]).unwrap_or(0),
        power_cycles: int(&r, &["power_cycle_count"]),
        temperature_c: int(&r, &["temperature", "current"]),
        temp_trip_c: int(&r, &["temperature", "drive_trip"])
            .or_else(|| int(&r, &["temperature", "op_limit_max"])),
        power_on_hours: int(&r, &["power_on_time", "hours"]),
        ..Default::default()
    };
    if rep.firmware.is_empty() {
        rep.firmware = string(&r, &["scsi_revision"]);
    }
    for m in at(&r, &["smartctl", "messages"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let s = m
            .get("string")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let u = s.to_uppercase();
        if u.contains("STANDBY MODE") || u.contains("SLEEP MODE") {
            rep.standby = true;
        }
        rep.messages.push(s);
    }
    match rep.protocol.to_uppercase().as_str() {
        "ATA" => {
            rep.protocol = "ATA".into();
            parse_ata(&r, &mut rep);
        }
        "NVME" => {
            rep.protocol = "NVMe".into();
            parse_nvme(&r, &mut rep);
        }
        "SCSI" => {
            rep.protocol = "SCSI".into();
            parse_scsi(&r, &mut rep);
        }
        _ => {}
    }
    Ok(rep)
}

fn parse_ata(r: &Value, rep: &mut Report) {
    for a in at(r, &["ata_smart_attributes", "table"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let raw = int(a, &["raw", "value"]).unwrap_or(0);
        let attr = Attribute {
            id: int(a, &["id"]).unwrap_or(0),
            name: string(a, &["name"]),
            value: int(a, &["value"]).unwrap_or(0),
            worst: int(a, &["worst"]).unwrap_or(0),
            thresh: int(a, &["thresh"]).unwrap_or(0),
            raw,
            raw_string: string(a, &["raw", "string"]),
            when_failed: string(a, &["when_failed"]),
            prefailure: boolean(a, &["flags", "prefailure"]).unwrap_or(false),
        };
        match attr.id {
            5 => rep.reallocated = Some(raw),
            197 => rep.pending = Some(raw),
            198 => rep.offline_uncorrectable = Some(raw),
            187 => rep.reported_uncorrectable = Some(raw),
            199 => rep.crc_errors = Some(raw),
            9 => {
                rep.power_on_hours.get_or_insert(raw);
            }
            12 => {
                rep.power_cycles.get_or_insert(raw);
            }
            194 | 190 => {
                rep.temperature_c.get_or_insert(raw & 0xff);
            }
            _ => {}
        }
        rep.attributes.push(attr);
    }
    // Lifetime traffic and SSD wear.
    let block = uint(r, &["logical_block_size"]).unwrap_or(512);
    for a in &rep.attributes {
        if a.raw <= 0 {
            continue;
        }
        let n = a.name.to_ascii_lowercase();
        let unit = if n.contains("32mib") {
            32 << 20
        } else if n.contains("gib") {
            1 << 30
        } else if n.contains("lba") || n.contains("sector") {
            block
        } else {
            0
        };
        let bytes = (a.raw as u64).saturating_mul(unit);
        match a.id {
            241 | 246 if unit > 0 => {
                rep.written_bytes.get_or_insert(bytes);
            }
            242 if unit > 0 => {
                rep.read_bytes.get_or_insert(bytes);
            }
            _ => {}
        }
        // Normalized value of these attributes is "life remaining %".
        if [
            "wear_leveling_count",
            "ssd_life_left",
            "media_wearout_indicator",
            "percent_lifetime_remain",
            "remaining_lifetime_perc",
            "percent_life_remaining",
        ]
        .contains(&n.as_str())
            && rep.rotation_rate == 0
            && (1..=100).contains(&a.value)
        {
            rep.wear_used_pct.get_or_insert(100 - a.value);
        }
    }

    // Error log: prefer the extended log when present.
    let log = at(r, &["ata_smart_error_log", "extended"])
        .filter(|e| e.get("count").is_some())
        .or_else(|| at(r, &["ata_smart_error_log", "summary"]));
    if let Some(l) = log {
        rep.ata_error_count = int(l, &["count"]);
        if let Some(first) = l
            .get("table")
            .and_then(Value::as_array)
            .and_then(|t| t.first())
        {
            rep.ata_last_error = string(first, &["error_description"]);
            rep.ata_last_error_hours = int(first, &["lifetime_hours"]);
        }
    }
    if let Some(st) = at(r, &["ata_smart_data", "self_test"]) {
        if let Some(v) = int(st, &["status", "value"]) {
            if v >> 4 == 0xf {
                rep.running = Some(Running {
                    description: string(st, &["status", "string"]),
                    remaining_percent: int(st, &["status", "remaining_percent"]),
                });
            }
        }
        rep.short_minutes = int(st, &["polling_minutes", "short"]).unwrap_or(0);
        rep.long_minutes = int(st, &["polling_minutes", "extended"]).unwrap_or(0);
    }
    for e in at(r, &["ata_smart_self_test_log", "standard", "table"])
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let v = int(e, &["status", "value"]).unwrap_or(0);
        let passed = boolean(e, &["status", "passed"]);
        let hi = v >> 4;
        let outcome = if hi == 0xf {
            "running"
        } else if hi == 1 || hi == 2 {
            "aborted"
        } else if passed == Some(true) {
            "passed"
        } else if passed == Some(false) {
            "failed"
        } else if hi == 0 {
            "passed"
        } else {
            "failed"
        };
        rep.self_tests.push(SelfTest {
            kind: string(e, &["type", "string"]),
            status: string(e, &["status", "string"]),
            outcome: outcome.into(),
            lifetime_hours: int(e, &["lifetime_hours"]),
            lba: uint(e, &["lba"]),
            detail: String::new(),
        });
    }
}

fn parse_nvme(r: &Value, rep: &mut Report) {
    if let Some(h) = r.get("nvme_smart_health_information_log") {
        rep.nvme_critical_warning = int(h, &["critical_warning"]);
        rep.nvme_percent_used = int(h, &["percentage_used"]);
        rep.nvme_available_spare = int(h, &["available_spare"]);
        rep.nvme_spare_threshold = int(h, &["available_spare_threshold"]);
        rep.nvme_media_errors = int(h, &["media_errors"]);
        rep.nvme_unsafe_shutdowns = int(h, &["unsafe_shutdowns"]);
        if rep.power_on_hours.is_none() {
            rep.power_on_hours = int(h, &["power_on_hours"]);
        }
        if rep.power_cycles.is_none() {
            rep.power_cycles = int(h, &["power_cycles"]);
        }
        // One data unit is 1000 512-byte blocks.
        rep.nvme_data_written_tb =
            uint(h, &["data_units_written"]).map(|d| d as f64 * 512000.0 / 1e12);
        rep.written_bytes = uint(h, &["data_units_written"]).map(|d| d.saturating_mul(512_000));
        rep.read_bytes = uint(h, &["data_units_read"]).map(|d| d.saturating_mul(512_000));
        rep.wear_used_pct = rep.nvme_percent_used;
    }
    if let Some(l) = r.get("nvme_self_test_log") {
        if let Some(v) = int(l, &["current_self_test_operation", "value"]) {
            if v != 0 {
                rep.running = Some(Running {
                    description: string(l, &["current_self_test_operation", "string"]),
                    remaining_percent: int(l, &["current_self_test_completion_percent"])
                        .map(|c| 100 - c),
                });
            }
        }
        for e in l
            .get("table")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let v = int(e, &["self_test_result", "value"]).unwrap_or(0);
            let outcome = match v {
                0 => "passed",
                1..=3 => "aborted",
                0xf => "unknown",
                _ => "failed",
            };
            rep.self_tests.push(SelfTest {
                kind: string(e, &["self_test_code", "string"]),
                status: string(e, &["self_test_result", "string"]),
                outcome: outcome.into(),
                lifetime_hours: int(e, &["power_on_hours"]),
                lba: uint(e, &["lba"]),
                detail: String::new(),
            });
        }
    }
    rep.short_minutes = 2;
}

fn parse_scsi(r: &Value, rep: &mut Report) {
    if rep.model.is_empty() {
        rep.model = format!(
            "{} {}",
            string(r, &["scsi_vendor"]),
            string(r, &["scsi_product"])
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    }
    rep.grown_defects = int(r, &["scsi_grown_defect_list"]);
    let mut unc = 0;
    let mut have = false;
    for k in ["read", "write", "verify"] {
        if let Some(v) = int(
            r,
            &["scsi_error_counter_log", k, "total_uncorrected_errors"],
        ) {
            unc += v;
            have = true;
        }
    }
    if have {
        rep.uncorrected_errors = Some(unc);
    }
    if rep.power_cycles.is_none() {
        rep.power_cycles = int(
            r,
            &[
                "scsi_start_stop_cycle_counter",
                "accumulated_start_stop_cycles",
            ],
        );
    }
    if let Some(secs) = int(r, &["scsi_extended_self_test_seconds"]).filter(|s| *s > 0) {
        rep.long_minutes = (secs + 59) / 60;
    }
    rep.short_minutes = 2;
    // Bridged SATA disks report 0 here; treat that as unknown.
    let gb = |k: &str| {
        at(r, &["scsi_error_counter_log", k, "gigabytes_processed"])
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .filter(|g| *g > 0.0)
            .map(|g| (g * 1e9) as u64)
    };
    rep.written_bytes = gb("write");
    rep.read_bytes = gb("read");
    rep.wear_used_pct = int(r, &["scsi_percentage_used_endurance_indicator"]);

    // Self-test entries are top-level keys scsi_self_test_0..N, newest first.
    let mut idx: Vec<u32> = r
        .as_object()
        .map(|o| {
            o.keys()
                .filter_map(|k| k.strip_prefix("scsi_self_test_")?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    idx.sort_unstable();
    let mut max_hours = 0;
    for i in idx {
        let Some(e) = r.get(format!("scsi_self_test_{i}")) else {
            continue;
        };
        let hours = int(e, &["power_on_time", "hours"]);
        if let Some(h) = hours {
            max_hours = max_hours.max(h);
        }
        let v = int(e, &["result", "value"]).unwrap_or(0);
        let outcome = match v {
            0 => "passed",
            1 | 2 => "aborted",
            15 => "running",
            _ => "failed",
        };
        let mut t = SelfTest {
            kind: string(e, &["code", "string"]),
            status: string(e, &["result", "string"]),
            outcome: outcome.into(),
            lifetime_hours: hours,
            ..Default::default()
        };
        if outcome == "running" {
            rep.running = Some(Running {
                description: t.status.clone(),
                remaining_percent: None,
            });
        }
        if outcome == "failed" {
            t.detail = string(e, &["sense_key", "string"]);
            t.lba = uint(e, &["lba_first_failure", "value"]);
        }
        rep.self_tests.push(t);
    }
    // SATA disks behind some SAS bridges report 0 power-on hours through
    // the SCSI log pages; the self-test log still carries real hours.
    if rep.power_on_hours == Some(0) && max_hours > 0 {
        rep.power_on_hours = None;
        rep.notes.push(format!(
            "Power-on hours are not reported through this SCSI bridge (last self-test logged at {max_hours} h). Try ATA pass-through (-d sat) for full SMART data."
        ));
    }
}

impl Report {
    /// Probably a SATA disk behind a SAS/USB bridge, where -d sat gives
    /// much better data.
    pub fn looks_like_bridged_ata(&self) -> bool {
        self.protocol == "SCSI" && self.attributes.is_empty()
    }
}

#[cfg(test)]
mod tests;
