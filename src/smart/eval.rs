use serde::{Deserialize, Serialize};

use super::Report;

/// User-configurable alert levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Thresholds {
    pub temp_warn_c: i64,
    pub temp_crit_c: i64,
    pub trip_margin_c: i64,
    pub reallocated_warn: i64,
    pub reallocated_crit: i64,
    pub pending_warn: i64,
    pub pending_crit: i64,
    pub uncorrectable_warn: i64,
    pub crc_warn: i64,
    pub error_log_warn: i64,
    pub nvme_used_warn: i64,
    pub nvme_used_crit: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            temp_warn_c: 50,
            temp_crit_c: 60,
            trip_margin_c: 5,
            reallocated_warn: 1,
            reallocated_crit: 100,
            pending_warn: 1,
            pending_crit: 10,
            uncorrectable_warn: 1,
            crc_warn: 1,
            error_log_warn: 1,
            nvme_used_warn: 80,
            nvme_used_crit: 95,
        }
    }
}

pub const OK: &str = "ok";
pub const WARN: &str = "warn";
pub const CRIT: &str = "crit";
pub const UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub level: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Assessment {
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

impl Default for Assessment {
    fn default() -> Self {
        Assessment {
            status: UNKNOWN.into(),
            findings: vec![],
        }
    }
}

fn rank(s: &str) -> u8 {
    match s {
        CRIT => 3,
        WARN => 2,
        OK => 1,
        _ => 0,
    }
}

/// The more severe of two statuses.
pub fn worse<'a>(a: &'a str, b: &'a str) -> &'a str {
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// Checks a report against thresholds.
pub fn evaluate(r: &Report, t: &Thresholds) -> Assessment {
    if !r.smart_available {
        return Assessment {
            status: UNKNOWN.into(),
            findings: vec![Finding {
                level: UNKNOWN.into(),
                text: "SMART not available".into(),
            }],
        };
    }
    let mut a = Assessment {
        status: OK.into(),
        findings: vec![],
    };
    let mut add = |level: &str, text: String| {
        a.findings.push(Finding {
            level: level.into(),
            text,
        });
        a.status = worse(&a.status, level).to_string();
    };
    if r.passed == Some(false) {
        add(CRIT, "SMART overall health self-assessment: FAILED".into());
    }
    if r.exit_status & 8 != 0 {
        add(
            CRIT,
            "smartctl reports the disk is failing (exit bit 3)".into(),
        );
    }
    if r.exit_status & 16 != 0 {
        add(
            WARN,
            "a prefail attribute is at or below its threshold (exit bit 4)".into(),
        );
    }
    for at in &r.attributes {
        if at.when_failed == "now" {
            add(
                CRIT,
                format!(
                    "attribute {} {} failing now (value {} ≤ threshold {})",
                    at.id, at.name, at.value, at.thresh
                ),
            );
        }
    }

    if let Some(c) = r.temperature_c {
        let trip = r.temp_trip_c.filter(|x| *x > 0);
        if let Some(tr) = trip.filter(|tr| c >= *tr) {
            add(
                CRIT,
                format!("temperature {c}°C has reached the drive trip point {tr}°C"),
            );
        } else if c >= t.temp_crit_c {
            add(CRIT, format!("temperature {c}°C ≥ {}°C", t.temp_crit_c));
        } else if c >= t.temp_warn_c {
            add(WARN, format!("temperature {c}°C ≥ {}°C", t.temp_warn_c));
        } else if let Some(tr) = trip.filter(|tr| t.trip_margin_c > 0 && c >= tr - t.trip_margin_c)
        {
            add(
                WARN,
                format!(
                    "temperature {c}°C is within {}°C of the drive trip point {tr}°C",
                    tr - c
                ),
            );
        }
    }

    let mut level = |v: Option<i64>, warn: i64, crit: i64, what: &str| {
        let Some(v) = v.filter(|v| *v > 0) else {
            return;
        };
        if crit > 0 && v >= crit {
            add(CRIT, format!("{what}: {v}"));
        } else if warn > 0 && v >= warn {
            add(WARN, format!("{what}: {v}"));
        }
    };
    level(
        r.reallocated,
        t.reallocated_warn,
        t.reallocated_crit,
        "reallocated sectors",
    );
    level(r.pending, t.pending_warn, t.pending_crit, "pending sectors");
    level(
        r.offline_uncorrectable,
        t.uncorrectable_warn,
        0,
        "offline uncorrectable sectors",
    );
    level(
        r.reported_uncorrectable,
        t.uncorrectable_warn,
        0,
        "reported uncorrectable errors",
    );
    level(
        r.grown_defects,
        t.reallocated_warn,
        t.reallocated_crit,
        "grown defect list entries",
    );
    level(
        r.uncorrected_errors,
        t.uncorrectable_warn,
        0,
        "uncorrected read/write errors",
    );
    if let Some(c) = r.crc_errors.filter(|c| t.crc_warn > 0 && *c >= t.crc_warn) {
        add(
            WARN,
            format!("interface CRC errors: {c} (check cable/backplane)"),
        );
    }
    if let Some(n) = r
        .ata_error_count
        .filter(|n| t.error_log_warn > 0 && *n >= t.error_log_warn)
    {
        let mut msg = format!("ATA error log: {n} errors");
        if !r.ata_last_error.is_empty() {
            msg.push_str(", latest");
            if let Some(h) = r.ata_last_error_hours {
                msg.push_str(&format!(" at {h} h"));
            }
            msg.push_str(&format!(": {}", r.ata_last_error));
        }
        add(WARN, msg);
    }

    if let Some(w) = r.nvme_critical_warning.filter(|w| *w != 0) {
        add(CRIT, format!("NVMe critical warning flags: 0x{w:02x}"));
    }
    if let Some(u) = r.nvme_percent_used {
        if u >= t.nvme_used_crit {
            add(CRIT, format!("NVMe endurance used: {u}%"));
        } else if u >= t.nvme_used_warn {
            add(WARN, format!("NVMe endurance used: {u}%"));
        }
    }
    if let (Some(s), Some(th)) = (r.nvme_available_spare, r.nvme_spare_threshold) {
        if s < th {
            add(
                CRIT,
                format!("NVMe available spare {s}% below threshold {th}%"),
            );
        }
    }
    if let Some(m) = r.nvme_media_errors.filter(|m| *m > 0) {
        add(WARN, format!("NVMe media errors: {m}"));
    }

    // The most recent finished (not aborted/running) self-test decides.
    if let Some(st) = r
        .self_tests
        .iter()
        .find(|s| !matches!(s.outcome.as_str(), "aborted" | "running" | "unknown"))
    {
        if st.outcome == "failed" {
            let mut msg = format!("last self-test failed: {}", st.status);
            if !st.detail.is_empty() {
                msg.push_str(&format!(" ({})", st.detail));
            }
            if let Some(h) = st.lifetime_hours {
                msg.push_str(&format!(" at {h} h"));
            }
            add(CRIT, msg);
        }
    }
    a
}

/// Typical design life of a hard disk (≈ 5 years powered on). Real disks
/// vary widely; this only frames age, it is not a prediction.
pub const HDD_DESIGN_HOURS: i64 = 43_800;

/// Age, traffic and an estimate of the life left.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Life {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_hours: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_bytes: Option<u64>,
    /// Average reads + writes per year of power-on time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_bytes_per_year: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wear_used_pct: Option<i64>,
    /// Rough share of life left, 0-100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_pct: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_hours: Option<i64>,
    /// Flash only: writes left at the current wear rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_written_bytes: Option<u64>,
    /// How the estimate was made.
    pub basis: String,
    /// ok | warn | crit
    pub level: String,
    pub verdict: String,
}

/// Estimates remaining life from the wear indicator (flash) or age against
/// a typical service life (hard disks), overridden by health findings.
pub fn lifespan(r: &Report, status: &str) -> Life {
    let age = r.power_on_hours.filter(|h| *h >= 0);
    let mut l = Life {
        age_hours: age,
        written_bytes: r.written_bytes,
        read_bytes: r.read_bytes,
        wear_used_pct: r.wear_used_pct,
        ..Default::default()
    };
    if let (Some(h), true) = (age, r.written_bytes.is_some() || r.read_bytes.is_some()) {
        if h >= 24 * 30 {
            let total = r.written_bytes.unwrap_or(0) as f64 + r.read_bytes.unwrap_or(0) as f64;
            l.workload_bytes_per_year = Some((total / (h as f64 / 8766.0)) as u64);
        }
    }
    let flash = r.protocol == "NVMe" || r.rotation_rate == 0 && r.wear_used_pct.is_some();
    if let (true, Some(used)) = (flash, r.wear_used_pct) {
        let left = (100 - used).max(0);
        l.remaining_pct = Some(left);
        l.basis = format!("flash wear indicator: {used}% of rated endurance used");
        if used >= 1 {
            let f = left as f64 / used as f64;
            l.remaining_hours = age.map(|h| (h as f64 * f) as i64);
            l.remaining_written_bytes = r.written_bytes.map(|w| (w as f64 * f) as u64);
        }
    } else if let Some(h) = age {
        let left = (HDD_DESIGN_HOURS - h).max(0);
        l.remaining_pct = Some(left * 100 / HDD_DESIGN_HOURS);
        l.remaining_hours = Some(left);
        l.basis =
            "age against a typical 5-year hard disk service life; real lifespans vary a lot".into();
    } else {
        l.basis = "the drive does not report its age".into();
    }
    let (level, verdict) = match status {
        CRIT => (CRIT, "Failing: copy the data off and replace it"),
        WARN => (WARN, "Degrading: back up and plan a replacement"),
        _ if l.remaining_pct == Some(0) && flash => (CRIT, "Rated endurance used up: replace soon"),
        _ if l.remaining_pct == Some(0) => (
            WARN,
            "Past typical service life: healthy for now, keep backups",
        ),
        _ if l.remaining_pct.is_some_and(|p| p < 20) => {
            (WARN, "Getting old: healthy for now, keep backups")
        }
        _ => (OK, "Healthy"),
    };
    // Errors make an age-based figure meaningless; flash wear still counts.
    if status == CRIT {
        l.remaining_pct = Some(0);
        l.remaining_hours = Some(0);
        l.remaining_written_bytes = None;
    } else if status == WARN && !flash {
        l.remaining_pct = None;
        l.remaining_hours = None;
    }
    l.level = level.into();
    l.verdict = verdict.into();
    l
}
