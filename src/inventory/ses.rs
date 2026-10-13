use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// One non-slot SES element (PSU, fan, sensor...).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnclosureElement {
    #[serde(rename = "type")]
    pub kind: String,
    pub index: u32,
    /// SES status text, e.g. "OK", "Critical".
    pub status: String,
    /// ok | warn | crit | absent, or "ignored" when the user marked it as
    /// expected (e.g. an empty PSU bay).
    pub level: String,
    /// Stable identifier for ignoring the element (set by the web server).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

struct Res {
    typ: Regex,
    element: Regex,
    overall: Regex,
    status: Regex,
    temp: Regex,
    speed: Regex,
    volt: Regex,
    amps: Regex,
    flag: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        typ: Regex::new(r"^\s*Element type: ([^,]+),").unwrap(),
        element: Regex::new(r"^\s*Element (\d+) descriptor:").unwrap(),
        overall: Regex::new(r"^\s*Overall descriptor:").unwrap(),
        status: Regex::new(r"status: ([A-Za-z ]+?)\s*$").unwrap(),
        temp: Regex::new(r"Temperature=(-?\d+) C").unwrap(),
        speed: Regex::new(r"Actual speed=(\d+) rpm").unwrap(),
        volt: Regex::new(r"Voltage: ([\d.]+) Volts").unwrap(),
        amps: Regex::new(r"Current: ([\d.]+) Amps").unwrap(),
        flag: Regex::new(
            r"(Fail|AC fail|DC fail|Off|Overtmp fail|Temperature warn|DC overvoltage|DC undervoltage|DC overcurrent|OT failure|OT warning|Failure indication|Warning indication)=1",
        )
        .unwrap(),
    })
}

const TYPES: [&str; 7] = [
    "Power supply",
    "Cooling",
    "Temperature sensor",
    "Voltage sensor",
    "Current sensor",
    "Enclosure services controller electronics",
    "Enclosure",
];

fn level(status: &str) -> &'static str {
    match status.trim().to_lowercase().as_str() {
        "critical" | "unrecoverable" => "crit",
        "noncritical" | "non-critical" => "warn",
        "not installed" | "unsupported" | "unavailable" | "no access allowed" => "absent",
        _ => "ok",
    }
}

/// Parses `sg_ses -p 0x2` text. Device slots (sysfs maps those to disks)
/// and vendor-specific element types are skipped.
pub fn parse_ses_status(text: &str) -> Vec<EnclosureElement> {
    let r = res();
    let mut out: Vec<EnclosureElement> = Vec::new();
    let mut cur: Option<EnclosureElement> = None;
    let mut flags: Vec<String> = Vec::new();
    let mut typ = String::new();
    let mut in_overall = false;
    let flush = |cur: &mut Option<EnclosureElement>,
                 flags: &mut Vec<String>,
                 out: &mut Vec<EnclosureElement>| {
        if let Some(mut e) = cur.take() {
            if !flags.is_empty() {
                if !e.detail.is_empty() {
                    e.detail.push_str("; ");
                }
                e.detail.push_str(&flags.join(", "));
            }
            out.push(e);
        }
        flags.clear();
    };
    for line in text.lines() {
        if let Some(c) = r.typ.captures(line) {
            flush(&mut cur, &mut flags, &mut out);
            typ = c[1].trim().to_string();
            continue;
        }
        if r.overall.is_match(line) {
            flush(&mut cur, &mut flags, &mut out);
            in_overall = true;
            continue;
        }
        if let Some(c) = r.element.captures(line) {
            flush(&mut cur, &mut flags, &mut out);
            in_overall = false;
            if TYPES.contains(&typ.as_str()) {
                cur = Some(EnclosureElement {
                    kind: typ.clone(),
                    index: c[1].parse().unwrap_or(0),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(e) = cur.as_mut() else { continue };
        if in_overall {
            continue;
        }
        if let Some(c) = r.status.captures(line) {
            e.status = c[1].to_string();
            e.level = level(&c[1]).to_string();
        }
        if let Some(c) = r.temp.captures(line) {
            e.detail = format!("{} °C", &c[1]);
        }
        if let Some(c) = r.speed.captures(line) {
            e.detail = format!("{} rpm", &c[1]);
        }
        if let Some(c) = r.volt.captures(line) {
            e.detail = format!("{} V", &c[1]);
        }
        if let Some(c) = r.amps.captures(line) {
            e.detail = format!("{} A", &c[1]);
        }
        for c in r.flag.captures_iter(line) {
            flags.push(c[1].to_lowercase());
        }
    }
    flush(&mut cur, &mut flags, &mut out);
    // "Failure indication" on the enclosure element is the fault LED.
    for e in out.iter_mut() {
        if e.kind == "Enclosure" && e.detail.contains("failure indication") && e.level == "ok" {
            e.level = "warn".into();
        }
    }
    out
}

/// crit > warn > ok.
pub fn enclosure_level(els: &[EnclosureElement]) -> String {
    if els.iter().any(|e| e.level == "crit") {
        "crit".into()
    } else if els.iter().any(|e| e.level == "warn") {
        "warn".into()
    } else {
        "ok".into()
    }
}
