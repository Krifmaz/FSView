use serde_json::Value;

use super::{Server, SmartChoice};
use crate::proto::SmartGetResult;
use crate::smart::{self, Report};

fn norm(s: &str) -> String {
    s.trim().to_uppercase()
}

impl Server {
    pub(super) fn cached_smart_type(&self, dev: &str) -> String {
        self.smart_types
            .lock()
            .unwrap()
            .get(dev)
            .map(|c| c.devtype.clone())
            .unwrap_or_default()
    }

    fn smartctl(
        &self,
        dev: &str,
        devtype: &str,
        wake: bool,
        info: bool,
    ) -> Result<(SmartGetResult, Option<Report>), String> {
        let path = format!("/dev/{dev}");
        let mut args = vec!["-j", if info { "-i" } else { "-a" }];
        if !wake {
            args.extend(["-n", "standby"]);
        }
        if !devtype.is_empty() {
            args.extend(["-d", devtype]);
        }
        args.push(&path);
        let out = self
            .runner
            .run("smartctl", &args)
            .map_err(|e| e.to_string())?;
        let raw: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        let rep = smart::parse(&out.stdout, devtype).ok();
        let res = SmartGetResult {
            device: dev.into(),
            devtype: devtype.into(),
            exit_status: out.code,
            standby: rep.as_ref().is_some_and(|r| r.standby),
            raw,
        };
        Ok((res, rep))
    }

    /// Queries a disk. For SCSI-looking disks without ATA data it tries ATA
    /// pass-through (-d sat), which SATA disks behind SAS bridges need for
    /// real SMART data. Pass-through is only accepted when it reports the
    /// same serial as the disk's own SCSI identity: some bridges route
    /// pass-through commands to a different drive.
    pub(super) fn smart_get(&self, dev: &str, wake: bool) -> Result<SmartGetResult, String> {
        let cached = self.smart_types.lock().unwrap().get(dev).cloned();
        match cached {
            Some(c) if c.devtype == "sat" => {
                let (out, rep) = self.smartctl(dev, "sat", wake, false)?;
                match rep {
                    Some(r) if !r.standby && norm(&r.serial) != c.serial => {
                        // Serial changed (disk renamed or swapped): re-detect.
                        self.smart_types.lock().unwrap().remove(dev);
                    }
                    _ => return Ok(out),
                }
            }
            Some(_) => return Ok(self.smartctl(dev, "", wake, false)?.0),
            None => {}
        }

        let (mut out, rep) = self.smartctl(dev, "", wake, false)?;
        let Some(rep) = rep.filter(|r| !r.standby && out.exit_status & 0x3 == 0) else {
            return Ok(out);
        };
        let native = norm(&rep.serial);
        if rep.looks_like_bridged_ata() {
            if let Ok((sat_out, Some(sat))) = self.smartctl(dev, "sat", wake, false) {
                if sat.protocol == "ATA" && !sat.attributes.is_empty() {
                    if !native.is_empty() && norm(&sat.serial) == native {
                        self.smart_types.lock().unwrap().insert(
                            dev.into(),
                            SmartChoice {
                                devtype: "sat".into(),
                                serial: native,
                            },
                        );
                        return Ok(sat_out);
                    }
                    eprintln!(
                        "fsview-helper: SAFETY: {dev}: ATA pass-through answered with serial {:?} but the disk reports {:?}; pass-through disabled for this disk",
                        sat.serial, rep.serial
                    );
                    annotate(&mut out.raw, &format!(
                        "ATA pass-through (-d sat) answered with serial {}, but this disk reports {}. The bridge may route pass-through commands to another drive, so FSView will not use -d sat for {dev}.",
                        sat.serial, rep.serial
                    ));
                }
            }
        }
        self.smart_types.lock().unwrap().insert(
            dev.into(),
            SmartChoice {
                devtype: String::new(),
                serial: native,
            },
        );
        Ok(out)
    }

    /// Confirms, right before a write, that -d sat still reaches the
    /// addressed disk.
    pub(super) fn verify_pass_through(&self, dev: &str) -> Result<(), String> {
        let (_, native) = self.smartctl(dev, "", true, true)?;
        let (_, sat) = self.smartctl(dev, "sat", true, true)?;
        let ns = native.map(|r| r.serial).unwrap_or_default();
        let ss = sat.map(|r| r.serial).unwrap_or_default();
        if ns.is_empty() || norm(&ns) != norm(&ss) {
            return Err(format!("refusing: ATA pass-through to {dev} answered with serial {ss:?} but the disk reports {ns:?}"));
        }
        Ok(())
    }
}

/// Adds a message to smartctl's "smartctl.messages" so the UI shows it.
fn annotate(raw: &mut Value, msg: &str) {
    let Some(doc) = raw.as_object_mut() else {
        return;
    };
    let sc = doc
        .entry("smartctl")
        .or_insert_with(|| Value::Object(Default::default()));
    let Some(sc) = sc.as_object_mut() else { return };
    let msgs = sc.entry("messages").or_insert_with(|| Value::Array(vec![]));
    if let Some(a) = msgs.as_array_mut() {
        a.push(serde_json::json!({"string": format!("FSView: {msg}"), "severity": "warning"}));
    }
}
