use std::sync::OnceLock;

use regex::Regex;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{AuditRecord, Server};
use crate::bootcheck;
use crate::events;
use crate::inventory::{Collector, Inventory};
use crate::proto::*;
use crate::runner::command_line;

/// How dangerous an operation is.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Class {
    Read,
    Write,
    Destructive,
}

/// What a write operation intends to do. `prepare` validates everything;
/// execution only runs `commands`.
pub(super) struct Plan {
    targets: Vec<String>,
    commands: Vec<Vec<String>>,
    summary: String,
}

/// Operation failure: (error code, message).
pub(super) type OpError = (&'static str, String);

fn bad(msg: impl Into<String>) -> OpError {
    (CODE_BAD_REQUEST, msg.into())
}
fn failed(msg: impl Into<String>) -> OpError {
    (CODE_EXEC_FAILED, msg.into())
}

fn class_of(op: &str) -> Option<Class> {
    Some(match op {
        OP_STATUS | OP_INVENTORY | OP_SMART_GET | OP_JOURNAL_KERNEL | OP_BOOT_COLLECT
        | OP_AUDIT_LIST | OP_HIDDEN_SCAN => Class::Read,
        OP_SMART_SELFTEST => Class::Write,
        _ => return None,
    })
}

fn decode<T: DeserializeOwned + Default>(req: &Request) -> Result<T, OpError> {
    if req.params.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(req.params.clone()).map_err(|e| bad(format!("invalid params: {e}")))
}

fn disk_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(sd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,3}|xvd[a-z]{1,3}|hd[a-z]|mmcblk[0-9]{1,3}|loop[0-9]{1,4})$").unwrap())
}

fn cursor_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9=;_\-]+$").unwrap())
}

fn tool_exists(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().any(|d| {
        std::fs::metadata(format!("{d}/{name}"))
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

impl Server {
    /// Dispatches one request; `uid` is the verified peer uid.
    pub fn handle(&self, req: &Request, uid: u32) -> Response {
        let Some(class) = class_of(&req.op) else {
            return Response::err(CODE_UNKNOWN_OP, format!("unknown operation {:?}", req.op));
        };
        if class == Class::Read {
            return match self.read_op(req) {
                Ok(v) => Response {
                    ok: true,
                    result: v,
                    ..Default::default()
                },
                Err((code, msg)) => Response::err(code, msg),
            };
        }
        self.handle_write(class, req, uid)
    }

    fn read_op(&self, req: &Request) -> Result<Value, OpError> {
        let to =
            |v: Result<Value, serde_json::Error>| v.map_err(|e| (CODE_INTERNAL, e.to_string()));
        match req.op.as_str() {
            OP_STATUS => {
                let mut st = StatusResult {
                    version: self.cfg.version.clone(),
                    hostname: crate::inventory::hostname(),
                    writes_enabled: self.cfg.writes_enabled,
                    boot_id: bootcheck::read_boot_id(),
                    ..Default::default()
                };
                for t in [
                    "smartctl",
                    "lsblk",
                    "findmnt",
                    "journalctl",
                    "lspci",
                    "sg_ses",
                    "zpool",
                    "mdadm",
                    "mergerfs",
                    "lvs",
                ] {
                    st.tools.insert(t.into(), tool_exists(t));
                }
                to(serde_json::to_value(st))
            }
            OP_INVENTORY => to(serde_json::to_value(self.inventory().map_err(failed)?)),
            OP_SMART_GET => {
                let p: SmartGetParams = decode(req)?;
                self.valid_disk(&p.device)?;
                to(serde_json::to_value(
                    self.smart_get(&p.device, p.wake).map_err(failed)?,
                ))
            }
            OP_JOURNAL_KERNEL => {
                let p: JournalParams = decode(req)?;
                let lines = if p.lines == 0 || p.lines > 20000 {
                    2000
                } else {
                    p.lines
                }
                .to_string();
                let mut args = vec!["-k", "-o", "json", "--no-pager", "-n", &lines];
                if p.current_boot {
                    args.push("-b");
                }
                if !p.after_cursor.is_empty() {
                    if p.after_cursor.len() > 512 || !cursor_re().is_match(&p.after_cursor) {
                        return Err(bad("invalid cursor"));
                    }
                    args.extend(["--after-cursor", &p.after_cursor]);
                }
                let out = self
                    .runner
                    .run("journalctl", &args)
                    .map_err(|e| failed(e.to_string()))?;
                to(serde_json::to_value(events::parse_json_lines(&out.stdout)))
            }
            OP_BOOT_COLLECT => to(serde_json::to_value(
                bootcheck::collect(&*self.runner, &self.cfg.fstab_path).map_err(failed)?,
            )),
            OP_AUDIT_LIST => {
                let p: AuditListParams = decode(req)?;
                let limit = if p.limit == 0 || p.limit > 5000 {
                    500
                } else {
                    p.limit
                };
                let recs = match &self.audit {
                    Some(a) => a.tail(limit).map_err(failed)?,
                    None => vec![],
                };
                to(serde_json::to_value(recs))
            }
            OP_HIDDEN_SCAN => {
                let p: HiddenScanParams = decode(req)?;
                to(serde_json::to_value(
                    self.scan_hidden(!p.all).map_err(failed)?,
                ))
            }
            _ => Err((CODE_UNKNOWN_OP, "unknown".into())),
        }
    }

    pub(super) fn inventory(&self) -> Result<Inventory, String> {
        let mut c = Collector::new(&*self.runner, self.cfg.include_loop);
        c.sysfs = crate::inventory::Sysfs::new(&self.cfg.sys_root);
        c.collect()
    }

    /// Syntactically valid whole-disk name that exists right now.
    pub(super) fn valid_disk(&self, name: &str) -> Result<(), OpError> {
        if !disk_re().is_match(name) {
            return Err(bad(format!("invalid device name {name:?}")));
        }
        if name.starts_with("loop") && !self.cfg.include_loop {
            return Err(bad("loop devices are not enabled"));
        }
        if !self.cfg.sys_root.join("block").join(name).exists() {
            return Err(bad(format!("device {name} does not exist")));
        }
        Ok(())
    }

    fn audit(&self, rec: AuditRecord) {
        if let Some(a) = &self.audit {
            if let Err(e) = a.write(rec.clone()) {
                eprintln!("fsview-helper: AUDIT WRITE FAILED: {e} ({rec:?})");
            }
        }
    }

    fn prepare(&self, req: &Request) -> Result<Plan, OpError> {
        match req.op.as_str() {
            OP_SMART_SELFTEST => self.prep_smart_selftest(req),
            _ => Err((CODE_UNKNOWN_OP, "unknown".into())),
        }
    }

    fn handle_write(&self, class: Class, req: &Request, uid: u32) -> Response {
        let mut rec = AuditRecord {
            time: chrono::Utc::now(),
            actor: req.actor.clone(),
            client_ip: req.client_ip.clone(),
            peer_uid: uid,
            op: req.op.clone(),
            params: req.params.clone(),
            dry_run: req.dry_run,
            ..Default::default()
        };
        let reject = |rec: &mut AuditRecord, code: &str, msg: String| {
            rec.result = "rejected".into();
            rec.error = msg.clone();
            self.audit(rec.clone());
            Response::err(code, msg)
        };
        if !self.cfg.writes_enabled {
            return reject(&mut rec, CODE_WRITES_OFF, "write operations are disabled in the helper configuration (writes_enabled = false)".into());
        }
        let plan = match self.prepare(req) {
            Ok(p) => p,
            Err((code, msg)) => return reject(&mut rec, code, msg),
        };
        rec.targets = plan.targets.clone();
        rec.commands = plan.commands.iter().map(|c| command_line(c)).collect();

        if class == Class::Destructive {
            let inv = match self.inventory() {
                Ok(i) => i,
                Err(e) => {
                    return reject(
                        &mut rec,
                        CODE_EXEC_FAILED,
                        format!("cannot verify targets: {e}"),
                    )
                }
            };
            if let Err(e) = check_destructive(&inv, &plan.targets, &req.confirm_text, !req.dry_run)
            {
                let code = if e.contains("protected") {
                    CODE_PROTECTED
                } else {
                    CODE_NEED_CONFIRM
                };
                return reject(&mut rec, code, e);
            }
        }
        if req.dry_run {
            rec.result = "dry-run".into();
            self.audit(rec.clone());
            return Response {
                ok: true,
                dry_run: true,
                plan: rec.commands,
                ..Default::default()
            };
        }
        if class == Class::Write && !req.confirmed {
            return reject(
                &mut rec,
                CODE_NEED_CONFIRM,
                "operation must be confirmed".into(),
            );
        }

        let mut output = String::new();
        for c in &plan.commands {
            let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
            let res = self.runner.run(&c[0], &args);
            let err = match &res {
                Ok(o) => {
                    output.push_str(&String::from_utf8_lossy(&o.stdout));
                    output.push_str(&String::from_utf8_lossy(&o.stderr));
                    (o.code != 0 && !tolerated_exit(c, o.code))
                        .then(|| format!("{} exited with status {}", c[0], o.code))
                }
                Err(e) => Some(e.to_string()),
            };
            if let Some(e) = err {
                rec.result = "error".into();
                rec.error = e.clone();
                rec.output = output.clone();
                self.audit(rec.clone());
                let tail: Vec<&str> = output.trim().lines().rev().take(5).collect();
                let tail: Vec<&str> = tail.into_iter().rev().collect();
                return Response {
                    code: CODE_EXEC_FAILED.into(),
                    error: format!("{e}: {}", tail.join("\n")),
                    plan: rec.commands,
                    ..Default::default()
                };
            }
        }
        rec.result = "ok".into();
        rec.output = output.clone();
        let plan_lines = rec.commands.clone();
        self.audit(rec);
        let mut resp =
            Response::ok(&serde_json::json!({"summary": plan.summary, "output": output}));
        resp.plan = plan_lines;
        resp
    }

    fn prep_smart_selftest(&self, req: &Request) -> Result<Plan, OpError> {
        let p: SmartSelfTestParams = decode(req)?;
        self.valid_disk(&p.device)?;
        let flag = match p.test.as_str() {
            "short" => "short",
            "long" => "long",
            "abort" => "X",
            _ => return Err(bad("test must be short, long or abort")),
        };
        let devtype = self.cached_smart_type(&p.device);
        if devtype == "sat" {
            self.verify_pass_through(&p.device).map_err(failed)?;
        }
        let mut args = vec!["smartctl".to_string()];
        if !devtype.is_empty() {
            args.extend(["-d".into(), devtype]);
        }
        if flag == "X" {
            args.push("-X".into());
        } else {
            args.extend(["-t".into(), flag.into()]);
        }
        args.push(format!("/dev/{}", p.device));
        Ok(Plan {
            targets: vec![p.device.clone()],
            commands: vec![args],
            summary: format!("SMART {} self-test on /dev/{}", p.test, p.device),
        })
    }
}

/// smartctl uses exit bits 2-7 to report disk state, not command failure.
fn tolerated_exit(cmd: &[String], code: i32) -> bool {
    cmd[0] == "smartctl" && code & 0x3 == 0
}

/// Enforces the protected-disk rule and the typed confirmation (device
/// name or label of the target disk).
pub fn check_destructive(
    inv: &Inventory,
    targets: &[String],
    confirm: &str,
    require_confirm: bool,
) -> Result<(), String> {
    if targets.is_empty() {
        return Err("destructive operation without targets".into());
    }
    for t in targets {
        let d = inv
            .find_disk(t)
            .ok_or_else(|| format!("target {t} not found"))?;
        if d.protected {
            return Err(format!(
                "{t} is a protected system disk: {}",
                d.protected_reasons.join("; ")
            ));
        }
    }
    if !require_confirm {
        return Ok(());
    }
    let confirm = confirm.trim();
    if confirm.is_empty() {
        return Err("type the disk's device name or label to confirm".into());
    }
    for t in targets {
        let d = inv.find_disk(t).expect("checked above");
        let mut ok = confirm == d.name || (!d.label.is_empty() && confirm == d.label);
        d.walk(&mut |n| {
            if !n.label.is_empty() && confirm == n.label {
                ok = true;
            }
        });
        if !ok {
            return Err(format!(
                "confirmation text does not match {t} (expected its device name or label)"
            ));
        }
    }
    Ok(())
}
