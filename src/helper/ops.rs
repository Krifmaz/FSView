use std::path::PathBuf;
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
/// execution only performs `actions`, in order, stopping at the first
/// failure.
pub(super) struct Plan {
    pub(super) targets: Vec<String>,
    pub(super) actions: Vec<Action>,
    pub(super) summary: String,
    /// Extra text for the audit log and the response (e.g. a diff).
    pub(super) detail: String,
}

/// One step of a write operation.
pub(super) enum Action {
    /// Run a command (argv, no shell).
    Run(Vec<String>),
    /// Copy `src` to the new file `dst` (fails if `dst` exists).
    Backup { src: PathBuf, dst: PathBuf },
    /// Create a directory (and missing parents) with mode 0755.
    Mkdir(PathBuf),
    /// Atomically replace `path` with `content`, but only if its current
    /// content still hashes to `expect_sha256`.
    WriteFile {
        path: PathBuf,
        content: String,
        expect_sha256: String,
    },
    /// Write a value to a sysfs attribute (e.g. an enclosure locate LED).
    WriteSysfs { path: PathBuf, value: String },
    /// Wait up to 30 s for a device node to appear.
    WaitDevice(PathBuf),
}

impl Action {
    pub(super) fn describe(&self) -> String {
        match self {
            Action::Run(c) => command_line(c),
            Action::Backup { src, dst } => {
                format!("cp --preserve=mode {} {}", src.display(), dst.display())
            }
            Action::Mkdir(p) => format!("mkdir -p -m 0755 {}", p.display()),
            Action::WriteFile { path, content, .. } => format!(
                "write {} ({} bytes, atomic replace)",
                path.display(),
                content.len()
            ),
            Action::WriteSysfs { path, value } => format!("echo {value} > {}", path.display()),
            Action::WaitDevice(p) => format!("wait for {}", p.display()),
        }
    }
}

/// Operation failure: (error code, message).
pub(super) type OpError = (&'static str, String);

pub(super) fn bad(msg: impl Into<String>) -> OpError {
    (CODE_BAD_REQUEST, msg.into())
}
pub(super) fn failed(msg: impl Into<String>) -> OpError {
    (CODE_EXEC_FAILED, msg.into())
}

fn class_of(op: &str) -> Option<Class> {
    Some(match op {
        OP_STATUS | OP_INVENTORY | OP_SMART_GET | OP_JOURNAL_KERNEL | OP_BOOT_COLLECT
        | OP_AUDIT_LIST | OP_HIDDEN_SCAN | OP_FSTAB_READ | OP_FSTAB_PREVIEW | OP_FSTAB_BACKUP
        | OP_MOUNTS_LIST => Class::Read,
        OP_SMART_SELFTEST
        | OP_FSTAB_WRITE
        | OP_FSTAB_ROLLBACK
        | OP_MOUNT
        | OP_UMOUNT
        | OP_FS_CHECK
        | OP_LOCATE
        | OP_FS_LABEL
        | OP_PROTECT_MOUNTPOINTS => Class::Write,
        OP_FS_FORMAT | OP_FS_REPAIR => Class::Destructive,
        _ => return None,
    })
}

pub(super) fn decode<T: DeserializeOwned + Default>(req: &Request) -> Result<T, OpError> {
    if req.params.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(req.params.clone()).map_err(|e| bad(format!("invalid params: {e}")))
}

pub(super) fn disk_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(sd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,3}|xvd[a-z]{1,3}|hd[a-z]|mmcblk[0-9]{1,3}|loop[0-9]{1,4})$").unwrap())
}

fn cursor_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9=;_\-]+$").unwrap())
}

pub(super) fn tool_exists(name: &str) -> bool {
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
                    "sgdisk",
                    "wipefs",
                    "fuser",
                    "mkfs.ext4",
                    "mkfs.xfs",
                    "mkfs.btrfs",
                    "mkfs.vfat",
                    "mkfs.exfat",
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
            OP_FSTAB_READ => to(serde_json::to_value(self.fstab_read()?)),
            OP_MOUNTS_LIST => to(serde_json::to_value(self.mounts_list()?)),
            OP_FSTAB_PREVIEW => {
                let p: FstabPreviewParams = decode(req)?;
                to(serde_json::to_value(self.fstab_preview(&p.doc)?))
            }
            OP_FSTAB_BACKUP => {
                let p: FstabBackupParams = decode(req)?;
                to(serde_json::to_value(self.fstab_backup_view(&p.name)?))
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
            OP_FSTAB_WRITE => self.prep_fstab_write(req),
            OP_FSTAB_ROLLBACK => self.prep_fstab_rollback(req),
            OP_MOUNT => self.prep_mount(req),
            OP_UMOUNT => self.prep_umount(req),
            OP_PROTECT_MOUNTPOINTS => self.prep_protect_mountpoints(),
            OP_FS_FORMAT => self.prep_format(req),
            OP_FS_CHECK => self.prep_fs_check(req, false),
            OP_FS_REPAIR => self.prep_fs_check(req, true),
            OP_LOCATE => self.prep_locate(req),
            OP_FS_LABEL => self.prep_label(req),
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
        rec.commands = plan.actions.iter().map(Action::describe).collect();

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
                result: serde_json::json!({"summary": plan.summary, "output": plan.detail}),
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

        let mut output = plan.detail.clone();
        for a in &plan.actions {
            let err = match a {
                Action::Run(c) => {
                    let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
                    match self.runner.run(&c[0], &args) {
                        Ok(o) => {
                            output.push_str(&String::from_utf8_lossy(&o.stdout));
                            output.push_str(&String::from_utf8_lossy(&o.stderr));
                            if o.code != 0 && tolerated_exit(c, o.code) {
                                output.push_str(&format!("[{} exit status {}]\n", c[0], o.code));
                            }
                            (o.code != 0 && !tolerated_exit(c, o.code))
                                .then(|| format!("{} exited with status {}", c[0], o.code))
                        }
                        Err(e) => Some(e.to_string()),
                    }
                }
                other => super::fstabops::apply_file_action(other).err(),
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
            actions: vec![Action::Run(args)],
            summary: format!("SMART {} self-test on /dev/{}", p.test, p.device),
            detail: String::new(),
        })
    }
}

/// smartctl uses exit bits 2-7 to report disk state, not command failure.
/// Exit codes that report findings rather than failure: smartctl uses
/// bits 2-7 for disk state; read-only filesystem checks exit non-zero when
/// they find problems, which is the result the user asked for.
fn tolerated_exit(cmd: &[String], code: i32) -> bool {
    let read_only = cmd.iter().any(|a| a == "-n" || a == "--readonly");
    match cmd[0].as_str() {
        "smartctl" => code & 0x3 == 0,
        // 1 = errors corrected, 2 = reboot advised, 4 = errors left (-n)
        "e2fsck" => code < if read_only { 8 } else { 4 },
        "xfs_repair" | "fsck.vfat" | "fsck.exfat" | "btrfs" => read_only && code == 1,
        // Protecting a mountpoint is best effort (e.g. a filesystem without
        // the immutable flag); the mount or unmount itself already worked.
        "chattr" => true,
        _ => false,
    }
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
