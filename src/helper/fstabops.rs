//! fstab editor operations: read, preview (validation + findmnt --verify),
//! write and rollback. Writes always back up the current file first and
//! replace it atomically.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use regex::Regex;

use super::ops::{bad, decode, failed, Action, OpError, Plan};
use super::Server;
use crate::fstab::{self, Doc};
use crate::proto::*;

/// Backups kept per file; older ones are deleted after a new backup.
pub const KEEP_BACKUPS: usize = 50;

fn backup_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^fstab\.\d{8}-\d{6}(\.\d{1,3})?$").unwrap())
}

/// Serializes findmnt --verify runs (they share one scratch file).
static VERIFY_LOCK: Mutex<()> = Mutex::new(());

fn kernel_filesystems() -> Vec<String> {
    std::fs::read_to_string("/proc/filesystems")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().last().map(str::to_string))
        .collect()
}

fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}

impl Server {
    fn read_fstab(&self) -> Result<(String, String), OpError> {
        let text = std::fs::read_to_string(&self.cfg.fstab_path)
            .map_err(|e| failed(format!("{}: {e}", self.cfg.fstab_path.display())))?;
        let sha = fstab::sha256_hex(&text);
        Ok((text, sha))
    }

    fn check_base(&self, base: &str) -> Result<(String, String), OpError> {
        let (text, sha) = self.read_fstab()?;
        if base != sha {
            return Err(bad(format!(
                "{} changed since it was loaded; reload and review again",
                self.cfg.fstab_path.display()
            )));
        }
        Ok((text, sha))
    }

    fn fstab_devices(&self) -> Result<Vec<fstab::Device>, OpError> {
        Ok(fstab::devices(&self.inventory().map_err(failed)?))
    }

    fn validate_doc(&self, doc: &Doc, devices: &[fstab::Device]) -> Vec<fstab::Issue> {
        let kfs = kernel_filesystems();
        fstab::validate(
            doc,
            &fstab::Context {
                devices,
                kernel_fs: &kfs,
                path_exists: &path_exists,
            },
        )
    }

    fn backups(&self) -> Vec<FstabBackup> {
        let mut out: Vec<FstabBackup> = std::fs::read_dir(&self.cfg.backup_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if !backup_re().is_match(&name) {
                    return None;
                }
                let m = e.metadata().ok()?;
                Some(FstabBackup {
                    name,
                    time: m.modified().ok()?.into(),
                    size: m.len(),
                })
            })
            .collect();
        out.sort_by(|a, b| b.name.cmp(&a.name));
        out
    }

    fn backup_path(&self, name: &str) -> Result<PathBuf, OpError> {
        if !backup_re().is_match(name) {
            return Err(bad(format!("invalid backup name {name:?}")));
        }
        let p = self.cfg.backup_dir.join(name);
        if !p.is_file() {
            return Err(bad(format!("backup {name} does not exist")));
        }
        Ok(p)
    }

    fn new_backup_path(&self) -> PathBuf {
        let base = format!("fstab.{}", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        let mut p = self.cfg.backup_dir.join(&base);
        let mut n = 1;
        while p.exists() && n < 1000 {
            p = self.cfg.backup_dir.join(format!("{base}.{n}"));
            n += 1;
        }
        p
    }

    /// Runs `findmnt --verify` against `text` without touching the real
    /// fstab.
    fn verify(&self, doc: &Doc, text: &str, will_create: &[String]) -> fstab::Verify {
        let _g = VERIFY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = self.cfg.scratch_dir.join("fstab.verify");
        let write = || -> std::io::Result<()> {
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(text.as_bytes())
        };
        let res = write().and_then(|_| {
            let t = tmp.to_string_lossy();
            self.runner
                .run("findmnt", &["--verify", "--verbose", "--tab-file", &t])
        });
        let _ = std::fs::remove_file(&tmp);
        match res {
            Ok(o) => fstab::parse_verify(
                &String::from_utf8_lossy(&o.stdout),
                &String::from_utf8_lossy(&o.stderr),
                doc,
                will_create,
            ),
            Err(e) => fstab::Verify {
                ok: false,
                errors: vec![format!("findmnt --verify could not run: {e}")],
                ..Default::default()
            },
        }
    }

    pub(super) fn fstab_read(&self) -> Result<FstabState, OpError> {
        let (text, sha) = self.read_fstab()?;
        let doc = fstab::parse(&text);
        let devices = self.fstab_devices()?;
        let issues = self.validate_doc(&doc, &devices);
        Ok(FstabState {
            path: self.cfg.fstab_path.display().to_string(),
            text,
            sha256: sha,
            doc,
            issues,
            devices,
            backups: self.backups(),
            backup_dir: self.cfg.backup_dir.display().to_string(),
            writes_enabled: self.cfg.writes_enabled,
        })
    }

    pub(super) fn fstab_preview(&self, doc: &Doc) -> Result<FstabPreview, OpError> {
        let (old, sha) = self.read_fstab()?;
        let text = fstab::render(doc);
        if text.len() > 1 << 20 {
            return Err(bad("fstab too large"));
        }
        let devices = self.fstab_devices()?;
        let issues = self.validate_doc(doc, &devices);
        let create_dirs = fstab::mountpoints_to_create(doc, &path_exists);
        let verify = self.verify(doc, &text, &create_dirs);
        let changed = text != old;
        let can_apply = changed && verify.ok && !issues.iter().any(|i| i.level == "error");
        Ok(FstabPreview {
            base_sha256: sha,
            diff: fstab::diff(&old, &text),
            text,
            changed,
            issues,
            verify,
            create_dirs,
            can_apply,
        })
    }

    pub(super) fn fstab_backup_view(&self, name: &str) -> Result<FstabBackupView, OpError> {
        let p = self.backup_path(name)?;
        let text = std::fs::read_to_string(&p).map_err(|e| failed(e.to_string()))?;
        let (cur, sha) = self.read_fstab()?;
        Ok(FstabBackupView {
            name: name.into(),
            diff: fstab::diff(&cur, &text),
            text,
            base_sha256: sha,
        })
    }

    fn reload_action() -> Option<Action> {
        // Regenerates the systemd mount units from fstab. Skipped when the
        // host does not run systemd (containers, tests).
        Path::new("/run/systemd/system")
            .exists()
            .then(|| Action::Run(vec!["systemctl".into(), "daemon-reload".into()]))
    }

    pub(super) fn prep_fstab_write(&self, req: &Request) -> Result<Plan, OpError> {
        let p: FstabWriteParams = decode(req)?;
        let (_, sha) = self.check_base(&p.base_sha256)?;
        let pv = self.fstab_preview(&p.doc)?;
        if pv.base_sha256 != sha {
            return Err(bad("fstab changed during validation; reload"));
        }
        if !pv.changed {
            return Err(bad("no changes to apply"));
        }
        let mut problems: Vec<String> = pv
            .issues
            .iter()
            .filter(|i| i.level == "error")
            .map(|i| match i.line {
                Some(l) => format!("line {}: {}", l + 1, i.message),
                None => i.message.clone(),
            })
            .collect();
        problems.extend(pv.verify.errors.iter().map(|e| format!("findmnt: {e}")));
        if !problems.is_empty() {
            return Err(bad(format!(
                "fstab has errors; fix them first:\n{}",
                problems.join("\n")
            )));
        }
        let path = self.cfg.fstab_path.clone();
        let mut actions = vec![Action::Backup {
            src: path.clone(),
            dst: self.new_backup_path(),
        }];
        actions.extend(pv.create_dirs.iter().map(|d| Action::Mkdir(d.into())));
        actions.push(Action::WriteFile {
            path: path.clone(),
            content: pv.text.clone(),
            expect_sha256: sha,
        });
        actions.extend(Self::reload_action());
        Ok(Plan {
            targets: vec![path.display().to_string()],
            actions,
            summary: format!("update {}", path.display()),
            detail: fstab::diff_text(&pv.diff),
        })
    }

    pub(super) fn prep_fstab_rollback(&self, req: &Request) -> Result<Plan, OpError> {
        let p: FstabRollbackParams = decode(req)?;
        let (cur, sha) = self.check_base(&p.base_sha256)?;
        let src = self.backup_path(&p.name)?;
        let text = std::fs::read_to_string(&src).map_err(|e| failed(e.to_string()))?;
        if text == cur {
            return Err(bad("the backup is identical to the current file"));
        }
        let path = self.cfg.fstab_path.clone();
        let mut actions = vec![
            // The current file is backed up too, so a rollback can be undone.
            Action::Backup {
                src: path.clone(),
                dst: self.new_backup_path(),
            },
            Action::WriteFile {
                path: path.clone(),
                content: text.clone(),
                expect_sha256: sha,
            },
        ];
        actions.extend(Self::reload_action());
        Ok(Plan {
            targets: vec![path.display().to_string()],
            actions,
            summary: format!("restore {} from backup {}", path.display(), p.name),
            detail: fstab::diff_text(&fstab::diff(&cur, &text)),
        })
    }
}

/// Executes the file-system actions of a plan (commands are run by the
/// caller).
pub(super) fn apply_file_action(a: &Action) -> Result<(), String> {
    match a {
        Action::Run(_) | Action::RunBestEffort(_) | Action::TrySysfs { .. } => {
            Err("internal: Run is not a file action".into())
        }
        Action::Backup { src, dst } => backup(src, dst),
        Action::Mkdir(p) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(p)
            .map_err(|e| format!("mkdir {}: {e}", p.display())),
        Action::WriteFile {
            path,
            content,
            expect_sha256,
        } => write_atomic(path, content, expect_sha256),
        Action::WriteSysfs { path, value } => {
            std::fs::write(path, value).map_err(|e| format!("write {}: {e}", path.display()))
        }
        Action::WaitDevice(p) => {
            for _ in 0..60 {
                if p.exists() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(format!("{} did not appear", p.display()))
        }
    }
}

fn backup(src: &Path, dst: &Path) -> Result<(), String> {
    let err = |e: std::io::Error| format!("backup {} to {}: {e}", src.display(), dst.display());
    let dir = dst.parent().ok_or("backup path has no directory")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(err)?;
    let data = std::fs::read(src).map_err(err)?;
    let mode = std::fs::metadata(src).map_err(err)?.permissions().mode() & 0o777;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)
        .map_err(err)?;
    f.write_all(&data).map_err(err)?;
    f.sync_all().map_err(err)?;
    // Verify before anything is changed.
    if std::fs::read(dst).map_err(err)? != data {
        return Err(format!(
            "backup {} does not match its source",
            dst.display()
        ));
    }
    prune(dir, src);
    Ok(())
}

/// Keeps the newest KEEP_BACKUPS backups of `src` in `dir`.
fn prune(dir: &Path, src: &Path) {
    let prefix = format!("{}.", src.file_name().unwrap_or_default().to_string_lossy());
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix) && backup_re().is_match(n))
        .collect();
    names.sort();
    let excess = names.len().saturating_sub(KEEP_BACKUPS);
    for n in &names[..excess] {
        let _ = std::fs::remove_file(dir.join(n));
    }
}

fn write_atomic(path: &Path, content: &str, expect_sha256: &str) -> Result<(), String> {
    let err = |e: std::io::Error| format!("write {}: {e}", path.display());
    let cur = std::fs::read_to_string(path).map_err(err)?;
    if fstab::sha256_hex(&cur) != expect_sha256 {
        return Err(format!(
            "{} changed while the operation ran; nothing was written",
            path.display()
        ));
    }
    let meta = std::fs::metadata(path).map_err(err)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".fsview-new");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(meta.permissions().mode() & 0o777)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        if nix::unistd::geteuid().is_root() {
            nix::unistd::chown(
                &tmp,
                Some(nix::unistd::Uid::from_raw(meta.uid())),
                Some(nix::unistd::Gid::from_raw(meta.gid())),
            )?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(err(e));
    }
    Ok(())
}
