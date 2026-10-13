use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One line in the audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditRecord {
    pub time: DateTime<Utc>,
    pub actor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_ip: String,
    pub peer_uid: u32,
    pub op: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    /// ok | error | rejected | dry-run
    pub result: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output: String,
}

/// Append-only JSON-lines log, root-owned, group-readable by fsview.
pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>, gid: Option<u32>) -> Result<AuditLog, String> {
        let path = path.into();
        let dir = path.parent().unwrap_or(Path::new("/"));
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if let (Some(g), true) = (gid, nix::unistd::geteuid().is_root()) {
            let gid = Some(nix::unistd::Gid::from_raw(g));
            let _ = nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(0)), gid);
            let _ = nix::unistd::chown(dir, Some(nix::unistd::Uid::from_raw(0)), gid);
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
        }
        Ok(AuditLog {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn write(&self, mut rec: AuditRecord) -> Result<(), String> {
        let _g = self.lock.lock().unwrap();
        if rec.output.len() > 4096 {
            let mut cut = 4096;
            while !rec.output.is_char_boundary(cut) {
                cut -= 1;
            }
            rec.output.truncate(cut);
            rec.output.push_str("…(truncated)");
        }
        let mut line = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        f.write_all(&line).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())
    }

    /// Newest `limit` records, newest first.
    pub fn tail(&self, limit: usize) -> Result<Vec<AuditRecord>, String> {
        let _g = self.lock.lock().unwrap();
        let f = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.to_string()),
        };
        let mut all: Vec<AuditRecord> = BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect();
        if all.len() > limit {
            all.drain(..all.len() - limit);
        }
        all.reverse();
        Ok(all)
    }
}
