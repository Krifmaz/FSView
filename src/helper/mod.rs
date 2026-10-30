//! Root-privileged half of FSView. Listens on a Unix socket, accepts only
//! peers whose UID is allowed (SO_PEERCRED), and executes a fixed allow-list
//! of typed operations. Safety rules (writes switch, confirmations,
//! protected disks, audit log) are enforced here regardless of what the web
//! process sends.

mod audit;
mod fstabops;
mod hidden;
mod ops;
mod poolhealth;
mod smart;
mod storage;
mod tune;

pub use audit::{AuditLog, AuditRecord};
pub use hidden::plan_hidden_scan;
pub use ops::check_destructive;
pub use storage::{is_mergerfs, mergerfs_branch_modes, mergerfs_branches};

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::proto::{self, Request, Response};
use crate::runner::Runner;

#[derive(Debug, Clone)]
pub struct Config {
    pub socket: PathBuf,
    /// Peers allowed to connect.
    pub allowed_uids: Vec<u32>,
    /// Group owner of the socket.
    pub socket_gid: Option<u32>,
    pub writes_enabled: bool,
    pub include_loop: bool,
    pub fstab_path: PathBuf,
    /// Where backups of fstab are kept (root only).
    pub backup_dir: PathBuf,
    /// Default /sys.
    pub sys_root: PathBuf,
    /// Directory for temporary mountpoints (default /tmp).
    pub scratch_dir: PathBuf,
    pub version: String,
    /// Mount table read for pool health (default /proc/mounts).
    pub mounts_file: PathBuf,
    /// `/proc/sys` (tests point it elsewhere).
    pub proc_sys: PathBuf,
    /// Where device nodes are looked up when pool health checks that a
    /// branch's disk is still attached (default /dev; tests change it).
    pub dev_dir: PathBuf,
    /// Commands run before a pool branch repair, to stop programs that use
    /// the pool (argv each, no shell; failures are ignored). Set only in the
    /// root-owned helper configuration, never by the web process.
    pub repair_stop: Vec<Vec<String>>,
    /// Commands run after a successful branch repair, e.g. restarting an
    /// LXC container that still holds the old mergerfs instance in its
    /// mount namespace (argv each, no shell; failures are ignored).
    pub repair_post: Vec<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket: "/run/fsview/helper.sock".into(),
            allowed_uids: vec![],
            socket_gid: None,
            writes_enabled: false,
            include_loop: false,
            fstab_path: "/etc/fstab".into(),
            backup_dir: "/var/lib/fsview-helper/backups".into(),
            sys_root: "/sys".into(),
            scratch_dir: std::env::temp_dir(),
            version: crate::VERSION.into(),
            mounts_file: "/proc/mounts".into(),
            dev_dir: "/dev".into(),
            proc_sys: "/proc/sys".into(),
            repair_stop: vec![],
            repair_post: vec![],
        }
    }
}

/// Chosen smartctl -d type for a disk plus the serial the disk reported
/// natively, so pass-through answers can be verified.
#[derive(Debug, Clone)]
struct SmartChoice {
    devtype: String,
    serial: String,
}

pub struct Server {
    cfg: Config,
    runner: Arc<dyn Runner>,
    audit: Option<AuditLog>,
    smart_types: Mutex<HashMap<String, SmartChoice>>,
    /// Tuning files whose write failed (not supported by the device); not
    /// retried, so a failing write does not fill the audit log every minute.
    tune_failed: Mutex<std::collections::HashSet<PathBuf>>,
    /// When automatic branch repairs ran, per mountpoint (rate limit).
    repairs: Mutex<HashMap<String, Vec<std::time::SystemTime>>>,
    /// Held while a pool heal runs; a heal can include a long fsck.
    heal_lock: Mutex<()>,
}

impl Server {
    pub fn new(cfg: Config, runner: Arc<dyn Runner>, audit: Option<AuditLog>) -> Arc<Server> {
        Arc::new(Server {
            cfg,
            runner,
            audit,
            smart_types: Mutex::new(HashMap::new()),
            tune_failed: Mutex::new(Default::default()),
            repairs: Mutex::new(HashMap::new()),
            heal_lock: Mutex::new(()),
        })
    }

    /// Creates the socket with mode 0660 and the configured group.
    pub fn listen(&self) -> std::io::Result<UnixListener> {
        // Bind under a temporary name, fix mode/owner, then rename into
        // place, so the final path never exists with loose permissions.
        // (Changing the umask instead would affect every thread.)
        let sock = &self.cfg.socket;
        let dir = sock.parent().unwrap_or(std::path::Path::new("/"));
        let tmp = dir.join(format!(
            ".helper-{}.sock",
            hex::encode(crate::auth::random_bytes::<6>())
        ));
        let l = UnixListener::bind(&tmp)?;
        let fix = || -> std::io::Result<()> {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o660))?;
            if let (Some(g), true) = (self.cfg.socket_gid, nix::unistd::geteuid().is_root()) {
                nix::unistd::chown(
                    &tmp,
                    Some(nix::unistd::Uid::from_raw(0)),
                    Some(nix::unistd::Gid::from_raw(g)),
                )?;
            }
            std::fs::rename(&tmp, sock)
        };
        if let Err(e) = fix() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(l)
    }

    /// Accepts connections until the listener fails or `shutdown` resolves.
    pub async fn serve(
        self: Arc<Self>,
        l: UnixListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                acc = l.accept() => match acc {
                    Ok((c, _)) => {
                        let s = self.clone();
                        tokio::spawn(async move { s.handle_conn(c).await });
                    }
                    Err(e) => {
                        eprintln!("fsview-helper: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    async fn handle_conn(self: Arc<Self>, mut c: UnixStream) {
        let uid = match c.peer_cred() {
            Ok(cred) if self.cfg.allowed_uids.contains(&cred.uid()) => cred.uid(),
            other => {
                let uid = other.map(|c| c.uid() as i64).unwrap_or(-1);
                eprintln!("fsview-helper: rejected connection from uid {uid}");
                let _ = write_resp(
                    &mut c,
                    &Response::err(proto::CODE_NOT_PERMITTED, "peer not permitted"),
                )
                .await;
                return;
            }
        };
        let mut line = Vec::new();
        let read = {
            let mut br = BufReader::new((&mut c).take(proto::MAX_MESSAGE as u64));
            tokio::time::timeout(Duration::from_secs(30), br.read_until(b'\n', &mut line)).await
        };
        if !matches!(read, Ok(Ok(n)) if n > 0) {
            return;
        }
        let req: Request = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(_) => {
                let _ = write_resp(
                    &mut c,
                    &Response::err(proto::CODE_BAD_REQUEST, "invalid request json"),
                )
                .await;
                return;
            }
        };
        let s = self.clone();
        let work = tokio::task::spawn_blocking(move || s.handle(&req, uid));
        let resp = match tokio::time::timeout(Duration::from_secs(600), work).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Response::err(proto::CODE_INTERNAL, format!("operation panicked: {e}")),
            Err(_) => Response::err(proto::CODE_INTERNAL, "operation timed out"),
        };
        let _ = tokio::time::timeout(Duration::from_secs(30), write_resp(&mut c, &resp)).await;
    }
}

async fn write_resp(c: &mut UnixStream, r: &Response) -> std::io::Result<()> {
    let mut b = serde_json::to_vec(r)
        .unwrap_or_else(|_| br#"{"ok":false,"code":"internal","error":"marshal failed"}"#.to_vec());
    b.push(b'\n');
    c.write_all(&b).await
}

#[cfg(test)]
mod tests;
