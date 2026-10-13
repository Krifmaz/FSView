//! Root-privileged half of FSView. Listens on a Unix socket, accepts only
//! peers whose UID is allowed (SO_PEERCRED), and executes a fixed allow-list
//! of typed operations. Safety rules (writes switch, confirmations,
//! protected disks, audit log) are enforced here regardless of what the web
//! process sends.

mod audit;
mod hidden;
mod ops;
mod smart;

pub use audit::{AuditLog, AuditRecord};
pub use hidden::plan_hidden_scan;
pub use ops::check_destructive;

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
    /// Default /sys.
    pub sys_root: PathBuf,
    /// Directory for temporary mountpoints (default /tmp).
    pub scratch_dir: PathBuf,
    pub version: String,
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
            sys_root: "/sys".into(),
            scratch_dir: std::env::temp_dir(),
            version: crate::VERSION.into(),
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
}

impl Server {
    pub fn new(cfg: Config, runner: Arc<dyn Runner>, audit: Option<AuditLog>) -> Arc<Server> {
        Arc::new(Server {
            cfg,
            runner,
            audit,
            smart_types: Mutex::new(HashMap::new()),
        })
    }

    /// Creates the socket with mode 0660 and the configured group.
    pub fn listen(&self) -> std::io::Result<UnixListener> {
        let _ = std::fs::remove_file(&self.cfg.socket);
        let old = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o117));
        let l = UnixListener::bind(&self.cfg.socket);
        nix::sys::stat::umask(old);
        let l = l?;
        std::fs::set_permissions(&self.cfg.socket, std::fs::Permissions::from_mode(0o660))?;
        if let (Some(g), true) = (self.cfg.socket_gid, nix::unistd::geteuid().is_root()) {
            nix::unistd::chown(
                &self.cfg.socket,
                Some(nix::unistd::Uid::from_raw(0)),
                Some(nix::unistd::Gid::from_raw(g)),
            )?;
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
