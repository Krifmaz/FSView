#![forbid(unsafe_code)]
//! fsview serve  [--config /etc/fsview/fsview.conf]   unprivileged web server
//! fsview helper [--config /etc/fsview/helper.conf]   root helper
//! fsview user add|passwd|del|list [NAME] [--generate]
//! fsview version

use std::io::BufRead;
use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use fsview::{config, helper, helperclient, netutil, runner, store, web, VERSION};

#[derive(Parser)]
#[command(name = "fsview", version = VERSION, about = "Disk, filesystem and storage-pool manager for Proxmox VE hosts")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the unprivileged web server.
    Serve {
        #[arg(long, short = 'c', default_value = "/etc/fsview/fsview.conf")]
        config: PathBuf,
    },
    /// Run the root helper.
    Helper {
        #[arg(long, short = 'c', default_value = "/etc/fsview/helper.conf")]
        config: PathBuf,
    },
    /// Manage web users.
    User {
        #[command(subcommand)]
        action: UserCmd,
        #[arg(
            long,
            short = 'c',
            global = true,
            default_value = "/etc/fsview/fsview.conf"
        )]
        config: PathBuf,
    },
    /// Print the version.
    Version,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create a user.
    Add {
        name: String,
        /// Generate a random password and print it.
        #[arg(long)]
        generate: bool,
    },
    /// Change a user's password (signs out their sessions).
    Passwd {
        name: String,
        #[arg(long)]
        generate: bool,
    },
    /// Delete a user.
    Del { name: String },
    /// List users.
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Serve { config } => serve(&config),
        Cmd::Helper { config } => run_helper(&config),
        Cmd::User { action, config } => user(action, &config),
        Cmd::Version => {
            println!("fsview {VERSION}");
            Ok(())
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fsview: {e}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("signal handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

fn serve(path: &Path) -> Result<(), String> {
    if nix::unistd::geteuid().is_root() {
        return Err("refusing to run the web server as root; run it as the fsview user".into());
    }
    let cfg = config::load_web(path)?;
    let lan = netutil::lan_address()
        .map_err(|e| eprintln!("fsview: LAN detection: {e}"))
        .ok();
    let listen = netutil::resolve_listen(&cfg.listen, cfg.port, lan.map(|l| l.0))?;
    let allow = netutil::resolve_allow(&cfg.allow, lan.map(|l| l.1))?;
    let st = Arc::new(store::Store::open(&cfg.data_dir)?);
    if st.users().is_empty() {
        eprintln!(
            "fsview: warning: no users exist; create one with `fsview user add admin --generate`"
        );
    }
    let opt = web::Options {
        version: VERSION.into(),
        allow,
        listen,
        tls_cert: cfg.tls_cert,
        tls_key: cfg.tls_key,
        smart_poll: cfg.smart_poll,
        journal_poll: cfg.journal_poll,
    };
    let app = web::App::new(
        opt,
        st,
        Arc::new(helperclient::Client::new(&cfg.helper_socket)),
    );
    runtime()?.block_on(app.run(shutdown_signal()))
}

fn run_helper(path: &Path) -> Result<(), String> {
    if !nix::unistd::geteuid().is_root() {
        return Err("the helper must run as root".into());
    }
    let cfg = config::load_helper(path)?;
    let u = nix::unistd::User::from_name(&cfg.client_user)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("client user {:?} does not exist", cfg.client_user))?;
    if u.uid.is_root() {
        return Err("client_user must not be root".into());
    }
    let audit = helper::AuditLog::open(&cfg.audit_log, Some(u.gid.as_raw()))
        .map_err(|e| format!("audit log: {e}"))?;
    let socket = PathBuf::from(&cfg.socket);
    let scratch = socket
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let hc = helper::Config {
        socket: socket.clone(),
        allowed_uids: vec![u.uid.as_raw()],
        socket_gid: Some(u.gid.as_raw()),
        writes_enabled: cfg.writes_enabled,
        include_loop: cfg.include_loop,
        scratch_dir: scratch,
        backup_dir: PathBuf::from(&cfg.backup_dir),
        version: VERSION.into(),
        ..Default::default()
    };
    let srv = helper::Server::new(hc, Arc::new(runner::Exec), Some(audit));
    let rt = runtime()?;
    rt.block_on(async {
        let l = srv
            .listen()
            .map_err(|e| format!("{}: {e}", socket.display()))?;
        eprintln!(
            "fsview-helper {VERSION}: listening on {} for uid {} (writes_enabled={})",
            socket.display(),
            u.uid,
            cfg.writes_enabled
        );
        srv.serve(l, shutdown_signal()).await;
        Ok(())
    })
}

fn read_password() -> Result<String, String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("New password: ").map_err(|e| e.to_string())?;
        let b = rpassword::prompt_password("Repeat: ").map_err(|e| e.to_string())?;
        if a != b {
            return Err("passwords do not match".into());
        }
        return Ok(a);
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Hands the data directory back to the fsview user when run as root.
fn fix_ownership(dir: &Path) {
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let Ok(Some(u)) = nix::unistd::User::from_name("fsview") else {
        return;
    };
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let _ = chown(&p, Some(u.uid.as_raw()), Some(u.gid.as_raw()));
        if p.is_dir() {
            stack.extend(
                std::fs::read_dir(&p)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path()),
            );
        }
    }
}

fn user(action: UserCmd, path: &Path) -> Result<(), String> {
    let cfg = config::load_web(path)?;
    let st = store::Store::open(&cfg.data_dir)?;
    let res = match action {
        UserCmd::List => {
            for u in st.users() {
                println!("{}\tcreated {}", u.name, u.created_at.format("%Y-%m-%d"));
            }
            Ok(())
        }
        UserCmd::Del { name } => st.delete_user(&name),
        a @ (UserCmd::Add { .. } | UserCmd::Passwd { .. }) => {
            let (name, generate, create) = match a {
                UserCmd::Add { name, generate } => (name, generate, true),
                UserCmd::Passwd { name, generate } => (name, generate, false),
                _ => unreachable!(),
            };
            let pw = if generate {
                fsview::auth::generate_password(20)
            } else {
                read_password()?
            };
            st.set_password(&name, &pw, create)?;
            if generate {
                println!("user {name} password: {pw}");
            } else {
                println!("password for {name} set");
            }
            Ok(())
        }
    };
    fix_ownership(Path::new(&cfg.data_dir));
    res
}
