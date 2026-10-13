//! Integration tests: need root and loop devices, and only ever touch loop
//! devices backed by temporary files. Run in a privileged container:
//!
//!   cargo test --features integration --test integration -- --test-threads=1
#![cfg(feature = "integration")]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use fsview::bootcheck;
use fsview::helper::{AuditLog, Config, Server};
use fsview::helperclient::{call_as, params, Client, HelperApi};
use fsview::inventory::{Collector, Inventory};
use fsview::proto::*;
use fsview::runner::Exec;

const CHILD_ENV: &str = "FSVIEW_IT_CHILD_SOCKET";

fn root() -> bool {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("integration tests require root; skipping");
        return false;
    }
    true
}

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{cmd}: {e}"));
    assert!(
        out.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Loop {
    dev: String,
    label: String,
    uuid: String,
    _img: tempfile::TempDir,
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.dev]).status();
    }
}

impl Loop {
    fn name(&self) -> String {
        Path::new(&self.dev)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
}

fn new_loop(label: &str) -> Loop {
    let d = tempfile::tempdir().unwrap();
    let img = d.path().join(format!("{label}.img"));
    std::fs::File::create(&img)
        .unwrap()
        .set_len(128 << 20)
        .unwrap();
    let dev = run("losetup", &["-f", "--show", img.to_str().unwrap()]);
    run("mkfs.ext4", &["-q", "-F", "-L", label, &dev]);
    let uuid = run("blkid", &["-s", "UUID", "-o", "value", &dev]);
    let _ = Command::new("udevadm").arg("settle").status();
    Loop {
        dev,
        label: label.into(),
        uuid,
        _img: d,
    }
}

struct Mounted(PathBuf, Option<tempfile::TempDir>);

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("umount")
            .args(["-l", self.0.to_str().unwrap()])
            .status();
    }
}

fn mount_at(dev: &str, at: &Path) -> Mounted {
    run("mount", &[dev, at.to_str().unwrap()]);
    Mounted(at.into(), None)
}

fn mount(dev: &str) -> Mounted {
    let d = tempfile::tempdir().unwrap();
    let mut m = mount_at(dev, d.path());
    m.1 = Some(d);
    m
}

fn collect() -> Inventory {
    Collector::new(&Exec, true).collect().unwrap()
}

#[test]
fn inventory_on_loop_devices() {
    if !root() {
        return;
    }
    let a = new_loop("fsvtest1");
    let b = new_loop("fsvtest2");
    let mp = mount(&a.dev);
    let inv = collect();
    for l in [&a, &b] {
        let d = inv
            .find_disk(&l.name())
            .unwrap_or_else(|| panic!("{} missing", l.dev));
        assert_eq!(
            (d.fstype.as_str(), d.label.as_str()),
            ("ext4", l.label.as_str()),
            "{}",
            l.dev
        );
        assert!(d.uuid.eq_ignore_ascii_case(&l.uuid));
        assert!(
            !d.protected,
            "{} must not be protected: {:?}",
            l.dev, d.protected_reasons
        );
    }
    let da = inv.find_disk(&a.name()).unwrap();
    assert_eq!(da.mountpoints, vec![mp.0.to_string_lossy().to_string()]);
    assert!(da.usage.is_some_and(|u| u.size_bytes > 0));
    let root_src = run("findmnt", &["-n", "-o", "SOURCE", "/"]);
    if root_src.starts_with("/dev/") {
        assert!(
            inv.disks.iter().any(|d| d.protected),
            "root is on {root_src} but no disk is protected"
        );
    } else {
        eprintln!("root filesystem is {root_src:?}; skipping protection check");
    }
}

struct Helper {
    socket: PathBuf,
    audit_path: PathBuf,
    _dir: tempfile::TempDir,
    _rt: tokio::runtime::Runtime,
}

fn start_helper(mut cfg: Config) -> Helper {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    cfg.socket = dir.path().join("helper.sock");
    cfg.scratch_dir = dir.path().into();
    // Never write backups to the host's real backup directory.
    cfg.backup_dir = dir.path().join("backups");
    let audit_path = dir.path().join("audit.log");
    let srv = Server::new(
        cfg.clone(),
        Arc::new(Exec),
        Some(AuditLog::open(&audit_path, None).unwrap()),
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let l = rt.block_on(async { srv.listen() }).unwrap();
    rt.spawn(srv.serve(l, std::future::pending()));
    Helper {
        socket: cfg.socket,
        audit_path,
        _dir: dir,
        _rt: rt,
    }
}

fn call(h: &Helper, req: Request) -> Result<Response, fsview::helperclient::HelperError> {
    let c = Client::new(&h.socket);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(c.call(req))
}

#[test]
fn helper_over_socket() {
    if !root() {
        return;
    }
    let a = new_loop("fsvtest3");
    let h = start_helper(Config {
        allowed_uids: vec![0],
        include_loop: true,
        version: "it".into(),
        ..Default::default()
    });
    let inv: Inventory = serde_json::from_value(
        call(
            &h,
            Request {
                op: OP_INVENTORY.into(),
                ..Default::default()
            },
        )
        .unwrap()
        .result,
    )
    .unwrap();
    assert!(inv.find_disk(&a.name()).is_some());

    let req = Request {
        op: OP_SMART_SELFTEST.into(),
        actor: "it".into(),
        confirmed: true,
        params: params(&SmartSelfTestParams {
            device: a.name(),
            test: "short".into(),
        }),
        ..Default::default()
    };
    assert_eq!(call(&h, req).unwrap_err().code, CODE_WRITES_OFF);
    let recs = AuditLog::open(&h.audit_path, None)
        .unwrap()
        .tail(5)
        .unwrap();
    assert!(
        recs.len() == 1 && recs[0].result == "rejected" && recs[0].actor == "it",
        "{recs:?}"
    );

    for dev in [
        format!("../{}", a.name()),
        format!("{};id", a.name()),
        "sda1".into(),
    ] {
        let r = call(
            &h,
            Request {
                op: OP_SMART_GET.into(),
                params: params(&SmartGetParams {
                    device: dev.clone(),
                    wake: false,
                }),
                ..Default::default()
            },
        );
        assert_eq!(r.unwrap_err().code, CODE_BAD_REQUEST, "{dev}");
    }
}

#[test]
fn helper_dry_run_with_writes_enabled() {
    if !root() {
        return;
    }
    let a = new_loop("fsvtest4");
    let h = start_helper(Config {
        allowed_uids: vec![0],
        include_loop: true,
        writes_enabled: true,
        version: "it".into(),
        ..Default::default()
    });
    let resp = call(
        &h,
        Request {
            op: OP_SMART_SELFTEST.into(),
            actor: "it".into(),
            dry_run: true,
            params: params(&SmartSelfTestParams {
                device: a.name(),
                test: "long".into(),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        resp.dry_run && resp.plan == vec![format!("smartctl -t long /dev/{}", a.name())],
        "{resp:?}"
    );
    let recs = AuditLog::open(&h.audit_path, None)
        .unwrap()
        .tail(5)
        .unwrap();
    assert!(recs.len() == 1 && recs[0].result == "dry-run");
}

/// Child mode for peer_credential_rejection: connect as an unprivileged user.
#[test]
fn child_probe() {
    let Ok(sock) = std::env::var(CHILD_ENV) else {
        return;
    };
    use std::io::{Read, Write};
    match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(mut c) => {
            c.write_all(b"{\"op\":\"status\"}\n").unwrap();
            let mut s = String::new();
            let _ = c.read_to_string(&mut s);
            println!("\nCHILD-RESULT {}", s.trim());
        }
        Err(e) => println!("CHILD-RESULT dial-error {e}"),
    }
}

#[test]
fn peer_credential_rejection() {
    if !root() || std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    // Socket group 65534 lets the child connect at the file-permission
    // level, so this exercises the SO_PEERCRED check itself.
    let h = start_helper(Config {
        allowed_uids: vec![0],
        socket_gid: Some(65534),
        version: "it".into(),
        ..Default::default()
    });
    let exe_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(exe_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = exe_dir.path().join("it");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(&exe)
        .args(["--exact", "child_probe", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD_ENV, &h.socket)
        .uid(65534)
        .gid(65534)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find_map(|l| l.split_once("CHILD-RESULT ").map(|(_, r)| r))
        .unwrap_or_else(|| panic!("no child output: {stdout}"));
    let resp: Response = serde_json::from_str(line).unwrap_or_else(|_| panic!("child: {line}"));
    assert!(!resp.ok && resp.code == CODE_NOT_PERMITTED, "{resp:?}");
}

#[test]
fn bootcheck_with_loop_fstab() {
    if !root() {
        return;
    }
    let a = new_loop("fsvtest5");
    let b = new_loop("fsvtest6");
    let mp_a = mount(&a.dev);
    let dir = tempfile::tempdir().unwrap();
    let mp_b = dir.path().join("notmounted");
    let fstab = dir.path().join("fstab");
    std::fs::write(
        &fstab,
        format!(
            "UUID={} {} ext4 defaults,nofail 0 2\nLABEL={} {} ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2\nLABEL=missing-disk /mnt/nowhere ext4 nofail 0 0\n",
            a.uuid,
            mp_a.0.display(),
            b.label,
            mp_b.display()
        ),
    )
    .unwrap();
    let data = bootcheck::collect(&Exec, &fstab).unwrap();
    let inv = collect();
    let rep = bootcheck::analyze(&data, Some(&inv));
    assert_eq!(rep.entries.len(), 3);
    let (e0, e1, e2) = (&rep.entries[0], &rep.entries[1], &rep.entries[2]);
    assert!(
        e0.mounted && e0.disk == a.name() && e0.status != "failed",
        "{e0:?}"
    );
    assert!(
        !e1.mounted && e1.status == "failed" && e1.disk == b.name() && e1.device_timeout_sec == 5.0,
        "{e1:?}"
    );
    assert!(
        e2.status == "failed" && e2.problems.join(" ").contains("device not found"),
        "{e2:?}"
    );
}

/// The spiritlab incident: files written into a mountpoint directory while
/// the disk was not mounted are hidden once it mounts.
#[test]
fn hidden_data_under_mountpoint() {
    if !root() {
        return;
    }
    let parent = new_loop("fsvparent");
    let child = new_loop("fsvchild");
    let pm = mount(&parent.dev);
    let stray = pm.0.join("pool/downloads");
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(stray.join("movie.mkv"), vec![0u8; 3 << 20]).unwrap();
    let cm = mount_at(&child.dev, &pm.0.join("pool"));
    let before = run("findmnt", &["-rn", "-o", "TARGET"]);

    let h = start_helper(Config {
        allowed_uids: vec![0],
        version: "it".into(),
        ..Default::default()
    });
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (res, _): (Vec<HiddenResult>, _) = rt
        .block_on(call_as(
            &Client::new(&h.socket) as &dyn HelperApi,
            Request {
                op: OP_HIDDEN_SCAN.into(),
                params: params(&HiddenScanParams { all: true }),
                ..Default::default()
            },
        ))
        .unwrap();
    let want = cm.0.to_string_lossy().to_string();
    let hit = res
        .iter()
        .find(|r| r.mountpoint == want)
        .unwrap_or_else(|| panic!("hidden data not found: {res:?}"));
    assert_eq!(
        (hit.files, hit.bytes, hit.samples[0].name.as_str()),
        (1, 3 << 20, "downloads")
    );
    assert_eq!(
        run("findmnt", &["-rn", "-o", "TARGET"]),
        before,
        "scan leaked mounts into the host namespace"
    );
    drop(cm);
}

fn fstab_call(h: &Helper, op: &str, p: serde_json::Value, dry: bool) -> Response {
    call(
        h,
        Request {
            op: op.into(),
            actor: "it".into(),
            dry_run: dry,
            confirmed: !dry,
            params: p,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{op}: {} {}", e.code, e.msg))
}

/// fstab editor end to end on a temporary fstab: real findmnt --verify,
/// write with backup, mount from the written file, rollback. /etc/fstab
/// is never touched.
#[test]
fn fstab_edit_apply_and_rollback() {
    if !root() {
        return;
    }
    let real_before = std::fs::read("/etc/fstab").ok();
    let a = new_loop("fsvtest7");
    let dir = tempfile::tempdir().unwrap();
    let fstab_path = dir.path().join("fstab");
    let original = "# fsview integration test\n";
    std::fs::write(&fstab_path, original).unwrap();
    let mp = format!("/mnt/fsview-it-{}", std::process::id());
    let h = start_helper(Config {
        allowed_uids: vec![0],
        include_loop: true,
        writes_enabled: true,
        fstab_path: fstab_path.clone(),
        version: "it".into(),
        ..Default::default()
    });

    let st: FstabState =
        serde_json::from_value(fstab_call(&h, OP_FSTAB_READ, serde_json::Value::Null, true).result)
            .unwrap();
    assert_eq!(st.text, original);
    assert!(
        st.devices.iter().any(|d| d.path == a.dev),
        "{:?}",
        st.devices
    );

    let mut doc = st.doc.clone();
    doc.lines.push(fsview::fstab::Line::Entry {
        raw: String::new(),
        entry: fsview::fstab::FsEntry {
            spec: a.dev.clone(),
            file: mp.clone(),
            vfstype: "ext4".into(),
            options: "defaults,nofail".into(),
            freq: 0,
            passno: 2,
        },
    });
    let pv: FstabPreview = serde_json::from_value(
        fstab_call(
            &h,
            OP_FSTAB_PREVIEW,
            serde_json::json!({ "doc": doc }),
            true,
        )
        .result,
    )
    .unwrap();
    assert!(pv.can_apply, "{pv:#?}");
    assert_eq!(pv.create_dirs, vec![mp.clone()]);

    let dry = fstab_call(
        &h,
        OP_FSTAB_WRITE,
        serde_json::json!({"doc": doc, "base_sha256": st.sha256}),
        true,
    );
    assert!(
        dry.dry_run && dry.plan.iter().any(|p| p.contains(&mp)),
        "{dry:?}"
    );
    assert_eq!(std::fs::read_to_string(&fstab_path).unwrap(), original);

    fstab_call(
        &h,
        OP_FSTAB_WRITE,
        serde_json::json!({"doc": doc, "base_sha256": st.sha256}),
        false,
    );
    let _cleanup = Rmdir(mp.clone());
    let written = std::fs::read_to_string(&fstab_path).unwrap();
    assert!(
        written.starts_with(original) && written.contains(&mp),
        "{written}"
    );
    assert!(Path::new(&mp).is_dir(), "mountpoint created");

    // The written file is usable by mount(8).
    run("mount", &["-T", fstab_path.to_str().unwrap(), &mp]);
    let src = run("findmnt", &["-n", "-o", "SOURCE", &mp]);
    run("umount", &[&mp]);
    assert_eq!(src, a.dev);

    let st2: FstabState =
        serde_json::from_value(fstab_call(&h, OP_FSTAB_READ, serde_json::Value::Null, true).result)
            .unwrap();
    assert_eq!(st2.backups.len(), 1);
    fstab_call(
        &h,
        OP_FSTAB_ROLLBACK,
        serde_json::json!({"name": st2.backups[0].name, "base_sha256": st2.sha256}),
        false,
    );
    assert_eq!(std::fs::read_to_string(&fstab_path).unwrap(), original);

    let recs = AuditLog::open(&h.audit_path, None)
        .unwrap()
        .tail(10)
        .unwrap();
    let ops: Vec<(&str, &str)> = recs
        .iter()
        .map(|r| (r.op.as_str(), r.result.as_str()))
        .collect();
    assert_eq!(
        ops,
        vec![
            (OP_FSTAB_ROLLBACK, "ok"),
            (OP_FSTAB_WRITE, "ok"),
            (OP_FSTAB_WRITE, "dry-run")
        ]
    );
    assert_eq!(
        std::fs::read("/etc/fstab").ok(),
        real_before,
        "/etc/fstab changed"
    );
}

struct Rmdir(String);

impl Drop for Rmdir {
    fn drop(&mut self) {
        let _ = Command::new("umount").args(["-l", &self.0]).status();
        let _ = std::fs::remove_dir(&self.0);
    }
}
