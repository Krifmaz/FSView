use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::helperclient::{params, Client, HelperApi};
use crate::inventory::{mark_protected, parse_lsblk, Inventory, SystemInfo};
use crate::proto::*;
use crate::runner::{Fake, Output};

fn td(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/spiritlab")
            .join(name),
    )
    .unwrap()
}

struct T {
    srv: Arc<Server>,
    fake: Arc<Fake>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

impl T {
    fn audit(&self) -> Vec<AuditRecord> {
        self.srv.audit.as_ref().unwrap().tail(10).unwrap()
    }
}

fn server(writes: bool, responses: Vec<(&str, Output)>) -> T {
    let sys = tempfile::tempdir().unwrap();
    for d in ["sdb", "sdc"] {
        std::fs::create_dir_all(sys.path().join("block").join(d)).unwrap();
    }
    let ad = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(ad.path().join("audit.log"), None).unwrap();
    let fake = Arc::new(Fake::new(responses));
    let cfg = Config {
        writes_enabled: writes,
        sys_root: sys.path().into(),
        version: "test".into(),
        ..Default::default()
    };
    T {
        srv: Server::new(cfg, fake.clone(), Some(audit)),
        fake,
        _dirs: (sys, ad),
    }
}

fn req(op: &str, p: serde_json::Value) -> Request {
    Request {
        op: op.into(),
        actor: "admin".into(),
        client_ip: "192.168.1.10".into(),
        params: p,
        ..Default::default()
    }
}

#[test]
fn unknown_op_and_bad_device() {
    let t = server(true, vec![]);
    assert_eq!(
        t.srv.handle(&req("shell.exec", json!(null)), 1).code,
        CODE_UNKNOWN_OP
    );
    for dev in ["../../etc/passwd", "sdb; rm -rf /", "sdz", "loop0", "sda1"] {
        let r = t
            .srv
            .handle(&req(OP_SMART_GET, json!({ "device": dev })), 1);
        assert!(!r.ok && r.code == CODE_BAD_REQUEST, "{dev} accepted: {r:?}");
    }
    let r = t.srv.handle(
        &req(OP_SMART_GET, json!({"device": "sdb", "args": "-X"})),
        1,
    );
    assert_eq!(r.code, CODE_BAD_REQUEST, "unknown param accepted");
}

#[test]
fn writes_disabled_is_audited() {
    let t = server(false, vec![]);
    let mut r = req(OP_SMART_SELFTEST, json!({"device": "sdb", "test": "short"}));
    r.confirmed = true;
    assert_eq!(t.srv.handle(&r, 1000).code, CODE_WRITES_OFF);
    assert!(t.fake.calls().is_empty());
    let a = t.audit();
    assert_eq!(a.len(), 1);
    assert_eq!(
        (a[0].result.as_str(), a[0].actor.as_str(), a[0].peer_uid),
        ("rejected", "admin", 1000)
    );
}

#[test]
fn selftest_dry_run_confirm_and_run() {
    let t = server(
        true,
        vec![(
            "smartctl -t short /dev/sdb",
            Output {
                stdout: b"Testing has begun.".to_vec(),
                code: 4,
                ..Default::default()
            },
        )],
    );
    let mut r = req(OP_SMART_SELFTEST, json!({"device": "sdb", "test": "short"}));
    r.dry_run = true;
    let resp = t.srv.handle(&r, 1);
    assert!(
        resp.ok && resp.dry_run && resp.plan == vec!["smartctl -t short /dev/sdb"],
        "{resp:?}"
    );
    assert!(t.fake.calls().is_empty(), "dry run executed commands");
    r.dry_run = false;
    assert_eq!(t.srv.handle(&r, 1).code, CODE_NEED_CONFIRM);
    r.confirmed = true;
    assert!(t.srv.handle(&r, 1).ok);
    let a = t.audit();
    assert_eq!(
        a.iter().map(|x| x.result.as_str()).collect::<Vec<_>>(),
        ["ok", "rejected", "dry-run"]
    );
    assert_eq!(
        (a[0].commands[0].as_str(), a[0].targets[0].as_str()),
        ("smartctl -t short /dev/sdb", "sdb")
    );
    let mut bad = req(
        OP_SMART_SELFTEST,
        json!({"device": "sdb", "test": "conveyance; reboot"}),
    );
    bad.confirmed = true;
    assert_eq!(t.srv.handle(&bad, 1).code, CODE_BAD_REQUEST);
}

#[test]
fn smart_auto_sat() {
    let t = server(
        true,
        vec![
            (
                "smartctl -j -a -n standby /dev/sdb",
                Fake::ok(&td("smart_sdb_scsi.json")),
            ),
            (
                "smartctl -j -a -n standby -d sat /dev/sdb",
                Fake::ok(&td("smart_sdb_sat_synthetic.json")),
            ),
            (
                "smartctl -j -i /dev/sdb",
                Fake::ok(&td("smart_sdb_scsi.json")),
            ),
            (
                "smartctl -j -i -d sat /dev/sdb",
                Fake::ok(&td("smart_sdb_sat_synthetic.json")),
            ),
            ("smartctl -d sat -t long /dev/sdb", Fake::ok(b"ok")),
        ],
    );
    let resp = t
        .srv
        .handle(&req(OP_SMART_GET, json!({"device": "sdb"})), 1);
    let out: SmartGetResult = serde_json::from_value(resp.result).unwrap();
    assert_eq!(out.devtype, "sat");
    assert!(out.raw.to_string().contains("ST6000DM003"));
    t.fake.calls.lock().unwrap().clear();
    t.srv
        .handle(&req(OP_SMART_GET, json!({"device": "sdb"})), 1);
    let calls = t.fake.calls();
    assert!(calls.len() == 1 && calls[0].contains("-d sat"), "{calls:?}");
    let mut r = req(OP_SMART_SELFTEST, json!({"device": "sdb", "test": "long"}));
    r.confirmed = true;
    let resp = t.srv.handle(&r, 1);
    assert!(
        resp.ok && resp.plan[0] == "smartctl -d sat -t long /dev/sdb",
        "{resp:?}"
    );
}

/// Real spiritlab output: `smartctl -d sat /dev/sdb` answered with another
/// disk's identity. Pass-through must not be used then.
#[test]
fn smart_sat_serial_mismatch() {
    let t = server(
        true,
        vec![
            (
                "smartctl -j -a -n standby /dev/sdb",
                Fake::ok(&td("smart_sdb_scsi.json")),
            ),
            (
                "smartctl -j -a -n standby -d sat /dev/sdb",
                Output {
                    stdout: td("smart_ZXA0R1KK_sat.json"),
                    code: 64,
                    ..Default::default()
                },
            ),
            ("smartctl -t short /dev/sdb", Fake::ok(b"ok")),
        ],
    );
    let resp = t
        .srv
        .handle(&req(OP_SMART_GET, json!({"device": "sdb"})), 1);
    let out: SmartGetResult = serde_json::from_value(resp.result).unwrap();
    let raw = out.raw.to_string();
    assert!(
        out.devtype.is_empty()
            && raw.contains("ZCT1RSPR")
            && raw.contains("FSView: ATA pass-through")
    );
    let mut r = req(OP_SMART_SELFTEST, json!({"device": "sdb", "test": "short"}));
    r.confirmed = true;
    let resp = t.srv.handle(&r, 1);
    assert!(
        resp.ok && resp.plan[0] == "smartctl -t short /dev/sdb",
        "{resp:?}"
    );
}

/// If the bridge starts misrouting after detection, writes are refused.
#[test]
fn selftest_reverifies_pass_through() {
    let t = server(
        true,
        vec![
            (
                "smartctl -j -a -n standby /dev/sdb",
                Fake::ok(&td("smart_sdb_scsi.json")),
            ),
            (
                "smartctl -j -a -n standby -d sat /dev/sdb",
                Fake::ok(&td("smart_sdb_sat_synthetic.json")),
            ),
            (
                "smartctl -j -i /dev/sdb",
                Fake::ok(&td("smart_sdb_scsi.json")),
            ),
            (
                "smartctl -j -i -d sat /dev/sdb",
                Fake::ok(&td("smart_ZXA0R1KK_sat.json")),
            ),
        ],
    );
    t.srv
        .handle(&req(OP_SMART_GET, json!({"device": "sdb"})), 1);
    assert_eq!(t.srv.cached_smart_type("sdb"), "sat");
    let mut r = req(OP_SMART_SELFTEST, json!({"device": "sdb", "test": "short"}));
    r.confirmed = true;
    let resp = t.srv.handle(&r, 1);
    assert!(!resp.ok && resp.error.contains("ZXA0R1KK"), "{resp:?}");
    assert!(t.fake.calls().iter().all(|c| !c.contains(" -t ")));
}

#[test]
fn destructive_checks() {
    let mut disks = parse_lsblk(&td("lsblk.json"), false).unwrap();
    mark_protected(&mut disks, &SystemInfo::default(), &|p: &str| {
        p.rsplit('/').next().unwrap().to_string()
    });
    let inv = Inventory {
        disks,
        ..Default::default()
    };
    let t = |v: &str| vec![v.to_string()];
    assert!(check_destructive(&inv, &t("nvme0n1"), "nvme0n1", true)
        .unwrap_err()
        .contains("protected"));
    assert!(
        check_destructive(&inv, &t("nvme0n1"), "", false).is_err(),
        "protected disk allowed in dry run"
    );
    assert!(check_destructive(&inv, &t("sdi"), "", true).is_err());
    assert!(check_destructive(&inv, &t("sdi"), "media2", true).is_err());
    for ok in ["sdi", "media1", " media1 "] {
        assert!(check_destructive(&inv, &t("sdi"), ok, true).is_ok(), "{ok}");
    }
    assert!(
        check_destructive(&inv, &t("sda"), "cache", true).is_ok(),
        "partition label"
    );
}

#[test]
fn hidden_scan_plan() {
    let jobs = plan_hidden_scan(&td("findmnt.json"), true).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].parent, "/");
    for want in ["/boot/efi", "/mnt/cache", "/etc/pve", "/sys", "/tmp"] {
        assert!(jobs[0].children.iter().any(|c| c == want), "missing {want}");
    }
    assert_eq!(
        plan_hidden_scan(&td("findmnt.json"), false).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn socket_peer_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let me = nix::unistd::getuid().as_raw();
    for (i, (uids, ok)) in [(vec![me], true), (vec![424242], false)]
        .into_iter()
        .enumerate()
    {
        let sock = dir.path().join(format!("h{i}.sock"));
        let cfg = Config {
            socket: sock.clone(),
            allowed_uids: uids,
            version: "t".into(),
            ..Default::default()
        };
        let srv = Server::new(cfg, Arc::new(Fake::default()), None);
        let l = srv.listen().unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let h = tokio::spawn(srv.serve(l, async {
            let _ = rx.await;
        }));
        let c = Client::new(&sock);
        let r = c
            .call(Request {
                op: OP_STATUS.into(),
                params: params(&()),
                ..Default::default()
            })
            .await;
        if ok {
            let resp = r.unwrap();
            assert_eq!(resp.result["version"], "t");
        } else {
            assert_eq!(r.unwrap_err().code, CODE_NOT_PERMITTED);
        }
        let _ = tx.send(());
        h.await.unwrap();
    }
}

// ---- fstab editor ----

struct FsT {
    t: T,
    fstab: std::path::PathBuf,
    backups: std::path::PathBuf,
    _d: tempfile::TempDir,
}

const FSTAB0: &str =
    "# test fstab\nUUID=c69cfb3b-4f39-449a-bb21-cd2e4ba23d49 /tmp ext4 defaults,nofail 0 2\n";

fn fstab_server(writes: bool) -> FsT {
    let d = tempfile::tempdir().unwrap();
    let fstab = d.path().join("fstab");
    std::fs::write(&fstab, FSTAB0).unwrap();
    let verify_key = format!(
        "findmnt --verify --verbose --tab-file {}",
        d.path().join("fstab.verify").display()
    );
    let lsblk_key = format!("lsblk {}", crate::inventory::LSBLK_ARGS.join(" "));
    let mut t = server(
        writes,
        vec![
            (lsblk_key.as_str(), Fake::ok(&td("lsblk.json"))),
            (
                "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS",
                Fake::ok(&td("findmnt.json")),
            ),
            (
                verify_key.as_str(),
                Fake::ok(b"0 parse errors, 0 errors, 0 warnings\n"),
            ),
            ("systemctl daemon-reload", Fake::ok(b"")),
        ],
    );
    let mut cfg = t.srv.cfg.clone();
    cfg.fstab_path = fstab.clone();
    cfg.backup_dir = d.path().join("backups");
    cfg.scratch_dir = d.path().into();
    let audit = AuditLog::open(d.path().join("audit.log"), None).unwrap();
    t.srv = Server::new(cfg, t.fake.clone(), Some(audit));
    FsT {
        t,
        backups: d.path().join("backups"),
        fstab,
        _d: d,
    }
}

fn edited_doc(state: &FstabState, options: &str, file: &str) -> crate::fstab::Doc {
    let mut doc = state.doc.clone();
    for l in doc.lines.iter_mut() {
        if let crate::fstab::Line::Entry { entry, .. } = l {
            entry.options = options.into();
            entry.file = file.into();
        }
    }
    doc
}

fn write_req(doc: &crate::fstab::Doc, sha: &str, dry: bool, confirmed: bool) -> Request {
    let mut r = req(OP_FSTAB_WRITE, json!({"doc": doc, "base_sha256": sha}));
    r.dry_run = dry;
    r.confirmed = confirmed;
    r
}

#[test]
fn fstab_write_and_rollback() {
    let f = fstab_server(true);
    let r = f.t.srv.handle(&req(OP_FSTAB_READ, json!(null)), 1);
    assert!(r.ok, "{r:?}");
    let st: FstabState = serde_json::from_value(r.result).unwrap();
    assert_eq!(st.text, FSTAB0);
    assert!(
        st.issues.iter().all(|i| i.level != "error"),
        "{:?}",
        st.issues
    );
    let doc = edited_doc(&st, "defaults,nofail,x-systemd.device-timeout=5min", "/tmp");

    // Preview shows the diff and passes.
    let r =
        f.t.srv
            .handle(&req(OP_FSTAB_PREVIEW, json!({ "doc": doc })), 1);
    let pv: FstabPreview = serde_json::from_value(r.result).unwrap();
    assert!(pv.can_apply && pv.changed, "{pv:?}");
    assert_eq!(pv.diff.iter().filter(|l| l.op != " ").count(), 2);

    // Stale base is refused.
    let r = f.t.srv.handle(&write_req(&doc, "deadbeef", false, true), 1);
    assert_eq!(r.code, CODE_BAD_REQUEST);
    assert!(r.error.contains("changed since"), "{}", r.error);

    // Dry run changes nothing and shows the plan.
    let r = f.t.srv.handle(&write_req(&doc, &st.sha256, true, false), 1);
    assert!(r.ok && r.dry_run, "{r:?}");
    assert!(r.plan[0].starts_with("cp --preserve=mode"), "{:?}", r.plan);
    assert!(r.plan.iter().any(|p| p.starts_with("write ")));
    assert!(r.result["output"]
        .as_str()
        .unwrap()
        .contains("+UUID=c69cfb3b"));
    assert_eq!(std::fs::read_to_string(&f.fstab).unwrap(), FSTAB0);
    assert!(!f.backups.exists());

    // Unconfirmed is refused.
    let r =
        f.t.srv
            .handle(&write_req(&doc, &st.sha256, false, false), 1);
    assert_eq!(r.code, CODE_NEED_CONFIRM);

    // Confirmed: backup, then atomic write.
    let r = f.t.srv.handle(&write_req(&doc, &st.sha256, false, true), 1);
    assert!(r.ok, "{r:?}");
    let new = std::fs::read_to_string(&f.fstab).unwrap();
    assert!(new.contains("x-systemd.device-timeout=5min"), "{new}");
    assert!(new.starts_with("# test fstab\n"), "comment kept");
    let backups: Vec<_> = std::fs::read_dir(&f.backups).unwrap().flatten().collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), FSTAB0);
    let a = f.t.audit();
    let last = &a[0];
    assert_eq!(last.result, "ok");
    assert_eq!(last.actor, "admin");
    assert!(last.output.contains("-UUID=c69cfb3b"), "{}", last.output);

    // Same document again: nothing to apply.
    let r = f.t.srv.handle(&req(OP_FSTAB_READ, json!(null)), 1);
    let st2: FstabState = serde_json::from_value(r.result).unwrap();
    assert_eq!(st2.backups.len(), 1);
    let r =
        f.t.srv
            .handle(&write_req(&st2.doc, &st2.sha256, false, true), 1);
    assert!(r.error.contains("no changes"), "{r:?}");

    // Backup view and rollback.
    let name = st2.backups[0].name.clone();
    let r =
        f.t.srv
            .handle(&req(OP_FSTAB_BACKUP, json!({ "name": name })), 1);
    let bv: FstabBackupView = serde_json::from_value(r.result).unwrap();
    assert_eq!(bv.text, FSTAB0);
    for bad_name in ["../fstab", "fstab.x", "/etc/fstab"] {
        let r =
            f.t.srv
                .handle(&req(OP_FSTAB_BACKUP, json!({ "name": bad_name })), 1);
        assert_eq!(r.code, CODE_BAD_REQUEST, "{bad_name}");
    }
    let mut rb = req(
        OP_FSTAB_ROLLBACK,
        json!({"name": name, "base_sha256": st2.sha256}),
    );
    rb.confirmed = true;
    let r = f.t.srv.handle(&rb, 1);
    assert!(r.ok, "{r:?}");
    assert_eq!(std::fs::read_to_string(&f.fstab).unwrap(), FSTAB0);
    assert_eq!(
        std::fs::read_dir(&f.backups).unwrap().count(),
        2,
        "rollback backs up the current file too"
    );
}

#[test]
fn fstab_write_rejects_errors_and_disabled_writes() {
    let f = fstab_server(true);
    let r = f.t.srv.handle(&req(OP_FSTAB_READ, json!(null)), 1);
    let st: FstabState = serde_json::from_value(r.result).unwrap();
    let doc = edited_doc(&st, "defaults,nofail", "relative/path");
    let r = f.t.srv.handle(&write_req(&doc, &st.sha256, false, true), 1);
    assert_eq!(r.code, CODE_BAD_REQUEST);
    assert!(r.error.contains("absolute path"), "{}", r.error);
    assert_eq!(std::fs::read_to_string(&f.fstab).unwrap(), FSTAB0);
    assert_eq!(f.t.audit()[0].result, "rejected");

    let f = fstab_server(false);
    let doc = edited_doc(&st, "defaults,nofail,noatime", "/tmp");
    let r = f.t.srv.handle(&write_req(&doc, &st.sha256, false, true), 1);
    assert_eq!(r.code, CODE_WRITES_OFF);
    assert_eq!(std::fs::read_to_string(&f.fstab).unwrap(), FSTAB0);
    // Reads still work with writes disabled.
    assert!(f.t.srv.handle(&req(OP_FSTAB_READ, json!(null)), 1).ok);
}

#[test]
fn fstab_write_detects_concurrent_change() {
    let f = fstab_server(true);
    let r = f.t.srv.handle(&req(OP_FSTAB_READ, json!(null)), 1);
    let st: FstabState = serde_json::from_value(r.result).unwrap();
    std::fs::write(&f.fstab, "# someone else\n").unwrap();
    let doc = edited_doc(&st, "defaults,nofail,noatime", "/tmp");
    let r = f.t.srv.handle(&write_req(&doc, &st.sha256, false, true), 1);
    assert_eq!(r.code, CODE_BAD_REQUEST);
    assert_eq!(
        std::fs::read_to_string(&f.fstab).unwrap(),
        "# someone else\n"
    );
}

// ---- mounts and filesystems ----

fn storage_req(op: &str, p: serde_json::Value, dry: bool, confirm: &str) -> Request {
    let mut r = req(op, p);
    r.dry_run = dry;
    r.confirmed = !dry;
    r.confirm_text = confirm.into();
    r
}

#[test]
fn umount_rules() {
    let f = fstab_server(true);
    for (t, frag) in [
        ("/", "system mount"),
        ("/boot/efi", "system mount"),
        ("/proc", "system mount"),
        ("/mnt/nothere", "not mounted"),
        ("relative", "absolute"),
    ] {
        let r =
            f.t.srv
                .handle(&storage_req(OP_UMOUNT, json!({ "target": t }), true, ""), 1);
        assert!(
            r.code == CODE_BAD_REQUEST && r.error.contains(frag),
            "{t}: {r:?}"
        );
    }
    let r = f.t.srv.handle(
        &storage_req(OP_UMOUNT, json!({"target": "/mnt/cache"}), true, ""),
        1,
    );
    assert!(r.ok && r.plan[0] == "umount /mnt/cache", "{r:?}");
    // The empty mountpoint is then protected against stray writes.
    if tool_exists_for_test("chattr") {
        assert_eq!(r.plan[1..], ["chattr +i /mnt/cache"], "{r:?}");
    }
}

#[test]
fn format_rules() {
    let f = fstab_server(true);
    // Protected (root VG) or in use: always refused.
    for dev in ["nvme0n1", "nvme0n1p2"] {
        let r = f.t.srv.handle(
            &storage_req(
                OP_FS_FORMAT,
                json!({"device": dev, "fstype": "ext4", "label": "x"}),
                false,
                dev,
            ),
            1,
        );
        assert!(!r.ok, "{dev} formatted: {r:?}");
        assert!(
            r.code == CODE_PROTECTED || r.error.contains("in use") || r.error.contains("used by"),
            "{dev}: {r:?}"
        );
    }
    // Mounted cache partition.
    let r = f.t.srv.handle(
        &storage_req(
            OP_FS_FORMAT,
            json!({"device": "sda1", "fstype": "ext4", "label": "x"}),
            true,
            "",
        ),
        1,
    );
    assert!(r.error.contains("in use"), "{r:?}");
    for bad_label in ["", "a b", "x;reboot"] {
        let r = f.t.srv.handle(
            &storage_req(
                OP_FS_FORMAT,
                json!({"device": "sdc", "fstype": "ext4", "label": bad_label}),
                true,
                "",
            ),
            1,
        );
        assert_eq!(r.code, CODE_BAD_REQUEST, "{bad_label:?}");
    }
    if !tool_exists_for_test("mkfs.ext4") || !tool_exists_for_test("wipefs") {
        return;
    }
    let p = json!({"device": "sdc", "fstype": "ext4", "label": "media3"});
    let r =
        f.t.srv
            .handle(&storage_req(OP_FS_FORMAT, p.clone(), true, ""), 1);
    assert!(r.ok && r.dry_run, "{r:?}");
    assert_eq!(r.plan[0], "wipefs -a /dev/sdc");
    assert!(
        r.plan
            .iter()
            .any(|c| c == "mkfs.ext4 -F -L media3 /dev/sdc"),
        "{:?}",
        r.plan
    );
    let r =
        f.t.srv
            .handle(&storage_req(OP_FS_FORMAT, p.clone(), false, ""), 1);
    assert_eq!(r.code, CODE_NEED_CONFIRM);
    let r =
        f.t.srv
            .handle(&storage_req(OP_FS_FORMAT, p, false, "sdd"), 1);
    assert_eq!(r.code, CODE_NEED_CONFIRM, "wrong disk name accepted");
    assert!(
        !f.t.fake
            .calls()
            .iter()
            .any(|c| c.starts_with("wipefs") || c.starts_with("mkfs")),
        "nothing may run without confirmation: {:?}",
        f.t.fake.calls()
    );
}

#[test]
fn label_rules() {
    let f = fstab_server(true);
    let r = f.t.srv.handle(
        &storage_req(
            OP_FS_LABEL,
            json!({"device": "nvme0n1p2", "label": "x"}),
            true,
            "",
        ),
        1,
    );
    assert!(r.error.contains("protected"), "{r:?}");
    std::fs::write(
        &f.fstab,
        "LABEL=media3 /mnt/media3 ext4 defaults,nofail 0 2\n",
    )
    .unwrap();
    let r = f.t.srv.handle(
        &storage_req(
            OP_FS_LABEL,
            json!({"device": "sdc", "label": "media9"}),
            true,
            "",
        ),
        1,
    );
    assert!(r.error.contains("by its label"), "{r:?}");
    std::fs::write(&f.fstab, "# none\n").unwrap();
    if tool_exists_for_test("e2label") {
        let r = f.t.srv.handle(
            &storage_req(
                OP_FS_LABEL,
                json!({"device": "sdc", "label": "media9"}),
                true,
                "",
            ),
            1,
        );
        assert!(r.ok && r.plan[0] == "e2label /dev/sdc media9", "{r:?}");
    }
}

fn tool_exists_for_test(t: &str) -> bool {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .any(|d| std::path::Path::new(d).join(t).exists())
}

#[test]
fn mount_requires_fstab_entry_and_pool_branches() {
    let f = fstab_server(true);
    std::fs::write(
        &f.fstab,
        "/mnt/b1:/mnt/b2 /mnt/pool fuse.mergerfs defaults,nofail 0 0\nUUID=x /mnt/b1 ext4 defaults,nofail 0 2\n",
    )
    .unwrap();
    let r = f.t.srv.handle(
        &storage_req(OP_MOUNT, json!({"target": "/mnt/other"}), true, ""),
        1,
    );
    assert!(r.error.contains("not in"), "{r:?}");
    if tool_exists_for_test("mergerfs") {
        let r = f.t.srv.handle(
            &storage_req(OP_MOUNT, json!({"target": "/mnt/pool"}), true, ""),
            1,
        );
        assert!(r.error.contains("/mnt/b1 which is not mounted"), "{r:?}");
    }
}

#[test]
fn protect_mountpoints_plan() {
    if !tool_exists_for_test("chattr") {
        return;
    }
    let f = fstab_server(true);
    std::fs::write(
        &f.t.srv.cfg.fstab_path,
        "UUID=x /mnt/cache ext4 defaults,nofail 0 2\n/mnt/cache /mnt/pool fuse.mergerfs allow_other 0 0\n",
    )
    .unwrap();
    let r =
        f.t.srv
            .handle(&storage_req(OP_PROTECT_MOUNTPOINTS, json!({}), true, ""), 1);
    assert!(r.ok, "{r:?}");
    assert!(
        r.plan.iter().any(|l| l.starts_with("mount --bind / ")),
        "{r:?}"
    );
    assert!(
        r.plan
            .iter()
            .any(|l| l.starts_with("chattr +i ") && l.ends_with("/mnt/cache")),
        "{r:?}"
    );
    assert!(r.plan.iter().any(|l| l.ends_with("/mnt/pool")), "{r:?}");
    assert!(r.plan.last().unwrap().starts_with("umount "), "{r:?}");
}

/// A pool of two branches: media2 (sdb, healthy apart from 8 remapped
/// sectors) and media1 (sdi, shut down by the kernel after an aborted
/// journal, and SMART shows pending and uncorrectable sectors).
fn pool_health_server(stop: &[&str], post: &[&str]) -> (FsT, tempfile::TempDir) {
    let f = fstab_server(true);
    let d = tempfile::tempdir().unwrap();
    let mounts = d.path().join("mounts");
    std::fs::write(
        &mounts,
        "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n\
         /dev/sdb /mnt/media2 ext4 rw,relatime 0 0\n\
         /dev/sdi /mnt/media1 ext4 ro,relatime,emergency_ro 0 0\n\
         mergerfs-pool /mnt/pool fuse.mergerfs rw,nosuid,nodev,allow_other 0 0\n",
    )
    .unwrap();
    std::fs::write(
        &f.fstab,
        "/mnt/media2:/mnt/media1 /mnt/pool fuse.mergerfs defaults,allow_other,category.create=mfs,nofail 0 0\n\
         UUID=a /mnt/media2 ext4 defaults,nofail 0 2\n\
         UUID=b /mnt/media1 ext4 defaults,nofail 0 2\n",
    )
    .unwrap();
    let dev = d.path().join("dev");
    std::fs::create_dir_all(&dev).unwrap();
    for n in ["sdb", "sdi"] {
        std::fs::write(dev.join(n), b"").unwrap();
    }
    let journal = [
        (1000, "s=1", "sd 2:0:9:0: [sdi] attempting task abort!scmd(0x1)"),
        (1200, "s=2", "mpt2sas_cm0: log_info(0x31110d00): originator(PL), code(0x11)"),
        (1500, "s=3", "EXT4-fs error (device sdi): ext4_journal_check_start:86: comm kworker: Detected aborted journal"),
        (1501, "s=4", "EXT4-fs (sdi): Remounting filesystem read-only"),
    ]
    .iter()
    .map(|(t, c, m)| {
        json!({"__CURSOR": c, "__REALTIME_TIMESTAMP": (t * 1_000_000i64).to_string(),
               "__MONOTONIC_TIMESTAMP": "1", "_BOOT_ID": "b", "PRIORITY": "3", "MESSAGE": m})
        .to_string()
    })
    .collect::<Vec<_>>()
    .join("\n");
    let fake = &f.t.fake;
    let mut r = fake.responses.lock().unwrap();
    let mut put = |k: &str, o: Output| {
        r.insert(k.to_string(), o);
    };
    put(
        "getfattr --only-values -n user.mergerfs.branches /mnt/pool/.mergerfs",
        Fake::ok(b"/mnt/media2=RW:/mnt/media1=RO"),
    );
    put(
        "getfattr --only-values -n user.mergerfs.fullpath /mnt/pool/music/a.flac",
        Fake::ok(b"/mnt/media2/music/a.flac"),
    );
    put(
        "journalctl -k -b -o json --no-pager -n 200000",
        Fake::ok(journal.as_bytes()),
    );
    for (disk, scsi, sat) in [
        ("sdb", "smart_sdb_scsi.json", "smart_sdb_sat_synthetic.json"),
        ("sdi", "smart_sdi_scsi.json", "smart_ZXA0R1KK_sat.json"),
    ] {
        for wake in ["", " -n standby"] {
            put(
                &format!("smartctl -j -a{wake} /dev/{disk}"),
                Fake::ok(&td(scsi)),
            );
            put(
                &format!("smartctl -j -a{wake} -d sat /dev/{disk}"),
                Fake::ok(&td(sat)),
            );
        }
    }
    drop(r);
    let mut cfg = f.t.srv.cfg.clone();
    cfg.mounts_file = mounts;
    cfg.dev_dir = dev;
    cfg.repair_stop = stop
        .iter()
        .map(|c| crate::config::commands(c).remove(0))
        .collect();
    cfg.repair_post = post
        .iter()
        .map(|c| crate::config::commands(c).remove(0))
        .collect();
    let audit = AuditLog::open(d.path().join("audit.log"), None).unwrap();
    let srv = Server::new(cfg, f.t.fake.clone(), Some(audit));
    let f = FsT {
        t: T {
            srv,
            fake: f.t.fake.clone(),
            _dirs: f.t._dirs,
        },
        ..f
    };
    (f, d)
}

#[test]
fn pool_health_flags_branches() {
    use crate::poolhealth::{FlagKind, PoolHealth};
    let (f, _d) = pool_health_server(&[], &[]);
    let r = f.t.srv.handle(&req(OP_POOL_HEALTH, json!({})), 1);
    assert!(r.ok, "{r:?}");
    let pools: Vec<PoolHealth> = serde_json::from_value(r.result).unwrap();
    assert_eq!(pools.len(), 1);
    let p = &pools[0];
    assert_eq!(p.mountpoint, "/mnt/pool");
    let (m2, m1) = (&p.branches[0], &p.branches[1]);

    assert_eq!((m2.path.as_str(), m2.disk.as_str()), ("/mnt/media2", "sdb"));
    let k2: Vec<FlagKind> = m2.flags.iter().map(|f| f.kind).collect();
    assert_eq!(k2, [FlagKind::SmartReallocated], "{:?}", m2.flags);
    assert!(!m2.read_only());
    assert_eq!(m2.repair_blocker, "", "media2 can be repaired");

    let k1: Vec<FlagKind> = m1.flags.iter().map(|f| f.kind).collect();
    for k in [
        FlagKind::BranchRo,
        FlagKind::EmergencyRo,
        FlagKind::Ext4Errors,
        FlagKind::SmartUncorrected,
    ] {
        assert!(k1.contains(&k), "{k:?} missing: {:?}", m1.flags);
    }
    assert!(m1.read_only());
    assert_eq!(m1.ext4_error_count, 2);
    // the reset and the controller message before the first error
    assert_eq!(m1.trigger.len(), 2);
    assert!(m1.trigger[0].message.contains("task abort"));
    assert!(
        m1.repair_blocker.contains("uncorrected"),
        "{}",
        m1.repair_blocker
    );

    // the watcher skips SMART
    let r =
        f.t.srv
            .handle(&req(OP_POOL_HEALTH, json!({"skip_smart": true})), 1);
    let pools: Vec<PoolHealth> = serde_json::from_value(r.result).unwrap();
    assert!(pools[0].branches[1].read_only());
    assert!(pools[0].branches[1].smart.is_none());
}

#[test]
fn pool_locate_file() {
    let (f, _d) = pool_health_server(&[], &[]);
    let r = f.t.srv.handle(
        &req(
            OP_POOL_LOCATE,
            json!({"pool": "/mnt/pool", "path": "/mnt/pool/music/a.flac"}),
        ),
        1,
    );
    assert!(r.ok, "{r:?}");
    let l: PoolLocateResult = serde_json::from_value(r.result).unwrap();
    assert_eq!(l.fullpath, "/mnt/media2/music/a.flac");
    assert_eq!(l.branch, "/mnt/media2");
    for (pool, path, frag) in [
        ("/mnt/pool", "../etc/shadow", ".."),
        ("/mnt/pool", "/etc/passwd", "not inside"),
        ("/mnt/nopool", "a", "not a mounted"),
        ("/mnt/pool", "missing.flac", "not found"),
    ] {
        let r =
            f.t.srv
                .handle(&req(OP_POOL_LOCATE, json!({"pool": pool, "path": path})), 1);
        assert!(!r.ok && r.error.contains(frag), "{path}: {r:?}");
    }
}

#[test]
fn pool_repair_rules_and_plan() {
    if !tool_exists_for_test("fsck.ext4") {
        return;
    }
    let (f, _d) = pool_health_server(&["pct exec 200 -- docker stop encore"], &["pct reboot 200"]);
    let repair = |branch: &str, dry: bool, confirm: &str| {
        f.t.srv.handle(
            &storage_req(
                OP_POOL_REPAIR,
                json!({"pool": "/mnt/pool", "branch": branch}),
                dry,
                confirm,
            ),
            1,
        )
    };
    // SMART shows pending/uncorrectable sectors on sdi: refused
    let r = repair("/mnt/media1", true, "sdi");
    assert!(!r.ok && r.error.contains("could not correct"), "{r:?}");
    // not a branch
    let r = repair("/mnt/other", true, "sdb");
    assert!(!r.ok && r.error.contains("not a branch"), "{r:?}");
    // destructive: the confirmation must name the disk
    let r = repair("/mnt/media2", false, "wrong");
    assert!(!r.ok && r.error.contains("confirmation"), "{r:?}");

    let r = repair("/mnt/media2", true, "");
    assert!(r.ok, "{r:?}");
    let plan = &r.plan;
    assert_eq!(
        plan[0],
        "pct exec 200 -- docker stop encore (errors ignored)"
    );
    assert_eq!(plan[1], "umount /mnt/pool");
    assert_eq!(plan[2], "umount /mnt/media2");
    assert_eq!(plan[3], "fsck.ext4 -f -y /dev/sdb");
    assert!(
        plan[4].ends_with(&format!("mount -T {} /mnt/media2", f.fstab.display())),
        "{}",
        plan[4]
    );
    assert!(
        plan[5].ends_with(
            "mergerfs -o allow_other,category.create=mfs /mnt/media2:/mnt/media1 /mnt/pool"
        ),
        "{}",
        plan[5]
    );
    assert_eq!(plan[6], "pct reboot 200 (errors ignored)");
    assert_eq!(plan.len(), 7);

    // run it: fsck exit 1 (errors fixed) is success; the post command has
    // no fake answer (fails) and is ignored
    let fake = &f.t.fake;
    {
        let mut r = fake.responses.lock().unwrap();
        for k in [
            "pct exec 200 -- docker stop encore",
            "umount /mnt/pool",
            "umount /mnt/media2",
        ] {
            r.insert(k.into(), Fake::ok(b""));
        }
        r.insert(
            "fsck.ext4 -f -y /dev/sdb".into(),
            Output {
                code: 1,
                stdout: b"media2: ***** FILE SYSTEM WAS MODIFIED *****\n".to_vec(),
                ..Default::default()
            },
        );
        for line in &plan[4..6] {
            r.insert(line.clone(), Fake::ok(b""));
        }
    }
    let r = repair("/mnt/media2", false, "media2");
    assert!(r.ok, "{r:?}");
    let calls = fake.calls();
    let i = |c: &str| {
        calls
            .iter()
            .position(|x| x == c)
            .unwrap_or_else(|| panic!("{c} not run: {calls:?}"))
    };
    assert!(i("umount /mnt/pool") < i("umount /mnt/media2"));
    assert!(i("umount /mnt/media2") < i("fsck.ext4 -f -y /dev/sdb"));
    assert!(i("fsck.ext4 -f -y /dev/sdb") < i("pct reboot 200"));
    let rec = f.t.srv.audit.as_ref().unwrap().tail(1).unwrap().remove(0);
    assert_eq!(rec.result, "ok");
    assert!(rec.output.contains("FILE SYSTEM WAS MODIFIED"));
    assert!(
        rec.output.contains("pct exit status") || rec.output.contains("continuing"),
        "{}",
        rec.output
    );
}

#[test]
fn pool_repair_logs_trigger() {
    if !tool_exists_for_test("fsck.ext4") {
        return;
    }
    // media1's trigger is logged even though its repair is refused later;
    // check the detail on a repairable branch with errors instead
    let (f, d) = pool_health_server(&[], &[]);
    std::fs::write(
        d.path().join("mounts"),
        "/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/sdb /mnt/media2 ext4 rw 0 0\n/dev/sdi /mnt/media1 ext4 rw 0 0\nmergerfs-pool /mnt/pool fuse.mergerfs rw 0 0\n",
    )
    .unwrap();
    // journal errors are on sdi; give sdb its own error
    let line = json!({"__CURSOR": "s=9", "__REALTIME_TIMESTAMP": "1700000000", "__MONOTONIC_TIMESTAMP": "1",
        "_BOOT_ID": "b", "PRIORITY": "3", "MESSAGE": "EXT4-fs error (device sdb): ext4_lookup: deleted inode referenced"});
    let reset = json!({"__CURSOR": "s=8", "__REALTIME_TIMESTAMP": "1690000000", "__MONOTONIC_TIMESTAMP": "1",
        "_BOOT_ID": "b", "PRIORITY": "4", "MESSAGE": "sd 2:0:3:0: [sdb] tag#9 timing out command, waited 180s"});
    f.t.fake.responses.lock().unwrap().insert(
        "journalctl -k -b -o json --no-pager -n 200000".into(),
        Fake::ok(format!("{reset}\n{line}\n").as_bytes()),
    );
    let r = f.t.srv.handle(
        &storage_req(
            OP_POOL_REPAIR,
            json!({"pool": "/mnt/pool", "branch": "/mnt/media2"}),
            true,
            "",
        ),
        1,
    );
    assert!(r.ok, "{r:?}");
    let out = r.result["output"].as_str().unwrap();
    assert!(out.contains("First ext4 error"), "{out}");
    assert!(out.contains("timing out command"), "{out}");
    assert!(out.contains("No stop commands are configured"), "{out}");
}
