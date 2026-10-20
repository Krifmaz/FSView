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
