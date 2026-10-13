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
