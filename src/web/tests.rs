use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request as HttpRequest, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::helperclient::{CallFuture, HelperApi, HelperError};
use crate::inventory::{mark_protected, parse_lsblk, SystemInfo};
use crate::netutil::Prefix;
use crate::store::Store;

fn fx(n: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/spiritlab")
            .join(n),
    )
    .unwrap()
}

#[derive(Default)]
struct FakeHelper {
    writes: Mutex<bool>,
    reqs: Mutex<Vec<Request>>,
}

impl HelperApi for FakeHelper {
    fn call(&self, req: Request) -> CallFuture<'_> {
        self.reqs.lock().unwrap().push(req.clone());
        let writes = *self.writes.lock().unwrap();
        Box::pin(async move {
            let e = |code: &str, msg: &str| {
                Err(HelperError {
                    code: code.into(),
                    msg: msg.into(),
                    plan: vec![],
                })
            };
            let mut resp = Response {
                ok: true,
                ..Default::default()
            };
            resp.result = match req.op.as_str() {
                OP_INVENTORY => {
                    let mut disks = parse_lsblk(&fx("lsblk.json"), false).unwrap();
                    mark_protected(&mut disks, &SystemInfo::default(), &|p: &str| p.rsplit('/').next().unwrap().to_string());
                    serde_json::to_value(crate::inventory::Inventory { hostname: "spiritlab".into(), disks, ..Default::default() }).unwrap()
                }
                OP_SMART_GET => match req.params["device"].as_str() {
                    Some("sdc") => json!({"device": "sdc", "devtype": "", "exit_status": 0, "standby": false, "raw": serde_json::from_slice::<Value>(&fx("smart_sdc_scsi.json")).unwrap()}),
                    Some("sdb") => json!({"device": "sdb", "devtype": "sat", "exit_status": 0, "standby": false, "raw": serde_json::from_slice::<Value>(&fx("smart_sdb_sat_synthetic.json")).unwrap()}),
                    _ => return e(CODE_EXEC_FAILED, "no data"),
                },
                OP_SMART_SELFTEST => {
                    if !writes {
                        return e(CODE_WRITES_OFF, "writes disabled");
                    }
                    resp.dry_run = req.dry_run;
                    resp.plan = vec!["smartctl -d sat -t short /dev/sdb".into()];
                    json!({"summary": "x"})
                }
                OP_JOURNAL_KERNEL => serde_json::to_value(crate::events::parse_json_lines(
                    br#"{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1791851200000000","__MONOTONIC_TIMESTAMP":"1270000000","PRIORITY":"3","MESSAGE":"I/O error, dev sdc, sector 1"}"#,
                ))
                .unwrap(),
                OP_HIDDEN_SCAN => json!([{"mountpoint": "/mnt/drivepool", "parent": "/", "parent_source": "/dev/mapper/pve-root", "files": 22, "bytes": 78000430137u64, "samples": [{"name": "downloads", "bytes": 78000430137u64}]}]),
                OP_STATUS => json!({"version": "t", "hostname": "h", "writes_enabled": writes, "boot_id": "", "tools": {}}),
                _ => json!({}),
            };
            Ok(resp)
        })
    }
}

struct T {
    app: Arc<App>,
    helper: Arc<FakeHelper>,
    _dir: tempfile::TempDir,
}

fn setup() -> T {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    store.set_password("admin", "supersecret1", true).unwrap();
    let helper = Arc::new(FakeHelper::default());
    let opt = Options {
        version: "t".into(),
        allow: vec![
            Prefix::parse("192.168.1.0/24").unwrap(),
            Prefix::parse("100.64.0.0/10").unwrap(),
        ],
        ..Default::default()
    };
    T {
        app: App::new(opt, store, helper.clone()),
        helper,
        _dir: dir,
    }
}

async fn send(
    t: &T,
    method: &str,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    csrf: bool,
    remote: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut b = HttpRequest::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "fsview.lan:9200");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, format!("fsview_session={c}"));
    }
    if csrf {
        b = b.header("x-fsview-request", "1");
    }
    let mut req = b.body(Body::from(body.to_string())).unwrap();
    let addr: SocketAddr = remote.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(PeerAddr(addr)));
    let res = router(t.app.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 24)
        .await
        .unwrap();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

const LAN: &str = "192.168.1.50:5555";

async fn login(t: &T) -> String {
    let (s, h, b) = send(
        t,
        "POST",
        "/api/login",
        r#"{"username":"admin","password":"supersecret1"}"#,
        None,
        true,
        LAN,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let c = h
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        c.contains("HttpOnly") && c.contains("SameSite=Strict"),
        "{c}"
    );
    c.split(';')
        .next()
        .unwrap()
        .trim_start_matches("fsview_session=")
        .to_string()
}

#[tokio::test]
async fn access_control() {
    let t = setup();
    assert_eq!(
        send(&t, "GET", "/api/me", "", None, false, "8.8.8.8:1")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&t, "GET", "/", "", None, false, "10.0.0.1:1").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&t, "GET", "/api/me", "", None, false, "100.90.1.2:1")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "tailscale IP must reach auth"
    );
    assert_eq!(
        send(
            &t,
            "POST",
            "/api/login",
            r#"{"username":"admin","password":"supersecret1"}"#,
            None,
            false,
            LAN
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "csrf"
    );
    for _ in 0..5 {
        send(
            &t,
            "POST",
            "/api/login",
            r#"{"username":"admin","password":"wrong"}"#,
            None,
            true,
            "192.168.1.66:1",
        )
        .await;
    }
    assert_eq!(
        send(
            &t,
            "POST",
            "/api/login",
            r#"{"username":"admin","password":"supersecret1"}"#,
            None,
            true,
            "192.168.1.66:1"
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let tok = login(&t).await;
    let (s, _, b) = send(&t, "GET", "/api/me", "", Some(&tok), false, LAN).await;
    assert!(s == StatusCode::OK && b.contains("admin"));

    let mut req = HttpRequest::builder()
        .method("POST")
        .uri("/api/logout")
        .header(header::HOST, "fsview.lan:9200")
        .header("x-fsview-request", "1")
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(PeerAddr(LAN.parse().unwrap())));
    assert_eq!(
        router(t.app.clone()).oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "cross-origin post"
    );

    assert_eq!(
        send(&t, "POST", "/api/logout", "", Some(&tok), true, LAN)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&t, "GET", "/api/me", "", Some(&tok), false, LAN)
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "session survived logout"
    );
    let (_, h, _) = send(&t, "GET", "/", "", None, false, LAN).await;
    assert!(h.get(header::CONTENT_SECURITY_POLICY).is_some());
}

#[tokio::test]
async fn overview_and_smart() {
    let t = setup();
    let tok = login(&t).await;
    t.app.refresh_smart("sdc", false).await;
    t.app.refresh_smart("sdb", false).await;
    let (s, _, b) = send(&t, "GET", "/api/overview", "", Some(&tok), false, LAN).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    let disk = |n: &str| {
        v["disks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(disk("sdc")["health"]["status"], "crit");
    assert_eq!(disk("sdb")["display_transport"], "SATA via SAS");
    assert_eq!(disk("sdb")["display_model"], "ST6000DM003-2CY186");
    assert_eq!(disk("nvme0n1")["protected"], true);
    assert_eq!(
        (
            v["summary"]["protected"].as_u64(),
            v["summary"]["crit"].as_u64()
        ),
        (Some(1), Some(1))
    );
    let (s, _, b) = send(
        &t,
        "GET",
        "/api/disks/sdc?raw=1",
        "",
        Some(&tok),
        false,
        LAN,
    )
    .await;
    assert!(s == StatusCode::OK && b.contains("Failed in segment") && b.contains("\"raw\""));
    let (s, _, _) = send(&t, "GET", "/api/disks/..%2fetc", "", Some(&tok), false, LAN).await;
    assert_ne!(s, StatusCode::OK);
}

#[tokio::test]
async fn selftest_and_settings() {
    let t = setup();
    let tok = login(&t).await;
    let (s, _, b) = send(
        &t,
        "POST",
        "/api/disks/sdb/selftest",
        r#"{"test":"short","confirmed":true}"#,
        Some(&tok),
        true,
        LAN,
    )
    .await;
    assert!(
        s == StatusCode::FORBIDDEN && b.contains("writes_disabled"),
        "{s} {b}"
    );
    *t.helper.writes.lock().unwrap() = true;
    let (s, _, b) = send(
        &t,
        "POST",
        "/api/disks/sdb/selftest",
        r#"{"test":"short","dry_run":true}"#,
        Some(&tok),
        true,
        LAN,
    )
    .await;
    assert!(
        s == StatusCode::OK && b.contains("smartctl -d sat -t short /dev/sdb"),
        "{b}"
    );
    let last = t.helper.reqs.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        (last.actor.as_str(), last.client_ip.as_str(), last.dry_run),
        ("admin", "192.168.1.50", true)
    );

    let (s, _, _) = send(
        &t,
        "PUT",
        "/api/settings",
        r#"{"thresholds":{"temp_warn_c":70,"temp_crit_c":60}}"#,
        Some(&tok),
        true,
        LAN,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut good = crate::store::Settings::default();
    good.thresholds.temp_warn_c = 45;
    let (s, _, b) = send(
        &t,
        "PUT",
        "/api/settings",
        &serde_json::to_string(&good).unwrap(),
        Some(&tok),
        true,
        LAN,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn journal_poll_and_events() {
    let t = setup();
    let tok = login(&t).await;
    t.app.poll_journal().await;
    t.app.poll_journal().await; // duplicate cursor must not duplicate
    let (_, _, b) = send(
        &t,
        "GET",
        "/api/events?severity=error",
        "",
        Some(&tok),
        false,
        LAN,
    )
    .await;
    let evs: Vec<crate::events::Event> = serde_json::from_str(&b).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(
        (evs[0].device.as_str(), evs[0].category.as_str()),
        ("sdc", crate::events::CAT_IO_ERROR)
    );
    assert_eq!(t.app.store.journal_cursor(), "c1");
    assert_eq!(
        EventStore::open(t.app.store.dir(), 100)
            .list(&Filter::default())
            .len(),
        1,
        "events not persisted"
    );
}

#[tokio::test]
async fn hidden_scan() {
    let t = setup();
    let tok = login(&t).await;
    let (s, _, b) = send(
        &t,
        "POST",
        "/api/hidden/scan?all=1",
        "",
        Some(&tok),
        true,
        LAN,
    )
    .await;
    assert!(
        s == StatusCode::OK && b.contains("\"files\":22") && b.contains("\"all\":true"),
        "{b}"
    );
    assert_eq!(
        t.helper.reqs.lock().unwrap().last().unwrap().params["all"],
        true
    );
    let (_, _, b) = send(&t, "GET", "/api/overview", "", Some(&tok), false, LAN).await;
    assert!(b.contains("/mnt/drivepool"));
}
