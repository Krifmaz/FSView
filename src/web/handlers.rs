use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body as HttpBody;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, Request as HttpRequest, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures_util::{Stream, StreamExt};
use regex::Regex;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_stream::wrappers::BroadcastStream;

use super::{App, PeerAddr};
use crate::helperclient::{call_as, params, HelperError};
use crate::inventory::Disk;
use crate::netutil::allowed;
use crate::proto::*;
use crate::smart::{self, Finding, Running};
use crate::store::{Settings, SESSION_ABSOLUTE};

const COOKIE: &str = "fsview_session";

type AppState = State<Arc<App>>;

#[derive(Embed)]
#[folder = "web/dist/"]
struct Assets;

pub fn router(app: Arc<App>) -> Router {
    let api = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/me/password", post(change_password))
        .route("/api/status", get(status))
        .route("/api/overview", get(overview))
        .route("/api/disks/{name}", get(disk))
        .route("/api/disks/{name}/smart/refresh", post(smart_refresh))
        .route("/api/disks/{name}/selftest", post(selftest))
        .route("/api/events", get(events_list))
        .route("/api/events/stream", get(events_stream))
        .route("/api/bootcheck", get(bootcheck))
        .route("/api/audit", get(audit))
        .route("/api/hidden", get(hidden))
        .route("/api/hidden/scan", post(hidden_scan))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/enclosures/ignore", post(enclosure_ignore))
        .route("/api/fstab", get(fstab_get))
        .route("/api/fstab/preview", post(fstab_preview))
        .route("/api/fstab/apply", post(fstab_apply))
        .route("/api/fstab/backups/{name}", get(fstab_backup))
        .route("/api/fstab/rollback", post(fstab_rollback))
        .route("/api/storage", get(storage))
        .route("/api/mounts/mount", post(mount))
        .route("/api/mounts/umount", post(umount))
        .route("/api/mounts/protect", post(protect_mountpoints))
        .route("/api/pools/health", get(pool_health))
        .route("/api/pools/locate", get(pool_locate))
        .route("/api/pools/repair", post(pool_repair))
        .route("/api/disks/{name}/format", post(format))
        .route("/api/disks/{name}/check", post(fs_check))
        .route("/api/disks/{name}/locate", post(locate))
        .route("/api/disks/{name}/label", post(relabel))
        .route("/api/disks/{name}/acknowledge", post(acknowledge))
        .fallback(|| async { err(StatusCode::NOT_FOUND, "not_found", "no such endpoint") })
        .layer(middleware::from_fn(csrf));
    Router::new()
        .merge(api)
        .fallback(static_files)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(app.clone(), ip_filter))
        .with_state(app)
}

// ---- helpers ----

fn err(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        no_store(),
        Json(json!({"error": msg.into(), "code": code})),
    )
        .into_response()
}

fn no_store() -> [(header::HeaderName, &'static str); 1] {
    [(header::CACHE_CONTROL, "no-store")]
}

fn ok<T: Serialize>(v: T) -> Response {
    (no_store(), Json(v)).into_response()
}

fn helper_err(e: HelperError) -> Response {
    let status = match e.code.as_str() {
        CODE_BAD_REQUEST => StatusCode::BAD_REQUEST,
        CODE_WRITES_OFF | CODE_PROTECTED | CODE_NOT_PERMITTED => StatusCode::FORBIDDEN,
        CODE_NEED_CONFIRM => StatusCode::PRECONDITION_REQUIRED,
        _ => StatusCode::BAD_GATEWAY,
    };
    (
        status,
        no_store(),
        Json(json!({"error": e.msg, "code": e.code, "plan": e.plan})),
    )
        .into_response()
}

fn client_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<PeerAddr>>()
        .map(|c| crate::netutil::unmap(c.0 .0.ip()))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

fn set_cookie(app: &App, value: &str, max_age: i64) -> [(header::HeaderName, HeaderValue); 1] {
    let secure = if app.opt.tls_cert.is_empty() {
        ""
    } else {
        "; Secure"
    };
    let v =
        format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}");
    [(
        header::SET_COOKIE,
        HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static("")),
    )]
}

/// Authenticated user (from the session cookie).
pub struct User(pub String, pub IpAddr);

impl FromRequestParts<Arc<App>> for User {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        app: &Arc<App>,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip(parts)
            .ok_or_else(|| err(StatusCode::FORBIDDEN, "forbidden", "no client address"))?;
        let tok = cookie_value(&parts.headers, COOKIE).ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "login required",
            )
        })?;
        let store = app.store.clone();
        let sess = tokio::task::spawn_blocking(move || store.session(&tok))
            .await
            .ok()
            .flatten();
        sess.map(|s| User(s.user, ip)).ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "session expired",
            )
        })
    }
}

/// Strict JSON body (unknown fields rejected), with a uniform error.
pub struct JsonBody<T>(pub T);

impl<T: serde::de::DeserializeOwned> axum::extract::FromRequest<Arc<App>> for JsonBody<T> {
    type Rejection = Response;
    async fn from_request(req: HttpRequest, _: &Arc<App>) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .map_err(|_| err(StatusCode::BAD_REQUEST, "bad_request", "body too large"))?;
        serde_json::from_slice(&bytes).map(JsonBody).map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid body: {e}"),
            )
        })
    }
}

// ---- middleware ----

/// Defence in depth behind the filtered listener.
async fn ip_filter(State(app): AppState, req: HttpRequest, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<PeerAddr>>()
        .map(|c| c.0 .0.ip());
    match ip {
        Some(ip) if app.opt.allow.is_empty() || allowed(ip, &app.opt.allow) => next.run(req).await,
        _ => (StatusCode::FORBIDDEN, "forbidden").into_response(),
    }
}

async fn security_headers(req: HttpRequest, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    res
}

/// State-changing requests need a custom header (browsers cannot send it
/// cross-origin without a CORS preflight, which is never allowed) and a
/// matching Origin.
async fn csrf(req: HttpRequest, next: Next) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        if req
            .headers()
            .get("x-fsview-request")
            .and_then(|v| v.to_str().ok())
            != Some("1")
        {
            return err(
                StatusCode::FORBIDDEN,
                "csrf",
                "missing X-FSView-Request header",
            );
        }
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let o_host = origin.split_once("://").map(|(_, h)| h).unwrap_or("");
            if o_host.is_empty() || o_host != host {
                return err(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "cross-origin request rejected",
                );
            }
        }
    }
    next.run(req).await
}

// ---- auth ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    username: String,
    password: String,
}

async fn login(
    State(app): AppState,
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
    JsonBody(b): JsonBody<LoginBody>,
) -> Response {
    let ip = crate::netutil::unmap(peer.0.ip());
    if app.login_blocked(ip) {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many failed logins; try again in 15 minutes",
        );
    }
    let store = app.store.clone();
    let (u, p) = (b.username.clone(), b.password);
    let good = tokio::task::spawn_blocking(move || store.check_password(&u, &p))
        .await
        .unwrap_or(false);
    if !good {
        app.login_failed(ip);
        eprintln!("fsview: failed login for {:?} from {ip}", b.username);
        return err(
            StatusCode::UNAUTHORIZED,
            "bad_credentials",
            "invalid username or password",
        );
    }
    app.login_reset(ip);
    let Ok(tok) = app.store.create_session(&b.username, &ip.to_string()) else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "could not create session",
        );
    };
    eprintln!("fsview: login {:?} from {ip}", b.username);
    (
        set_cookie(&app, &tok, SESSION_ABSOLUTE.as_secs() as i64),
        Json(json!({"user": b.username})),
    )
        .into_response()
}

async fn logout(State(app): AppState, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_value(&headers, COOKIE) {
        app.store.delete_session(&t);
    }
    (set_cookie(&app, "", 0), Json(json!({"ok": true}))).into_response()
}

async fn me(User(u, _): User) -> Response {
    ok(json!({"user": u}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current: String,
    new: String,
}

async fn change_password(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<PasswordBody>,
) -> Response {
    let store = app.store.clone();
    let user = u.clone();
    let res = tokio::task::spawn_blocking(move || {
        if !store.check_password(&user, &b.current) {
            return Err((
                StatusCode::FORBIDDEN,
                "bad_credentials",
                "current password is wrong".to_string(),
            ));
        }
        store
            .set_password(&user, &b.new, false)
            .map_err(|e| (StatusCode::BAD_REQUEST, "bad_request", e))
    })
    .await
    .unwrap_or_else(|_| {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "failed".into(),
        ))
    });
    if let Err((s, c, m)) = res {
        return err(s, c, m);
    }
    match app.store.create_session(&u, &ip.to_string()) {
        Ok(tok) => (
            set_cookie(&app, &tok, SESSION_ABSOLUTE.as_secs() as i64),
            Json(json!({"ok": true})),
        )
            .into_response(),
        Err(_) => ok(json!({"ok": true})),
    }
}

// ---- data ----

async fn status(State(app): AppState, User(u, _): User) -> Response {
    let mut resp = json!({
        "version": app.opt.version,
        "listen": app.opt.listen.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "allow": app.opt.allow,
        "user": u,
        "tls": !app.opt.tls_cert.is_empty(),
    });
    match call_as::<StatusResult>(
        &*app.helper,
        Request {
            op: OP_STATUS.into(),
            ..Default::default()
        },
    )
    .await
    {
        Ok((st, _)) => resp["helper"] = serde_json::to_value(st).unwrap_or_default(),
        Err(e) => resp["helper_error"] = json!(e.msg),
    }
    ok(resp)
}

/// SMART summary attached to a disk in API responses.
#[derive(Serialize)]
struct HealthView {
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature_c: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    power_on_hours: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    devtype: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    model: String,
    standby: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    self_test_running: Option<Running>,
    #[serde(skip_serializing_if = "Option::is_none")]
    life: Option<smart::Life>,
    updated_at: Option<chrono::DateTime<Utc>>,
    checked_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Serialize)]
struct DiskView {
    #[serde(flatten)]
    disk: Disk,
    display_model: String,
    display_transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<HealthView>,
}

fn disk_view(app: &App, d: &Disk) -> DiskView {
    let mut v = DiskView {
        disk: d.clone(),
        display_model: d.model.clone(),
        display_transport: if d.transport.is_empty() {
            "?".into()
        } else {
            d.transport.to_uppercase()
        },
        health: None,
    };
    if let Some(e) = app.smart_for(&d.name) {
        let mut h = HealthView {
            status: e.assessment.status.clone(),
            findings: e.assessment.findings.clone(),
            temperature_c: None,
            power_on_hours: None,
            protocol: String::new(),
            devtype: String::new(),
            model: String::new(),
            standby: e.standby,
            self_test_running: None,
            life: e.life.clone(),
            updated_at: e.updated_at,
            checked_at: e.checked_at,
            error: e.error.clone(),
        };
        if let Some(r) = &e.report {
            h.temperature_c = r.temperature_c;
            h.power_on_hours = r.power_on_hours;
            h.protocol = r.protocol.clone();
            h.devtype = r.devtype.clone();
            h.model = r.model.clone();
            h.self_test_running = r.running.clone();
            if r.protocol == "ATA" && !r.model.is_empty() {
                v.display_model = r.model.clone();
            }
            if r.protocol == "ATA" && d.transport == "sas" {
                v.display_transport = "SATA via SAS".into();
            }
        }
        v.health = Some(h);
    }
    v
}

#[derive(Deserialize, Default)]
struct FreshQ {
    #[serde(default)]
    fresh: String,
    #[serde(default)]
    wake: String,
    #[serde(default)]
    raw: String,
    #[serde(default)]
    all: String,
}

async fn overview(State(app): AppState, _u: User, Query(q): Query<FreshQ>) -> Response {
    let inv = match app.inventory(q.fresh == "1").await {
        Ok(i) => i,
        Err(e) => return err(StatusCode::BAD_GATEWAY, "helper_unavailable", e),
    };
    let mut sum: BTreeMap<&str, usize> = [
        ("disks", inv.disks.len()),
        ("crit", 0),
        ("warn", 0),
        ("ok", 0),
        ("unknown", 0),
        ("protected", 0),
    ]
    .into();
    let views: Vec<DiskView> = inv
        .disks
        .iter()
        .map(|d| {
            let v = disk_view(&app, d);
            let st = v
                .health
                .as_ref()
                .map(|h| h.status.as_str())
                .unwrap_or(smart::UNKNOWN);
            *sum.entry(match st {
                "crit" => "crit",
                "warn" => "warn",
                "ok" => "ok",
                _ => "unknown",
            })
            .or_default() += 1;
            if d.protected {
                *sum.entry("protected").or_default() += 1;
            }
            v
        })
        .collect();
    ok(json!({
        "hostname": inv.hostname,
        "collected_at": inv.collected_at,
        "disks": views,
        "hbas": inv.hbas,
        "enclosures": enclosures_view(&inv.enclosures, &app.store.settings().ignored_elements),
        "warnings": inv.warnings,
        "summary": sum,
        "events_24h": app.events.counts(Utc::now() - chrono::Duration::hours(24)),
        "hidden": app.hidden_snapshot(),
    }))
}

/// Adds element keys and applies the user's ignore list.
pub(crate) fn enclosures_view(
    encs: &[crate::inventory::Enclosure],
    ignored: &[String],
) -> Vec<crate::inventory::Enclosure> {
    let mut out = encs.to_vec();
    for e in out.iter_mut() {
        // logical_id is the shelf's SES WWN; the SCSI address can change
        // between boots.
        let id = if e.logical_id.is_empty() {
            format!("{} {}", e.vendor, e.model)
        } else {
            e.logical_id.clone()
        };
        for el in e.elements.iter_mut() {
            el.key = format!("{}/{}/{}", id.trim(), el.kind, el.index);
            if ignored.contains(&el.key) && el.level != "absent" {
                el.level = "ignored".into();
            }
        }
        if !e.elements.is_empty() {
            e.status = crate::inventory::enclosure_level(&e.elements);
        }
    }
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoreBody {
    key: String,
    ignore: bool,
}

async fn enclosure_ignore(
    State(app): AppState,
    _u: User,
    JsonBody(b): JsonBody<IgnoreBody>,
) -> Response {
    if b.key.is_empty() || b.key.len() > 200 || b.key.chars().any(char::is_control) {
        return err(StatusCode::BAD_REQUEST, "bad_request", "invalid key");
    }
    let mut s = app.store.settings();
    s.ignored_elements.retain(|k| *k != b.key);
    if b.ignore {
        if s.ignored_elements.len() >= 200 {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "too many ignored elements",
            );
        }
        s.ignored_elements.push(b.key);
    }
    match app.store.set_settings(s.clone()) {
        Ok(()) => ok(json!({"ignored_elements": s.ignored_elements})),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    /// true: acknowledge the current error counts; false: forget them.
    acknowledge: bool,
}

/// Records a disk's current SMART error-log and CRC counts so only new
/// errors warn. These counters never reset on the drive itself.
async fn acknowledge(
    State(app): AppState,
    _u: User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<AckBody>,
) -> Response {
    let d = match find_disk(&app, &name).await {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let Some(rep) = app.smart_for(&d.name).and_then(|e| e.report) else {
        return err(
            StatusCode::CONFLICT,
            "no_smart",
            "no SMART data for this disk yet",
        );
    };
    if rep.serial.is_empty() {
        return err(
            StatusCode::CONFLICT,
            "no_serial",
            "the disk reports no serial number",
        );
    }
    let mut s = app.store.settings();
    if b.acknowledge {
        if s.acknowledged.len() >= 500 && !s.acknowledged.contains_key(&rep.serial) {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "too many acknowledged disks",
            );
        }
        s.acknowledged.insert(
            rep.serial.clone(),
            smart::Ack {
                ata_errors: rep.ata_error_count.unwrap_or(0),
                crc_errors: rep.crc_errors.unwrap_or(0),
            },
        );
    } else {
        s.acknowledged.remove(&rep.serial);
    }
    if let Err(e) = app.store.set_settings(s) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e);
    }
    ok(json!({"disk": disk_view(&app, &d), "smart": app.smart_for(&d.name)}))
}

fn name_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-z0-9]{2,16}$").unwrap())
}

async fn find_disk(app: &App, name: &str) -> Result<Disk, Box<Response>> {
    if !name_re().is_match(name) {
        return Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid disk name",
        )));
    }
    let inv = app
        .inventory(false)
        .await
        .map_err(|e| Box::new(err(StatusCode::BAD_GATEWAY, "helper_unavailable", e)))?;
    inv.find_disk(name)
        .cloned()
        .ok_or_else(|| Box::new(err(StatusCode::NOT_FOUND, "not_found", "no such disk")))
}

async fn disk(
    State(app): AppState,
    _u: User,
    Path(name): Path<String>,
    Query(q): Query<FreshQ>,
) -> Response {
    let d = match find_disk(&app, &name).await {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let e = match app.smart_for(&d.name) {
        Some(e) => e,
        None => app.refresh_smart(&d.name, false).await,
    };
    let mut resp = json!({"disk": disk_view(&app, &d), "smart": e});
    if q.raw == "1" && !e.raw.is_null() {
        resp["raw"] = e.raw.clone();
    }
    ok(resp)
}

async fn smart_refresh(
    State(app): AppState,
    _u: User,
    Path(name): Path<String>,
    Query(q): Query<FreshQ>,
) -> Response {
    let d = match find_disk(&app, &name).await {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let e = app.refresh_smart(&d.name, q.wake == "1").await;
    ok(json!({"disk": disk_view(&app, &d), "smart": e}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfTestBody {
    test: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirmed: bool,
}

async fn selftest(
    State(app): AppState,
    User(u, ip): User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<SelfTestBody>,
) -> Response {
    let d = match find_disk(&app, &name).await {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let req = Request {
        op: OP_SMART_SELFTEST.into(),
        actor: u,
        client_ip: ip.to_string(),
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        params: params(&SmartSelfTestParams {
            device: d.name.clone(),
            test: b.test,
        }),
        ..Default::default()
    };
    match app.helper.call(req).await {
        Ok(resp) => {
            if !resp.dry_run {
                app.kick_smart(d.name.clone());
            }
            ok(
                json!({"ok": true, "dry_run": resp.dry_run, "plan": resp.plan, "result": resp.result}),
            )
        }
        Err(e) => helper_err(e),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EventsQ {
    severity: String,
    category: String,
    device: String,
    q: String,
    limit: String,
    hours: String,
}

async fn events_list(State(app): AppState, _u: User, Query(q): Query<EventsQ>) -> Response {
    let f = super::Filter {
        severity: q.severity,
        category: q.category,
        device: q.device,
        query: q.q,
        limit: q.limit.parse().unwrap_or(0),
        since: q
            .hours
            .parse::<i64>()
            .ok()
            .filter(|h| *h > 0)
            .map(|h| Utc::now() - chrono::Duration::hours(h)),
    };
    ok(app.events.list(&f))
}

async fn events_stream(
    State(app): AppState,
    _u: User,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = BroadcastStream::new(app.events.subscribe())
        .filter_map(|r| async move { r.ok() })
        .map(|e| {
            Ok(SseEvent::default()
                .event("disk")
                .data(serde_json::to_string(&e).unwrap_or_default()))
        });
    let hello = futures_util::stream::once(async { Ok(SseEvent::default().comment("connected")) });
    Sse::new(hello.chain(stream)).keep_alive(KeepAlive::new().interval(Duration::from_secs(25)))
}

async fn bootcheck(State(app): AppState, _u: User, Query(q): Query<FreshQ>) -> Response {
    match app.boot_report(q.fresh == "1").await {
        Ok(r) => ok(&*r),
        Err(e) => helper_err(e),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LimitQ {
    limit: String,
}

async fn audit(State(app): AppState, _u: User, Query(q): Query<LimitQ>) -> Response {
    let req = Request {
        op: OP_AUDIT_LIST.into(),
        params: params(&AuditListParams {
            limit: q.limit.parse().unwrap_or(0),
        }),
        ..Default::default()
    };
    match call_as::<Value>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

async fn hidden(State(app): AppState, _u: User) -> Response {
    ok(app.hidden_snapshot())
}

async fn hidden_scan(State(app): AppState, _u: User, Query(q): Query<FreshQ>) -> Response {
    app.scan_hidden(q.all == "1").await;
    ok(app.hidden_snapshot())
}

// ---- mounts, filesystems, pools ----

/// Common fields of every write request from the UI.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WriteBody<T> {
    #[serde(flatten)]
    p: T,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    confirm_text: String,
}

async fn helper_write<T: Serialize>(
    app: &App,
    (u, ip): (String, IpAddr),
    op: &str,
    b: WriteBody<T>,
) -> Response {
    let req = Request {
        op: op.into(),
        actor: u,
        client_ip: ip.to_string(),
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        confirm_text: b.confirm_text,
        params: params(&b.p),
    };
    match app.helper.call(req).await {
        Ok(resp) => {
            if !resp.dry_run {
                app.invalidate_caches().await;
            }
            ok(
                json!({"ok": true, "dry_run": resp.dry_run, "plan": resp.plan, "result": resp.result}),
            )
        }
        Err(e) => helper_err(e),
    }
}

async fn mount(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<WriteBody<MountParams>>,
) -> Response {
    helper_write(&app, (u, ip), OP_MOUNT, b).await
}

async fn umount(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<WriteBody<MountParams>>,
) -> Response {
    helper_write(&app, (u, ip), OP_UMOUNT, b).await
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

async fn protect_mountpoints(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<WriteBody<NoParams>>,
) -> Response {
    helper_write(&app, (u, ip), OP_PROTECT_MOUNTPOINTS, b).await
}

/// The device must be the disk in the URL or one of its partitions.
async fn device_of(app: &App, disk: &str, device: &str) -> Result<(), Box<Response>> {
    let d = find_disk(app, disk).await?;
    let mut ok = d.name == device;
    d.walk(&mut |n| ok |= n.name == device);
    if ok {
        Ok(())
    } else {
        Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            format!("{device} is not on {disk}"),
        )))
    }
}

async fn format(
    State(app): AppState,
    User(u, ip): User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<WriteBody<FormatParams>>,
) -> Response {
    if let Err(r) = device_of(&app, &name, &b.p.device).await {
        return *r;
    }
    helper_write(&app, (u, ip), OP_FS_FORMAT, b).await
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct CheckBody {
    device: String,
    #[serde(default)]
    repair: bool,
}

async fn fs_check(
    State(app): AppState,
    User(u, ip): User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<WriteBody<CheckBody>>,
) -> Response {
    if let Err(r) = device_of(&app, &name, &b.p.device).await {
        return *r;
    }
    let op = if b.p.repair {
        OP_FS_REPAIR
    } else {
        OP_FS_CHECK
    };
    let b = WriteBody {
        p: FsCheckParams { device: b.p.device },
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        confirm_text: b.confirm_text,
    };
    helper_write(&app, (u, ip), op, b).await
}

async fn relabel(
    State(app): AppState,
    User(u, ip): User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<WriteBody<LabelParams>>,
) -> Response {
    if let Err(r) = device_of(&app, &name, &b.p.device).await {
        return *r;
    }
    helper_write(&app, (u, ip), OP_FS_LABEL, b).await
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct LocateBody {
    on: bool,
}

async fn locate(
    State(app): AppState,
    User(u, ip): User,
    Path(name): Path<String>,
    JsonBody(b): JsonBody<WriteBody<LocateBody>>,
) -> Response {
    let b = WriteBody {
        p: LocateParams {
            device: name,
            on: b.p.on,
        },
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        confirm_text: String::new(),
    };
    helper_write(&app, (u, ip), OP_LOCATE, b).await
}

/// fstab entries joined with live mounts, plus mergerfs pools with the
/// state of each branch.
/// `GET /api/pools/health`: per-branch health of every mounted mergerfs
/// pool (mode, mount state, ext4 journal errors and their trigger, SMART).
async fn pool_health(State(app): AppState, _u: User) -> Response {
    let req = Request {
        op: OP_POOL_HEALTH.into(),
        params: params(&PoolHealthParams::default()),
        ..Default::default()
    };
    match call_as::<Vec<crate::poolhealth::PoolHealth>>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

/// `GET /api/pools/locate?pool=/mnt/pool&path=music/a.flac`: which branch
/// a file lives on (`user.mergerfs.fullpath`).
async fn pool_locate(
    State(app): AppState,
    _u: User,
    Query(q): Query<PoolLocateParams>,
) -> Response {
    let req = Request {
        op: OP_POOL_LOCATE.into(),
        params: params(&q),
        ..Default::default()
    };
    match call_as::<PoolLocateResult>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

/// `POST /api/pools/repair`: guided repair of one branch. Destructive (the
/// disk's name or label must be typed); a dry run returns the plan and the
/// kernel messages that led to the first ext4 error.
async fn pool_repair(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<WriteBody<PoolRepairParams>>,
) -> Response {
    helper_write(&app, (u, ip), OP_POOL_REPAIR, b).await
}

async fn storage(State(app): AppState, _u: User) -> Response {
    let fs = call_as::<FstabState>(
        &*app.helper,
        Request {
            op: OP_FSTAB_READ.into(),
            ..Default::default()
        },
    );
    let ms = call_as::<Vec<MountInfo>>(
        &*app.helper,
        Request {
            op: OP_MOUNTS_LIST.into(),
            ..Default::default()
        },
    );
    let st = call_as::<StatusResult>(
        &*app.helper,
        Request {
            op: OP_STATUS.into(),
            ..Default::default()
        },
    );
    let (fs, ms, st) = tokio::join!(fs, ms, st);
    let (fs, ms) = match (fs, ms) {
        (Ok((f, _)), Ok((m, _))) => (f, m),
        (Err(e), _) | (_, Err(e)) => return helper_err(e),
    };
    let st = st.ok().map(|(s, _)| s);
    ok(storage_view(&fs, &ms, st.as_ref()))
}

pub(crate) fn storage_view(fs: &FstabState, ms: &[MountInfo], st: Option<&StatusResult>) -> Value {
    use crate::fstab::Line;
    use crate::helper::{is_mergerfs, mergerfs_branch_modes};
    let entries: Vec<(usize, &crate::fstab::FsEntry)> = fs
        .doc
        .lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| match l {
            Line::Entry { entry, .. } => Some((i, entry)),
            _ => None,
        })
        .collect();
    let mount_of = |t: &str| ms.iter().find(|m| m.target == t);
    let usage = |m: Option<&MountInfo>| {
        m.map(|m| json!({"size_bytes": m.size_bytes, "used_bytes": m.used_bytes, "avail_bytes": m.avail_bytes}))
    };
    let owner = |b: &str, own: &str| {
        entries
            .iter()
            .map(|(_, e)| e)
            .filter(|e| e.file != "/" && e.file != own && e.vfstype != "swap")
            .filter(|e| b == e.file || b.starts_with(&format!("{}/", e.file)))
            .max_by_key(|e| e.file.len())
            .map(|e| e.file.clone())
    };
    let virt = ["proc", "sysfs", "tmpfs", "devpts", "cgroup2", "efivarfs"];
    let mut out_entries = vec![];
    let mut pools = vec![];
    for (i, e) in &entries {
        if e.vfstype == "swap" || virt.contains(&e.vfstype.as_str()) {
            continue;
        }
        let m = mount_of(&e.file);
        let dev = fs.devices.iter().find(|d| {
            let s = e.spec.to_lowercase();
            (!d.uuid.is_empty() && s == format!("uuid={}", d.uuid.to_lowercase()))
                || (!d.label.is_empty() && e.spec == format!("LABEL={}", d.label))
                || (!d.partuuid.is_empty()
                    && s == format!("partuuid={}", d.partuuid.to_lowercase()))
                || e.spec == d.path
        });
        let opts = crate::fstab::split_options(&e.options);
        let pool = is_mergerfs(e);
        let system =
            ["/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home"].contains(&e.file.as_str());
        let v = json!({
            "line": i,
            "spec": e.spec,
            "file": e.file,
            "vfstype": e.vfstype,
            "options": e.options,
            "mounted": m.is_some(),
            "source": m.map(|m| m.source.clone()),
            "usage": usage(m),
            "device": dev.map(|d| json!({"name": d.name, "disk": d.disk, "label": d.label, "fstype": d.fstype, "size_bytes": d.size_bytes, "protected": d.protected})),
            "present": pool || dev.is_some() || !e.spec.contains('='),
            "system": system,
            "nofail": opts.iter().any(|(k, _)| k == "nofail"),
            "pool": pool,
        });
        if pool {
            let branches: Vec<Value> = mergerfs_branch_modes(e)
                .into_iter()
                .map(|(b, mode)| {
                    let on = owner(&b, &e.file);
                    let bm = on.as_deref().and_then(mount_of);
                    json!({
                        "path": b,
                        "mode": mode,
                        "mount": on,
                        "mounted": on.is_none() || bm.is_some(),
                        "usage": usage(bm),
                        "required": opts.iter().any(|(k, v)| (k == "x-systemd.requires-mounts-for" || k == "x-systemd.wants-mounts-for") && v.as_deref() == on.as_deref()),
                    })
                })
                .collect();
            let mut p = v.clone();
            p["branches"] = json!(branches);
            p["policy"] = json!(opts
                .iter()
                .find(|(k, _)| k == "category.create")
                .and_then(|(_, v)| v.clone())
                .unwrap_or_else(|| "epmfs".into()));
            pools.push(p);
        }
        out_entries.push(v);
    }
    let known: Vec<&str> = entries.iter().map(|(_, e)| e.file.as_str()).collect();
    let other: Vec<Value> = ms
        .iter()
        .filter(|m| !known.contains(&m.target.as_str()))
        .filter(|m| !["/", "/boot", "/boot/efi"].contains(&m.target.as_str()))
        .filter(|m| !m.target.starts_with("/run/") && !m.target.starts_with("/var/lib/"))
        .map(|m| json!({"target": m.target, "source": m.source, "fstype": m.fstype, "usage": usage(Some(m))}))
        .collect();
    json!({
        "fstab_sha256": fs.sha256,
        "writes_enabled": fs.writes_enabled,
        "mergerfs_installed": st.map(|s| s.tools.get("mergerfs").copied().unwrap_or(false)),
        "tools": st.map(|s| s.tools.clone()),
        "entries": out_entries,
        "pools": pools,
        "other_mounts": other,
        "devices": fs.devices,
    })
}

// ---- fstab editor ----

async fn fstab_get(State(app): AppState, _u: User) -> Response {
    let req = Request {
        op: OP_FSTAB_READ.into(),
        ..Default::default()
    };
    match call_as::<FstabState>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

async fn fstab_preview(
    State(app): AppState,
    _u: User,
    JsonBody(b): JsonBody<FstabPreviewParams>,
) -> Response {
    let req = Request {
        op: OP_FSTAB_PREVIEW.into(),
        params: params(&b),
        ..Default::default()
    };
    match call_as::<FstabPreview>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

async fn fstab_backup(State(app): AppState, _u: User, Path(name): Path<String>) -> Response {
    let req = Request {
        op: OP_FSTAB_BACKUP.into(),
        params: params(&FstabBackupParams { name }),
        ..Default::default()
    };
    match call_as::<FstabBackupView>(&*app.helper, req).await {
        Ok((v, _)) => ok(v),
        Err(e) => helper_err(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FstabApplyBody {
    doc: crate::fstab::Doc,
    base_sha256: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FstabRollbackBody {
    name: String,
    base_sha256: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirmed: bool,
}

async fn fstab_write(app: &App, req: Request) -> Response {
    match app.helper.call(req).await {
        Ok(resp) => {
            if !resp.dry_run {
                app.invalidate_boot().await;
            }
            ok(
                json!({"ok": true, "dry_run": resp.dry_run, "plan": resp.plan, "result": resp.result}),
            )
        }
        Err(e) => helper_err(e),
    }
}

async fn fstab_apply(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<FstabApplyBody>,
) -> Response {
    let req = Request {
        op: OP_FSTAB_WRITE.into(),
        actor: u,
        client_ip: ip.to_string(),
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        params: params(&FstabWriteParams {
            doc: b.doc,
            base_sha256: b.base_sha256,
        }),
        ..Default::default()
    };
    fstab_write(&app, req).await
}

async fn fstab_rollback(
    State(app): AppState,
    User(u, ip): User,
    JsonBody(b): JsonBody<FstabRollbackBody>,
) -> Response {
    let req = Request {
        op: OP_FSTAB_ROLLBACK.into(),
        actor: u,
        client_ip: ip.to_string(),
        dry_run: b.dry_run,
        confirmed: b.confirmed,
        params: params(&FstabRollbackParams {
            name: b.name,
            base_sha256: b.base_sha256,
        }),
        ..Default::default()
    };
    fstab_write(&app, req).await
}

async fn get_settings(State(app): AppState, _u: User) -> Response {
    ok(app.store.settings())
}

async fn put_settings(
    State(app): AppState,
    _u: User,
    JsonBody(mut v): JsonBody<Settings>,
) -> Response {
    // Managed through /api/enclosures/ignore.
    v.ignored_elements = app.store.settings().ignored_elements;
    // Managed through /api/disks/{name}/acknowledge.
    v.acknowledged = app.store.settings().acknowledged;
    let t = v.thresholds;
    let bad = |m: &str| err(StatusCode::BAD_REQUEST, "bad_request", m);
    if t.temp_warn_c < 20
        || t.temp_warn_c > 100
        || t.temp_crit_c < t.temp_warn_c
        || t.temp_crit_c > 110
    {
        return bad("temperature thresholds must satisfy 20 ≤ warn ≤ crit ≤ 110");
    }
    if !(0..=30).contains(&t.trip_margin_c) {
        return bad("trip margin must be 0-30");
    }
    if [
        t.reallocated_warn,
        t.reallocated_crit,
        t.pending_warn,
        t.pending_crit,
        t.uncorrectable_warn,
        t.crc_warn,
        t.error_log_warn,
    ]
    .iter()
    .any(|x| *x < 0)
    {
        return bad("counters must not be negative");
    }
    if t.nvme_used_warn < 1 || t.nvme_used_crit < t.nvme_used_warn {
        return bad("NVMe wear thresholds must satisfy 1 ≤ warn ≤ crit");
    }
    if !(5..=3600).contains(&v.late_device_sec) {
        return bad("late device threshold must be 5-3600 seconds");
    }
    if !(100..=200_000).contains(&v.event_retention) {
        return bad("event retention must be 100-200000");
    }
    match app.store.set_settings(v.clone()) {
        Ok(()) => ok(v),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e),
    }
}

// ---- static UI ----

async fn static_files(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(f) = Assets::get(path) {
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            [
                (header::CONTENT_TYPE, f.metadata.mimetype().to_string()),
                (header::CACHE_CONTROL, cache.to_string()),
            ],
            f.data.into_owned(),
        )
            .into_response();
    }
    match Assets::get("index.html") {
        // SPA fallback.
        Some(f) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            f.data.into_owned(),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            HttpBody::from("FSView UI is not built into this binary. Run `make ui` and rebuild.\n"),
        )
            .into_response(),
    }
}
