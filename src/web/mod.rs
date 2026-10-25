//! Unprivileged HTTP server: login, sessions, the JSON API and the embedded
//! React UI. Everything that needs root goes through the helper socket.

mod eventstore;
mod handlers;
mod listener;

pub use eventstore::{EventStore, Filter};
pub use handlers::router;
pub use listener::PeerAddr;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::bootcheck;
use crate::events;
use crate::helperclient::{call_as, params, HelperApi};
use crate::inventory::Inventory;
use crate::netutil::Prefix;
use crate::proto::*;
use crate::smart::{self, Assessment, Report};
use crate::store::Store;

#[derive(Clone, Debug)]
pub struct Options {
    pub version: String,
    pub allow: Vec<Prefix>,
    pub listen: Vec<SocketAddr>,
    pub tls_cert: String,
    pub tls_key: String,
    pub smart_poll: Duration,
    pub journal_poll: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            version: crate::VERSION.into(),
            allow: vec![],
            listen: vec![],
            tls_cert: String::new(),
            tls_key: String::new(),
            smart_poll: Duration::from_secs(1800),
            journal_poll: Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SmartEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
    pub assessment: Assessment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub life: Option<smart::Life>,
    pub updated_at: Option<DateTime<Utc>>,
    pub checked_at: Option<DateTime<Utc>>,
    pub standby: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip)]
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HiddenView {
    pub results: Vec<HiddenResult>,
    pub all: bool,
    pub checked_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub struct App {
    pub opt: Options,
    pub store: Arc<Store>,
    pub helper: Arc<dyn HelperApi>,
    pub events: EventStore,
    login_fails: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    inv: tokio::sync::Mutex<Option<(Arc<Inventory>, Instant)>>,
    smart: Mutex<HashMap<String, SmartEntry>>,
    boot: tokio::sync::Mutex<Option<(Arc<bootcheck::Report>, Instant)>>,
    hidden: Mutex<HiddenView>,
    smart_kick: mpsc::Sender<String>,
    smart_kick_rx: Mutex<Option<mpsc::Receiver<String>>>,
}

impl App {
    pub fn new(opt: Options, store: Arc<Store>, helper: Arc<dyn HelperApi>) -> Arc<App> {
        let (tx, rx) = mpsc::channel(64);
        let retention = store.settings().event_retention;
        Arc::new(App {
            events: EventStore::open(store.dir(), retention),
            opt,
            store,
            helper,
            login_fails: Mutex::new(HashMap::new()),
            inv: tokio::sync::Mutex::new(None),
            smart: Mutex::new(HashMap::new()),
            boot: tokio::sync::Mutex::new(None),
            hidden: Mutex::new(HiddenView::default()),
            smart_kick: tx,
            smart_kick_rx: Mutex::new(Some(rx)),
        })
    }

    /// Serves until `shutdown` resolves.
    pub async fn run(
        self: Arc<Self>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), String> {
        if self.opt.listen.is_empty() {
            return Err("no listen addresses".into());
        }
        let tls = if self.opt.tls_cert.is_empty() {
            None
        } else {
            Some(listener::tls_acceptor(
                &self.opt.tls_cert,
                &self.opt.tls_key,
            )?)
        };
        tokio::spawn(self.clone().journal_loop());
        tokio::spawn(self.clone().smart_loop());
        tokio::spawn(self.clone().hidden_loop());
        tokio::spawn(self.clone().pool_heal_loop());
        tokio::spawn(self.clone().pool_health_loop());

        let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut servers = Vec::new();
        for addr in self.opt.listen.clone() {
            let l =
                listener::FilteredListener::bind(addr, self.opt.allow.clone(), tls.clone()).await?;
            eprintln!(
                "fsview: listening on {}://{addr} (allowed: {})",
                if tls.is_some() { "https" } else { "http" },
                self.opt
                    .allow
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let app = router(self.clone()).into_make_service_with_connect_info::<PeerAddr>();
            let mut rx = stop_tx.subscribe();
            servers.push(tokio::spawn(async move {
                axum::serve(l, app)
                    .with_graceful_shutdown(async move {
                        let _ = rx.recv().await;
                    })
                    .await
            }));
        }
        shutdown.await;
        let _ = stop_tx.send(());
        for s in servers {
            let _ = tokio::time::timeout(Duration::from_secs(5), s).await;
        }
        Ok(())
    }

    // ---- login rate limiting ----

    const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
    const LOGIN_MAX_FAILS: usize = 5;

    pub(crate) fn login_blocked(&self, ip: IpAddr) -> bool {
        let mut m = self.login_fails.lock().unwrap();
        let v = m.entry(ip).or_default();
        v.retain(|t| t.elapsed() < Self::LOGIN_WINDOW);
        v.len() >= Self::LOGIN_MAX_FAILS
    }
    pub(crate) fn login_failed(&self, ip: IpAddr) {
        self.login_fails
            .lock()
            .unwrap()
            .entry(ip)
            .or_default()
            .push(Instant::now());
    }
    pub(crate) fn login_reset(&self, ip: IpAddr) {
        self.login_fails.lock().unwrap().remove(&ip);
    }

    // ---- background loops ----

    async fn journal_loop(self: Arc<Self>) {
        let mut t = tokio::time::interval(self.opt.journal_poll);
        loop {
            t.tick().await;
            self.poll_journal().await;
        }
    }

    pub async fn poll_journal(&self) {
        let cur = self.store.journal_cursor();
        let p = if cur.is_empty() {
            JournalParams {
                current_boot: true,
                lines: 20000,
                ..Default::default()
            }
        } else {
            JournalParams {
                after_cursor: cur,
                lines: 2000,
                ..Default::default()
            }
        };
        let fut = call_as::<Vec<events::Entry>>(
            &*self.helper,
            Request {
                op: OP_JOURNAL_KERNEL.into(),
                params: params(&p),
                ..Default::default()
            },
        );
        let Ok(Ok((entries, _))) = tokio::time::timeout(Duration::from_secs(30), fut).await else {
            return;
        };
        let Some(last) = entries.last().map(|e| e.cursor.clone()) else {
            return;
        };
        let late = self.store.settings().late_device_sec as f64;
        let mut evs: Vec<events::Event> = entries
            .iter()
            .filter_map(|e| events::classify(e, late))
            .collect();
        evs.sort_by_key(|e| e.time);
        self.events.add(evs);
        if !last.is_empty() {
            let _ = self.store.set_journal_cursor(&last);
        }
    }

    async fn smart_loop(self: Arc<Self>) {
        let mut rx = self
            .smart_kick_rx
            .lock()
            .unwrap()
            .take()
            .expect("smart loop started once");
        let mut t = tokio::time::interval(self.opt.smart_poll);
        loop {
            tokio::select! {
                _ = t.tick() => self.refresh_all_smart().await,
                Some(dev) = rx.recv() => { self.refresh_smart(&dev, false).await; }
            }
        }
    }

    /// Puts dropped pool disks back once they return healthy (see
    /// OP_POOL_HEAL). Disks SMART rates critical are left alone.
    async fn pool_heal_loop(self: Arc<Self>) {
        let mut t = tokio::time::interval(Duration::from_secs(60));
        t.tick().await;
        loop {
            t.tick().await;
            if !self.store.settings().auto_heal_pools {
                continue;
            }
            let devs: Vec<String> = self.smart.lock().unwrap().keys().cloned().collect();
            let skip: Vec<String> = devs
                .into_iter()
                .filter(|d| {
                    self.smart_for(d)
                        .is_some_and(|e| e.assessment.status == smart::CRIT)
                })
                .collect();
            let req = Request {
                op: OP_POOL_HEAL.into(),
                actor: "fsview (auto-heal)".into(),
                confirmed: true,
                params: params(&PoolHealParams { skip_disks: skip }),
                ..Default::default()
            };
            match self.helper.call(req).await {
                Ok(r) if r.ok && !r.plan.is_empty() => {
                    eprintln!(
                        "fsview: auto-heal: {}",
                        r.result["summary"].as_str().unwrap_or("")
                    );
                    self.invalidate_caches().await;
                }
                Ok(r) if !r.ok && r.code != CODE_WRITES_OFF => {
                    eprintln!("fsview: auto-heal: {}", r.error)
                }
                Err(e) => eprintln!("fsview: auto-heal: {e}"),
                _ => {}
            }
        }
    }

    /// Optional pool health watch (Settings → Pools): every 5 minutes reads
    /// pool health without SMART and records an event when a branch goes
    /// read-only (mergerfs `=RO`, `ro` or `emergency_ro` mount) and when it
    /// is writable again. Events appear on the Events page and in its live
    /// stream. The first check after start only records branches that are
    /// already read-only, once.
    async fn pool_health_loop(self: Arc<Self>) {
        let mut t = tokio::time::interval(POOL_HEALTH_INTERVAL);
        let mut known: Option<HashMap<String, String>> = None;
        loop {
            t.tick().await;
            if !self.store.settings().pool_health_watch {
                known = None;
                continue;
            }
            let req = Request {
                op: OP_POOL_HEALTH.into(),
                params: params(&PoolHealthParams { skip_smart: true }),
                ..Default::default()
            };
            let Ok((pools, _)) =
                call_as::<Vec<crate::poolhealth::PoolHealth>>(&*self.helper, req).await
            else {
                continue;
            };
            let now: HashMap<String, String> = pools
                .iter()
                .flat_map(|p| {
                    p.branches.iter().filter(|b| b.read_only()).map(move |b| {
                        (
                            format!("{}|{}", p.mountpoint, b.path),
                            b.read_only_reasons(),
                        )
                    })
                })
                .collect();
            let devices: HashMap<String, String> = pools
                .iter()
                .flat_map(|p| {
                    p.branches.iter().map(move |b| {
                        (
                            format!("{}|{}", p.mountpoint, b.path),
                            crate::poolhealth::kernel_name(&b.device).to_string(),
                        )
                    })
                })
                .collect();
            let before = known.take().unwrap_or_default();
            let evs = pool_transitions(&before, &now, &devices, Utc::now());
            self.events.add(evs);
            known = Some(now);
        }
    }

    pub(crate) fn kick_smart(&self, dev: String) {
        let tx = self.smart_kick.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = tx.try_send(dev);
        });
    }

    async fn refresh_all_smart(&self) {
        let Ok(inv) = self.inventory(true).await else {
            return;
        };
        for d in &inv.disks {
            self.refresh_smart(&d.name, false).await;
        }
    }

    pub async fn refresh_smart(&self, dev: &str, wake: bool) -> SmartEntry {
        let req = Request {
            op: OP_SMART_GET.into(),
            params: params(&SmartGetParams {
                device: dev.into(),
                wake,
            }),
            ..Default::default()
        };
        let res = tokio::time::timeout(
            Duration::from_secs(120),
            call_as::<SmartGetResult>(&*self.helper, req),
        )
        .await;
        let now = Utc::now();
        let settings = self.store.settings();
        let mut m = self.smart.lock().unwrap();
        let mut e = m.get(dev).cloned().unwrap_or_default();
        e.checked_at = Some(now);
        match res {
            Err(_) => e.error = "helper timed out".into(),
            Ok(Err(err)) => e.error = err.msg,
            Ok(Ok((r, _))) if r.standby => {
                e.standby = true;
                e.error.clear();
            }
            Ok(Ok((r, _))) => match serde_json::to_vec(&r.raw)
                .map_err(|e| e.to_string())
                .and_then(|b| smart::parse(&b, &r.devtype))
            {
                Ok(rep) => {
                    e.report = Some(rep);
                    e.raw = r.raw;
                    e.standby = false;
                    e.error.clear();
                    e.updated_at = Some(now);
                }
                Err(err) => e.error = err,
            },
        }
        e.assessment = e
            .report
            .as_ref()
            .map(|r| eval_report(r, &settings))
            .unwrap_or_default();
        e.life = e
            .report
            .as_ref()
            .map(|r| smart::lifespan(r, &e.assessment.status));
        m.insert(dev.into(), e.clone());
        e
    }

    /// Cached entry, re-evaluated against the current thresholds.
    pub fn smart_for(&self, dev: &str) -> Option<SmartEntry> {
        let mut e = self.smart.lock().unwrap().get(dev).cloned()?;
        if let Some(r) = &e.report {
            e.assessment = eval_report(r, &self.store.settings());
            e.life = Some(smart::lifespan(r, &e.assessment.status));
        }
        Some(e)
    }

    pub async fn inventory(&self, fresh: bool) -> Result<Arc<Inventory>, String> {
        let mut g = self.inv.lock().await;
        if let Some((inv, at)) = g.as_ref() {
            if !fresh && at.elapsed() < Duration::from_secs(15) {
                return Ok(inv.clone());
            }
        }
        let fut = call_as::<Inventory>(
            &*self.helper,
            Request {
                op: OP_INVENTORY.into(),
                ..Default::default()
            },
        );
        match tokio::time::timeout(Duration::from_secs(60), fut).await {
            Ok(Ok((inv, _))) => {
                let inv = Arc::new(inv);
                *g = Some((inv.clone(), Instant::now()));
                Ok(inv)
            }
            Ok(Err(e)) => g.as_ref().map(|(i, _)| i.clone()).ok_or(e.msg),
            Err(_) => g
                .as_ref()
                .map(|(i, _)| i.clone())
                .ok_or_else(|| "helper timed out".into()),
        }
    }

    pub async fn boot_report(
        &self,
        fresh: bool,
    ) -> Result<Arc<bootcheck::Report>, crate::helperclient::HelperError> {
        let mut g = self.boot.lock().await;
        if let Some((r, at)) = g.as_ref() {
            if !fresh && at.elapsed() < Duration::from_secs(30) {
                return Ok(r.clone());
            }
        }
        let (data, _) = call_as::<bootcheck::Data>(
            &*self.helper,
            Request {
                op: OP_BOOT_COLLECT.into(),
                ..Default::default()
            },
        )
        .await?;
        let inv = self.inventory(false).await.ok();
        let rep = Arc::new(bootcheck::analyze(&data, inv.as_deref()));
        *g = Some((rep.clone(), Instant::now()));
        Ok(rep)
    }

    /// Drops cached inventory and boot report after a write.
    pub async fn invalidate_caches(&self) {
        *self.inv.lock().await = None;
        *self.boot.lock().await = None;
    }

    /// Drops the cached boot report (fstab changed).
    pub async fn invalidate_boot(&self) {
        *self.boot.lock().await = None;
    }

    /// Checks the root filesystem for hidden data 30 s after start, then
    /// every 6 hours. Full scans (may wake sleeping disks) run on request.
    async fn hidden_loop(self: Arc<Self>) {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let mut t = tokio::time::interval(Duration::from_secs(6 * 3600));
        loop {
            t.tick().await;
            self.scan_hidden(false).await;
        }
    }

    pub async fn scan_hidden(&self, all: bool) {
        let req = Request {
            op: OP_HIDDEN_SCAN.into(),
            params: params(&HiddenScanParams { all }),
            ..Default::default()
        };
        let res = tokio::time::timeout(
            Duration::from_secs(180),
            call_as::<Vec<HiddenResult>>(&*self.helper, req),
        )
        .await;
        let mut h = self.hidden.lock().unwrap();
        match res {
            Ok(Ok((r, _))) => {
                *h = HiddenView {
                    results: r,
                    all,
                    checked_at: Some(Utc::now()),
                    error: String::new(),
                }
            }
            Ok(Err(e)) => h.error = e.msg,
            Err(_) => h.error = "hidden-data scan timed out".into(),
        }
    }

    pub fn hidden_snapshot(&self) -> HiddenView {
        self.hidden.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests;

/// Evaluates a SMART report with the user's thresholds and acknowledged
/// error counts.
/// How often the optional pool health watch runs.
const POOL_HEALTH_INTERVAL: Duration = Duration::from_secs(300);

/// Events for branches that went read-only (in `now`, not in `before`) or
/// recovered (the other way round). Both maps go from `"<pool>|<branch>"`
/// to the read-only reasons.
fn pool_transitions(
    before: &HashMap<String, String>,
    now: &HashMap<String, String>,
    devices: &HashMap<String, String>,
    stamp: DateTime<Utc>,
) -> Vec<events::Event> {
    let mut evs = vec![];
    for (k, why) in now {
        if !before.contains_key(k) {
            evs.push(pool_event(
                k,
                devices,
                stamp,
                "error",
                &format!("went read-only: {why}"),
            ));
        }
    }
    for k in before.keys() {
        if !now.contains_key(k) {
            evs.push(pool_event(k, devices, stamp, "info", "is writable again"));
        }
    }
    evs.sort_by(|a, b| a.message.cmp(&b.message));
    evs
}

/// An Events entry for a pool branch state change. `key` is
/// `"<pool>|<branch>"`.
fn pool_event(
    key: &str,
    devices: &HashMap<String, String>,
    time: DateTime<Utc>,
    severity: &str,
    what: &str,
) -> events::Event {
    let (pool, branch) = key.split_once('|').unwrap_or((key, ""));
    events::Event {
        cursor: format!("fsview-pool:{key}:{}", time.timestamp_micros()),
        time,
        category: events::CAT_POOL.into(),
        severity: severity.into(),
        device: devices.get(key).cloned().unwrap_or_default(),
        message: format!("Pool {pool}: branch {branch} {what}"),
        ..Default::default()
    }
}

fn eval_report(r: &smart::Report, s: &crate::store::Settings) -> smart::Assessment {
    smart::evaluate_with(r, &s.thresholds, s.acknowledged.get(&r.serial))
}

#[cfg(test)]
mod pool_watch_tests {
    use super::*;

    #[test]
    fn transitions() {
        let m = |v: &[(&str, &str)]| -> HashMap<String, String> {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        let dev = m(&[("/mnt/pool|/mnt/media5", "sdc1")]);
        let t = Utc::now();
        let evs = pool_transitions(
            &m(&[]),
            &m(&[("/mnt/pool|/mnt/media5", "mounted emergency_ro")]),
            &dev,
            t,
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].severity, "error");
        assert_eq!(evs[0].category, events::CAT_POOL);
        assert_eq!(evs[0].device, "sdc1");
        assert_eq!(
            evs[0].message,
            "Pool /mnt/pool: branch /mnt/media5 went read-only: mounted emergency_ro"
        );
        // unchanged: nothing; recovered: one info event
        let ro = m(&[("/mnt/pool|/mnt/media5", "x")]);
        assert!(pool_transitions(&ro, &ro, &dev, t).is_empty());
        let evs = pool_transitions(&ro, &m(&[]), &dev, t);
        assert_eq!(evs[0].severity, "info");
        assert!(evs[0].message.ends_with("is writable again"));
    }
}
