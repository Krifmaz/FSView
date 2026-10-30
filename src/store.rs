//! Small persistent state (users, sessions, settings) in JSON files that
//! are written atomically with mode 0600.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth;
use crate::smart::{Ack, Thresholds};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub thresholds: Thresholds,
    pub late_device_sec: i64,
    pub event_retention: usize,
    /// Enclosure elements the user marked as expected (keys from
    /// `EnclosureElement::key`), e.g. empty PSU bays.
    pub ignored_elements: Vec<String>,
    /// Run non-destructive actions (mount, unmount, self-tests, rename...)
    /// without a confirmation dialog. Destructive ones always need the
    /// typed confirmation.
    pub skip_confirm: bool,
    /// Acknowledged SMART error counts by disk serial number.
    pub acknowledged: HashMap<String, Ack>,
    /// Every minute, remount pool disks that dropped out and came
    /// back healthy, and undo read-only branches mergerfs set.
    pub auto_heal_pools: bool,
    /// Every 5 minutes, check pool branches and record an event when one
    /// goes read-only (and when it recovers).
    pub pool_health_watch: bool,
    /// Protect SMR disks (queue depth 1, long timeout, small writeback
    /// batches), re-applied every minute so it survives disk re-attaches.
    pub smr_protection: bool,
    /// Per-disk SMR override by serial: true = treat as SMR, false = never.
    /// Disks without an entry follow the known-model list.
    pub smr_overrides: HashMap<String, bool>,
    /// Let auto-heal fsck a pool branch whose filesystem recorded errors
    /// (detached from the running pool meanwhile).
    pub auto_repair_branches: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            thresholds: Thresholds::default(),
            late_device_sec: 60,
            event_retention: 20000,
            ignored_elements: vec![],
            skip_confirm: false,
            acknowledged: HashMap::new(),
            auto_heal_pools: true,
            pool_health_watch: false,
            smr_protection: true,
            smr_overrides: HashMap::new(),
            auto_repair_branches: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    users: Vec<User>,
    settings: Settings,
    #[serde(skip_serializing_if = "String::is_empty")]
    journal_cursor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token_hash: String,
    pub user: String,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub client_ip: String,
}

pub const SESSION_IDLE: Duration = Duration::from_secs(12 * 3600);
pub const SESSION_ABSOLUTE: Duration = Duration::from_secs(7 * 24 * 3600);

struct Inner {
    st: State,
    sessions: HashMap<String, Session>,
    last_save: DateTime<Utc>,
}

pub struct Store {
    dir: PathBuf,
    inner: Mutex<Inner>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Writes JSON via a temporary file, fsync and rename.
pub fn write_json_atomic<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".tmp-{}", hex::encode(auth::random_bytes::<6>())));
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("{}: {e}", path.display()))
}

fn hash_token(tok: &str) -> String {
    hex::encode(Sha256::digest(tok.as_bytes()))
}

fn user_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[a-z_][a-z0-9_.-]{0,31}$").unwrap())
}

/// Bounds concurrent argon2id verifications (64 MiB each) so a burst of
/// logins cannot exhaust memory.
static VERIFY_SLOTS: Mutex<u32> = Mutex::new(0);
static VERIFY_CV: std::sync::Condvar = std::sync::Condvar::new();
const MAX_VERIFY: u32 = 2;

fn with_verify_slot<T>(f: impl FnOnce() -> T) -> T {
    let mut n = VERIFY_SLOTS.lock().unwrap();
    while *n >= MAX_VERIFY {
        n = VERIFY_CV.wait(n).unwrap();
    }
    *n += 1;
    drop(n);
    let out = f();
    *VERIFY_SLOTS.lock().unwrap() -= 1;
    VERIFY_CV.notify_one();
    out
}

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| auth::hash_password("fsview-dummy-password").unwrap_or_default())
}

fn chrono_dur(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

impl Store {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Store, String> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let mut st: State = read_json(&dir.join("state.json"))?.unwrap_or_default();
        if st.settings.event_retention == 0 {
            st.settings.event_retention = 20000;
        }
        let sessions: Vec<Session> = read_json(&dir.join("sessions.json"))?.unwrap_or_default();
        Ok(Store {
            dir,
            inner: Mutex::new(Inner {
                st,
                sessions: sessions
                    .into_iter()
                    .map(|s| (s.token_hash.clone(), s))
                    .collect(),
                last_save: Utc::now(),
            }),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn save_state(&self, i: &Inner) -> Result<(), String> {
        write_json_atomic(&self.dir.join("state.json"), &i.st)
    }

    fn save_sessions(&self, i: &mut Inner) -> Result<(), String> {
        i.last_save = Utc::now();
        let l: Vec<&Session> = i.sessions.values().collect();
        write_json_atomic(&self.dir.join("sessions.json"), &l)
    }

    // ---- users ----

    pub fn set_password(&self, name: &str, password: &str, create: bool) -> Result<(), String> {
        if !user_re().is_match(name) {
            return Err(format!("invalid user name {name:?}"));
        }
        if password.chars().count() < 10 {
            return Err("password must be at least 10 characters".into());
        }
        let h = auth::hash_password(password)?;
        let mut i = self.inner.lock().unwrap();
        if let Some(u) = i.st.users.iter_mut().find(|u| u.name == name) {
            u.hash = h;
            i.sessions.retain(|_, s| s.user != name);
            self.save_sessions(&mut i)?;
            return self.save_state(&i);
        }
        if !create {
            return Err("not found".into());
        }
        i.st.users.push(User {
            name: name.into(),
            hash: h,
            created_at: Utc::now(),
        });
        self.save_state(&i)
    }

    pub fn delete_user(&self, name: &str) -> Result<(), String> {
        let mut i = self.inner.lock().unwrap();
        let before = i.st.users.len();
        i.st.users.retain(|u| u.name != name);
        if i.st.users.len() == before {
            return Err("not found".into());
        }
        i.sessions.retain(|_, s| s.user != name);
        self.save_sessions(&mut i)?;
        self.save_state(&i)
    }

    pub fn users(&self) -> Vec<User> {
        let mut u = self.inner.lock().unwrap().st.users.clone();
        u.sort_by(|a, b| a.name.cmp(&b.name));
        u
    }

    /// Verifies credentials (same cost whether or not the user exists).
    pub fn check_password(&self, name: &str, password: &str) -> bool {
        let hash = self
            .inner
            .lock()
            .unwrap()
            .st
            .users
            .iter()
            .find(|u| u.name == name)
            .map(|u| u.hash.clone());
        with_verify_slot(|| match hash {
            Some(h) => auth::verify_password(password, &h).unwrap_or(false),
            None => {
                let _ = auth::verify_password(password, dummy_hash());
                false
            }
        })
    }

    // ---- sessions ----

    pub fn create_session(&self, user: &str, ip: &str) -> Result<String, String> {
        let tok = auth::random_token();
        let now = Utc::now();
        let mut i = self.inner.lock().unwrap();
        let th = hash_token(&tok);
        i.sessions.insert(
            th.clone(),
            Session {
                token_hash: th,
                user: user.into(),
                created_at: now,
                last_seen: now,
                client_ip: ip.into(),
            },
        );
        self.save_sessions(&mut i)?;
        Ok(tok)
    }

    /// Validates a token and refreshes its idle timer.
    pub fn session(&self, tok: &str) -> Option<Session> {
        if tok.is_empty() {
            return None;
        }
        let h = hash_token(tok);
        let now = Utc::now();
        let mut i = self.inner.lock().unwrap();
        let s = i.sessions.get(&h)?.clone();
        let exists = i.st.users.iter().any(|u| u.name == s.user);
        if now - s.last_seen > chrono_dur(SESSION_IDLE)
            || now - s.created_at > chrono_dur(SESSION_ABSOLUTE)
            || !exists
        {
            i.sessions.remove(&h);
            let _ = self.save_sessions(&mut i);
            return None;
        }
        if let Some(x) = i.sessions.get_mut(&h) {
            x.last_seen = now;
        }
        if now - i.last_save > chrono::Duration::minutes(1) {
            let _ = self.save_sessions(&mut i);
        }
        i.sessions.get(&h).cloned()
    }

    pub fn delete_session(&self, tok: &str) {
        let mut i = self.inner.lock().unwrap();
        i.sessions.remove(&hash_token(tok));
        let _ = self.save_sessions(&mut i);
    }

    #[cfg(test)]
    fn age_sessions(&self, by: Duration) {
        let mut i = self.inner.lock().unwrap();
        for s in i.sessions.values_mut() {
            s.last_seen -= chrono_dur(by);
        }
    }

    // ---- settings & cursor ----

    pub fn settings(&self) -> Settings {
        self.inner.lock().unwrap().st.settings.clone()
    }

    pub fn set_settings(&self, v: Settings) -> Result<(), String> {
        let mut i = self.inner.lock().unwrap();
        i.st.settings = v;
        self.save_state(&i)
    }

    pub fn journal_cursor(&self) -> String {
        self.inner.lock().unwrap().st.journal_cursor.clone()
    }

    pub fn set_journal_cursor(&self, c: &str) -> Result<(), String> {
        let mut i = self.inner.lock().unwrap();
        if i.st.journal_cursor == c {
            return Ok(());
        }
        i.st.journal_cursor = c.into();
        self.save_state(&i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_and_sessions() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        assert!(s.set_password("admin", "short", true).is_err());
        assert!(s.set_password("Bad Name", "longenoughpw", true).is_err());
        s.set_password("admin", "longenoughpw", true).unwrap();
        assert!(s.check_password("admin", "longenoughpw"));
        assert!(!s.check_password("admin", "nope"));
        assert!(!s.check_password("ghost", "longenoughpw"));
        let tok = s.create_session("admin", "192.168.1.2").unwrap();
        assert_eq!(s.session(&tok).unwrap().user, "admin");
        let raw = fs::read_to_string(d.path().join("sessions.json")).unwrap();
        assert!(
            !raw.is_empty() && !raw.contains(&tok),
            "token stored in clear text"
        );
        let s2 = Store::open(d.path()).unwrap();
        assert!(s2.session(&tok).is_some(), "session lost across restart");
        s2.set_password("admin", "anotherlongpw", false).unwrap();
        assert!(
            s2.session(&tok).is_none(),
            "session survived password change"
        );
        let tok2 = s2.create_session("admin", "x").unwrap();
        s2.age_sessions(SESSION_IDLE + Duration::from_secs(60));
        assert!(s2.session(&tok2).is_none(), "idle session accepted");
        let mode = fs::metadata(d.path().join("state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
