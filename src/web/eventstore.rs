use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use tokio::sync::broadcast;

use crate::events::Event;

/// Classified disk events in memory, persisted as JSON lines.
pub struct EventStore {
    path: PathBuf,
    max: usize,
    inner: Mutex<Inner>,
    tx: broadcast::Sender<Event>,
}

struct Inner {
    events: Vec<Event>, // oldest first
    seen: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct Filter {
    pub severity: String,
    pub category: String,
    pub device: String,
    pub query: String,
    pub since: Option<DateTime<Utc>>,
    pub limit: usize,
}

impl EventStore {
    pub fn open(dir: &Path, max: usize) -> EventStore {
        let max = if max == 0 { 20000 } else { max };
        let (tx, _) = broadcast::channel(256);
        let s = EventStore {
            path: dir.join("events.jsonl"),
            max,
            inner: Mutex::new(Inner {
                events: vec![],
                seen: HashSet::new(),
            }),
            tx,
        };
        if let Ok(f) = fs::File::open(&s.path) {
            let mut i = s.inner.lock().unwrap();
            for e in BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str::<Event>(&l).ok())
            {
                if i.seen.insert(e.cursor.clone()) {
                    i.events.push(e);
                }
            }
            s.trim(&mut i, true);
        }
        s
    }

    /// Stores new events (duplicates by cursor are ignored), notifies
    /// subscribers.
    pub fn add(&self, evs: Vec<Event>) {
        let mut i = self.inner.lock().unwrap();
        let fresh: Vec<Event> = evs
            .into_iter()
            .filter(|e| e.cursor.is_empty() || i.seen.insert(e.cursor.clone()))
            .collect();
        if fresh.is_empty() {
            return;
        }
        if let Ok(f) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            let mut w = BufWriter::new(f);
            for e in &fresh {
                if let Ok(b) = serde_json::to_vec(e) {
                    let _ = w.write_all(&b);
                    let _ = w.write_all(b"\n");
                }
            }
        }
        i.events.extend(fresh.iter().cloned());
        self.trim(&mut i, false);
        drop(i);
        for e in fresh {
            let _ = self.tx.send(e);
        }
    }

    fn trim(&self, i: &mut Inner, force: bool) {
        if i.events.len() > self.max {
            let cut = i.events.len() - self.max;
            for e in i.events.drain(..cut) {
                i.seen.remove(&e.cursor);
            }
        }
        // Rewrite the file once it has grown well past the cap.
        let big = fs::metadata(&self.path)
            .map(|m| m.len() > self.max as u64 * 600)
            .unwrap_or(false);
        if force || big {
            let tmp = self.path.with_extension("jsonl.tmp");
            if let Ok(f) = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
            {
                let mut w = BufWriter::new(f);
                for e in &i.events {
                    if let Ok(b) = serde_json::to_vec(e) {
                        let _ = w.write_all(&b);
                        let _ = w.write_all(b"\n");
                    }
                }
                drop(w);
                let _ = fs::rename(&tmp, &self.path);
            }
        }
    }

    /// Matching events, newest first.
    pub fn list(&self, f: &Filter) -> Vec<Event> {
        let limit = if f.limit == 0 || f.limit > 5000 {
            500
        } else {
            f.limit
        };
        let q = f.query.to_lowercase();
        let i = self.inner.lock().unwrap();
        i.events
            .iter()
            .rev()
            .filter(|e| f.severity.is_empty() || e.severity == f.severity)
            .filter(|e| f.category.is_empty() || e.category == f.category)
            .filter(|e| f.device.is_empty() || e.device.starts_with(&f.device))
            .filter(|e| f.since.is_none_or(|s| e.time >= s))
            .filter(|e| q.is_empty() || e.message.to_lowercase().contains(&q))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Events per severity since `since`.
    pub fn counts(&self, since: DateTime<Utc>) -> std::collections::BTreeMap<String, usize> {
        let mut c: std::collections::BTreeMap<String, usize> = ["error", "warn", "info"]
            .iter()
            .map(|k| (k.to_string(), 0))
            .collect();
        let i = self.inner.lock().unwrap();
        for e in i.events.iter().rev().take_while(|e| e.time >= since) {
            *c.entry(e.severity.clone()).or_default() += 1;
        }
        c
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}
