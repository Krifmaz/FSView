//! Runs external tools directly (never through a shell) with a fixed
//! environment.

use std::collections::HashMap;
use std::io;
use std::process::Command;
use std::sync::Mutex;

/// Outcome of a command. A non-zero exit code is not an error: smartctl in
/// particular reports disk state through exit bits.
#[derive(Debug, Clone, Default)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: i32,
}

pub trait Runner: Send + Sync {
    fn run(&self, name: &str, args: &[&str]) -> io::Result<Output>;
}

/// Environment given to every child process.
pub const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub struct Exec;

impl Runner for Exec {
    fn run(&self, name: &str, args: &[&str]) -> io::Result<Output> {
        let out = Command::new(name)
            .args(args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .output()?;
        Ok(Output {
            stdout: out.stdout,
            stderr: out.stderr,
            code: out.status.code().unwrap_or(-1),
        })
    }
}

/// Renders a command line for display and the audit log.
pub fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|p| {
            if p.is_empty() || p.chars().any(|c| " \t\"'\\$`".contains(c)) {
                format!("{p:?}")
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Test runner keyed by the full command line.
#[derive(Default)]
pub struct Fake {
    pub responses: Mutex<HashMap<String, Output>>,
    pub calls: Mutex<Vec<String>>,
}

impl Fake {
    pub fn new(pairs: Vec<(&str, Output)>) -> Self {
        let f = Fake::default();
        for (k, v) in pairs {
            f.responses.lock().unwrap().insert(k.to_string(), v);
        }
        f
    }
    pub fn ok(stdout: &[u8]) -> Output {
        Output {
            stdout: stdout.to_vec(),
            ..Default::default()
        }
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Runner for Fake {
    fn run(&self, name: &str, args: &[&str]) -> io::Result<Output> {
        let mut key = name.to_string();
        for a in args {
            key.push(' ');
            key.push_str(a);
        }
        self.calls.lock().unwrap().push(key.clone());
        self.responses
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name}: not found")))
    }
}
