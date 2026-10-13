//! Simple `key = value` configuration files.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct Values(pub HashMap<String, String>);

pub fn parse(text: &str) -> Result<Values, String> {
    let mut v = HashMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (k, val) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key = value", i + 1))?;
        v.insert(k.trim().to_lowercase(), val.trim().to_string());
    }
    Ok(Values(v))
}

/// Loads a file; a missing file yields empty values.
pub fn load(path: &Path) -> Result<Values, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Values::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

impl Values {
    pub fn string(&self, k: &str, def: &str) -> String {
        match self.0.get(k) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => def.to_string(),
        }
    }
    pub fn boolean(&self, k: &str, def: bool) -> Result<bool, String> {
        match self.0.get(k).map(|s| s.to_lowercase()) {
            None => Ok(def),
            Some(s) if s.is_empty() => Ok(def),
            Some(s) => match s.as_str() {
                "1" | "true" | "yes" | "on" | "enabled" => Ok(true),
                "0" | "false" | "no" | "off" | "disabled" => Ok(false),
                _ => Err(format!("{k}: invalid boolean {s:?}")),
            },
        }
    }
    pub fn int(&self, k: &str, def: i64) -> Result<i64, String> {
        match self.0.get(k) {
            None => Ok(def),
            Some(s) if s.is_empty() => Ok(def),
            Some(s) => s.parse().map_err(|_| format!("{k}: invalid integer {s:?}")),
        }
    }
    pub fn duration(&self, k: &str, def: Duration) -> Result<Duration, String> {
        match self.0.get(k) {
            None => Ok(def),
            Some(s) if s.is_empty() => Ok(def),
            Some(s) => parse_duration(s).ok_or_else(|| format!("{k}: invalid duration {s:?}")),
        }
    }
    pub fn list(&self, k: &str) -> Vec<String> {
        self.0
            .get(k)
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Parses "30m", "3s", "1h30m", "500ms".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let re = regex::Regex::new(r"^(?:(\d+(?:\.\d+)?)(ms|s|m|h))+$").ok()?;
    if !re.is_match(s) {
        return None;
    }
    let part = regex::Regex::new(r"(\d+(?:\.\d+)?)(ms|s|m|h)").ok()?;
    let mut total = 0f64;
    for c in part.captures_iter(s) {
        let n: f64 = c[1].parse().ok()?;
        total += n * match &c[2] {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            _ => 3600.0,
        };
    }
    Some(Duration::from_secs_f64(total))
}

#[derive(Debug, Clone)]
pub struct Web {
    pub listen: Vec<String>,
    pub port: u16,
    pub allow: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub data_dir: String,
    pub helper_socket: String,
    pub smart_poll: Duration,
    pub journal_poll: Duration,
}

pub fn load_web(path: &Path) -> Result<Web, String> {
    let v = load(path)?;
    let mut w = Web {
        listen: v.list("listen"),
        port: v
            .int("port", 9200)?
            .try_into()
            .map_err(|_| "port out of range".to_string())?,
        allow: v.list("allow"),
        tls_cert: v.string("tls_cert", ""),
        tls_key: v.string("tls_key", ""),
        data_dir: v.string("data_dir", "/var/lib/fsview"),
        helper_socket: v.string("helper_socket", "/run/fsview/helper.sock"),
        smart_poll: v.duration("smart_poll", Duration::from_secs(1800))?,
        journal_poll: v.duration("journal_poll", Duration::from_secs(3))?,
    };
    if w.listen.is_empty() {
        w.listen = vec!["auto".into()];
    }
    if w.allow.is_empty() {
        w.allow = vec!["auto".into()];
    }
    if w.tls_cert.is_empty() != w.tls_key.is_empty() {
        return Err("tls_cert and tls_key must be set together".into());
    }
    Ok(w)
}

/// Root-owned helper configuration; the web process cannot change it.
#[derive(Debug, Clone)]
pub struct Helper {
    pub socket: String,
    pub client_user: String,
    pub writes_enabled: bool,
    pub audit_log: String,
    pub include_loop: bool,
}

pub fn load_helper(path: &Path) -> Result<Helper, String> {
    let v = load(path)?;
    Ok(Helper {
        socket: v.string("socket", "/run/fsview/helper.sock"),
        client_user: v.string("client_user", "fsview"),
        writes_enabled: v.boolean("writes_enabled", false)?,
        audit_log: v.string("audit_log", "/var/log/fsview/audit.log"),
        include_loop: v.boolean("include_loop_devices", false)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_values() {
        let v =
            parse("# c\nListen = 192.168.1.5 , 10.0.0.1\nport=9300 # x\n\nwrites_enabled = yes\n")
                .unwrap();
        assert_eq!(v.list("listen"), vec!["192.168.1.5", "10.0.0.1"]);
        assert_eq!(v.int("port", 1).unwrap(), 9300);
        assert!(v.boolean("writes_enabled", false).unwrap());
        assert!(parse("nonsense\n").is_err());
    }

    #[test]
    fn defaults() {
        let d = tempfile::tempdir().unwrap();
        let w = load_web(&d.path().join("missing")).unwrap();
        assert_eq!(w.port, 9200);
        assert_eq!(w.listen, vec!["auto"]);
        assert_eq!(w.smart_poll, Duration::from_secs(1800));
        assert!(
            !load_helper(&d.path().join("missing"))
                .unwrap()
                .writes_enabled,
            "writes must default to off"
        );
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("10 bananas"), None);
    }
}
