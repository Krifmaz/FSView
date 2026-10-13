use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use super::{Enclosure, EnclosureComponent, EnclosureSlot, Topology};

/// Reads topology from a sysfs tree: "/sys" in production, a temporary
/// directory in tests.
#[derive(Debug, Clone)]
pub struct Sysfs {
    pub root: PathBuf,
}

struct Res {
    pci: Regex,
    host: Regex,
    ata: Regex,
    usb: Regex,
    expander: Regex,
    end_dev: Regex,
    nvme_ctl: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        pci: Regex::new(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$").unwrap(),
        host: Regex::new(r"^host[0-9]+$").unwrap(),
        ata: Regex::new(r"^ata[0-9]+$").unwrap(),
        usb: Regex::new(r"^[0-9]+-[0-9.]+$").unwrap(),
        expander: Regex::new(r"^expander-[0-9:]+$").unwrap(),
        end_dev: Regex::new(r"^end_device-[0-9:]+$").unwrap(),
        nvme_ctl: Regex::new(r"^nvme[0-9]+$").unwrap(),
    })
}

pub(crate) fn read_trim(p: &Path) -> String {
    fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn read_int(p: &Path) -> Option<i64> {
    read_trim(p).parse().ok()
}

fn base(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn glob_prefix(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| base(p).starts_with(prefix))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

impl Sysfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Sysfs { root: root.into() }
    }

    fn path(&self, parts: &[&str]) -> PathBuf {
        let mut p = self.root.clone();
        for x in parts {
            p.push(x);
        }
        p
    }

    fn real_root(&self) -> PathBuf {
        fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone())
    }

    /// Resolves where block device `name` is attached.
    pub fn topology(&self, name: &str) -> Topology {
        let mut t = Topology::default();
        let Ok(real) = fs::canonicalize(self.path(&["block", name])) else {
            return t;
        };
        let root = self.real_root();
        let rel = real
            .strip_prefix(&root)
            .unwrap_or(&real)
            .to_string_lossy()
            .into_owned();
        t.devpath = format!("/{}", rel.trim_start_matches('/'));
        let segs: Vec<&str> = rel.trim_matches('/').split('/').collect();
        let r = res();
        let mut last_pci: Option<usize> = None;
        let mut hba_idx: Option<usize> = None;
        for (i, seg) in segs.iter().enumerate() {
            if r.pci.is_match(seg) {
                last_pci = Some(i);
            } else if r.host.is_match(seg) && t.scsi_host.is_empty() {
                t.scsi_host = seg.to_string();
                if let Some(p) = last_pci {
                    t.hba = segs[p].to_string();
                    hba_idx = Some(p);
                }
            } else if r.nvme_ctl.is_match(seg) && i > 0 && segs[i - 1] == "nvme" && t.hba.is_empty()
            {
                if let Some(p) = last_pci {
                    t.hba = segs[p].to_string();
                    hba_idx = Some(p);
                }
                t.port = seg.to_string();
            } else if r.ata.is_match(seg) {
                t.port = seg.to_string();
            } else if r.usb.is_match(seg) && t.scsi_host.is_empty() {
                t.port = format!("usb {seg}");
            } else if r.expander.is_match(seg) {
                t.expander = seg.to_string();
            } else if r.end_dev.is_match(seg) {
                t.end_device = seg.to_string();
            }
        }
        if let Some(p) = hba_idx {
            let pci_dir = root.join(segs[..=p].join("/"));
            if let Ok(drv) = fs::read_link(pci_dir.join("driver")) {
                t.hba_driver = base(&drv);
            }
        }
        let dev_dir = self.path(&["block", name, "device"]);
        t.sas_address = read_trim(&dev_dir.join("sas_address"));
        if !t.end_device.is_empty() {
            t.bay_id =
                read_int(&self.path(&["class", "sas_device", &t.end_device, "bay_identifier"]));
        }
        t.enclosure = self.enclosure_slot(&dev_dir);
        t
    }

    /// Follows the "enclosure_device:<component>" link the ses driver
    /// creates in the SCSI device directory.
    fn enclosure_slot(&self, dev_dir: &Path) -> Option<EnclosureSlot> {
        let m = glob_prefix(dev_dir, "enclosure_device:")
            .into_iter()
            .next()?;
        let comp = fs::canonicalize(&m).ok()?;
        Some(EnclosureSlot {
            enclosure: base(comp.parent()?),
            component: base(&m).trim_start_matches("enclosure_device:").to_string(),
            slot: read_int(&comp.join("slot")),
            status: read_trim(&comp.join("status")),
            fault: read_trim(&comp.join("fault")) == "1",
            locate: read_trim(&comp.join("locate")) == "1",
        })
    }

    /// Lists SES enclosures and their components.
    pub fn enclosures(&self) -> Vec<Enclosure> {
        let mut out = Vec::new();
        for d in glob_prefix(&self.path(&["class", "enclosure"]), "") {
            let mut e = Enclosure {
                id: base(&d),
                logical_id: read_trim(&d.join("id")),
                vendor: read_trim(&d.join("device/vendor")),
                model: read_trim(&d.join("device/model")),
                ..Default::default()
            };
            for cd in glob_prefix(&d, "") {
                if !cd.is_dir() || !(cd.join("status").exists() || cd.join("slot").exists()) {
                    continue;
                }
                let disk = glob_prefix(&cd.join("device/block"), "")
                    .into_iter()
                    .next()
                    .map(|p| base(&p))
                    .unwrap_or_default();
                e.components.push(EnclosureComponent {
                    name: base(&cd),
                    slot: read_int(&cd.join("slot")),
                    status: read_trim(&cd.join("status")),
                    fault: read_trim(&cd.join("fault")) == "1",
                    locate: read_trim(&cd.join("locate")) == "1",
                    active: read_trim(&cd.join("active")) == "1",
                    disk,
                });
            }
            e.components.sort_by(|a, b| match (a.slot, b.slot) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => a.name.cmp(&b.name),
            });
            out.push(e);
        }
        out
    }

    /// Maps SCSI host names (host2) to PCI addresses, so HBAs without
    /// disks still show up.
    pub fn sas_hosts(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let root = self.real_root();
        for d in glob_prefix(&self.path(&["class", "sas_host"]), "") {
            let Ok(real) = fs::canonicalize(&d) else {
                continue;
            };
            let rel = real
                .strip_prefix(&root)
                .unwrap_or(&real)
                .to_string_lossy()
                .into_owned();
            let mut pci = String::new();
            for seg in rel.trim_matches('/').split('/') {
                if res().pci.is_match(seg) {
                    pci = seg.to_string();
                }
                if res().host.is_match(seg) {
                    break;
                }
            }
            if !pci.is_empty() {
                out.insert(base(&d), pci);
            }
        }
        out
    }

    pub fn pci_driver(&self, pci: &str) -> String {
        fs::read_link(self.path(&["bus", "pci", "devices", pci, "driver"]))
            .map(|p| base(&p))
            .unwrap_or_default()
    }

    /// SCSI generic device (sgN) of an enclosure with SCSI address `id`.
    pub fn sg_for_enclosure(&self, id: &str) -> String {
        for d in glob_prefix(&self.path(&["class", "scsi_generic"]), "sg") {
            if read_trim(&d.join("device/type")) != "13" {
                continue;
            }
            if let Ok(real) = fs::canonicalize(d.join("device")) {
                if base(&real) == id {
                    return base(&d);
                }
            }
        }
        String::new()
    }
}
