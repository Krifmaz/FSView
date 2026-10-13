use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;

use super::protect::Resolver;
use super::*;
use crate::runner::Runner;

/// Gathers an Inventory using external tools and sysfs.
pub struct Collector<'a> {
    pub runner: &'a dyn Runner,
    pub sysfs: Sysfs,
    pub proc_swaps: PathBuf,
    pub include_loop: bool,
    pub resolve: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub udev_data_dir: PathBuf,
    pci_names: Mutex<HashMap<String, String>>,
}

impl<'a> Collector<'a> {
    pub fn new(runner: &'a dyn Runner, include_loop: bool) -> Self {
        Collector {
            runner,
            sysfs: Sysfs::new("/sys"),
            proc_swaps: "/proc/swaps".into(),
            include_loop,
            resolve: Box::new(real_resolver),
            udev_data_dir: "/run/udev/data".into(),
            pci_names: Mutex::new(HashMap::new()),
        }
    }

    pub fn collect(&self) -> Result<Inventory, String> {
        let mut inv = Inventory {
            collected_at: Utc::now(),
            hostname: hostname(),
            ..Default::default()
        };
        let res = self
            .runner
            .run("lsblk", &LSBLK_ARGS)
            .map_err(|e| format!("lsblk: {e}"))?;
        if res.code != 0 {
            return Err(format!(
                "lsblk exited {}: {}",
                res.code,
                String::from_utf8_lossy(&res.stderr).trim()
            ));
        }
        let mut disks = parse_lsblk(&res.stdout, self.include_loop)?;

        if !self.udev_data_dir.exists() {
            // Without udev, lsblk cannot report filesystems. blkid probes
            // the devices directly (it reads them, so it is never used when
            // udev data exists: that would wake sleeping disks).
            if let Ok(r) = self
                .runner
                .run("blkid", &["-c", "/dev/null", "-o", "export"])
            {
                merge_blkid(
                    &mut disks,
                    &parse_blkid_export(&String::from_utf8_lossy(&r.stdout)),
                );
            }
            inv.warnings
                .push("udev database not found; filesystem details come from blkid probing".into());
        }

        let (sys, warns) = self.system_info();
        inv.warnings.extend(warns);
        let resolve: Resolver = &*self.resolve;
        mark_protected(&mut disks, &sys, resolve);

        let mut hbas: BTreeMap<String, Hba> = BTreeMap::new();
        for (host, pci) in self.sysfs.sas_hosts() {
            let h = hbas.entry(pci.clone()).or_insert_with(|| Hba {
                pci,
                ..Default::default()
            });
            if !h.hosts.contains(&host) {
                h.hosts.push(host);
            }
        }
        for d in disks.iter_mut() {
            d.topology = self.sysfs.topology(&d.name);
            if d.transport.is_empty() && d.topology.port.starts_with("usb") {
                d.transport = "usb".into();
            }
            let pci = d.topology.hba.clone();
            if pci.is_empty() {
                continue;
            }
            let h = hbas.entry(pci.clone()).or_insert_with(|| Hba {
                pci,
                ..Default::default()
            });
            if !d.topology.scsi_host.is_empty() && !h.hosts.contains(&d.topology.scsi_host) {
                h.hosts.push(d.topology.scsi_host.clone());
            }
            h.disks.push(d.name.clone());
            if h.driver.is_empty() {
                h.driver = d.topology.hba_driver.clone();
            }
        }
        for h in hbas.values_mut() {
            if h.driver.is_empty() {
                h.driver = self.sysfs.pci_driver(&h.pci);
            }
            h.name = self.pci_name(&h.pci);
            h.hosts.sort();
        }
        for d in disks.iter_mut() {
            if let Some(h) = hbas.get(&d.topology.hba) {
                d.topology.hba_name = h.name.clone();
            }
        }
        inv.hbas = hbas.into_values().collect();
        inv.disks = disks;
        inv.enclosures = self.sysfs.enclosures();
        let warns = self.enclosure_health(&mut inv.enclosures);
        inv.warnings.extend(warns);
        Ok(inv)
    }

    /// Mounts, swap, root VG PVs and root ZFS pool vdevs.
    fn system_info(&self) -> (SystemInfo, Vec<String>) {
        let mut sys = SystemInfo::default();
        let mut warns = Vec::new();
        match self
            .runner
            .run("findmnt", &["-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
        {
            Ok(r) if r.code == 0 => match parse_findmnt(&r.stdout) {
                Ok(m) => sys.mounts = m,
                Err(e) => warns.push(e),
            },
            _ => warns.push("findmnt failed; protected-disk detection relies on lsblk only".into()),
        }
        if let Ok(s) = std::fs::read_to_string(&self.proc_swaps) {
            sys.swap_devices = parse_proc_swaps(&s);
        }
        let Some(root) = sys.mounts.iter().find(|m| m.target == "/").cloned() else {
            return (sys, warns);
        };

        // LVM: protect every PV of the volume group holding /.
        if root.source.starts_with("/dev/mapper/") || root.source.starts_with("/dev/dm-") {
            let root_k = (self.resolve)(&root.source);
            if let Ok(r) = self.runner.run(
                "lvs",
                &["--reportformat", "json", "-o", "vg_name,lv_dm_path"],
            ) {
                if r.code == 0 {
                    let rows = parse_lvm_report(&r.stdout, "lv").unwrap_or_default();
                    let vg = rows
                        .iter()
                        .filter(|r| {
                            let p = r.get("lv_dm_path").map(String::as_str).unwrap_or("");
                            !p.is_empty() && (p == root.source || (self.resolve)(p) == root_k)
                        })
                        .filter_map(|r| r.get("vg_name").cloned())
                        .last();
                    if let Some(vg) = vg {
                        if let Ok(p) = self
                            .runner
                            .run("pvs", &["--reportformat", "json", "-o", "pv_name,vg_name"])
                        {
                            for row in parse_lvm_report(&p.stdout, "pv").unwrap_or_default() {
                                if row.get("vg_name") == Some(&vg) {
                                    if let Some(pv) = row.get("pv_name") {
                                        sys.extra_system_devices
                                            .insert(pv.clone(), format!("LVM PV of root VG {vg}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ZFS root (Proxmox "rpool" installs): protect every vdev.
        for m in sys.mounts.clone() {
            if m.fstype != "zfs" || !(m.target == "/" || m.target == "/boot") {
                continue;
            }
            let pool = m.source.split('/').next().unwrap_or("").to_string();
            match self.runner.run("zpool", &["list", "-v", "-H", "-P", &pool]) {
                Ok(r) if r.code == 0 => {
                    for dev in parse_zpool_vdevs(&String::from_utf8_lossy(&r.stdout)) {
                        sys.extra_system_devices
                            .insert(dev, format!("vdev of root ZFS pool {pool}"));
                    }
                }
                _ => warns.push(format!("could not list vdevs of root pool {pool}")),
            }
        }
        (sys, warns)
    }

    fn pci_name(&self, pci: &str) -> String {
        if let Some(n) = self.pci_names.lock().unwrap().get(pci) {
            return n.clone();
        }
        let name = match self.runner.run("lspci", &["-mm", "-s", pci]) {
            Ok(r) if r.code == 0 => parse_lspci_name(&String::from_utf8_lossy(&r.stdout)),
            _ => String::new(),
        };
        self.pci_names
            .lock()
            .unwrap()
            .insert(pci.to_string(), name.clone());
        name
    }

    /// Adds sg_ses element status to each enclosure. SES queries go to the
    /// enclosure processor, never to disks.
    fn enclosure_health(&self, encs: &mut [Enclosure]) -> Vec<String> {
        let re = regex::Regex::new(r"^sg[0-9]{1,4}$").unwrap();
        let mut warns = Vec::new();
        for e in encs.iter_mut() {
            let sg = self.sysfs.sg_for_enclosure(&e.id);
            if !re.is_match(&sg) {
                continue;
            }
            e.sg_device = sg.clone();
            match self
                .runner
                .run("sg_ses", &["-p", "0x2", &format!("/dev/{sg}")])
            {
                Ok(r) if r.code == 0 => {
                    e.elements = parse_ses_status(&String::from_utf8_lossy(&r.stdout));
                    e.status = enclosure_level(&e.elements);
                }
                Ok(r) => warns.push(format!("sg_ses on {sg} exited {}", r.code)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => warns.push(format!("sg_ses on {sg}: {err}")),
            }
        }
        warns
    }
}

pub fn hostname() -> String {
    nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `lspci -mm` line: 0c:00.0 "Class" "Vendor" "Device" -r05 ...
pub fn parse_lspci_name(line: &str) -> String {
    let fields: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
    if fields.len() < 3 {
        return String::new();
    }
    format!("{} {}", fields[1], fields[2]).trim().to_string()
}

/// `blkid -o export` output: device -> tags.
pub fn parse_blkid_export(out: &str) -> HashMap<String, HashMap<String, String>> {
    let mut res = HashMap::new();
    let mut cur: HashMap<String, String> = HashMap::new();
    for line in out.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.is_empty() {
            if let Some(dev) = cur.get("DEVNAME").cloned() {
                res.insert(dev, std::mem::take(&mut cur));
            }
            cur.clear();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.insert(k.to_string(), v.to_string());
        }
    }
    res
}

/// Fills empty filesystem fields from blkid tags.
pub fn merge_blkid(disks: &mut [Disk], tags: &HashMap<String, HashMap<String, String>>) {
    fn fill(
        t: &HashMap<String, String>,
        fstype: &mut String,
        label: &mut String,
        uuid: &mut String,
    ) {
        for (dst, k) in [(fstype, "TYPE"), (label, "LABEL"), (uuid, "UUID")] {
            if dst.is_empty() {
                *dst = t.get(k).cloned().unwrap_or_default();
            }
        }
    }
    for d in disks.iter_mut() {
        if let Some(t) = tags.get(&d.path) {
            fill(t, &mut d.fstype, &mut d.label, &mut d.uuid);
        }
        d.walk_mut(&mut |n| {
            if let Some(t) = tags.get(&n.path) {
                fill(t, &mut n.fstype, &mut n.label, &mut n.uuid);
                if n.partuuid.is_empty() {
                    n.partuuid = t.get("PARTUUID").cloned().unwrap_or_default();
                }
            }
        });
    }
}
