//! Picture of the host's disks from lsblk, sysfs, findmnt and sg_ses, plus
//! the decision which disks are protected system disks.

mod collect;
mod lsblk;
mod protect;
mod ses;
mod sysfs;

pub use collect::{hostname, merge_blkid, parse_blkid_export, parse_lspci_name, Collector};
pub use lsblk::{display_model, parse_lsblk, LSBLK_ARGS};
pub use protect::{
    mark_protected, parse_findmnt, parse_lvm_report, parse_proc_swaps, parse_zpool_vdevs,
    real_resolver, Mount, SystemInfo, SYSTEM_MOUNTPOINTS,
};
pub use ses::{enclosure_level, parse_ses_status, EnclosureElement};
pub use sysfs::Sysfs;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub hostname: String,
    pub collected_at: DateTime<Utc>,
    pub disks: Vec<Disk>,
    pub hbas: Vec<Hba>,
    pub enclosures: Vec<Enclosure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Inventory {
    pub fn find_disk(&self, name: &str) -> Option<&Disk> {
        self.disks.iter().find(|d| d.name == name)
    }
}

/// A whole block device (type "disk", or "loop" when enabled for tests).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Disk {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wwn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
    pub size_bytes: u64,
    pub transport: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hctl: String,
    pub rotational: bool,
    pub removable: bool,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pttype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fstype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fsver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mountpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
    pub topology: Topology,
    pub protected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_reasons: Vec<String>,
}

impl Disk {
    /// Visits every node below the disk, depth first.
    pub fn walk<'a>(&'a self, f: &mut dyn FnMut(&'a Node)) {
        fn rec<'a>(ns: &'a [Node], f: &mut dyn FnMut(&'a Node)) {
            for n in ns {
                f(n);
                rec(&n.children, f);
            }
        }
        rec(&self.children, f);
    }

    pub fn walk_mut(&mut self, f: &mut dyn FnMut(&mut Node)) {
        fn rec(ns: &mut [Node], f: &mut dyn FnMut(&mut Node)) {
            for n in ns {
                f(n);
                rec(&mut n.children, f);
            }
        }
        rec(&mut self.children, f);
    }
}

/// Anything below a disk: partitions, LVM volumes, md arrays, crypt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub kname: String,
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fstype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fsver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub partuuid: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub partlabel: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parttypename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partn: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mountpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Usage {
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub avail_bytes: u64,
}

/// Where a disk physically lives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Topology {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub devpath: String,
    /// PCI address of the controller.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hba: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hba_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hba_driver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scsi_host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expander: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub end_device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sas_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bay_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclosure: Option<EnclosureSlot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclosureSlot {
    pub enclosure: String,
    pub component: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fault: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub locate: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hba {
    pub pci: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub driver: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Enclosure {
    /// SCSI address of the SES device.
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logical_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    pub components: Vec<EnclosureComponent>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sg_device: String,
    /// ok | warn | crit (from sg_ses)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<EnclosureElement>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclosureComponent {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fault: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub locate: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disk: String,
}

#[cfg(test)]
mod tests;
