//! SMR (shingled) drive detection and the protection FSView applies to
//! them.
//!
//! Drive-managed SMR disks accept writes into a cache zone and rewrite
//! shingled bands in the background. Under a long write burst (a pool sending
//! every new download to the emptiest disk) the cache fills and the drive
//! stops answering for seconds at a time. Behind a SAS shelf that shows up as
//! "Aborted Command - Commands cleared by device server": the whole command
//! queue is dropped, writes are lost and ext4 aborts its journal.
//!
//! Two settings make that much less likely and cost nothing on CMR disks
//! because they are only applied to SMR ones:
//!
//! * queue depth 1 ([`QUEUE_DEPTH`]): the drive gets one command at a time,
//!   so a stall cannot take a full queue of writes with it;
//! * a long command timeout ([`TIMEOUT_SECS`]) so the kernel waits out a
//!   stall instead of resetting the drive.
//!
//! While any SMR disk is protected, the kernel's dirty page limits are also
//! capped ([`DIRTY_BYTES`], [`DIRTY_BACKGROUND_BYTES`]) so writeback flushes
//! small batches instead of gigabytes at once.
//!
//! Detection uses a list of models known to be SMR ([`is_known_smr`]); the
//! user can override it per disk (by serial) when a model is missing or
//! misdetected.

/// Queue depth for SMR disks.
pub const QUEUE_DEPTH: u32 = 1;
/// SCSI command timeout for SMR disks, in seconds.
pub const TIMEOUT_SECS: u32 = 180;
/// `vm.dirty_bytes` while SMR protection is active (256 MiB).
pub const DIRTY_BYTES: u64 = 256 << 20;
/// `vm.dirty_background_bytes` while SMR protection is active (64 MiB).
pub const DIRTY_BACKGROUND_BYTES: u64 = 64 << 20;

/// Model numbers documented as drive-managed SMR (manufacturer statements
/// and data sheets). Matched as a prefix-free substring of the model, so
/// suffixes like `-1R8174` and vendor prefixes do not matter.
const KNOWN_SMR: &[&str] = &[
    // Seagate BarraCuda (3.5" and 2.5"), Archive
    "ST1000LM048",
    "ST1000LM049",
    "ST2000LM007",
    "ST2000LM015",
    "ST3000LM024",
    "ST4000LM024",
    "ST5000LM000",
    "ST2000DM005",
    "ST2000DM008",
    "ST3000DM007",
    "ST4000DM004",
    "ST4000DM005",
    "ST6000DM003",
    "ST8000DM004",
    "ST5000AS0011",
    "ST8000AS0002",
    // WD Red (EFAX), Blue 2.5", My Passport internals
    "WD20EFAX",
    "WD30EFAX",
    "WD40EFAX",
    "WD60EFAX",
    "WD10SPZX",
    "WD20SPZX",
    "WD40NDZW",
    "WD50NDZW",
    // Toshiba P300 / DT02 / L200 / MQ04
    "DT02ABA400",
    "DT02ABA600",
    "HDWD240",
    "HDWD260",
    "HDWL110",
    "HDWL120",
    "MQ04ABF100",
    "MQ04ABD200",
];

/// True when `model` is a known SMR model. Spaces are ignored and case does
/// not matter, so a SATA disk behind a SAS bridge that reports vendor
/// `ST2000LM` and model `007-1R8174` matches when both are passed joined.
pub fn is_known_smr(model: &str) -> bool {
    let m: String = model
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    !m.is_empty() && KNOWN_SMR.iter().any(|k| m.contains(k))
}

/// Whether FSView treats a disk as SMR: the user's override for its serial
/// if there is one, otherwise the known-model list applied to every model
/// string we have for it (SMART model, inventory vendor+model).
pub fn effective(models: &[&str], override_: Option<bool>) -> bool {
    override_.unwrap_or_else(|| models.iter().any(|m| is_known_smr(m)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_models() {
        assert!(is_known_smr("ST2000LM007-1R8174"));
        assert!(is_known_smr("ST6000DM003-2CY186"));
        // bridged SATA: vendor and model split, joined by the caller
        assert!(is_known_smr("ST2000LM 007-1R8174 SM"));
        assert!(is_known_smr("wdc wd40efax-68jh4n1"));
        assert!(!is_known_smr("HGST HUS726060ALS640"));
        assert!(!is_known_smr("ST4000VN008-2DR166"));
        assert!(!is_known_smr(""));
    }

    #[test]
    fn overrides() {
        assert!(effective(&["", "ST6000DM003-2CY186"], None));
        assert!(!effective(&["ST6000DM003-2CY186"], Some(false)));
        assert!(effective(&["HUS726060ALS640"], Some(true)));
        assert!(!effective(&["HUS726060ALS640"], None));
    }
}
