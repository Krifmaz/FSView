//! Wire protocol between the web server and the root helper: one JSON
//! request per connection, one JSON response back, newline terminated.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OP_STATUS: &str = "status";
pub const OP_INVENTORY: &str = "inventory";
pub const OP_SMART_GET: &str = "smart.get";
pub const OP_SMART_SELFTEST: &str = "smart.selftest";
pub const OP_JOURNAL_KERNEL: &str = "journal.kernel";
pub const OP_BOOT_COLLECT: &str = "boot.collect";
pub const OP_AUDIT_LIST: &str = "audit.list";
pub const OP_HIDDEN_SCAN: &str = "hidden.scan";
pub const OP_FSTAB_READ: &str = "fstab.read";
pub const OP_FSTAB_PREVIEW: &str = "fstab.preview";
pub const OP_FSTAB_BACKUP: &str = "fstab.backup";
pub const OP_FSTAB_WRITE: &str = "fstab.write";
pub const OP_FSTAB_ROLLBACK: &str = "fstab.rollback";
pub const OP_MOUNTS_LIST: &str = "mounts.list";
pub const OP_MOUNT: &str = "mount";
pub const OP_UMOUNT: &str = "umount";
pub const OP_FS_FORMAT: &str = "fs.format";
pub const OP_FS_CHECK: &str = "fs.check";
pub const OP_FS_REPAIR: &str = "fs.repair";
pub const OP_LOCATE: &str = "enclosure.locate";
pub const OP_FS_LABEL: &str = "fs.label";

/// Upper bound for requests and responses on the socket.
pub const MAX_MESSAGE: usize = 32 << 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub op: String,
    /// Web user on whose behalf the request is made (audited, not verified).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_ip: String,
    /// Return the plan without executing anything.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Required for non-destructive write operations.
    #[serde(default, skip_serializing_if = "is_false")]
    pub confirmed: bool,
    /// Must equal the target disk's device name or label for destructive
    /// operations.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub confirm_text: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

pub fn is_false(b: &bool) -> bool {
    !*b
}

pub const CODE_BAD_REQUEST: &str = "bad_request";
pub const CODE_UNKNOWN_OP: &str = "unknown_op";
pub const CODE_WRITES_OFF: &str = "writes_disabled";
pub const CODE_NEED_CONFIRM: &str = "confirmation_required";
pub const CODE_PROTECTED: &str = "protected_disk";
pub const CODE_EXEC_FAILED: &str = "exec_failed";
pub const CODE_INTERNAL: &str = "internal";
pub const CODE_NOT_PERMITTED: &str = "not_permitted";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    /// Exact commands that will run (or ran).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plan: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

impl Response {
    pub fn err(code: &str, msg: impl Into<String>) -> Self {
        Response {
            code: code.into(),
            error: msg.into(),
            ..Default::default()
        }
    }
    pub fn ok<T: Serialize>(v: &T) -> Self {
        match serde_json::to_value(v) {
            Ok(result) => Response {
                ok: true,
                result,
                ..Default::default()
            },
            Err(e) => Response::err(CODE_INTERNAL, format!("marshal result: {e}")),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartGetParams {
    pub device: String,
    /// Allow querying a disk in standby (spins it up).
    #[serde(default)]
    pub wake: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmartGetResult {
    pub device: String,
    pub devtype: String,
    pub exit_status: i32,
    pub standby: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub raw: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartSelfTestParams {
    pub device: String,
    /// short | long | abort
    pub test: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalParams {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after_cursor: String,
    #[serde(default)]
    pub current_boot: bool,
    #[serde(default)]
    pub lines: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListParams {
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusResult {
    pub version: String,
    pub hostname: String,
    pub writes_enabled: bool,
    pub boot_id: String,
    pub tools: std::collections::BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HiddenScanParams {
    /// Scan every real filesystem; otherwise only the root filesystem.
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HiddenSample {
    pub name: String,
    pub bytes: u64,
}

/// Files hidden underneath an active mountpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HiddenResult {
    pub mountpoint: String,
    pub parent: String,
    pub parent_source: String,
    pub files: u64,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<HiddenSample>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

// ---- fstab editor ----

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FstabBackup {
    pub name: String,
    pub time: chrono::DateTime<chrono::Utc>,
    pub size: u64,
}

/// Current /etc/fstab with everything the editor needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FstabState {
    pub path: String,
    pub text: String,
    pub sha256: String,
    pub doc: crate::fstab::Doc,
    pub issues: Vec<crate::fstab::Issue>,
    pub devices: Vec<crate::fstab::Device>,
    pub backups: Vec<FstabBackup>,
    pub backup_dir: String,
    pub writes_enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstabPreviewParams {
    pub doc: crate::fstab::Doc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FstabPreview {
    /// sha256 of the file on disk the preview was made against.
    pub base_sha256: String,
    pub text: String,
    pub changed: bool,
    pub diff: Vec<crate::fstab::DiffLine>,
    pub issues: Vec<crate::fstab::Issue>,
    pub verify: crate::fstab::Verify,
    /// Mountpoint directories that will be created.
    pub create_dirs: Vec<String>,
    /// No errors from validation or findmnt --verify.
    pub can_apply: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstabWriteParams {
    pub doc: crate::fstab::Doc,
    /// Must match the file on disk (protects against concurrent edits).
    pub base_sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstabBackupParams {
    pub name: String,
}

/// A backup and how restoring it would change the current file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FstabBackupView {
    pub name: String,
    pub text: String,
    pub base_sha256: String,
    pub diff: Vec<crate::fstab::DiffLine>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstabRollbackParams {
    pub name: String,
    pub base_sha256: String,
}

// ---- mounts and filesystems ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountParams {
    /// Mountpoint of an fstab entry (mount) or of an active mount (umount).
    pub target: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatParams {
    /// Disk ("sdb") or partition ("sdb1") name.
    pub device: String,
    /// ext4 | xfs | btrfs | vfat | exfat
    pub fstype: String,
    pub label: String,
    /// Whole disk only: replace the partition table with GPT and one
    /// partition spanning the disk, then format that partition.
    #[serde(default)]
    pub partition: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsCheckParams {
    /// Disk or partition holding the filesystem.
    pub device: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocateParams {
    /// Disk whose enclosure slot LED to switch.
    pub device: String,
    pub on: bool,
}

/// An active mount with usage (from findmnt).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MountInfo {
    pub target: String,
    pub source: String,
    pub fstype: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub options: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub avail_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelParams {
    /// Disk or partition holding the filesystem.
    pub device: String,
    pub label: String,
}
