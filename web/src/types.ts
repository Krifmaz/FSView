export type Status = "ok" | "warn" | "crit" | "unknown";

export interface Usage {
  size_bytes: number;
  used_bytes: number;
  avail_bytes: number;
}

export interface Node {
  name: string;
  kname: string;
  path: string;
  type: string;
  size_bytes: number;
  fstype?: string;
  fsver?: string;
  label?: string;
  uuid?: string;
  partuuid?: string;
  partlabel?: string;
  parttypename?: string;
  partn?: number;
  read_only?: boolean;
  mountpoints?: string[];
  usage?: Usage;
  children?: Node[];
}

export interface EnclosureSlot {
  enclosure: string;
  component: string;
  slot?: number;
  status?: string;
  fault?: boolean;
  locate?: boolean;
}

export interface Topology {
  devpath?: string;
  hba?: string;
  hba_name?: string;
  hba_driver?: string;
  scsi_host?: string;
  port?: string;
  expander?: string;
  end_device?: string;
  sas_address?: string;
  bay_id?: number;
  enclosure?: EnclosureSlot;
}

export interface Finding {
  level: Status;
  text: string;
  /** A cumulative error counter that can be acknowledged. */
  ackable?: boolean;
}

export interface Running {
  description: string;
  remaining_percent?: number;
}

export interface HealthView {
  status: Status;
  findings?: Finding[];
  temperature_c?: number;
  power_on_hours?: number;
  protocol?: string;
  devtype?: string;
  model?: string;
  standby: boolean;
  self_test_running?: Running;
  life?: Life;
  updated_at: string | null;
  checked_at: string | null;
  error?: string;
}

export interface Disk {
  name: string;
  path: string;
  type: string;
  model: string;
  vendor?: string;
  serial?: string;
  wwn?: string;
  revision?: string;
  size_bytes: number;
  transport: string;
  hctl?: string;
  rotational: boolean;
  removable: boolean;
  read_only: boolean;
  state?: string;
  pttype?: string;
  fstype?: string;
  fsver?: string;
  label?: string;
  uuid?: string;
  mountpoints?: string[];
  usage?: Usage;
  children?: Node[];
  topology: Topology;
  protected: boolean;
  protected_reasons?: string[];
  display_model: string;
  display_transport: string;
  health?: HealthView;
}

export interface HBA {
  pci: string;
  name?: string;
  driver?: string;
  hosts?: string[];
  disks?: string[];
}

export interface EnclosureComponent {
  name: string;
  slot?: number;
  status?: string;
  fault?: boolean;
  locate?: boolean;
  active?: boolean;
  disk?: string;
}

export interface EnclosureElement {
  type: string;
  index: number;
  status: string;
  level: "ok" | "warn" | "crit" | "absent" | "ignored";
  detail?: string;
  key?: string;
}

export interface Enclosure {
  id: string;
  sg_device?: string;
  status?: "ok" | "warn" | "crit";
  elements?: EnclosureElement[];
  logical_id?: string;
  vendor?: string;
  model?: string;
  components: EnclosureComponent[];
}

export interface Overview {
  hostname: string;
  collected_at: string;
  disks: Disk[];
  hbas: HBA[] | null;
  enclosures: Enclosure[] | null;
  warnings?: string[] | null;
  summary: Record<string, number>;
  events_24h: Record<string, number>;
  hidden?: HiddenView;
}

export interface Attribute {
  id: number;
  name: string;
  value: number;
  worst: number;
  thresh: number;
  raw: number;
  raw_string: string;
  when_failed?: string;
  prefailure: boolean;
}

export interface SelfTest {
  type: string;
  status: string;
  outcome: "passed" | "failed" | "aborted" | "running" | "unknown";
  lifetime_hours?: number;
  lba?: number;
  detail?: string;
}

export interface SmartReport {
  device: string;
  devtype: string;
  protocol: string;
  model: string;
  family?: string;
  serial: string;
  firmware?: string;
  capacity_bytes: number;
  rotation_rate: number;
  smart_available: boolean;
  smart_enabled: boolean;
  passed?: boolean;
  standby: boolean;
  temperature_c?: number;
  temp_trip_c?: number;
  power_on_hours?: number;
  power_cycles?: number;
  reallocated?: number;
  pending?: number;
  offline_uncorrectable?: number;
  reported_uncorrectable?: number;
  crc_errors?: number;
  grown_defects?: number;
  uncorrected_errors?: number;
  ata_error_count?: number;
  ata_last_error?: string;
  ata_last_error_hours?: number;
  nvme_critical_warning?: number;
  nvme_percent_used?: number;
  nvme_available_spare?: number;
  nvme_spare_threshold?: number;
  nvme_media_errors?: number;
  nvme_unsafe_shutdowns?: number;
  nvme_data_written_tb?: number;
  attributes?: Attribute[];
  self_tests?: SelfTest[];
  self_test_running?: Running;
  short_test_minutes?: number;
  long_test_minutes?: number;
  exit_status: number;
  messages?: string[];
  notes?: string[];
}

export interface Life {
  age_hours?: number;
  written_bytes?: number;
  read_bytes?: number;
  workload_bytes_per_year?: number;
  wear_used_pct?: number;
  remaining_pct?: number;
  remaining_hours?: number;
  remaining_written_bytes?: number;
  /** Errors present: the estimate is a best case. */
  upper_bound?: boolean;
  basis: string;
  level: "ok" | "warn" | "crit";
  verdict: string;
}

export interface SmartEntry {
  report?: SmartReport;
  assessment: { status: Status; findings?: Finding[] };
  life?: Life;
  updated_at: string | null;
  checked_at: string | null;
  standby: boolean;
  error?: string;
}

export interface DiskDetail {
  disk: Disk;
  smart: SmartEntry | null;
  raw?: unknown;
}

export interface DiskEvent {
  cursor: string;
  time: string;
  boot_id: string;
  monotonic_sec: number;
  category: string;
  severity: "error" | "warn" | "info";
  device?: string;
  message: string;
  late?: boolean;
}

export interface BootEntry {
  line: number;
  spec: string;
  mountpoint: string;
  fstype: string;
  options: string;
  status: "ok" | "failed" | "late" | "skipped";
  problems?: string[];
  hints?: string[];
  device?: string;
  disk?: string;
  mounted: boolean;
  mounted_sec?: number;
  device_appeared_sec?: number;
  device_timeout_sec: number;
  nofail: boolean;
  noauto: boolean;
  depends_on?: string[];
}

export interface BootReport {
  boot_id: string;
  collected_at: string;
  userspace_start_sec: number;
  boot_finished_sec: number;
  entries: BootEntry[];
  late_devices: { device: string; appeared_sec: number; after_timeout: boolean; mountpoints?: string[]; message: string }[];
  summary: { ok: number; failed: number; late: number; skipped: number };
  fstab_errors?: string[];
}

export interface AuditRecord {
  time: string;
  actor: string;
  client_ip?: string;
  peer_uid: number;
  op: string;
  targets?: string[];
  params?: unknown;
  dry_run: boolean;
  commands?: string[];
  result: "ok" | "error" | "rejected" | "dry-run";
  error?: string;
  output?: string;
}

export interface Thresholds {
  temp_warn_c: number;
  temp_crit_c: number;
  trip_margin_c: number;
  reallocated_warn: number;
  reallocated_crit: number;
  pending_warn: number;
  pending_crit: number;
  uncorrectable_warn: number;
  crc_warn: number;
  error_log_warn: number;
  nvme_used_warn: number;
  nvme_used_crit: number;
}

export interface Settings {
  thresholds: Thresholds;
  late_device_sec: number;
  event_retention: number;
  ignored_elements?: string[];
  skip_confirm?: boolean;
}

export interface StatusInfo {
  version: string;
  listen: string[];
  allow: string[];
  user: string;
  tls: boolean;
  helper?: { version: string; hostname: string; writes_enabled: boolean; boot_id: string; tools: Record<string, boolean> };
  helper_error?: string;
}

export interface HiddenResult {
  mountpoint: string;
  parent: string;
  parent_source: string;
  files: number;
  bytes: number;
  truncated?: boolean;
  samples?: { name: string; bytes: number }[];
  error?: string;
}

export interface HiddenView {
  results: HiddenResult[];
  all: boolean;
  checked_at: string | null;
  error?: string;
}

// ---- fstab editor ----

export interface FsEntry {
  spec: string;
  file: string;
  vfstype: string;
  options: string;
  freq: number;
  passno: number;
}

export type FstabLine =
  | { kind: "comment"; text: string }
  | { kind: "invalid"; text: string }
  | { kind: "entry"; raw: string; entry: FsEntry };

export interface FstabDoc {
  lines: FstabLine[];
}

export interface FstabIssue {
  level: "error" | "warning";
  line?: number;
  field?: string;
  message: string;
}

export interface FstabDevice {
  path: string;
  name: string;
  disk: string;
  fstype: string;
  uuid?: string;
  label?: string;
  partuuid?: string;
  partlabel?: string;
  size_bytes: number;
  rotational: boolean;
  shelf: boolean;
  protected: boolean;
  mountpoints?: string[];
}

export interface FstabBackup {
  name: string;
  time: string;
  size: number;
}

export interface FstabState {
  path: string;
  text: string;
  sha256: string;
  doc: FstabDoc;
  issues: FstabIssue[];
  devices: FstabDevice[];
  backups: FstabBackup[];
  backup_dir: string;
  writes_enabled: boolean;
}

export interface DiffLine {
  op: " " | "+" | "-";
  text: string;
}

export interface FstabVerify {
  ok: boolean;
  errors: string[];
  warnings: string[];
  ignored?: string[];
}

export interface FstabPreview {
  base_sha256: string;
  text: string;
  changed: boolean;
  diff: DiffLine[];
  issues: FstabIssue[];
  verify: FstabVerify;
  create_dirs: string[];
  can_apply: boolean;
}

export interface FstabBackupView {
  name: string;
  text: string;
  base_sha256: string;
  diff: DiffLine[];
}

export interface WriteResult {
  ok: boolean;
  dry_run: boolean;
  plan: string[];
  result?: { summary?: string; output?: string };
}

// ---- mounts and pools ----

export interface UsageInfo {
  size_bytes: number;
  used_bytes: number;
  avail_bytes: number;
}

export interface StorageEntry {
  line: number;
  spec: string;
  file: string;
  vfstype: string;
  options: string;
  mounted: boolean;
  source?: string | null;
  usage?: UsageInfo | null;
  device?: { name: string; disk: string; label: string; fstype: string; size_bytes: number; protected: boolean } | null;
  present: boolean;
  system: boolean;
  nofail: boolean;
  pool: boolean;
}

export interface PoolBranch {
  path: string;
  mount?: string | null;
  mounted: boolean;
  usage?: UsageInfo | null;
  required: boolean;
}

export interface Pool extends StorageEntry {
  branches: PoolBranch[];
  policy: string;
}

export interface StorageView {
  fstab_sha256: string;
  writes_enabled: boolean;
  mergerfs_installed?: boolean | null;
  tools?: Record<string, boolean> | null;
  entries: StorageEntry[];
  pools: Pool[];
  other_mounts: { target: string; source: string; fstype: string; usage?: UsageInfo | null }[];
  devices: FstabDevice[];
}
