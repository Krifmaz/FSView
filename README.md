# FSView

Self-hosted web app for disks, filesystems and storage pools on Proxmox VE 9 / Debian 13 hosts. One install per host, systemd services, UI on `http://<host>:9200`.

Written in Rust (axum + tokio backend, no `unsafe` code) with a React + TypeScript UI embedded in the single binary.

**Status: phases 1-4 done** (monitoring, fstab editor, mounts and filesystems, mergerfs pools). Later phases add RAID/ZFS/SnapRAID wizards, notifications and multi-host.

## Features

- **Overview**: every disk with model, serial, size, transport (SATA/SAS/NVMe/USB, plus "SATA via SAS" for bridged disks), controller (PCI address, driver, name), expander, enclosure slot (kernel `ses` driver / SAS bay ID), partitions, LVM/md children, filesystem type, label, UUID, mountpoints and usage. Protected system disks are marked.
- **Health**: `smartctl -j` for ATA, SCSI and NVMe. SATA disks behind SAS bridges are retried with `-d sat` automatically. Polling uses `-n standby`, so it never wakes sleeping disks. Shows attributes, temperature vs. the drive's trip point, power-on hours, reallocated/pending sectors, the self-test log, and short/long/abort self-tests. Alert thresholds are configurable.
- **Events**: the kernel log filtered for disk events (I/O and medium errors, resets, link down, disks appearing late after boot, removals, filesystem errors). Streamed live, with persistent history.
- **Boot check**: for the current boot, every fstab entry is marked ok, failed, late or skipped, using systemd unit timings, systemd timeout messages and kernel disk-attach times. It also flags mergerfs pools whose branches did not mount, and lists disks that appeared after their mount timeout.
- **Hidden data**: finds files stored underneath active mountpoints, written while a disk was not mounted. They use space (often on the root disk) but are invisible. The root disk is checked every 6 hours, other disks on request. The scan runs read-only in a private mount namespace.
- **Enclosures**: SES shelves via `sg_ses`, showing power supplies, fans, temperatures, voltages and the fault LED.
- **fstab editor**: form-based editing of `/etc/fstab` that keeps comments and untouched lines as they are. "Add from disk" fills in `UUID=`, a mountpoint and safe options. Validation runs live:
  - errors block saving: the device does not exist (unless `nofail`), bad or duplicate mountpoints, unparsable options or durations;
  - warnings: a short `x-systemd.device-timeout` on spinning or shelf disks, `/dev/sdX` names, missing `nofail`, mergerfs pools without `x-systemd.requires-mounts-for`, a filesystem type mismatch.

  Every change runs `findmnt --verify` on a scratch copy and shows a diff. The dry-run plan appears in the confirm dialog. On save, the helper makes a timestamped backup in `/var/lib/fsview-helper/backups` (newest 50 kept), creates missing mountpoints under `/mnt`, `/media` and similar, replaces the file atomically (refusing if someone else changed it meanwhile), then runs `systemctl daemon-reload`. Restoring a backup takes one click and is itself backed up first. Mounting comes in phase 3; until then use `mount -a`.
- **Mounts**: every fstab entry with its live state (mounted, not mounted, disk missing) and usage, plus mounts that are not in fstab. Mount and unmount with one click. FSView never unmounts system mounts or anything on a protected disk, refuses to unmount a disk while a mounted pool uses it, and names the processes that keep a filesystem busy (e.g. Plex) instead of force-unmounting.
- **Filesystems**: per disk or partition: read-only check, repair, and format (ext4, XFS, Btrfs, exFAT, FAT32), optionally with a fresh GPT partition table and "add to fstab and mount" in the same step. Format and repair need the disk's name or label typed in; protected disks, mounted filesystems and RAID/LVM/ZFS members are refused by the helper.
- **mergerfs pools**: pools from fstab with per-branch status and usage; create, edit (policy, free-space reserve, caching, branch order) and remove pools. FSView always adds `nofail` and `x-systemd.requires-mounts-for` for every branch disk, and the helper refuses to mount a pool while one of its disks is missing, so a pool can never write onto the system disk.
- **Pool health**: for every mounted mergerfs pool (found in `/proc/mounts`, branches read from `user.mergerfs.branches` on `<pool>/.mergerfs`), each branch is checked for: mode `=RO` or `=NC`; its filesystem mounted `ro` or `emergency_ro`; ext4 journal trouble in this boot's kernel log (`EXT4-fs error`, aborted journal, `Remounting filesystem read-only`); and SMART errors the disk could not correct (ATA attributes 5/187/197/198, SAS error counter log). For a branch with ext4 errors it shows the kernel messages from the 10 minutes before the first one, which usually name the real trigger (a reset, a timeout, a disk dropping off). "Which disk?" tells you which branch a file lives on (`user.mergerfs.fullpath`). **Repair branch** is a guided fsck: it is refused when SMART shows uncorrected errors (copy the data off instead), otherwise it runs the stop commands from `helper.conf`, unmounts the pool and the branch, runs `fsck.ext4 -f -y`, mounts both again and runs the post commands (for example `pct reboot 200`, because an LXC container keeps the old mergerfs instance in its mount namespace). If any step fails, the rest is skipped. The trigger messages are written to the audit log with the repair. An optional watch (Settings → Pools) checks every 5 minutes and records an event when a branch goes read-only.
- **Enclosure locate LED**: blink a disk's bay on a SAS shelf (kernel `ses` driver) to find it.
- **Audit log**: every write attempt is recorded by the helper, including dry runs and rejected attempts.

## Install

On the Proxmox host, as root:

```bash
curl -fsSL https://github.com/Krifmaz/FSView/releases/latest/download/install.sh | bash
# or from a release tarball:  tar xzf fsview-vX.Y.Z-linux-amd64.tar.gz && cd fsview-*/ && ./install.sh
```

The installer:

- installs `smartmontools` and `pciutils` if they are missing;
- creates the `fsview` system user;
- installs `/usr/local/bin/fsview`, the configs in `/etc/fsview/` and two systemd units;
- generates an `admin` password and prints it once.

Re-running it upgrades the install and keeps your config and data. `./uninstall.sh` removes FSView; add `--purge` to also delete its config, data and audit log. Uninstalling never touches disks.

Optional: `apt install sg3-utils lsscsi` for more enclosure detail.

## Security model

| | |
|---|---|
| `fsview.service` | Web UI, auth, sessions, API. Runs as the unprivileged `fsview` user with heavy systemd sandboxing (no capabilities, read-only system, no device access). |
| `fsview-helper.service` | Root helper on `/run/fsview/helper.sock` (`root:fsview 0660`). It only accepts peers whose UID is `fsview` (checked with `SO_PEERCRED`) and only runs a fixed set of typed operations, never shell commands. Device names are validated against `/sys/block`, unknown parameters are rejected, and commands run with a fixed `PATH`/locale and no shell. |
| Safety rules | Enforced **in the helper**: the `writes_enabled` switch (root-owned `/etc/fsview/helper.conf`, off by default), dry run, confirmation, typed device name or label for destructive operations, protected disks (anything holding `/`, `/boot`, `/boot/efi`, swap, a PV of the root VG or a vdev of the root ZFS pool), and the audit log (`/var/log/fsview/audit.log`). |
| Network | Binds to the LAN IP of the default-route interface (never `0.0.0.0` unless configured). Connections from outside the LAN subnet and `100.64.0.0/10` (Tailscale) are closed before any HTTP is spoken. |
| Auth | argon2id password hashes. Random session tokens are stored only as SHA-256 hashes. Cookies are `HttpOnly` and `SameSite=Strict`. A custom header and Origin check guard against CSRF. Failed logins are rate-limited per IP. Strict CSP. |

If Tailscale runs on a subnet router (e.g. OPNsense), clients usually arrive with the router's LAN address, which is inside the allowed LAN range. Without SNAT they arrive from `100.64.0.0/10`, which is also allowed.

### Enabling write operations

```bash
sed -i 's/^writes_enabled = false/writes_enabled = true/' /etc/fsview/helper.conf
systemctl restart fsview-helper
```

The web UI cannot change this setting.

## Configuration

`/etc/fsview/fsview.conf` (web) and `/etc/fsview/helper.conf` (helper) are commented `key = value` files. Common changes:

- `listen = 192.168.1.20`: pin the listen address.
- `allow = 192.168.1.0/24, 100.64.0.0/10`: set the allowed client ranges explicitly.
- `tls_cert` / `tls_key`: serve HTTPS.
- `repair_stop` / `repair_post` (helper.conf): commands run as root before and after **Repair branch**, separated by `;`, with no shell. Example: `repair_stop = pct exec 200 -- docker stop encore` and `repair_post = pct reboot 200`. They live in the root-owned helper configuration on purpose: the web UI cannot add commands that run as root.

User management:

```bash
runuser -u fsview -- fsview user add alice           # prompts for a password
runuser -u fsview -- fsview user passwd admin --generate
runuser -u fsview -- fsview user list
```

## Development

```bash
make ui          # build the React UI into web/dist (embedded in the binary at compile time)
make build       # release binary in bin/fsview
make test        # cargo fmt --check, clippy -D warnings, cargo test, TypeScript typecheck
make integration # root + loop devices only (temporary images, never real disks)
make demo        # UI + API against recorded fixtures: http://127.0.0.1:9201 (demo / demo-password)
cd web && FSVIEW_DEV_API=http://127.0.0.1:9201 npm run dev   # hot-reload UI against the demo backend
```

- `testdata/spiritlab/` holds real `lsblk`/`smartctl`/`findmnt`/`fstab` output from a PVE 9 host with an LSI SAS2308 and an expander shelf. `smart_sdb_sat_synthetic.json` is synthetic, as its name says.
- CI runs unit tests and then the integration suite in a privileged `debian:trixie` container.
- Pushing a tag `vX.Y.Z` (or running the Release workflow manually) builds the x86_64 release tarball with checksums.

Layout: `src/main.rs` (CLI: `serve`, `helper`, `user`), `src/helper/` (root side), `src/web/` (HTTP side), `src/{inventory,smart,events,bootcheck}` (parsers and analysis, shared), `src/bin/fsview-demo.rs`, `tests/integration.rs`, `web/` (React + TypeScript), `deploy/` (installer, units, configs).
