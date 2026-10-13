#![forbid(unsafe_code)]
//! Serves the real UI and API against recorded fixtures (testdata/spiritlab)
//! instead of the root helper. A development aid for UI work and
//! screenshots; it never touches hardware.
//!
//!   cargo run --bin fsview-demo -- 127.0.0.1:9201
//!   login: demo / demo-password

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::{json, Value};

use fsview::bootcheck;
use fsview::events;
use fsview::fstab;
use fsview::helper::AuditRecord;
use fsview::helperclient::{CallFuture, HelperApi, HelperError};
use fsview::inventory::{
    self, Enclosure, EnclosureComponent, EnclosureSlot, Hba, Inventory, Mount, SystemInfo, Topology,
};
use fsview::netutil::Prefix;
use fsview::proto::*;
use fsview::store::Store;
use fsview::web::{App, Options};

/// Current fstab text and its backups (name, text), newest first.
type DemoFstab = (String, Vec<(String, String)>);

struct Demo {
    dir: PathBuf,
    audit: Mutex<Vec<AuditRecord>>,
    /// In-memory /etc/fstab and its backups (name, text).
    fstab: Mutex<Option<DemoFstab>>,
}

fn demo_path_exists(p: &str) -> bool {
    [
        "/",
        "/boot/efi",
        "/proc",
        "/mnt/media1",
        "/mnt/cache",
        "/mnt/drivepool",
    ]
    .contains(&p)
}

const DEMO_FS: [&str; 6] = ["ext4", "vfat", "xfs", "btrfs", "proc", "fuse"];

impl Demo {
    fn read(&self, n: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"))
    }

    fn inventory(&self) -> Inventory {
        let mut disks = inventory::parse_lsblk(&self.read("lsblk.json"), false).unwrap();
        let sys = SystemInfo {
            mounts: inventory::parse_findmnt(&self.read("findmnt.json")).unwrap(),
            swap_devices: vec!["/dev/mapper/pve-swap".into()],
            extra_system_devices: [(
                "/dev/nvme0n1p3".to_string(),
                "LVM PV of root VG pve".to_string(),
            )]
            .into(),
        };
        inventory::mark_protected(&mut disks, &sys, &|p: &str| {
            p.rsplit('/').next().unwrap_or("").to_string()
        });
        let mut comps = vec![];
        for d in disks.iter_mut() {
            if d.transport == "sas" {
                let slot: i64 = d
                    .hctl
                    .split(':')
                    .nth(2)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                d.topology = Topology {
                    hba: "0000:0c:00.0".into(),
                    hba_name: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2".into(),
                    hba_driver: "mpt3sas".into(),
                    scsi_host: "host2".into(),
                    expander: "expander-2:0".into(),
                    end_device: format!("end_device-2:0:{slot}"),
                    sas_address: d.wwn.clone(),
                    enclosure: Some(EnclosureSlot {
                        enclosure: "2:0:9:0".into(),
                        component: slot.to_string(),
                        slot: Some(slot),
                        status: "OK".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                comps.push(EnclosureComponent {
                    name: slot.to_string(),
                    slot: Some(slot),
                    status: "OK".into(),
                    disk: d.name.clone(),
                    ..Default::default()
                });
            } else {
                d.topology = Topology {
                    hba: "0000:01:00.0".into(),
                    hba_name: "Sandisk Corp PC SN530 NVMe SSD".into(),
                    hba_driver: "nvme".into(),
                    port: "nvme0".into(),
                    ..Default::default()
                };
            }
        }
        for s in 10..13 {
            comps.push(EnclosureComponent {
                name: s.to_string(),
                slot: Some(s),
                status: "Not Installed".into(),
                ..Default::default()
            });
        }
        let els =
            inventory::parse_ses_status(&String::from_utf8_lossy(&self.read("sg_ses_p2.txt")));
        Inventory {
            hostname: "spiritlab (demo)".into(),
            collected_at: Utc::now(),
            hbas: vec![
                Hba {
                    pci: "0000:01:00.0".into(),
                    name: "Sandisk Corp PC SN530 NVMe SSD".into(),
                    driver: "nvme".into(),
                    disks: vec!["nvme0n1".into()],
                    ..Default::default()
                },
                Hba {
                    pci: "0000:0c:00.0".into(),
                    name: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2".into(),
                    driver: "mpt3sas".into(),
                    hosts: vec!["host2".into()],
                    disks: disks
                        .iter()
                        .filter(|d| d.transport == "sas")
                        .map(|d| d.name.clone())
                        .collect(),
                },
                Hba {
                    pci: "0000:0e:00.0".into(),
                    name: "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2".into(),
                    driver: "mpt3sas".into(),
                    hosts: vec!["host3".into()],
                    ..Default::default()
                },
            ],
            enclosures: vec![Enclosure {
                id: "2:0:9:0".into(),
                sg_device: "sg9".into(),
                vendor: "NETAPP".into(),
                model: "DS424IOM6E".into(),
                components: comps,
                status: inventory::enclosure_level(&els),
                elements: els,
                ..Default::default()
            }],
            disks,
            warnings: vec![],
        }
    }

    fn fstab_text(&self) -> DemoFstab {
        let mut g = self.fstab.lock().unwrap();
        g.get_or_insert_with(|| {
            (
                String::from_utf8_lossy(&self.read("fstab")).into_owned(),
                vec![],
            )
        })
        .clone()
    }

    fn fstab_issues(&self, doc: &fstab::Doc) -> (Vec<fstab::Device>, Vec<fstab::Issue>) {
        let devices = fstab::devices(&self.inventory());
        let kfs: Vec<String> = DEMO_FS.iter().map(|s| s.to_string()).collect();
        let issues = fstab::validate(
            doc,
            &fstab::Context {
                devices: &devices,
                kernel_fs: &kfs,
                path_exists: &demo_path_exists,
            },
        );
        (devices, issues)
    }

    fn fstab_preview(&self, doc: &fstab::Doc) -> FstabPreview {
        let (old, _) = self.fstab_text();
        let text = fstab::render(doc);
        let (_, issues) = self.fstab_issues(doc);
        let create_dirs = fstab::mountpoints_to_create(doc, &demo_path_exists);
        let verify = fstab::Verify {
            ok: true,
            ..Default::default()
        };
        let changed = text != old;
        FstabPreview {
            base_sha256: fstab::sha256_hex(&old),
            diff: fstab::diff(&old, &text),
            can_apply: changed && !issues.iter().any(|i| i.level == "error"),
            text,
            changed,
            issues,
            verify,
            create_dirs,
        }
    }

    fn fstab_write(
        &self,
        req: &Request,
        new: String,
        mut plan: Vec<String>,
    ) -> Result<Response, HelperError> {
        let fail = |code: &str, msg: String| HelperError {
            code: code.into(),
            msg,
            plan: vec![],
        };
        let (old, mut backups) = self.fstab_text();
        if req.params["base_sha256"].as_str() != Some(&fstab::sha256_hex(&old)) {
            return Err(fail(
                CODE_BAD_REQUEST,
                "fstab changed since it was loaded; reload".into(),
            ));
        }
        if new == old {
            return Err(fail(CODE_BAD_REQUEST, "no changes to apply".into()));
        }
        let name = format!("fstab.{}", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        let name = if backups.iter().any(|(n, _)| *n == name) {
            format!("{name}.{}", backups.len())
        } else {
            name
        };
        plan.insert(
            0,
            format!("cp --preserve=mode /etc/fstab /var/lib/fsview-helper/backups/{name}"),
        );
        plan.push(format!(
            "write /etc/fstab ({} bytes, atomic replace)",
            new.len()
        ));
        plan.push("systemctl daemon-reload".into());
        let detail = fstab::diff_text(&fstab::diff(&old, &new));
        if !req.dry_run && !req.confirmed {
            return Err(fail(
                CODE_NEED_CONFIRM,
                "operation must be confirmed".into(),
            ));
        }
        self.audit.lock().unwrap().insert(
            0,
            AuditRecord {
                time: Utc::now(),
                actor: req.actor.clone(),
                client_ip: req.client_ip.clone(),
                op: req.op.clone(),
                targets: vec!["/etc/fstab".into()],
                dry_run: req.dry_run,
                commands: plan.clone(),
                result: if req.dry_run {
                    "dry-run".into()
                } else {
                    "ok".into()
                },
                output: detail.clone(),
                ..Default::default()
            },
        );
        if !req.dry_run {
            backups.insert(0, (name, old));
            *self.fstab.lock().unwrap() = Some((new, backups));
        }
        Ok(Response {
            ok: true,
            dry_run: req.dry_run,
            plan,
            result: json!({"summary": "update /etc/fstab (demo, in memory)", "output": detail}),
            ..Default::default()
        })
    }

    fn answer(&self, req: &Request) -> Result<Response, HelperError> {
        let bad = |msg: String| HelperError {
            code: CODE_BAD_REQUEST.into(),
            msg,
            plan: vec![],
        };
        match req.op.as_str() {
            OP_FSTAB_WRITE => {
                let p: FstabWriteParams =
                    serde_json::from_value(req.params.clone()).map_err(|e| bad(e.to_string()))?;
                let pv = self.fstab_preview(&p.doc);
                if let Some(i) = pv.issues.iter().find(|i| i.level == "error") {
                    return Err(bad(format!(
                        "fstab has errors; fix them first:\n{}",
                        i.message
                    )));
                }
                let plan = pv
                    .create_dirs
                    .iter()
                    .map(|d| format!("mkdir -p -m 0755 {d}"))
                    .collect();
                return self.fstab_write(req, pv.text, plan);
            }
            OP_FSTAB_ROLLBACK => {
                let p: FstabRollbackParams =
                    serde_json::from_value(req.params.clone()).map_err(|e| bad(e.to_string()))?;
                let (_, backups) = self.fstab_text();
                let Some((_, text)) = backups.into_iter().find(|(n, _)| *n == p.name) else {
                    return Err(bad(format!("backup {} does not exist", p.name)));
                };
                return self.fstab_write(req, text, vec![]);
            }
            _ => {}
        }
        let mut resp = Response {
            ok: true,
            ..Default::default()
        };
        let raw = |n: &str| serde_json::from_slice::<Value>(&self.read(n)).unwrap();
        resp.result = match req.op.as_str() {
            OP_STATUS => {
                json!({"version": "demo", "hostname": "spiritlab (demo)", "writes_enabled": true, "boot_id": "demo",
                "tools": {"smartctl": true, "lsblk": true, "sg_ses": true, "lspci": true, "zpool": false, "mergerfs": true}})
            }
            OP_INVENTORY => serde_json::to_value(self.inventory()).unwrap(),
            OP_SMART_GET => {
                let dev = req.params["device"].as_str().unwrap_or("");
                let wake = req.params["wake"].as_bool().unwrap_or(false);
                match dev {
                    "sdc" | "sdd" => {
                        json!({"device": dev, "devtype": "", "exit_status": 128, "standby": false, "raw": raw("smart_sdc_scsi.json")})
                    }
                    "sdi" => {
                        json!({"device": dev, "devtype": "sat", "exit_status": 64, "standby": false, "raw": raw("smart_ZXA0R1KK_sat.json")})
                    }
                    "nvme0n1" => {
                        json!({"device": dev, "devtype": "", "exit_status": 0, "standby": false, "raw": raw("smart_nvme0n1.json")})
                    }
                    "sdb" => {
                        json!({"device": dev, "devtype": "sat", "exit_status": 0, "standby": false, "raw": raw("smart_sdb_sat_synthetic.json")})
                    }
                    "sdh" if !wake => {
                        json!({"device": dev, "devtype": "", "exit_status": 2, "standby": true})
                    }
                    _ => {
                        let mut r = raw("smart_sdi_scsi.json");
                        r["temperature"] = json!({"current": 29, "drive_trip": 60});
                        json!({"device": dev, "devtype": "", "exit_status": 0, "standby": false, "raw": r})
                    }
                }
            }
            OP_SMART_SELFTEST => {
                let cmd = format!(
                    "smartctl -t {} /dev/{}",
                    req.params["test"].as_str().unwrap_or(""),
                    req.params["device"].as_str().unwrap_or("")
                );
                self.audit.lock().unwrap().insert(
                    0,
                    AuditRecord {
                        time: Utc::now(),
                        actor: req.actor.clone(),
                        client_ip: req.client_ip.clone(),
                        op: req.op.clone(),
                        targets: vec![req.params["device"].as_str().unwrap_or("").into()],
                        dry_run: req.dry_run,
                        commands: vec![cmd.clone()],
                        result: if req.dry_run {
                            "dry-run".into()
                        } else {
                            "ok".into()
                        },
                        ..Default::default()
                    },
                );
                resp.dry_run = req.dry_run;
                resp.plan = vec![cmd];
                json!({"summary": "demo"})
            }
            OP_JOURNAL_KERNEL => {
                if req.params["after_cursor"]
                    .as_str()
                    .is_some_and(|c| !c.is_empty())
                {
                    json!([])
                } else {
                    let boot = Utc::now().timestamp_micros() - 25 * 60 * 1_000_000;
                    let mk = |i: i32, sec: f64, prio: i64, msg: &str| events::Entry {
                        cursor: format!("demo-{i}"),
                        realtime_us: boot + (sec * 1e6) as i64,
                        monotonic_us: (sec * 1e6) as i64,
                        boot_id: "demo".into(),
                        priority: prio,
                        identifier: String::new(),
                        message: msg.into(),
                    };
                    serde_json::to_value(vec![
                        mk(1, 7.5, 5, "sd 2:0:1:0: [sda] Attached SCSI disk"),
                        mk(2, 7.7, 5, "sd 2:0:3:0: [sdc] Attached SCSI disk"),
                        mk(3, 300.0, 3, "sd 2:0:3:0: [sdc] tag#12 Sense Key : Medium Error [current]"),
                        mk(4, 300.1, 3, "I/O error, dev sdc, sector 179177313 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2"),
                        mk(5, 420.0, 4, "sd 2:0:4:0: attempting task abort!scmd(0x00000000a1b2c3d4), outstanding for 30060 ms & timeout 30000 ms"),
                        mk(6, 1260.0, 5, "sd 2:0:9:0: [sdi] Attached SCSI disk"),
                        mk(7, 1300.0, 6, "EXT4-fs (sda1): mounted filesystem df81e242-df1f-41a9-87ea-b441da0ee820 r/w with ordered data mode."),
                    ])
                    .unwrap()
                }
            }
            OP_BOOT_COLLECT => {
                let mut mounts = inventory::parse_findmnt(&self.read("findmnt.json")).unwrap();
                mounts.push(Mount {
                    target: "/mnt/drivepool".into(),
                    source: "/mnt/media1".into(),
                    fstype: "fuse.mergerfs".into(),
                    options: String::new(),
                });
                let m1 =
                    r"dev-disk-by\x2duuid-c69cfb3b\x2d4f39\x2d449a\x2dbb21\x2dcd2e4ba23d49.device";
                let u = |kv: &[(&str, &str)]| {
                    kv.iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                };
                let ev = |us: i64, m: &str| events::Entry {
                    monotonic_us: us,
                    message: m.into(),
                    ..Default::default()
                };
                let d = bootcheck::Data {
                    boot_id: "bede039a4a1e4487bf8a27be5fb490e8".into(),
                    collected_at: Utc::now(),
                    fstab: String::from_utf8_lossy(&self.read("fstab")).into_owned(),
                    manager: u(&[("UserspaceTimestampMonotonic", "3200000"), ("FinishTimestampMonotonic", "25000000")]),
                    units: [
                        ("mnt-media1.mount", u(&[("ActiveState", "inactive"), ("Result", "success")])),
                        ("mnt-cache.mount", u(&[("ActiveState", "active"), ("Result", "success"), ("ActiveEnterTimestampMonotonic", "9100000")])),
                        ("boot-efi.mount", u(&[("ActiveState", "active"), ("Result", "success"), ("ActiveEnterTimestampMonotonic", "6000000")])),
                        ("-.mount", u(&[("ActiveState", "active"), ("Result", "success"), ("ActiveEnterTimestampMonotonic", "1")])),
                        ("dev-pve-swap.swap", u(&[("ActiveState", "active"), ("Result", "success"), ("ActiveEnterTimestampMonotonic", "5000000")])),
                        (m1, u(&[("ActiveState", "active"), ("ActiveEnterTimestampMonotonic", "1260000000")])),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                    kernel: vec![ev(7_500_000, "sd 2:0:1:0: [sda] Attached SCSI disk"), ev(1_260_000_000, "sd 2:0:9:0: [sdi] Attached SCSI disk")],
                    systemd: vec![
                        ev(13_300_000, &format!("Timed out waiting for device {m1} - /dev/disk/by-uuid/c69cfb3b-4f39-449a-bb21-cd2e4ba23d49.")),
                        ev(13_300_000, "Dependency failed for mnt-media1.mount - /mnt/media1."),
                    ],
                    mounts,
                };
                serde_json::to_value(d).unwrap()
            }
            OP_HIDDEN_SCAN => json!([
                {"mountpoint": "/mnt/drivepool", "parent": "/", "parent_source": "/dev/mapper/pve-root", "files": 22, "bytes": 78000430137u64, "samples": [{"name": "downloads", "bytes": 78000430137u64}]},
                {"mountpoint": "/mnt/cache", "parent": "/", "parent_source": "/dev/mapper/pve-root", "files": 57, "bytes": 5798205849u64, "samples": [{"name": "incomplete", "bytes": 5798205849u64}]}
            ]),
            OP_AUDIT_LIST => serde_json::to_value(&*self.audit.lock().unwrap()).unwrap(),
            OP_FSTAB_READ => {
                let (text, backups) = self.fstab_text();
                let doc = fstab::parse(&text);
                let (devices, issues) = self.fstab_issues(&doc);
                serde_json::to_value(FstabState {
                    path: "/etc/fstab".into(),
                    sha256: fstab::sha256_hex(&text),
                    text,
                    doc,
                    issues,
                    devices,
                    backups: backups
                        .iter()
                        .map(|(n, t)| FstabBackup {
                            name: n.clone(),
                            time: Utc::now(),
                            size: t.len() as u64,
                        })
                        .collect(),
                    backup_dir: "/var/lib/fsview-helper/backups".into(),
                    writes_enabled: true,
                })
                .unwrap()
            }
            OP_FSTAB_PREVIEW => {
                let p: FstabPreviewParams =
                    serde_json::from_value(req.params.clone()).map_err(|e| bad(e.to_string()))?;
                serde_json::to_value(self.fstab_preview(&p.doc)).unwrap()
            }
            OP_FSTAB_BACKUP => {
                let name = req.params["name"].as_str().unwrap_or("");
                let (cur, backups) = self.fstab_text();
                let Some((_, text)) = backups.iter().find(|(n, _)| n == name) else {
                    return Err(bad(format!("backup {name} does not exist")));
                };
                serde_json::to_value(FstabBackupView {
                    name: name.into(),
                    diff: fstab::diff(&cur, text),
                    text: text.clone(),
                    base_sha256: fstab::sha256_hex(&cur),
                })
                .unwrap()
            }
            _ => {
                return Err(HelperError {
                    code: CODE_UNKNOWN_OP.into(),
                    msg: "unknown op".into(),
                    plan: vec![],
                })
            }
        };
        Ok(resp)
    }
}

impl HelperApi for Demo {
    fn call(&self, req: Request) -> CallFuture<'_> {
        let r = self.answer(&req);
        Box::pin(async move { r })
    }
}

fn main() {
    let listen = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9201".into());
    let fixtures = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "testdata/spiritlab".into());
    let data = tempfile_dir();
    let store = Arc::new(Store::open(&data).expect("store"));
    store
        .set_password("demo", "demo-password", true)
        .expect("user");
    let opt = Options {
        version: "demo".into(),
        listen: vec![listen.parse().expect("listen address")],
        allow: vec![
            Prefix::parse("127.0.0.0/8").unwrap(),
            Prefix::parse("::1/128").unwrap(),
        ],
        ..Default::default()
    };
    let app = App::new(
        opt,
        store,
        Arc::new(Demo {
            dir: fixtures.into(),
            audit: Mutex::new(vec![]),
            fstab: Mutex::new(None),
        }),
    );
    println!("demo UI on http://{listen}  (login demo / demo-password)");
    let rt = tokio::runtime::Runtime::new().unwrap();
    if let Err(e) = rt.block_on(app.run(async {
        let _ = tokio::signal::ctrl_c().await;
    })) {
        eprintln!("fsview-demo: {e}");
    }
    let _ = std::fs::remove_dir_all(&data);
}

fn tempfile_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("fsview-demo-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
