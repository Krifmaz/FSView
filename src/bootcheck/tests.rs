use std::time::Duration;

use super::*;
use crate::inventory::{parse_lsblk, Inventory, Mount};

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/spiritlab")
            .join(name),
    )
    .unwrap()
}

#[test]
fn escape() {
    for (i, w) in [
        ("/", "-"),
        ("/mnt/media1", "mnt-media1"),
        ("/boot/efi", "boot-efi"),
        (
            "/dev/disk/by-uuid/8B42-B13D",
            r"dev-disk-by\x2duuid-8B42\x2dB13D",
        ),
        ("/mnt/my disk", r"mnt-my\x20disk"),
        ("/.hidden/x", r"\x2ehidden-x"),
        ("//mnt//a/", "mnt-a"),
    ] {
        assert_eq!(escape_path(i), w, "{i}");
    }
}

#[test]
fn durations() {
    for (i, w) in [
        ("10s", 10),
        ("90", 90),
        ("1min 30s", 90),
        ("2m", 120),
        ("5min", 300),
    ] {
        assert_eq!(
            parse_systemd_duration(i),
            Some(Duration::from_secs(w)),
            "{i}"
        );
    }
    assert_eq!(
        parse_systemd_duration("500ms"),
        Some(Duration::from_millis(500))
    );
    assert_eq!(parse_systemd_duration("10 bananas"), None);
}

#[test]
fn fstab_parsing() {
    let (es, errs) = parse_fstab("# c\nUUID=x /mnt/my\\040disk ext4 defaults,nofail 0 2\nbad\n/a:/b=RO /pool fuse.mergerfs allow_other 0 0\n");
    assert_eq!((es.len(), errs.len()), (2, 1));
    assert_eq!(es[0].file, "/mnt/my disk");
    assert!(es[0].has("nofail"));
    assert_eq!(
        es[0].device_unit().as_deref(),
        Some(r"dev-disk-by\x2duuid-x.device")
    );
    assert_eq!(es[0].device_timeout(), Duration::from_secs(90));
    assert_eq!(es[1].mergerfs_branches(), vec!["/a", "/b"]);
    assert_eq!(es[1].device_unit(), None);
}

fn spiritlab() -> (Data, Inventory) {
    let disks = parse_lsblk(&fx("lsblk.json"), false).unwrap();
    let mounts = crate::inventory::parse_findmnt(&fx("findmnt.json")).unwrap();
    let media1 = r"dev-disk-by\x2duuid-c69cfb3b\x2d4f39\x2d449a\x2dbb21\x2dcd2e4ba23d49.device";
    let cache = r"dev-disk-by\x2duuid-df81e242\x2ddf1f\x2d41a9\x2d87ea\x2db441da0ee820.device";
    let unit = |kv: &[(&str, &str)]| {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let mut units = std::collections::BTreeMap::new();
    units.insert(
        "mnt-media1.mount".into(),
        unit(&[
            ("Id", "mnt-media1.mount"),
            ("ActiveState", "inactive"),
            ("Result", "success"),
        ]),
    );
    units.insert(
        "mnt-cache.mount".into(),
        unit(&[
            ("ActiveState", "active"),
            ("Result", "success"),
            ("ActiveEnterTimestampMonotonic", "9100000"),
        ]),
    );
    units.insert(
        "mnt-drivepool.mount".into(),
        unit(&[("ActiveState", "inactive"), ("Result", "success")]),
    );
    units.insert(
        "boot-efi.mount".into(),
        unit(&[
            ("ActiveState", "active"),
            ("Result", "success"),
            ("ActiveEnterTimestampMonotonic", "6000000"),
        ]),
    );
    units.insert(
        "-.mount".into(),
        unit(&[
            ("ActiveState", "active"),
            ("Result", "success"),
            ("ActiveEnterTimestampMonotonic", "1"),
        ]),
    );
    units.insert(
        "dev-pve-swap.swap".into(),
        unit(&[
            ("ActiveState", "active"),
            ("Result", "success"),
            ("ActiveEnterTimestampMonotonic", "5000000"),
        ]),
    );
    units.insert(
        media1.into(),
        unit(&[
            ("ActiveState", "active"),
            ("ActiveEnterTimestampMonotonic", "1260000000"),
        ]),
    );
    units.insert(
        cache.into(),
        unit(&[
            ("ActiveState", "active"),
            ("ActiveEnterTimestampMonotonic", "7600000"),
        ]),
    );
    let ev = |us: i64, m: &str| crate::events::Entry {
        monotonic_us: us,
        message: m.into(),
        ..Default::default()
    };
    let d = Data {
        boot_id: "b1".into(),
        fstab: String::from_utf8(fx("fstab")).unwrap(),
        manager: unit(&[("UserspaceTimestampMonotonic", "3200000"), ("FinishTimestampMonotonic", "25000000")]),
        units,
        kernel: vec![
            ev(7_500_000, "sd 2:0:1:0: [sda] Attached SCSI disk"),
            ev(7_700_000, "sd 2:0:2:0: [sdb] Attached SCSI disk"),
            ev(1_260_000_000, "sd 2:0:9:0: [sdi] Attached SCSI disk"),
        ],
        systemd: vec![
            ev(13_300_000, &format!("Timed out waiting for device {media1} - /dev/disk/by-uuid/c69cfb3b-4f39-449a-bb21-cd2e4ba23d49.")),
            ev(13_300_000, "Dependency failed for mnt-media1.mount - /mnt/media1."),
        ],
        mounts,
        ..Default::default()
    };
    (
        d,
        Inventory {
            disks,
            ..Default::default()
        },
    )
}

fn by<'a>(rep: &'a Report, mp: &str) -> &'a EntryResult {
    rep.entries.iter().find(|e| e.mountpoint == mp).unwrap()
}

#[test]
fn analyze_spiritlab() {
    let (d, inv) = spiritlab();
    let rep = analyze(&d, Some(&inv));
    let m1 = by(&rep, "/mnt/media1");
    assert_eq!(
        (m1.status.as_str(), m1.disk.as_str(), m1.device_timeout_sec),
        ("failed", "sdi", 10.0)
    );
    let all = m1.problems.join("\n");
    for frag in [
        "not mounted",
        "timed out waiting for the device after 10s",
        "dependency failed",
        "device sdi appeared at +21m0s",
    ] {
        assert!(all.contains(frag), "missing {frag:?} in\n{all}");
    }
    let dp = by(&rep, "/mnt/drivepool");
    assert_eq!(dp.status, "failed");
    assert!(dp.problems.join("\n").contains("depends on /mnt/media1"));
    let c = by(&rep, "/mnt/cache");
    assert_eq!(
        (c.status.as_str(), c.disk.as_str(), c.device.as_str()),
        ("ok", "sda", "sda1")
    );
    let r = by(&rep, "/");
    assert_eq!((r.status.as_str(), r.device.as_str()), ("ok", "pve-root"));
    let s = by(&rep, "none");
    assert_eq!((s.status.as_str(), s.fstype.as_str()), ("ok", "swap"));
    assert_eq!(by(&rep, "/proc").status, "skipped");
    assert_eq!((rep.summary.failed, rep.summary.skipped), (2, 1));
    assert_eq!(rep.late_devices.len(), 1);
    let l = &rep.late_devices[0];
    assert!(l.device == "sdi" && l.after_timeout && l.mountpoints == vec!["/mnt/media1"]);
}

/// Seen on spiritlab: the mergerfs pool mounted although its only branch
/// did not, so writes went to the root filesystem.
#[test]
fn pool_mounted_over_missing_branch() {
    let (mut d, inv) = spiritlab();
    d.mounts.push(Mount {
        target: "/mnt/drivepool".into(),
        source: "/mnt/media1".into(),
        fstype: "fuse.mergerfs".into(),
        options: String::new(),
    });
    let rep = analyze(&d, Some(&inv));
    let e = by(&rep, "/mnt/drivepool");
    assert!(
        e.status == "failed" && e.mounted && !e.hints.is_empty(),
        "{e:?}"
    );
    assert!(e
        .problems
        .join("\n")
        .contains("branch /mnt/media1 is not mounted, but this pool is"));
}

#[test]
fn show_parsing() {
    let b = parse_show(
        "Id=a.mount\nActiveState=active\n\nId=b.mount\nActiveState=failed\nResult=exit-code\n",
    );
    assert_eq!(b.len(), 2);
    assert_eq!(b[1]["Result"], "exit-code");
}
