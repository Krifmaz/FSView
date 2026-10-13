use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::*;
use crate::runner::Fake;

pub(crate) fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/spiritlab")
            .join(name),
    )
    .unwrap()
}

fn spiritlab_resolver(p: &str) -> String {
    match p {
        "/dev/mapper/pve-root" | "/dev/pve/root" => "dm-1".into(),
        "/dev/mapper/pve-swap" | "/dev/dm-0" => "dm-0".into(),
        _ => Path::new(p)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    }
}

#[test]
fn parse_lsblk_spiritlab() {
    let disks = parse_lsblk(&fixture("lsblk.json"), false).unwrap();
    assert_eq!(disks.len(), 10, "zram and loop must be skipped");
    let sdi = disks.iter().find(|d| d.name == "sdi").unwrap();
    assert_eq!(
        (sdi.label.as_str(), sdi.fstype.as_str(), sdi.size_bytes),
        ("media1", "ext4", 28001039286272)
    );
    assert_eq!(sdi.model, "ST28000N M000C-3WM103 SM");
    assert!(sdi.rotational && sdi.transport == "sas");
    let sda = disks.iter().find(|d| d.name == "sda").unwrap();
    assert_eq!(sda.children[0].mountpoints, vec!["/mnt/cache"]);
    assert!(sda.children[0].usage.is_some());
    // loop0 has size 0 and stays out even with include_loop.
    assert_eq!(parse_lsblk(&fixture("lsblk.json"), true).unwrap().len(), 10);
}

#[test]
fn display_models() {
    assert_eq!(display_model("ATA", "Samsung SSD 870"), "Samsung SSD 870");
    assert_eq!(display_model("WDC     ", "WD7500BPKT"), "WDC WD7500BPKT");
    assert_eq!(display_model("", "WDC CH SN530"), "WDC CH SN530");
    assert_eq!(display_model("SEAGATE", "SEAGATE ST4000"), "SEAGATE ST4000");
}

#[test]
fn protected_spiritlab() {
    let mut disks = parse_lsblk(&fixture("lsblk.json"), false).unwrap();
    let sys = SystemInfo {
        mounts: parse_findmnt(&fixture("findmnt.json")).unwrap(),
        swap_devices: parse_proc_swaps(&String::from_utf8(fixture("proc_swaps")).unwrap()),
        extra_system_devices: [(
            "/dev/nvme0n1p3".to_string(),
            "LVM PV of root VG pve".to_string(),
        )]
        .into(),
    };
    mark_protected(&mut disks, &sys, &spiritlab_resolver);
    for d in &disks {
        assert_eq!(
            d.protected,
            d.name == "nvme0n1",
            "{} {:?}",
            d.name,
            d.protected_reasons
        );
    }
    let all = disks
        .iter()
        .find(|d| d.name == "nvme0n1")
        .unwrap()
        .protected_reasons
        .join(";");
    for frag in [
        "holds /",
        "holds /boot/efi",
        "active swap",
        "LVM PV of root VG pve",
    ] {
        assert!(all.contains(frag), "missing {frag} in {all}");
    }
}

#[test]
fn protected_via_mounts_only() {
    let mut disks = parse_lsblk(&fixture("lsblk.json"), false).unwrap();
    mark_protected(&mut disks, &SystemInfo::default(), &spiritlab_resolver);
    assert!(
        disks
            .iter()
            .find(|d| d.name == "nvme0n1")
            .unwrap()
            .protected
    );
    assert!(!disks.iter().find(|d| d.name == "sda").unwrap().protected);
}

#[test]
fn parse_helpers() {
    let rows = parse_lvm_report(br#"{"report":[{"pv":[{"pv_name":"/dev/nvme0n1p3","vg_name":"pve"},{"pv_name":"/dev/sdz1","vg_name":"o"}]}]}"#, "pv").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["vg_name"], "pve");
    let z = parse_zpool_vdevs("rpool\t928G\n\tmirror-0\t928G\n\t/dev/disk/by-id/ata-X-part3\t-\n\t/dev/disk/by-id/ata-Y-part3\t-\n");
    assert_eq!(z.len(), 2);
    assert_eq!(
        parse_lspci_name(
            r#"0c:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05"#
        ),
        "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2"
    );
}

#[test]
fn blkid_merge() {
    let mut disks = vec![
        Disk {
            name: "loop0".into(),
            path: "/dev/loop0".into(),
            ..Default::default()
        },
        Disk {
            name: "sdx".into(),
            path: "/dev/sdx".into(),
            children: vec![Node {
                name: "sdx1".into(),
                path: "/dev/sdx1".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    ];
    let tags = parse_blkid_export("DEVNAME=/dev/loop0\nLABEL=media1\nUUID=abc\nTYPE=ext4\n\nDEVNAME=/dev/sdx1\nTYPE=xfs\nPARTUUID=p1\n");
    merge_blkid(&mut disks, &tags);
    assert_eq!(
        (disks[0].fstype.as_str(), disks[0].label.as_str()),
        ("ext4", "media1")
    );
    assert_eq!(
        (
            disks[1].children[0].fstype.as_str(),
            disks[1].children[0].partuuid.as_str()
        ),
        ("xfs", "p1")
    );
}

#[test]
fn ses_status() {
    let els = parse_ses_status(&String::from_utf8(fixture("sg_ses_p2.txt")).unwrap());
    let get = |t: &str, i: u32| {
        els.iter()
            .find(|e| e.kind == t && e.index == i)
            .cloned()
            .unwrap()
    };
    assert!(els.iter().all(|e| e.kind != "Device slot"
        && !e.kind.starts_with("Vendor")
        && e.kind != "SAS connector"));
    let psu = get("Power supply", 1);
    assert_eq!(
        (psu.level.as_str(), psu.status.as_str()),
        ("crit", "Critical")
    );
    assert!(
        psu.detail.contains("ac fail") && psu.detail.contains("off"),
        "{}",
        psu.detail
    );
    assert_eq!(get("Power supply", 0).detail, "");
    assert_eq!(get("Cooling", 3).detail, "3050 rpm");
    assert_eq!(get("Temperature sensor", 9).detail, "37 °C");
    assert_eq!(get("Voltage sensor", 0).detail, "5.03 V");
    assert_eq!(get("Current sensor", 1).detail, "3.94 A");
    assert_eq!(get("Temperature sensor", 11).level, "absent");
    assert_eq!(get("Voltage sensor", 2).level, "crit");
    let enc = get("Enclosure", 0);
    assert!(enc.level == "warn" && enc.detail.contains("failure indication"));
    assert_eq!(enclosure_level(&els), "crit");
}

/// sysfs tree shaped like spiritlab's: LSI SAS2308 at 0000:0c:00.0,
/// host2, an expander, end devices and an SES enclosure.
pub(crate) fn build_sysfs() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    let p = |s: &str| -> PathBuf { root.join(s) };
    let mk = |s: &str| fs::create_dir_all(p(s)).unwrap();
    let write = |s: &str, v: &str| {
        fs::create_dir_all(p(s).parent().unwrap()).unwrap();
        fs::write(p(s), format!("{v}\n")).unwrap();
    };
    let link = |target: &str, s: &str| {
        fs::create_dir_all(p(s).parent().unwrap()).unwrap();
        symlink(target, p(s)).unwrap();
    };
    let up = |s: &str| "../".repeat(s.matches('/').count());

    let hba = "devices/pci0000:00/0000:00:03.2/0000:0a:00.0/0000:0b:01.0/0000:0c:00.0";
    mk("bus/pci/drivers/mpt3sas");
    link(
        &format!("{}bus/pci/drivers/mpt3sas", up(&format!("{hba}/driver"))),
        &format!("{hba}/driver"),
    );
    let host = format!("{hba}/host2");
    let exp = format!("{host}/port-2:0/expander-2:0");
    let enc_dev = format!("{exp}/port-2:0:0/end_device-2:0:0/target2:0:0/2:0:0:0");
    let enc = format!("{enc_dev}/enclosure/2:0:0:0");
    write(&format!("{enc}/id"), "0x500605b000000abc");
    write(&format!("{enc_dev}/vendor"), "LSI");
    write(&format!("{enc_dev}/model"), "SAS2X36");
    link(&format!("../../{enc}"), "class/enclosure/2:0:0:0");
    link("../..", &format!("{enc}/device"));
    let sdi = format!("{exp}/port-2:0:9/end_device-2:0:9/target2:0:9/2:0:9:0");
    mk(&format!("{sdi}/block/sdi"));
    write(&format!("{sdi}/sas_address"), "0x500605ba0127a8d4");
    let slot9 = format!("{enc}/Slot 09");
    write(&format!("{slot9}/slot"), "9");
    write(&format!("{slot9}/status"), "OK");
    write(&format!("{slot9}/fault"), "0");
    write(&format!("{slot9}/locate"), "1");
    link(
        &format!("{}{sdi}", up(&format!("{slot9}/device"))),
        &format!("{slot9}/device"),
    );
    link(
        &format!("{}{slot9}", up(&format!("{sdi}/enclosure_device:Slot 09"))),
        &format!("{sdi}/enclosure_device:Slot 09"),
    );
    write(&format!("{enc}/Slot 03/slot"), "3");
    write(&format!("{enc}/Slot 03/status"), "Not Installed");
    link(&format!("../{sdi}/block/sdi"), "block/sdi");
    link(
        &format!("{}{sdi}", up(&format!("{sdi}/block/sdi/device"))),
        &format!("{sdi}/block/sdi/device"),
    );
    write("class/sas_device/end_device-2:0:9/bay_identifier", "9");
    link(&format!("../../{host}"), "class/sas_host/host2");
    let host3 = "devices/pci0000:00/0000:00:03.2/0000:0a:00.0/0000:0b:09.0/0000:0e:00.0/host3";
    mk(host3);
    link(&format!("../../{host3}"), "class/sas_host/host3");
    // SES generic device sg9 -> enclosure 2:0:0:0
    write(&format!("{enc_dev}/type"), "13");
    link(
        &format!("{}{enc_dev}", up("class/scsi_generic/sg9/device")),
        "class/scsi_generic/sg9/device",
    );
    let nv = "devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/nvme0/nvme0n1";
    mk(nv);
    link(&format!("../{nv}"), "block/nvme0n1");
    td
}

#[test]
fn sysfs_topology() {
    let td = build_sysfs();
    let s = Sysfs::new(td.path());
    let t = s.topology("sdi");
    assert_eq!(
        (
            t.hba.as_str(),
            t.scsi_host.as_str(),
            t.expander.as_str(),
            t.end_device.as_str()
        ),
        ("0000:0c:00.0", "host2", "expander-2:0", "end_device-2:0:9")
    );
    assert_eq!(t.hba_driver, "mpt3sas");
    assert_eq!(
        (t.sas_address.as_str(), t.bay_id),
        ("0x500605ba0127a8d4", Some(9))
    );
    let e = t.enclosure.unwrap();
    assert_eq!(
        (e.enclosure.as_str(), e.component.as_str(), e.slot, e.locate),
        ("2:0:0:0", "Slot 09", Some(9), true)
    );
    let nv = s.topology("nvme0n1");
    assert_eq!(
        (nv.hba.as_str(), nv.port.as_str()),
        ("0000:01:00.0", "nvme0")
    );
    let encs = s.enclosures();
    assert_eq!(encs.len(), 1);
    assert_eq!(encs[0].components.len(), 2);
    assert_eq!(encs[0].components[1].disk, "sdi");
    assert_eq!(encs[0].vendor, "LSI");
    let hosts = s.sas_hosts();
    assert_eq!(hosts["host2"], "0000:0c:00.0");
    assert_eq!(hosts["host3"], "0000:0e:00.0");
    assert_eq!(s.sg_for_enclosure("2:0:0:0"), "sg9");
}

#[test]
fn collect_with_fakes() {
    let td = build_sysfs();
    let swaps = td.path().join("swaps");
    fs::write(&swaps, fixture("proc_swaps")).unwrap();
    let lsblk_key = format!("lsblk {}", LSBLK_ARGS.join(" "));
    let fake = Fake::new(vec![
        (lsblk_key.as_str(), Fake::ok(&fixture("lsblk.json"))),
        ("findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS", Fake::ok(&fixture("findmnt.json"))),
        ("lvs --reportformat json -o vg_name,lv_dm_path", Fake::ok(br#"{"report":[{"lv":[{"vg_name":"pve","lv_dm_path":"/dev/mapper/pve-root"}]}]}"#)),
        ("pvs --reportformat json -o pv_name,vg_name", Fake::ok(br#"{"report":[{"pv":[{"pv_name":"/dev/nvme0n1p3","vg_name":"pve"}]}]}"#)),
        ("lspci -mm -s 0000:0c:00.0", Fake::ok(br#"0c:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05"#)),
        ("lspci -mm -s 0000:0e:00.0", Fake::ok(br#"0e:00.0 "Serial Attached SCSI controller" "Broadcom / LSI" "SAS2308 PCI-Express Fusion-MPT SAS-2" -r05"#)),
        ("lspci -mm -s 0000:01:00.0", Fake::ok(br#"01:00.0 "Non-Volatile memory controller" "Sandisk Corp" "PC SN530 NVMe SSD" -r01"#)),
        ("sg_ses -p 0x2 /dev/sg9", Fake::ok(&fixture("sg_ses_p2.txt"))),
    ]);
    let mut c = Collector::new(&fake, false);
    c.sysfs = Sysfs::new(td.path());
    c.proc_swaps = swaps;
    c.resolve = Box::new(spiritlab_resolver);
    c.udev_data_dir = td.path().to_path_buf();
    let inv = c.collect().unwrap();
    assert_eq!(inv.hbas.len(), 3);
    assert_eq!(
        inv.find_disk("sdi").unwrap().topology.hba_name,
        "Broadcom / LSI SAS2308 PCI-Express Fusion-MPT SAS-2"
    );
    assert!(inv.find_disk("nvme0n1").unwrap().protected);
    assert!(!inv.find_disk("sdi").unwrap().protected);
    assert!(inv.warnings.is_empty(), "{:?}", inv.warnings);
    assert_eq!(inv.enclosures[0].sg_device, "sg9");
    assert_eq!(inv.enclosures[0].status, "crit");
}
