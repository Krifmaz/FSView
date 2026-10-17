use super::*;

fn load(name: &str, devtype: &str) -> Report {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/spiritlab")
        .join(name);
    parse(&std::fs::read(p).unwrap(), devtype).unwrap()
}

#[test]
fn scsi_failed_self_test() {
    let r = load("smart_sdc_scsi.json", "");
    assert_eq!(
        (r.protocol.as_str(), r.model.as_str(), r.serial.as_str()),
        ("SCSI", "ST2000DM 006-2DM164 SM", "Z4Z9WWC9")
    );
    assert!(
        r.power_on_hours.is_none() && !r.notes.is_empty(),
        "bridge hours must be unknown"
    );
    assert_eq!(r.self_tests.len(), 2);
    assert_eq!(
        (
            r.self_tests[0].outcome.as_str(),
            r.self_tests[0].detail.as_str()
        ),
        ("failed", "Medium Error")
    );
    assert!(r.looks_like_bridged_ata());
    assert_eq!(r.long_minutes, 208);
    let a = evaluate(&r, &Thresholds::default());
    assert_eq!(a.status, CRIT);
    assert!(a.findings[0].text.contains("Failed in segment"));
}

#[test]
fn scsi_near_trip() {
    let r = load("smart_sdi_scsi.json", "");
    assert_eq!((r.temperature_c, r.temp_trip_c), (Some(36), Some(40)));
    let a = evaluate(&r, &Thresholds::default());
    assert_eq!(a.status, WARN);
    assert_eq!(a.findings.len(), 1);
    assert!(a.findings[0].text.contains("trip point 40"));
    assert_eq!(r.self_tests[0].outcome, "aborted");
}

#[test]
fn nvme() {
    let r = load("smart_nvme0n1.json", "");
    assert_eq!(
        (
            r.protocol.as_str(),
            r.power_on_hours,
            r.nvme_percent_used,
            r.temp_trip_c
        ),
        ("NVMe", Some(4883), Some(0), Some(79))
    );
    assert_eq!(r.self_tests[0].outcome, "aborted");
    assert_eq!(r.self_tests[1].outcome, "passed");
    let tb = r.nvme_data_written_tb.unwrap();
    assert!(tb > 23.0 && tb < 24.0);
    assert_eq!(evaluate(&r, &Thresholds::default()).status, OK);
}

#[test]
fn ata_via_sat() {
    let r = load("smart_sdb_sat_synthetic.json", "sat");
    assert_eq!((r.protocol.as_str(), r.devtype.as_str()), ("ATA", "sat"));
    assert_eq!(
        (r.reallocated, r.pending, r.temperature_c, r.power_on_hours),
        (Some(8), Some(0), Some(31), Some(36842))
    );
    assert_eq!((r.long_minutes, r.short_minutes), (744, 1));
    assert_eq!(r.self_tests[0].outcome, "passed");
    assert_eq!(r.self_tests[1].outcome, "failed");
    let a = evaluate(&r, &Thresholds::default());
    assert_eq!(a.status, WARN);
    assert!(a.findings[0].text.contains("reallocated sectors: 8"));
}

#[test]
fn real_sat_error_log() {
    let r = load("smart_ZXA0R1KK_sat.json", "sat");
    assert_eq!(r.serial, "ZXA0R1KK");
    assert_eq!(
        (
            r.reallocated,
            r.pending,
            r.offline_uncorrectable,
            r.reported_uncorrectable,
            r.temperature_c
        ),
        (Some(6), Some(4), Some(4), Some(138), Some(37))
    );
    assert_eq!(r.ata_error_count, Some(1020));
    assert!(r.ata_last_error.contains("UNC"));
    assert_eq!(r.self_tests[0].outcome, "aborted");
    assert_eq!(r.self_tests[2].outcome, "passed");
    let a = evaluate(&r, &Thresholds::default());
    let all: String = a.findings.iter().map(|f| f.text.clone() + "\n").collect();
    assert_eq!(a.status, WARN, "{all}");
    for frag in [
        "reallocated sectors: 6",
        "pending sectors: 4",
        "offline uncorrectable sectors: 4",
        "reported uncorrectable errors: 138",
        "ATA error log: 1020 errors, latest at 10624 h",
    ] {
        assert!(all.contains(frag), "missing {frag} in {all}");
    }
}

#[test]
fn standby_and_failed_overall() {
    let r = parse(br#"{"smartctl":{"exit_status":2,"messages":[{"string":"Device is in STANDBY mode, exit(2)","severity":"information"}]},"device":{"name":"/dev/sdx","type":"sat","protocol":"ATA"}}"#, "sat").unwrap();
    assert!(r.standby);
    let failed = Report {
        smart_available: true,
        passed: Some(false),
        ..Default::default()
    };
    assert_eq!(evaluate(&failed, &Thresholds::default()).status, CRIT);
    assert_eq!(
        evaluate(&Report::default(), &Thresholds::default()).status,
        UNKNOWN
    );
}

#[test]
fn lifetime_traffic_and_life() {
    let hdd = load("smart_ZXA0R1KK_sat.json", "sat");
    assert_eq!(hdd.written_bytes, Some(481_579_786_942 * 512));
    assert_eq!(hdd.read_bytes, Some(860_651_841_421 * 512));
    assert_eq!(hdd.wear_used_pct, None, "hard disks have no wear indicator");
    let l = lifespan(&hdd, OK);
    assert!(l.workload_bytes_per_year.unwrap() > 0);
    assert!(l.basis.contains("5-year"));
    assert_eq!(l.remaining_written_bytes, None);
    let failing = lifespan(&hdd, CRIT);
    assert_eq!(
        (failing.level.as_str(), failing.remaining_pct),
        (CRIT, Some(0))
    );
    let warn = lifespan(&hdd, WARN);
    assert!(warn.upper_bound);
    assert_eq!(warn.remaining_pct, lifespan(&hdd, OK).remaining_pct);

    let nvme = load("smart_nvme0n1.json", "");
    assert_eq!(nvme.written_bytes, Some(45_543_999 * 512_000));
    let l = lifespan(&nvme, OK);
    assert!(l.basis.contains("flash"), "{l:?}");
    if let Some(used) = nvme.wear_used_pct.filter(|u| *u >= 1) {
        assert_eq!(l.remaining_pct, Some(100 - used));
        assert!(l.remaining_written_bytes.unwrap() > nvme.written_bytes.unwrap());
    }

    // Bridged SATA disk reports 0 GB processed: unknown, not zero.
    let scsi = load("smart_sdc_scsi.json", "");
    assert_eq!(scsi.written_bytes, None);

    let old = Report {
        power_on_hours: Some(53_238),
        rotation_rate: 7200,
        protocol: "ATA".into(),
        ..Default::default()
    };
    let l = lifespan(&old, OK);
    assert_eq!((l.remaining_pct, l.level.as_str()), (Some(0), WARN));
}

#[test]
fn old_error_log_with_later_passing_test_is_not_a_warning() {
    let mut r = Report {
        power_on_hours: Some(1743),
        ata_error_count: Some(4),
        ata_last_error_hours: Some(673),
        ata_last_error: "Error: UNC".into(),
        passed: Some(true),
        smart_available: true,
        ..Default::default()
    };
    r.self_tests.push(SelfTest {
        kind: "Extended offline".into(),
        status: "Completed without error".into(),
        outcome: "passed".into(),
        lifetime_hours: Some(1690),
        lba: None,
        detail: String::new(),
    });
    let a = evaluate(&r, &Thresholds::default());
    assert_eq!(a.status, OK, "{:?}", a.findings);
    assert!(a.findings[0].text.contains("old"));

    // Recent errors still warn.
    r.ata_last_error_hours = Some(1700);
    assert_eq!(evaluate(&r, &Thresholds::default()).status, WARN);
    // Old errors without a later passing test still warn.
    r.ata_last_error_hours = Some(673);
    r.self_tests[0].lifetime_hours = Some(600);
    assert_eq!(evaluate(&r, &Thresholds::default()).status, WARN);
}

#[test]
fn acknowledged_errors_only_warn_when_new() {
    let r = Report {
        power_on_hours: Some(100),
        ata_error_count: Some(4),
        ata_last_error_hours: Some(90),
        crc_errors: Some(3),
        passed: Some(true),
        smart_available: true,
        ..Default::default()
    };
    let t = Thresholds::default();
    let a = evaluate(&r, &t);
    assert_eq!(a.status, WARN);
    assert!(a.findings.iter().all(|f| f.ackable));

    let ack = Ack {
        ata_errors: 4,
        crc_errors: 3,
    };
    let a = evaluate_with(&r, &t, Some(&ack));
    assert_eq!(a.status, OK, "{:?}", a.findings);
    assert!(a
        .findings
        .iter()
        .all(|f| f.text.ends_with("(acknowledged)") && !f.ackable));

    let newer = Report {
        ata_error_count: Some(6),
        ..r
    };
    let a = evaluate_with(&newer, &t, Some(&ack));
    assert_eq!(a.status, WARN);
    assert!(a
        .findings
        .iter()
        .any(|f| f.text.contains("2 new since acknowledged")));
}
