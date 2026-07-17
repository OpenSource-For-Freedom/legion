use legion_core::{
    alerts::{severity_from_label, Alert, AlertKind, Severity},
    Database,
};

fn make_alert() -> Alert {
    Alert {
        id: 0,
        kind: AlertKind::CveMatch,
        severity: Severity::Critical,
        title: "CVE match for vulnerable-package".to_string(),
        detail: "duplicate scanner finding should not accumulate".to_string(),
        package_name: Some("vulnerable-package".to_string()),
        package_ecosystem: Some("npm".to_string()),
        ip_address: None,
        cve_ids: vec!["CVE-2026-0001".to_string()],
        event_title: Some("test advisory".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
        acked: false,
        file_path: None,
        source: "test".to_string(),
    }
}

#[test]
fn severity_labels_are_case_insensitive() {
    assert_eq!(severity_from_label("critical"), Severity::Critical);
    assert_eq!(severity_from_label("HIGH"), Severity::High);
    assert_eq!(severity_from_label(" med "), Severity::Medium);
    assert_eq!(severity_from_label("Low"), Severity::Low);
}

#[test]
fn save_alerts_replaces_duplicate_active_finding() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("legion.db")).unwrap();
    let alert = make_alert();

    db.save_alerts(std::slice::from_ref(&alert)).unwrap();
    db.save_alerts(&[alert]).unwrap();

    let active = db.get_alerts(Some(false)).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].package_name.as_deref(),
        Some("vulnerable-package")
    );
    assert_eq!(active[0].cve_ids, vec!["CVE-2026-0001"]);
}

#[test]
fn clear_agent_alerts_removes_stale_unacked_ares_findings_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("legion.db")).unwrap();
    let mut agent_alert = make_alert();
    agent_alert.title = "ARES: SYS-09 Ares Rootkit Stealth Indicator".to_string();
    let normal_alert = make_alert();

    db.save_alerts(&[agent_alert, normal_alert]).unwrap();
    let deleted = db.clear_agent_alerts().unwrap();
    assert_eq!(deleted, 1);

    let active = db.get_alerts(Some(false)).unwrap();
    assert_eq!(active.len(), 1);
    assert!(!active[0].title.starts_with("ARES:"));
}

#[test]
fn clear_agent_alerts_also_removes_legacy_poncho_rows() {
    // The agent was formerly named "Poncho"; its rows carry a `PONCHO:` prefix.
    // Startup cleanup must purge both the current `ARES:` and legacy `PONCHO:`
    // artifact-less framework rollups, but leave real (artifact-bearing) findings.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("legion.db")).unwrap();
    let mut ares = make_alert();
    ares.title = "ARES: A01:2021 Broken Access Control".to_string();
    let mut poncho = make_alert();
    poncho.title = "PONCHO: SYS-04 Privilege Escalation Detected".to_string();
    let artifact = make_alert(); // real, artifact-bearing OSV finding

    db.save_alerts(&[ares, poncho, artifact]).unwrap();
    let deleted = db.clear_agent_alerts().unwrap();
    assert_eq!(deleted, 2, "both ARES: and PONCHO: rollups must be purged");

    let active = db.get_alerts(Some(false)).unwrap();
    assert_eq!(active.len(), 1);
    assert!(!active[0].title.starts_with("ARES:"));
    assert!(!active[0].title.starts_with("PONCHO:"));
}

#[test]
fn remediation_offers_update_and_remove() {
    use legion_core::quarantine::QuarantineManager;
    // With a known fixed version: an in-place upgrade AND a removal fallback.
    let r = QuarantineManager::remediation_cmd("npm", "lodash", Some("4.17.21"));
    assert_eq!(r.update.as_deref(), Some("npm install lodash@4.17.21"));
    assert_eq!(r.remove, "npm uninstall lodash");

    let c = QuarantineManager::remediation_cmd("crates", "rustls-webpki", Some("0.102.0"));
    assert_eq!(
        c.update.as_deref(),
        Some("cargo update -p rustls-webpki --precise 0.102.0")
    );

    // No fixed version -> removal only, no update command.
    let n = QuarantineManager::remediation_cmd("pypi", "requests", None);
    assert!(n.update.is_none());
    assert_eq!(n.remove, "pip uninstall -y requests");
}

#[test]
fn clear_alerts_removes_all_unacked_but_keeps_acked() {
    // Operator queue reset drops every UNacked alert; acknowledged alerts are
    // retained as triage history.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("legion.db")).unwrap();
    let mut a1 = make_alert();
    a1.title = "unacked one".to_string();
    let mut a2 = make_alert();
    a2.title = "unacked two".to_string();
    db.save_alerts(&[a1, a2]).unwrap();

    let active = db.get_alerts(Some(false)).unwrap();
    assert_eq!(active.len(), 2);
    db.ack_alert(active[0].id).unwrap();

    let removed = db.clear_alerts().unwrap();
    assert_eq!(removed, 1, "only the remaining unacked alert is cleared");

    assert!(db.get_alerts(Some(false)).unwrap().is_empty());
    assert_eq!(db.get_alerts(Some(true)).unwrap().len(), 1);
}

#[test]
fn sensor_alerted_keys_round_trip_through_the_database() {
    // Guards the seed that stops the package sensor re-popping every malicious
    // package on restart. This is a round trip on purpose: the `kind` column
    // stores the Display form ("Suspicious Pkg"), not the variant name, so a
    // query written against the variant name silently returns nothing and
    // disables the dedup without failing anything.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("t.db")).unwrap();

    let hit = legion_core::pkg_sensor::MaliciousHit {
        name: "openai-node".to_string(),
        ecosystem: "npm".to_string(),
        version: Some("9.9.9".to_string()),
        detail: "typosquat".to_string(),
        atlas_id: Some("AML.T0012".to_string()),
    };
    db.save_alerts(&[legion_core::pkg_sensor::to_alert(&hit)])
        .unwrap();

    let keys = db.sensor_alerted_keys().unwrap();
    assert!(
        keys.contains(&hit.key()),
        "stored sensor alert must seed the dedup; got {keys:?}"
    );

    // A seeded sensor must then stay silent for that package.
    let pkgs = vec![legion_core::scanner::ScannedPackage {
        ecosystem: legion_core::scanner::Ecosystem::Npm,
        name: "openai-node".to_string(),
        version: Some("9.9.9".to_string()),
        path: None,
    }];
    let mut sensor = legion_core::pkg_sensor::PackageSensor::with_seen(keys);
    assert!(
        sensor.new_hits(&pkgs).is_empty(),
        "restart must not re-pop an already-reported package"
    );
}

#[test]
fn sensor_keys_survive_the_operator_acking_the_alert() {
    // Acking means "I have dealt with this". Popping a critical desktop alert
    // for it again on the next launch would train the operator to ignore the
    // sensor, so acked rows must still seed the dedup.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("t.db")).unwrap();

    let hit = legion_core::pkg_sensor::MaliciousHit {
        name: "chatgpt".to_string(),
        ecosystem: "pypi".to_string(),
        version: None,
        detail: "known-malicious".to_string(),
        atlas_id: Some("AML.T0012".to_string()),
    };
    db.save_alerts(&[legion_core::pkg_sensor::to_alert(&hit)])
        .unwrap();
    for a in db.get_alerts(Some(false)).unwrap() {
        db.ack_alert(a.id).unwrap();
    }

    assert!(
        db.sensor_alerted_keys().unwrap().contains(&hit.key()),
        "an acked sensor alert must still suppress a re-pop"
    );
}
