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
fn clear_agent_alerts_removes_stale_unacked_poncho_findings_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("legion.db")).unwrap();
    let mut agent_alert = make_alert();
    agent_alert.title = "PONCHO: SYS-09 Mythos Rootkit Stealth Indicator".to_string();
    let normal_alert = make_alert();

    db.save_alerts(&[agent_alert, normal_alert]).unwrap();
    let deleted = db.clear_agent_alerts().unwrap();
    assert_eq!(deleted, 1);

    let active = db.get_alerts(Some(false)).unwrap();
    assert_eq!(active.len(), 1);
    assert!(!active[0].title.starts_with("PONCHO:"));
}
