//! Integration tests for legion-core: feeds parsing, scanner, alert correlation.

use legion_core::{
    alerts::{Alert, AlertEngine, AlertKind, Severity},
    feeds::{AbuseIpPayload, AffectedPackage, CyberEvent, Enrichment},
    scanner::{Ecosystem, ScannedPackage},
};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn make_event(name: &str, ecosystem: &str, cve: &str, severity: f64) -> CyberEvent {
    CyberEvent {
        id: "test_id".to_owned(),
        source: "test".to_owned(),
        source_url: None,
        title: format!("Test event for {name}"),
        summary: None,
        event_type: "cyber_attack".to_owned(),
        severity: Some(severity),
        risk_band: Some(5),
        date_start: Some("2024-01-01".to_owned()),
        date_end: None,
        country: None,
        admin1: None,
        city: None,
        lat: None,
        lon: None,
        casualties: None,
        tags: None,
        enrichment: Some(Enrichment {
            cve_ids: Some(vec![cve.to_owned()]),
            affected_packages: Some(vec![AffectedPackage {
                ecosystem: ecosystem.to_owned(),
                name: name.to_owned(),
                version_constraint: None,
                fixed_version: None,
            }]),
            threat_actors: None,
            campaigns: None,
            attack_techniques: Some(vec!["rce".to_owned()]),
            asset_buckets: None,
            references: None,
            so_what: None,
            model: None,
            generated_at: None,
        }),
    }
}

fn make_package(name: &str, ecosystem: Ecosystem) -> ScannedPackage {
    ScannedPackage {
        ecosystem,
        name: name.to_owned(),
        version: Some("1.0.0".to_owned()),
        path: None,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn test_parse_cyber_event_json() {
    let fixture =
        std::fs::read_to_string("../../tests/fixtures/mock_cyber.json").unwrap();
    let events: Vec<CyberEvent> = serde_json::from_str(&fixture).unwrap();
    assert_eq!(events.len(), 2);
    let first = &events[0];
    assert_eq!(first.id, "aabbccdd11223344");
    assert!(first.severity.unwrap() > 90.0);
    let enrichment = first.enrichment.as_ref().unwrap();
    let pkgs = enrichment.affected_packages.as_ref().unwrap();
    assert_eq!(pkgs.len(), 3);
    assert_eq!(pkgs[0].name, "openssl");
    assert_eq!(pkgs[0].ecosystem, "crates");
    let cves = enrichment.cve_ids.as_ref().unwrap();
    assert_eq!(cves[0], "CVE-2024-0001");
}

#[test]
fn test_parse_abuseipdb_json() {
    let fixture =
        std::fs::read_to_string("../../tests/fixtures/mock_abuseipdb.json").unwrap();
    let payload: AbuseIpPayload = serde_json::from_str(&fixture).unwrap();
    assert!(payload.ok);
    assert_eq!(payload.ips.len(), 3);
    assert_eq!(payload.ips[0].ip, "198.51.100.1");
    assert_eq!(payload.ips[0].abuse_score, Some(100));
}

#[test]
fn test_alert_cve_match_cargo() {
    let events = vec![make_event("openssl", "crates", "CVE-2024-0001", 95.0)];
    let packages = vec![make_package("openssl", Ecosystem::Cargo)];

    let alerts = AlertEngine::correlate(&packages, &events);
    assert_eq!(alerts.len(), 1);
    let a = &alerts[0];
    assert_eq!(a.kind, AlertKind::CveMatch);
    assert_eq!(a.severity, Severity::Critical);
    assert_eq!(a.package_name.as_deref(), Some("openssl"));
    assert_eq!(a.package_ecosystem.as_deref(), Some("crates"));
    assert!(a.cve_ids.contains(&"CVE-2024-0001".to_owned()));
}

#[test]
fn test_alert_cve_match_npm() {
    let events = vec![make_event("lodash", "npm", "CVE-2024-1234", 80.0)];
    let packages = vec![make_package("lodash", Ecosystem::Npm)];

    let alerts = AlertEngine::correlate(&packages, &events);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, AlertKind::CveMatch);
    assert_eq!(alerts[0].severity, Severity::High);
}

#[test]
fn test_alert_no_match() {
    let events = vec![make_event("evil-pkg", "crates", "CVE-2024-9999", 90.0)];
    let packages = vec![make_package("safe-pkg", Ecosystem::Cargo)];

    let alerts = AlertEngine::correlate(&packages, &events);
    assert!(alerts.is_empty());
}

#[test]
fn test_alert_case_insensitive_match() {
    // package names should match regardless of case
    let events = vec![make_event("OpenSSL", "crates", "CVE-2024-0001", 85.0)];
    let packages = vec![make_package("openssl", Ecosystem::Cargo)];

    let alerts = AlertEngine::correlate(&packages, &events);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_alert_ecosystem_mismatch() {
    // npm event should NOT match a Cargo package with same name
    let events = vec![make_event("lodash", "npm", "CVE-2024-1234", 80.0)];
    let packages = vec![make_package("lodash", Ecosystem::Cargo)];

    let alerts = AlertEngine::correlate(&packages, &events);
    assert!(alerts.is_empty());
}

#[test]
fn test_ip_alert() {
    let fixture =
        std::fs::read_to_string("../../tests/fixtures/mock_abuseipdb.json").unwrap();
    let payload: AbuseIpPayload = serde_json::from_str(&fixture).unwrap();

    let active = vec!["198.51.100.1".to_owned(), "10.0.0.1".to_owned()];
    let alerts = AlertEngine::check_ips(&active, &payload);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, AlertKind::IpBlacklist);
    assert_eq!(alerts[0].ip_address.as_deref(), Some("198.51.100.1"));
}

#[test]
fn test_severity_levels() {
    assert_eq!(Severity::from_score(95.0), Severity::Critical);
    assert_eq!(Severity::from_score(85.0), Severity::High);
    assert_eq!(Severity::from_score(55.0), Severity::Medium);
    assert_eq!(Severity::from_score(25.0), Severity::Low);
    assert_eq!(Severity::from_score(5.0),  Severity::Info);
}

#[test]
fn test_dedup_alerts_keeps_highest_severity() {
    let events = vec![
        make_event("openssl", "crates", "CVE-2024-0001", 95.0),
        make_event("openssl", "crates", "CVE-2024-0002", 70.0),
    ];
    let packages = vec![make_package("openssl", Ecosystem::Cargo)];

    let alerts = AlertEngine::correlate(&packages, &events);
    // Should deduplicate to 1 alert (highest severity wins)
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, Severity::Critical);
}
