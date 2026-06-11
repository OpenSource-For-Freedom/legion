use legion_core::{
    alerts::{AlertEngine, AlertKind, Severity},
    telemetry::{parse_linux_journal_events_for_testing, parse_macos_unified_events_for_testing},
};

#[test]
fn linux_journald_events_parse_and_correlate() {
    let fixture = std::fs::read_to_string("../../tests/fixtures/local_events_linux_journal.jsonl")
        .expect("linux journal fixture");
    let events = parse_linux_journal_events_for_testing(&fixture);
    assert_eq!(events.len(), 4);
    assert!(events.iter().any(|e| e.log_name == "nginx.service"));
    assert!(events
        .iter()
        .any(|e| e.log_name == "systemd-networkd.service"));

    let alerts = AlertEngine::from_local_events(&events);
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("System service failure")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Authentication failure")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Network service anomaly")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Audit policy or journal tampering")));
    assert!(alerts
        .iter()
        .any(|a| matches!(a.kind, AlertKind::SystemAnomaly)));
    assert!(alerts.iter().any(|a| matches!(a.severity, Severity::High)));
}

#[test]
fn macos_unified_events_parse_and_correlate() {
    let fixture = std::fs::read_to_string("../../tests/fixtures/local_events_macos_unified.json")
        .expect("macos unified log fixture");
    let events = parse_macos_unified_events_for_testing(&fixture);
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|e| e.log_name == "launchd"));
    assert!(events.iter().any(|e| e.log_name == "syspolicyd"));

    let alerts = AlertEngine::from_local_events(&events);
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("System service failure")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Authentication failure")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Mandatory access control denial")));
}

#[test]
fn rootkit_and_kernel_module_events_correlate_to_alerts() {
    let events = vec![
        legion_core::WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 0,
            level: "Critical".to_string(),
            log_name: "kernel".to_string(),
            message: "possible rootkit syscall hook hiding process entries".to_string(),
        },
        legion_core::WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 0,
            level: "Warning".to_string(),
            log_name: "audit".to_string(),
            message: "insmod loaded suspicious .ko kernel module".to_string(),
        },
    ];

    let alerts = AlertEngine::from_local_events(&events);
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Rootkit or kernel stealth indicator")));
    assert!(alerts
        .iter()
        .any(|a| a.title.contains("Kernel module or extension activity")));
    assert!(alerts
        .iter()
        .any(|a| matches!(a.severity, Severity::Critical)));
}
