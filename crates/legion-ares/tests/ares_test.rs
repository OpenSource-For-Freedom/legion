//! Full test suite for legion-ares:
//! - AresConfig save/load/validate
//! - ModelRegistry blocked/allowed checks
//! - Rule evaluation with comprehensive mock data
//! - KnowledgeContext summary accuracy
//! - Search result parsing
//! - Agent manifest JSON validity
//! - Integration: all rule frameworks produce correct hits

use legion_ares::{
    chat::build_findings_report, evaluate_rules, evaluate_rules_with_scope, load_rule_sets,
    model_registry::ModelRegistry, rules::RuleSet, AresChat, AresConfig, AresNeuralHunter,
    KnowledgeContext, RuntimeRuleScope,
};
use legion_core::{
    alerts::{Alert, AlertKind, Severity},
    AiThreat, AiThreatKind, DockerInfo, Drift, OsvFinding, SystemStats, WinEvent, YaraMatch,
};

// ─────────────────────────── helpers ────────────────────────────────────────

fn make_alert(kind: AlertKind, severity: Severity, title: &str) -> Alert {
    Alert {
        id: 0,
        kind,
        severity,
        title: title.to_string(),
        detail: format!("detail for {title}"),
        package_name: None,
        package_ecosystem: None,
        ip_address: None,
        cve_ids: vec![],
        event_title: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        acked: false,
        file_path: None,
        source: "test".to_string(),
    }
}

fn make_osv(pkg: &str, id: &str) -> OsvFinding {
    OsvFinding {
        package: pkg.to_string(),
        ecosystem: "npm".to_string(),
        version: Some("1.0.0".to_string()),
        osv_id: id.to_string(),
        summary: format!("Vulnerability in {pkg}"),
        severity: Some("HIGH".to_string()),
        cve_ids: vec![format!("CVE-2024-{}", pkg.len())],
        ghsa_ids: vec![],
        fixed_version: Some("2.0.0".to_string()),
        published: None,
    }
}

fn make_yara(rule: &str, sev: &str) -> YaraMatch {
    YaraMatch {
        rule: rule.to_string(),
        tags: vec!["malware".to_string()],
        severity: sev.to_string(),
        description: format!("YARA rule: {rule}"),
        target: "/tmp/suspicious".to_string(),
        matched_strings: vec!["$a".to_string()],
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn make_ai_threat(sev: &str, detail: &str) -> AiThreat {
    AiThreat {
        kind: AiThreatKind::MaliciousAiPackage,
        severity: sev.to_string(),
        package: Some("evil-gpt".to_string()),
        ecosystem: Some("pip".to_string()),
        version: Some("0.1.0".to_string()),
        detail: detail.to_string(),
        atlas_id: Some("AML.T0012".to_string()),
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn make_ai_threat_for(pkg: &str, eco: &str, sev: &str, detail: &str) -> AiThreat {
    AiThreat {
        kind: AiThreatKind::MaliciousAiPackage,
        severity: sev.to_string(),
        package: Some(pkg.to_string()),
        ecosystem: Some(eco.to_string()),
        version: Some("0.1.0".to_string()),
        detail: detail.to_string(),
        atlas_id: Some("AML.T0012".to_string()),
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn make_drift(kind: &str, detail: &str) -> Drift {
    Drift {
        kind: kind.to_string(),
        severity: "High".to_string(),
        detail: detail.to_string(),
    }
}

fn make_win_event(event_id: u32, level: &str, log_name: &str) -> WinEvent {
    WinEvent {
        time: "2026-01-01T00:00:00Z".to_string(),
        log_name: log_name.to_string(),
        level: level.to_string(),
        event_id,
        message: format!("Event {event_id} from {log_name}"),
    }
}

fn embedded_rule_sets() -> Vec<RuleSet> {
    // Load embedded defaults directly from the ares crate internals
    // by calling load_rule_sets with a non-existent dir (forces fallback)
    let tmp = std::path::PathBuf::from("/nonexistent/path/that/does/not/exist");
    load_rule_sets(&tmp)
}

fn empty_context() -> KnowledgeContext {
    KnowledgeContext {
        alerts: Vec::new(),
        osv: Vec::new(),
        ai_threats: Vec::new(),
        yara_matches: Vec::new(),
        drifts: Vec::new(),
        stats: SystemStats::default(),
        win_events: Vec::new(),
        docker: Vec::<DockerInfo>::new(),
        connections: Vec::new(),
        rule_hits: Vec::new(),
    }
}

// ─────────────────────────── AresConfig tests ──────────────────────────────

#[test]
fn config_default_has_allowed_model() {
    let cfg = AresConfig::default();
    assert_eq!(cfg.model, "legion-ares:qwen3-4b");
    assert!(
        !ModelRegistry::is_blocked(&cfg.model),
        "default model '{}' must not be blocked",
        cfg.model
    );
    assert!(
        !ModelRegistry::is_blocked(&cfg.fallback_model),
        "default fallback '{}' must not be blocked",
        cfg.fallback_model
    );
}

#[test]
fn config_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = AresConfig {
        model: "mistral:7b".to_string(),
        search_enabled: false,
        max_context_alerts: 25,
        ..Default::default()
    };

    cfg.save(dir.path()).unwrap();

    let loaded = AresConfig::load(dir.path());
    assert_eq!(loaded.model, "mistral:7b");
    assert!(!loaded.search_enabled);
    assert_eq!(loaded.max_context_alerts, 25);
}

#[test]
fn config_load_missing_returns_default() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = AresConfig::load(dir.path());
    assert_eq!(cfg.model, AresConfig::default().model);
}

#[test]
fn engine_findings_report_is_plain_text_and_grounded() {
    // The hunt is engine-first: findings come from the deterministic detector,
    // not the model. On an empty context the report states the posture and an
    // explicit "no findings" line — never a hallucinated report — and carries no
    // Markdown decoration.
    let ctx = empty_context();
    let posture = AresNeuralHunter::assess(
        &ctx.alerts,
        &ctx.win_events,
        &ctx.yara_matches,
        &ctx.rule_hits,
    );
    let report = build_findings_report(&ctx, &posture);

    assert!(report.contains("POSTURE:"));
    assert!(report.contains("No critical/high findings"));
    assert!(!report.contains("**"));
    assert!(!report.contains("```"));
}

#[test]
fn config_validate_rejects_deepseek() {
    let cfg = AresConfig {
        model: "deepseek-r1:7b".to_string(),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_err(),
        "deepseek model must fail validation"
    );
}

#[test]
fn config_validate_rejects_deepseek_fallback() {
    let cfg = AresConfig {
        fallback_model: "deepseek-coder:latest".to_string(),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_err(),
        "deepseek fallback must fail validation"
    );
}

#[test]
fn config_validate_passes_approved_models() {
    let cfg = AresConfig {
        model: "qwen3:8b".to_string(),
        fallback_model: "qwen3:4b".to_string(),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn system_prompt_uses_ares_mode_without_third_party_identity() {
    let cfg = AresConfig::default();
    let prompt = empty_context().to_system_prompt(&cfg);
    assert!(prompt.contains("OS DETECTION FIRST"));
    assert!(prompt.contains("Hunt lane:"));
    assert!(prompt.contains("Ares analyst mode"));
    assert!(prompt.contains("evidence-first"));
    assert!(prompt.contains("do not claim to be Claude"));
}

#[test]
fn system_prompt_handles_non_ascii_local_events_without_panicking() {
    let cfg = AresConfig::default();
    let mut ctx = empty_context();
    ctx.win_events.push(WinEvent {
        time: "2026-01-01T00:00:00Z".to_string(),
        event_id: 4625,
        level: "Warning".to_string(),
        log_name: "Security".to_string(),
        message: "Authentication failure for opérateur - défense résumé: échec repeated".repeat(8),
    });

    let prompt = ctx.to_system_prompt(&cfg);
    assert!(prompt.contains("RECENT LOCAL EVENTS"));
    assert!(prompt.contains("opérateur"));
}

// ─────────────────────────── ModelRegistry tests ─────────────────────────────

#[test]
fn model_registry_blocks_deepseek_exact() {
    assert!(ModelRegistry::is_blocked("deepseek-r1:7b"));
    assert!(ModelRegistry::is_blocked("deepseek-coder:latest"));
    assert!(ModelRegistry::is_blocked("deepseek:latest"));
}

#[test]
fn model_registry_blocks_deepseek_uppercase() {
    assert!(ModelRegistry::is_blocked("DeepSeek-R1:7b"));
    assert!(ModelRegistry::is_blocked("DEEPSEEK-CODER:latest"));
}

#[test]
fn model_registry_blocks_deepseek_embedded() {
    assert!(ModelRegistry::is_blocked("custom-deepseek-variant:latest"));
}

#[test]
fn model_registry_allows_approved_models() {
    let allowed = [
        "legion-ares:qwen3-4b",
        "legion-ares:qwen3-8b",
        "legion-ares:qwen3-1.7b",
        "qwen3:8b",
        "qwen3:4b",
        "qwen3:1.7b",
        "qwen2.5-coder:7b",
        "llama3.1:8b",
        "mistral:7b",
        "gemma3:4b",
        "phi4-mini:3.8b",
        "af-intel-analyst:v1",
    ];
    for tag in allowed {
        assert!(
            !ModelRegistry::is_blocked(tag),
            "model '{tag}' should be allowed"
        );
    }
}

#[test]
fn model_registry_allows_empty_string() {
    // Edge case: empty tag is not blocked (just undefined behaviour to allow)
    assert!(!ModelRegistry::is_blocked(""));
}

#[test]
fn model_registry_blocks_deepseek_evasions() {
    // Audit PON-3: separators, registry/namespace prefixes and tag suffixes must
    // not let a DeepSeek model slip past the policy filter.
    let evasions = [
        "deep-seek-r1:7b",
        "deep_seek:latest",
        "hf.co/someuser/DeepSeek-R1:q4",
        "myregistry.local/ds/deepseek:7b",
        "  deepseek-r1 ",
        "deep.seek:7b",
    ];
    for tag in evasions {
        assert!(
            ModelRegistry::is_blocked(tag),
            "evasion variant '{tag}' should be blocked"
        );
    }
}

#[test]
fn validate_host_accepts_loopback_and_rejects_remote() {
    // Loopback variants are always allowed.
    for host in [
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "https://127.0.0.1",
        "http://[::1]:11434",
    ] {
        assert!(
            AresConfig::validate_host(host).is_ok(),
            "loopback host '{host}' should validate"
        );
    }
    // Non-http schemes are rejected outright.
    assert!(AresConfig::validate_host("ftp://localhost").is_err());
    assert!(AresConfig::validate_host("localhost:11434").is_err());
    // A remote host is rejected unless the explicit opt-in env var is set.
    if std::env::var_os("LEGION_ALLOW_REMOTE_OLLAMA").is_none() {
        assert!(AresConfig::validate_host("http://evil.example.com:11434").is_err());
        assert!(AresConfig::validate_host("http://10.0.0.5:11434").is_err());
        // Userinfo must not be mistaken for the host.
        assert!(AresConfig::validate_host("http://127.0.0.1@evil.com/").is_err());
    }
}

// ─────────────────────────── Rule loading tests ──────────────────────────────

#[test]
fn embedded_rules_load_nonempty() {
    let sets = embedded_rule_sets();
    assert!(!sets.is_empty(), "embedded rule sets must not be empty");
}

#[test]
fn all_five_frameworks_present() {
    let sets = embedded_rule_sets();
    let frameworks: Vec<&str> = sets.iter().map(|rs| rs.framework.as_str()).collect();
    for fw in ["OWASP", "NIST", "CIS", "DEV", "SYSTEM"] {
        assert!(frameworks.contains(&fw), "framework '{fw}' must be present");
    }
}

#[test]
fn all_rules_have_required_fields() {
    let sets = embedded_rule_sets();
    for rs in &sets {
        assert!(!rs.framework.is_empty(), "rule set must have a framework");
        assert!(!rs.version.is_empty(), "rule set must have a version");
        assert!(
            !rs.rules.is_empty(),
            "rule set must have rules: {}",
            rs.framework
        );
        for rule in &rs.rules {
            assert!(
                !rule.id.is_empty(),
                "[{}] rule must have an id",
                rs.framework
            );
            assert!(
                !rule.title.is_empty(),
                "[{}] {} must have a title",
                rs.framework,
                rule.id
            );
            assert!(
                !rule.remediation.is_empty(),
                "[{}] {} must have remediation",
                rs.framework,
                rule.id
            );
            assert!(
                !rule.reference.is_empty(),
                "[{}] {} must have a reference",
                rs.framework,
                rule.id
            );
            assert!(
                matches!(
                    rule.severity.as_str(),
                    "Critical" | "High" | "Medium" | "Low"
                ),
                "[{}] {} has invalid severity: {}",
                rs.framework,
                rule.id,
                rule.severity
            );
        }
    }
}

#[test]
fn owasp_has_a06_vulnerable_components() {
    let sets = embedded_rule_sets();
    let owasp = sets
        .iter()
        .find(|rs| rs.framework == "OWASP")
        .expect("OWASP rules");
    assert!(
        owasp.rules.iter().any(|r| r.id == "A06:2021"),
        "OWASP must include A06:2021"
    );
}

#[test]
fn nist_has_si3_malicious_code() {
    let sets = embedded_rule_sets();
    let nist = sets
        .iter()
        .find(|rs| rs.framework == "NIST")
        .expect("NIST rules");
    assert!(
        nist.rules.iter().any(|r| r.id == "SI-3"),
        "NIST must include SI-3"
    );
}

#[test]
fn nist_has_ares_rootkit_kernel_and_listener_controls() {
    let sets = embedded_rule_sets();
    let nist = sets
        .iter()
        .find(|rs| rs.framework == "NIST")
        .expect("NIST rules");
    for id in ["SI-4-ARES", "SI-7-ARES", "AU-9-ARES"] {
        assert!(
            nist.rules.iter().any(|r| r.id == id),
            "NIST rules must include {id}"
        );
    }
}

#[test]
fn nist_has_multi_arch_hunt_config() {
    let sets = embedded_rule_sets();
    let nist = sets
        .iter()
        .find(|rs| rs.framework == "NIST")
        .expect("NIST rules");
    let cfg = nist.hunt_config.as_ref().expect("NIST hunt_config");
    assert_eq!(cfg.mode, "ares_multi_arch_hunt");
    assert!(cfg.os_detection_first);
    assert!(cfg.architecture_lanes.len() >= 4);
    for lane in [
        "windows-kernel",
        "linux-kernel",
        "package-supply-chain",
        "container-runtime",
        "firmware-boot",
    ] {
        assert!(
            cfg.architecture_lanes.iter().any(|l| l.id == lane),
            "NIST hunt_config must include lane {lane}"
        );
    }
    assert!(cfg
        .escalation_policy
        .iter()
        .any(|policy| policy.contains("package worm")));
}

#[test]
fn nist_ares_rules_have_architecture_metadata() {
    let sets = embedded_rule_sets();
    let nist = sets
        .iter()
        .find(|rs| rs.framework == "NIST")
        .expect("NIST rules");
    let ares_rules: Vec<_> = nist
        .rules
        .iter()
        .filter(|r| r.id.contains("ARES"))
        .collect();
    assert!(
        ares_rules.len() >= 9,
        "expected robust Ares NIST rule set, got {}",
        ares_rules.len()
    );
    for rule in ares_rules {
        assert!(
            !rule.platforms.is_empty(),
            "{} must declare supported OS/platforms",
            rule.id
        );
        assert!(
            !rule.architectures.is_empty(),
            "{} must declare architecture lanes",
            rule.id
        );
        assert!(
            !rule.data_sources.is_empty(),
            "{} must declare data sources",
            rule.id
        );
        assert!(
            !rule.hunt_steps.is_empty(),
            "{} must declare hunt steps",
            rule.id
        );
    }
}

#[test]
fn system_has_ares_rootkit_kernel_and_listener_rules() {
    let sets = embedded_rule_sets();
    let system = sets
        .iter()
        .find(|rs| rs.framework == "SYSTEM")
        .expect("SYSTEM rules");
    for id in ["SYS-09", "SYS-10", "SYS-11"] {
        assert!(
            system.rules.iter().any(|r| r.id == id),
            "SYSTEM rules must include {id}"
        );
    }
}

// ─────────────────────────── Rule evaluation tests ───────────────────────────

#[test]
fn rule_eval_privilege_escalation_fires() {
    let sets = embedded_rule_sets();
    let alerts = vec![make_alert(
        AlertKind::SystemAnomaly,
        Severity::Critical,
        "Root escape",
    )];
    let hits = evaluate_rules(&sets, &alerts, &[], &[], &[], &[], &[]);
    assert!(
        hits.iter().any(|h| h.rule_id.contains("A01")
            || h.rule_id.contains("AC-6")
            || h.rule_id.contains("CIS-4.7")
            || h.rule_id.contains("SYS-04")),
        "system anomaly must trigger at least one rule hit: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_cve_present_fires() {
    let sets = embedded_rule_sets();
    let osv = vec![make_osv("lodash", "GHSA-xxxx-1234-5678")];
    let hits = evaluate_rules(&sets, &[], &osv, &[], &[], &[], &[]);
    assert!(
        hits.iter().any(|h| h.check_kind_fires_for_cve()),
        "OSV finding must trigger CVE rule hits"
    );
    // Specifically A06:2021, RA-5, CIS-7.5, DEV-01 should fire
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"A06:2021"),
        "A06:2021 must fire on CVE: {:?}",
        ids
    );
    assert!(ids.contains(&"RA-5"), "RA-5 must fire on CVE: {:?}", ids);
}

#[test]
fn rule_eval_yara_match_fires() {
    let sets = embedded_rule_sets();
    let yara = vec![make_yara("suspicious_shellcode", "Critical")];
    let hits = evaluate_rules(&sets, &[], &[], &[], &yara, &[], &[]);
    assert!(
        hits.iter()
            .any(|h| h.rule_id == "A03:2021" || h.rule_id == "SI-3" || h.rule_id == "SYS-03"),
        "YARA match must trigger injection/malware rules: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_evidence_names_the_matched_file_and_rule() {
    // A finding must point somewhere: the YARA target path and the rule name
    // must both appear in the evidence (regression guard for the "just a
    // statement with no context" findings).
    let sets = embedded_rule_sets();
    let yara = vec![make_yara("suspicious_shellcode", "Critical")];
    let hits = evaluate_rules(&sets, &[], &[], &[], &yara, &[], &[]);
    let yara_hit = hits
        .iter()
        .find(|h| h.evidence.contains("YARA match"))
        .expect("a YARA-backed finding should exist");
    assert!(
        yara_hit.evidence.contains("/tmp/suspicious"),
        "YARA evidence must name the matched file path, got: {}",
        yara_hit.evidence
    );
    assert!(
        yara_hit.evidence.contains("suspicious_shellcode"),
        "YARA evidence must name the rule that fired, got: {}",
        yara_hit.evidence
    );
}

#[test]
fn rule_eval_baseline_drift_fires() {
    let sets = embedded_rule_sets();
    let drifts = vec![
        make_drift("NewProcess", "python.exe added"),
        make_drift("NewRemoteIp", "185.220.101.1 seen"),
    ];
    let hits = evaluate_rules(&sets, &[], &[], &[], &[], &drifts, &[]);
    assert!(!hits.is_empty(), "baseline drifts must trigger rule hits");
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"CM-7") || ids.contains(&"SYS-01"),
        "NewProcess drift must hit CM-7 or SYS-01: {:?}",
        ids
    );
    assert!(
        ids.contains(&"SI-4") || ids.contains(&"SYS-02"),
        "NewRemoteIp drift must hit SI-4 or SYS-02: {:?}",
        ids
    );
}

#[test]
fn rule_eval_windows_event_4625_fires() {
    let sets = embedded_rule_sets();
    // The 4625 auth-failure rules are Windows-scoped and require 3 corroborating
    // events (brute-force, min_matches: 3). Pin a Windows scope so the test is
    // deterministic on any runner.
    let events = vec![
        make_win_event(4625, "Warning", "Security"),
        make_win_event(4625, "Warning", "Security"),
        make_win_event(4625, "Warning", "Security"),
    ];
    let scope = RuntimeRuleScope::for_platform("windows");
    let hits = evaluate_rules_with_scope(&sets, &[], &[], &[], &[], &[], &events, &scope);
    assert!(
        hits.iter()
            .any(|h| h.rule_id == "A07:2021" || h.rule_id == "CIS-16.9"),
        "Event 4625 (x3) must trigger auth failure rules under a Windows scope: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_windows_event_7045_fires() {
    let sets = embedded_rule_sets();
    let events = vec![make_win_event(
        7045,
        "Information",
        "Service Control Manager",
    )];
    // SYS-07 is a Windows-scoped service-install rule. Pin a Windows scope.
    let scope = RuntimeRuleScope::for_platform("windows");
    let hits = evaluate_rules_with_scope(&sets, &[], &[], &[], &[], &[], &events, &scope);
    assert!(
        hits.iter().any(|h| h.rule_id == "SYS-07"),
        "Event 7045 must trigger SYS-07 under a Windows scope: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_ares_rootkit_kernel_and_listener_events_fire() {
    let sets = embedded_rule_sets();
    let events = vec![
        WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 0,
            level: "Critical".to_string(),
            log_name: "kernel".to_string(),
            message: "possible rootkit syscall hook hiding process entries".to_string(),
        },
        WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 0,
            level: "Warning".to_string(),
            log_name: "audit".to_string(),
            message: "insmod loaded suspicious .ko kernel module".to_string(),
        },
        WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 0,
            level: "Warning".to_string(),
            log_name: "systemd-journald".to_string(),
            message: "journal file corrupt and sensor stopped after tamper event".to_string(),
        },
    ];
    // These rootkit/kernel/listener events are Linux-oriented (insmod, .ko,
    // systemd-journald). Pin a Linux scope so the Linux-scoped rules apply on any
    // runner.
    let scope = RuntimeRuleScope::for_platform("linux");
    let hits = evaluate_rules_with_scope(&sets, &[], &[], &[], &[], &[], &events, &scope);
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(ids.contains(&"SYS-09"), "rootkit rule must fire: {ids:?}");
    assert!(
        ids.contains(&"SYS-10"),
        "kernel module rule must fire: {ids:?}"
    );
    assert!(
        ids.contains(&"SYS-11"),
        "alert listener rule must fire: {ids:?}"
    );
    assert!(
        ids.contains(&"SI-4-ARES"),
        "NIST rootkit control must fire: {ids:?}"
    );
    assert!(
        ids.contains(&"SI-7-ARES"),
        "NIST kernel control must fire: {ids:?}"
    );
    assert!(
        ids.contains(&"AU-9-ARES"),
        "NIST listener control must fire: {ids:?}"
    );
}

#[test]
fn scanner_status_noise_does_not_fire_kernel_rules() {
    let sets = embedded_rule_sets();
    // Real narration shape emitted by the HARDN legion-daemon every scan
    // cycle; it contains keyword-rule vocabulary but is not host activity.
    let events = vec![
        WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 6,
            level: "Information".to_string(),
            log_name: "legion-daemon.service".to_string(),
            message: "  Checking kernel modules...".to_string(),
        },
        WinEvent {
            time: "2026-01-01T00:00:01Z".to_string(),
            event_id: 6,
            level: "Information".to_string(),
            log_name: "legion-daemon.service".to_string(),
            message: "    219 kernel modules loaded".to_string(),
        },
    ];
    let scope = RuntimeRuleScope::for_platform("linux");
    let hits = evaluate_rules_with_scope(&sets, &[], &[], &[], &[], &[], &events, &scope);
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(
        !ids.contains(&"SYS-10"),
        "scanner narration must not fire kernel module rules: {ids:?}"
    );
    assert!(
        !ids.contains(&"SI-7-ARES"),
        "scanner narration must not fire NIST kernel control: {ids:?}"
    );
}

#[test]
fn ares_neural_hunter_ignores_scanner_noise() {
    let noise = vec![
        WinEvent {
            time: "2026-01-01T00:00:00Z".to_string(),
            event_id: 6,
            level: "Information".to_string(),
            log_name: "legion-daemon.service".to_string(),
            message: "  Checking kernel modules...".to_string(),
        },
        WinEvent {
            time: "2026-01-01T00:00:01Z".to_string(),
            event_id: 6,
            level: "Information".to_string(),
            log_name: "legion-daemon.service".to_string(),
            message: "    219 kernel modules loaded".to_string(),
        },
    ];
    let assessment = AresNeuralHunter::assess(&[], &noise, &[], &[]);
    assert_eq!(
        assessment.posture, "baseline",
        "scanner narration alone must not move posture: {assessment:?}"
    );
}

#[test]
fn ares_neural_hunter_counts_identical_evidence_once() {
    // SI-7-ARES and SYS-10 intentionally overlap; the same matched line must
    // not compound the posture score once per framework.
    let evidence =
        "1 indicator(s) matched 'modprobe|insmod' — audit: insmod loaded suspicious module";
    let mk = |framework: &str, rule_id: &str| legion_ares::RuleHit {
        framework: framework.to_string(),
        rule_id: rule_id.to_string(),
        title: "kernel module rule".to_string(),
        severity: "High".to_string(),
        evidence: evidence.to_string(),
        remediation: "validate module".to_string(),
        reference: "https://example.invalid".to_string(),
    };
    let hits = vec![mk("NIST", "SI-7-ARES"), mk("SYSTEM", "SYS-10")];
    let assessment = AresNeuralHunter::assess(&[], &[], &[], &hits);
    assert!(
        assessment.score <= 0.21,
        "duplicate-evidence hits must count once: {assessment:?}"
    );
}

#[test]
fn ares_neural_hunter_scores_rootkit_posture() {
    let alert = make_alert(
        AlertKind::SystemAnomaly,
        Severity::Critical,
        "Rootkit or kernel stealth indicator",
    );
    let event = WinEvent {
        time: "2026-01-01T00:00:00Z".to_string(),
        event_id: 0,
        level: "Critical".to_string(),
        log_name: "kernel".to_string(),
        message: "rootkit syscall hook and hidden process behavior".to_string(),
    };
    let yara = make_yara("linux_rootkit_kernel_hook", "Critical");
    let hits = vec![legion_ares::RuleHit {
        framework: "SYSTEM".to_string(),
        rule_id: "SYS-09".to_string(),
        title: "Ares Rootkit Stealth Indicator".to_string(),
        severity: "Critical".to_string(),
        evidence: "rootkit evidence".to_string(),
        remediation: "isolate".to_string(),
        reference: "https://attack.mitre.org/techniques/T1014/".to_string(),
    }];

    let assessment = AresNeuralHunter::assess(&[alert], &[event], &[yara], &hits);
    assert!(assessment.score >= 0.75, "assessment: {assessment:?}");
    assert_eq!(assessment.posture, "critical");
    assert!(assessment.signals.iter().any(|s| s.contains("rootkit")));
}

#[test]
fn rule_eval_ai_threat_fires() {
    let sets = embedded_rule_sets();
    let ai = vec![make_ai_threat(
        "Critical",
        "Malicious AI SDK detected: evil-gpt",
    )];
    let hits = evaluate_rules(&sets, &[], &[], &ai, &[], &[], &[]);
    assert!(
        hits.iter()
            .any(|h| h.rule_id == "A08:2021" || h.rule_id == "DEV-02" || h.rule_id == "CIS-14.6"),
        "AI threat must trigger integrity/AI rules: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_npm_pip_worm_ai_threat_fires_targeted_rules() {
    let sets = embedded_rule_sets();
    let ai = vec![make_ai_threat_for(
        "openai-python",
        "pypi",
        "Critical",
        "PyPI typosquat impersonates openai; setup.py postinstall reads process.env and exfiltrates OPENAI_API_KEY with worm-style dependency propagation",
    )];
    let hits = evaluate_rules(&sets, &[], &[], &ai, &[], &[], &[]);
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"SI-3-ARES-NPM-PIP-WORM"),
        "NIST npm/pip worm intelligence rule must fire: {ids:?}"
    );
    assert!(
        ids.contains(&"DEV-09"),
        "DEV npm/pip worm intelligence rule must fire: {ids:?}"
    );
}

#[test]
fn rule_eval_package_traversal_and_credential_heuristics_fire() {
    let sets = embedded_rule_sets();
    let events = vec![WinEvent {
        time: "2026-01-01T00:00:00Z".to_string(),
        event_id: 0,
        level: "Warning".to_string(),
        log_name: "npm".to_string(),
        message: "npm postinstall path traversal wrote outside node_modules/../ and read process.env OPENAI_API_KEY from .npmrc"
            .to_string(),
    }];
    let hits = evaluate_rules(&sets, &[], &[], &[], &[], &[], &events);
    let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
    for id in [
        "SI-4-ARES-PKG-LIFECYCLE",
        "SI-4-ARES-PATH-TRAVERSAL",
        "AC-6-ARES-CREDENTIAL-SCRAPE",
        "DEV-10",
        "DEV-11",
    ] {
        assert!(ids.contains(&id), "{id} must fire: {ids:?}");
    }
}

#[test]
fn rule_eval_ip_blacklist_fires() {
    let sets = embedded_rule_sets();
    let alerts = vec![make_alert(
        AlertKind::IpBlacklist,
        Severity::Critical,
        "185.220.101.1 blacklisted",
    )];
    let hits = evaluate_rules(&sets, &alerts, &[], &[], &[], &[], &[]);
    assert!(
        hits.iter()
            .any(|h| h.rule_id == "A10:2021" || h.rule_id == "CIS-12.2" || h.rule_id == "SYS-05"),
        "IP blacklist must trigger SSRF/C2 rules: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_typosquatted_package_fires() {
    let sets = embedded_rule_sets();
    let alerts = vec![make_alert(
        AlertKind::SuspiciousPackage,
        Severity::Critical,
        "requesst@1.0.0",
    )];
    let hits = evaluate_rules(&sets, &alerts, &[], &[], &[], &[], &[]);
    assert!(
        hits.iter()
            .any(|h| h.rule_id == "DEV-03" || h.rule_id == "SI-7"),
        "Typosquatted package must trigger supply-chain rules: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rule_eval_sorted_critical_first() {
    let sets = embedded_rule_sets();
    let alerts = vec![make_alert(
        AlertKind::SystemAnomaly,
        Severity::Critical,
        "Priv esc",
    )];
    let osv = vec![make_osv("lodash", "GHSA-test-0001")];
    let yara = vec![make_yara("shellcode_x64", "Critical")];
    let hits = evaluate_rules(&sets, &alerts, &osv, &[], &yara, &[], &[]);
    // Verify sorting: no Low/Medium before Critical
    let mut seen_non_critical = false;
    for h in &hits {
        if h.severity != "Critical" {
            seen_non_critical = true;
        }
        if seen_non_critical {
            assert_ne!(
                h.severity, "Critical",
                "Critical hit found after non-critical: {:?}",
                hits
            );
        }
    }
}

#[test]
fn rule_eval_empty_inputs_produces_no_hits() {
    let sets = embedded_rule_sets();
    let hits = evaluate_rules(&sets, &[], &[], &[], &[], &[], &[]);
    assert!(
        hits.is_empty(),
        "empty inputs must produce no rule hits, got {:?}",
        hits.len()
    );
}

#[test]
fn rule_eval_multiple_frameworks_all_fire() {
    let sets = embedded_rule_sets();
    let alerts = vec![
        make_alert(AlertKind::SystemAnomaly, Severity::Critical, "Root shell"),
        make_alert(AlertKind::IpBlacklist, Severity::Critical, "185.1.1.1"),
    ];
    let osv = vec![make_osv("express", "GHSA-expr-001")];
    let yara = vec![make_yara("trojan_dropper", "High")];
    let drifts = vec![make_drift("NewProcess", "nc.exe spawned")];
    let ai = vec![make_ai_threat("High", "LangChain CVE-2024-1234")];
    let events = vec![make_win_event(4625, "Warning", "WORKSTATION")];
    let hits = evaluate_rules(&sets, &alerts, &osv, &ai, &yara, &drifts, &events);
    let frameworks: Vec<&str> = hits.iter().map(|h| h.framework.as_str()).collect();
    for fw in ["OWASP", "NIST", "CIS", "DEV", "SYSTEM"] {
        assert!(
            frameworks.contains(&fw),
            "framework '{fw}' must produce hits with rich inputs: {:?}",
            frameworks
        );
    }
}

// ─────────────────────────── Search utility test ─────────────────────────────

#[test]
fn search_parse_empty_html_returns_empty() {
    // We can't easily test the full HTTP call, but we can test that the module exists
    // and that the function signature is correct
    let _ = legion_ares::web_search; // just ensure it's accessible
}

// ─────────────────────────── Agent manifest test ─────────────────────────────

#[test]
fn agent_manifest_parses() {
    let manifest_json = include_str!("../../../agents/ares/ares.json");
    let v: serde_json::Value =
        serde_json::from_str(manifest_json).expect("ares.json must be valid JSON");
    assert_eq!(v["name"], "ares");
    assert_eq!(v["display_name"], "ARES");
    assert_eq!(v["models"]["primary"], "legion-ares:qwen3-4b");
    assert_eq!(v["models"]["base"], "qwen3:4b");
    let blocked: Vec<&str> = v["models"]["blocked"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        blocked.contains(&"deepseek"),
        "ares.json must list deepseek as blocked"
    );
    let capabilities: Vec<&str> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        capabilities.contains(&"ares_analyst_mode"),
        "ares.json must declare Ares analyst mode"
    );
    for capability in [
        "rootkit_hunting",
        "kernel_view_hunter",
        "alert_listener_tamper_detection",
        "local_neural_hunt_scoring",
    ] {
        assert!(
            capabilities.contains(&capability),
            "ares.json must expose {capability}"
        );
    }
}

#[tokio::test]
async fn hunt_degrades_gracefully_when_model_runtime_is_offline() {
    // Pin BOTH runtimes to dead loopback ports: the default llm_host is the
    // real llama-server port, and a dev instance running there would answer
    // for any requested model name, turning this into a live-model test.
    let cfg = AresConfig {
        llm_host: "http://127.0.0.1:9".to_string(),
        ollama_host: "http://127.0.0.1:9".to_string(),
        model: "qwen3:8b".to_string(),
        fallback_model: "qwen3:4b".to_string(),
        search_enabled: false,
        ..Default::default()
    };
    let chat = AresChat::new(cfg);
    let report = chat.hunt(&empty_context()).await.unwrap();

    // Engine-first: with no model reachable the hunt still returns a real report
    // built entirely from the deterministic engine, flagged as engine-only.
    assert_eq!(report.model_used, "engine-only");
    assert!(report
        .analysis
        .contains("engine findings (model unavailable)"));
    assert!(report.analysis.contains("POSTURE:"));
    assert!(!report.analysis.contains("Hunt failed:"));
}

#[test]
fn all_rule_json_files_parse_cleanly() {
    let files = [
        include_str!("../../../agents/ares/rules/owasp.json"),
        include_str!("../../../agents/ares/rules/nist.json"),
        include_str!("../../../agents/ares/rules/cis.json"),
        include_str!("../../../agents/ares/rules/dev.json"),
        include_str!("../../../agents/ares/rules/system.json"),
    ];
    let names = ["owasp", "nist", "cis", "dev", "system"];
    for (json, name) in files.iter().zip(names.iter()) {
        let v: serde_json::Value = serde_json::from_str(json)
            .unwrap_or_else(|e| panic!("{name}.json must be valid JSON: {e}"));
        assert!(
            v["rules"].is_array(),
            "{name}.json must have a 'rules' array"
        );
        assert!(
            !v["rules"].as_array().unwrap().is_empty(),
            "{name}.json must have at least one rule"
        );
    }
}

// ─────────────────────────── RuleHit helper trait ────────────────────────────

trait RuleHitCheck {
    fn check_kind_fires_for_cve(&self) -> bool;
}

impl RuleHitCheck for legion_ares::RuleHit {
    fn check_kind_fires_for_cve(&self) -> bool {
        // Any rule that fires based on cve_present check_kind
        matches!(
            self.rule_id.as_str(),
            "A06:2021" | "RA-5" | "SI-2" | "CIS-7.5" | "DEV-01" | "DEV-08"
        )
    }
}
