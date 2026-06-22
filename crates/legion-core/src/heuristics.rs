//! Cross-OS heuristic baseline scoring.
//!
//! The raw baseline diff ([`crate::baseline::compare`]) emits one drift per new
//! process/package/peer, which on a busy host is hundreds of low-value items.
//! This module turns the host's *current* observations into a **small set of
//! meaningful alerts** instead: it scores execution provenance, outbound peers,
//! and process-count spikes, and correlates peers against the cached threat-intel
//! IP blacklist.
//!
//! Everything here is OS-agnostic. Process/peer collection comes from the
//! cross-platform [`crate::telemetry`] helpers and `sysinfo`; the suspicious-path
//! markers cover both Unix and Windows conventions. The scoring logic lives in
//! the pure [`evaluate`] function (unit-tested with synthetic input); [`score_host`]
//! is the thin wrapper that feeds it live data plus the DB blacklist lookup.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::Utc;

use crate::alerts::{Alert, AlertKind, Severity};
use crate::baseline::Baseline;
use crate::Database;

/// Execution directories that are unusual for a legitimate long-running binary,
/// matched case-insensitively against the process executable path. Covers both
/// Unix (`/tmp`, `/dev/shm`, …) and Windows (`\Temp\`, `\Downloads\`, …) layouts
/// so the heuristic stays general across OS models.
const SUSPICIOUS_PATH_MARKERS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm",
    "/run/user",
    "/private/tmp",
    "\\temp\\",
    "\\appdata\\local\\temp",
    "\\downloads\\",
    "\\users\\public\\",
    "\\programdata\\",
];

/// A current process observation: display name and executable path (may be empty
/// when the path is unavailable, e.g. a kernel thread).
#[derive(Debug, Clone)]
pub struct ProcObservation {
    pub name: String,
    pub exe_path: String,
}

/// True when a process executable path lives in a directory unusual for a
/// legitimate persistent binary (a classic dropper/staging location).
pub fn is_suspicious_exe_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let p = path.to_ascii_lowercase();
    SUSPICIOUS_PATH_MARKERS.iter().any(|m| p.contains(m))
}

/// True when an address is routable on the public internet — i.e. not loopback,
/// private (RFC1918 / unique-local), link-local, multicast, or unspecified. Used
/// to distinguish a noteworthy new outbound peer from ordinary LAN/host traffic.
pub fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            let is_unique_local = (seg[0] & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80; // fe80::/10
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_link_local)
        }
        Err(_) => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn alert(
    kind: AlertKind,
    severity: Severity,
    title: String,
    detail: String,
    ip: Option<String>,
    file_path: Option<String>,
    source: &str,
) -> Alert {
    Alert {
        id: 0,
        kind,
        severity,
        title,
        detail,
        package_name: None,
        package_ecosystem: None,
        ip_address: ip,
        cve_ids: vec![],
        event_title: None,
        created_at: Utc::now().to_rfc3339(),
        acked: false,
        file_path,
        source: source.to_string(),
    }
}

/// Pure heuristic scorer. Produces a deduplicated set of scored alerts from a
/// snapshot of host observations. `is_blacklisted` is injected so the threat-intel
/// lookup (a DB call in production) can be stubbed in tests.
///
/// Rules:
/// - **Process provenance** — any process executing from a suspicious directory →
///   `High` (point-in-time; fires even on the first run).
/// - **Malicious peer** — an active remote IP on the threat-intel blacklist →
///   `Critical` (point-in-time).
/// - **Process-count spike** — current count well above baseline → `Medium`.
///
/// Deliberately *no* "new public peer" rule: a novel outbound IP on its own is
/// not evidence of compromise (ordinary hosts contact countless new public IPs),
/// so it would only generate false positives. Novel peers are surfaced as
/// observations in the connections view, not as alerts.
pub fn evaluate<F>(
    processes: &[ProcObservation],
    active_ips: &[String],
    baseline: &Baseline,
    is_blacklisted: F,
) -> Vec<Alert>
where
    F: Fn(&str) -> bool,
{
    let mut out: Vec<Alert> = Vec::new();

    // 1. Execution provenance.
    for p in processes {
        if is_suspicious_exe_path(&p.exe_path) {
            out.push(alert(
                AlertKind::SystemAnomaly,
                Severity::High,
                format!("Process running from suspicious path: {}", p.name),
                format!("{} executes from {}", p.name, p.exe_path),
                None,
                Some(p.exe_path.clone()),
                "Heuristic: process provenance",
            ));
        }
    }

    // 2. Outbound peers: threat-intel correlation only.
    //
    // A *new* public peer on its own is NOT a finding. A normal host contacts
    // thousands of fresh public IPs (CDNs, update servers, every website), so
    // alerting on novelty alone is pure false-positive noise that never resolves.
    // Peers are only escalated when corroborated by the threat-intel blacklist;
    // novel peers stay visible in the live connections panel as observations.
    let mut seen_ips: BTreeSet<&str> = BTreeSet::new();
    for ip in active_ips {
        if !seen_ips.insert(ip.as_str()) {
            continue;
        }
        if is_blacklisted(ip) {
            out.push(alert(
                AlertKind::IpBlacklist,
                Severity::Critical,
                format!("Outbound connection to known-malicious IP {ip}"),
                format!("Active peer {ip} matches the cached threat-intel blacklist"),
                Some(ip.clone()),
                None,
                "Heuristic: threat-intel peer",
            ));
        }
    }

    // 3. Process-count spike (>50% above baseline plus a small absolute floor to
    //    avoid noise on tiny hosts).
    let current = processes.len();
    if baseline.proc_count > 0 && current > baseline.proc_count * 3 / 2 + 10 {
        out.push(alert(
            AlertKind::SystemAnomaly,
            Severity::Medium,
            "Process-count spike since baseline".to_string(),
            format!(
                "{current} processes now vs {} at baseline",
                baseline.proc_count
            ),
            None,
            None,
            "Heuristic: process-count spike",
        ));
    }

    out
}

/// Collect live host observations and score them against `baseline`, correlating
/// peers against the DB threat-intel blacklist. `current_ips` is passed in to
/// avoid a second socket enumeration (the caller already captured it).
pub fn score_host(db: &Database, baseline: &Baseline, current_ips: &[String]) -> Vec<Alert> {
    let processes = collect_processes();
    evaluate(&processes, current_ips, baseline, |ip| {
        db.is_ip_blacklisted(ip).unwrap_or(false)
    })
}

/// Enumerate current processes with their executable paths (cross-platform via
/// `sysinfo`).
fn collect_processes() -> Vec<ProcObservation> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    sys.processes()
        .values()
        .map(|p| ProcObservation {
            name: p.name().to_string_lossy().to_string(),
            exe_path: p
                .exe()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_with(ips: &[&str], proc_count: usize) -> Baseline {
        Baseline {
            remote_ips: ips.iter().map(|s| s.to_string()).collect(),
            proc_count,
            ..Default::default()
        }
    }

    #[test]
    fn suspicious_paths_detected_across_os() {
        assert!(is_suspicious_exe_path("/tmp/.x/payload"));
        assert!(is_suspicious_exe_path("/dev/shm/evil"));
        assert!(is_suspicious_exe_path(
            "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe"
        ));
        assert!(is_suspicious_exe_path("D:\\Downloads\\setup.exe"));
        assert!(!is_suspicious_exe_path("/usr/bin/bash"));
        assert!(!is_suspicious_exe_path(
            "C:\\Windows\\System32\\svchost.exe"
        ));
        assert!(!is_suspicious_exe_path(""));
    }

    #[test]
    fn public_vs_private_ip_classification() {
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("2606:4700:4700::1111"));
        assert!(!is_public_ip("10.0.0.5"));
        assert!(!is_public_ip("192.168.1.10"));
        assert!(!is_public_ip("172.16.4.4"));
        assert!(!is_public_ip("127.0.0.1"));
        assert!(!is_public_ip("::1"));
        assert!(!is_public_ip("fe80::1"));
        assert!(!is_public_ip("fd00::1")); // unique-local
        assert!(!is_public_ip("not-an-ip"));
    }

    #[test]
    fn blacklisted_peer_is_critical() {
        let base = baseline_with(&["8.8.8.8"], 100);
        let alerts = evaluate(&[], &["203.0.113.9".into()], &base, |ip| {
            ip == "203.0.113.9"
        });
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::IpBlacklist);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn novel_public_peer_is_not_alerted() {
        // A new public peer that is NOT on the blacklist must produce no alert —
        // novelty alone is not a finding (this is the false-positive fix).
        let base = baseline_with(&["8.8.8.8"], 100);
        let ips = vec!["8.8.8.8".into(), "10.1.2.3".into(), "1.1.1.1".into()];
        let alerts = evaluate(&[], &ips, &base, |_| false);
        assert!(alerts.is_empty());
    }

    #[test]
    fn blacklisted_peer_still_fires_regardless_of_baseline() {
        // Corroborated peers still escalate even when already in the baseline.
        let base = baseline_with(&["1.1.1.1", "8.8.8.8"], 100);
        let ips = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        let alerts = evaluate(&[], &ips, &base, |ip| ip == "1.1.1.1");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::IpBlacklist);
        assert_eq!(alerts[0].ip_address.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn provenance_fires_independent_of_baseline() {
        let base = baseline_with(&[], 0);
        let procs = vec![
            ProcObservation {
                name: "miner".into(),
                exe_path: "/tmp/miner".into(),
            },
            ProcObservation {
                name: "bash".into(),
                exe_path: "/usr/bin/bash".into(),
            },
        ];
        let alerts = evaluate(&procs, &[], &base, |_| false);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::SystemAnomaly);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn process_spike_flagged() {
        let base = baseline_with(&[], 100);
        let procs: Vec<ProcObservation> = (0..200)
            .map(|i| ProcObservation {
                name: format!("p{i}"),
                exe_path: "/usr/bin/p".into(),
            })
            .collect();
        let alerts = evaluate(&procs, &[], &base, |_| false);
        assert!(alerts
            .iter()
            .any(|a| a.title.contains("Process-count spike")));
    }
}
