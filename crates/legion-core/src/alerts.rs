//! Alert engine: correlates scan results and IP connections against threat feeds
//! to produce actionable security alerts.

use crate::{
    baseline::Drift,
    feeds::{AbuseIpPayload, CyberEvent},
    scanner::ScannedPackage,
    telemetry::WinEvent,
    yara::YaraMatch,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            90..=u32::MAX => Severity::Critical,
            70..=89 => Severity::High,
            40..=69 => Severity::Medium,
            10..=39 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertKind {
    CveMatch,
    IpBlacklist,
    SuspiciousPackage,
    SystemAnomaly,
    YaraMatch,
    BaselineDrift,
}

impl std::fmt::Display for AlertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertKind::CveMatch => write!(f, "CVE Match"),
            AlertKind::IpBlacklist => write!(f, "IP Blacklist"),
            AlertKind::SuspiciousPackage => write!(f, "Suspicious Pkg"),
            AlertKind::SystemAnomaly => write!(f, "System Anomaly"),
            AlertKind::YaraMatch => write!(f, "YARA Match"),
            AlertKind::BaselineDrift => write!(f, "Baseline Drift"),
        }
    }
}

pub fn severity_from_label(label: &str) -> Severity {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" | "emergency" | "alert" | "fault" | "error" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" | "warning" | "notice" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub package_name: Option<String>,
    pub package_ecosystem: Option<String>,
    pub ip_address: Option<String>,
    pub cve_ids: Vec<String>,
    pub event_title: Option<String>,
    pub created_at: String,
    pub acked: bool,
}

impl Alert {
    pub fn kind_str(&self) -> String {
        self.kind.to_string()
    }
}

#[derive(Debug, Error)]
pub enum AlertError {
    #[error("database error: {0}")]
    Db(String),
}

pub struct AlertEngine;

struct LocalEventRule {
    severity: &'static str,
    title: &'static str,
    detail: &'static str,
    sources: &'static [&'static str],
    messages: &'static [&'static str],
}

impl AlertEngine {
    pub fn correlate(packages: &[ScannedPackage], events: &[CyberEvent]) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = Vec::new();

        for event in events {
            let enrichment = match &event.enrichment {
                Some(e) => e,
                None => continue,
            };
            let affected = match &enrichment.affected_packages {
                Some(a) if !a.is_empty() => a,
                _ => continue,
            };

            for affected_pkg in affected {
                let eco_lower = affected_pkg.ecosystem.to_lowercase();
                for scanned in packages {
                    let scanned_eco = scanned.ecosystem_str().to_lowercase();
                    let eco_match = eco_lower == scanned_eco
                        || (eco_lower == "crates.io" && scanned_eco == "crates")
                        || (eco_lower == "pypi" && scanned_eco == "pypi")
                        || (eco_lower == "npm" && scanned_eco == "npm");

                    if eco_match && scanned.name.to_lowercase() == affected_pkg.name.to_lowercase()
                    {
                        let cves = enrichment.cve_ids.clone().unwrap_or_default();
                        let severity = Severity::from_score(event.severity.unwrap_or(50.0));
                        let detail = format!(
                            "Package '{}' ({}) found in cyber event '{}'. CVEs: {}. Techniques: {}",
                            scanned.name,
                            scanned.ecosystem_str(),
                            event.title,
                            if cves.is_empty() {
                                "none listed".to_owned()
                            } else {
                                cves.join(", ")
                            },
                            enrichment
                                .attack_techniques
                                .as_deref()
                                .unwrap_or_default()
                                .join(", ")
                        );

                        alerts.push(Alert {
                            id: 0,
                            kind: AlertKind::CveMatch,
                            severity,
                            title: format!(
                                "CVE Match: {} [{}]",
                                scanned.name,
                                scanned.ecosystem_str()
                            ),
                            detail,
                            package_name: Some(scanned.name.clone()),
                            package_ecosystem: Some(scanned.ecosystem_str()),
                            ip_address: None,
                            cve_ids: cves,
                            event_title: Some(event.title.clone()),
                            created_at: Utc::now().to_rfc3339(),
                            acked: false,
                        });
                    }
                }
            }
        }

        dedup_alerts(alerts)
    }

    pub fn check_ips(active_ips: &[String], blacklist: &AbuseIpPayload) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for conn_ip in active_ips {
            if let Some(entry) = blacklist.ips.iter().find(|e| e.ip == *conn_ip) {
                let score = entry.abuse_score.unwrap_or(100);
                alerts.push(Alert {
                    id: 0,
                    kind: AlertKind::IpBlacklist,
                    severity: Severity::from_score(score as f64),
                    title: format!("Blacklisted IP: {}", entry.ip),
                    detail: format!(
                        "Active connection to {} (country: {}, abuse score: {}/100, last reported: {})",
                        entry.ip,
                        entry.country.as_deref().unwrap_or("unknown"),
                        score,
                        entry.last_reported.as_deref().unwrap_or("unknown"),
                    ),
                    package_name: None,
                    package_ecosystem: None,
                    ip_address: Some(entry.ip.clone()),
                    cve_ids: vec![],
                    event_title: None,
                    created_at: Utc::now().to_rfc3339(),
                    acked: false,
                });
            }
        }
        alerts
    }

    pub fn from_yara_matches(matches: &[YaraMatch]) -> Vec<Alert> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut alerts = Vec::new();
        for m in matches {
            if m.severity == "Info" {
                continue;
            }
            let key = format!("{}|{}", m.rule, m.target);
            if !seen.insert(key) {
                continue;
            }
            let detail = if m.description.is_empty() {
                format!("File '{}' matched YARA rule '{}'", m.target, m.rule)
            } else {
                format!(
                    "File '{}' matched YARA rule '{}': {}",
                    m.target, m.rule, m.description
                )
            };
            alerts.push(Alert {
                id: 0,
                kind: AlertKind::YaraMatch,
                severity: severity_from_label(&m.severity),
                title: format!("YARA: {}", m.rule),
                detail,
                package_name: None,
                package_ecosystem: None,
                ip_address: None,
                cve_ids: vec![],
                event_title: None,
                created_at: Utc::now().to_rfc3339(),
                acked: false,
            });
        }
        alerts
    }

    pub fn from_drifts(drifts: &[Drift]) -> Vec<Alert> {
        drifts
            .iter()
            .map(|d| Alert {
                id: 0,
                kind: AlertKind::BaselineDrift,
                severity: severity_from_label(&d.severity),
                title: format!("Baseline drift: {}", d.kind),
                detail: d.detail.clone(),
                package_name: None,
                package_ecosystem: None,
                ip_address: None,
                cve_ids: vec![],
                event_title: None,
                created_at: Utc::now().to_rfc3339(),
                acked: false,
            })
            .collect()
    }

    pub fn from_local_events(events: &[WinEvent]) -> Vec<Alert> {
        let mut alerts = Self::from_win_events(events);
        alerts.extend(Self::from_unix_events(events));
        dedup_alerts(alerts)
    }

    pub fn from_win_events(events: &[WinEvent]) -> Vec<Alert> {
        const RULES: &[(u32, &str, &str, &str)] = &[
            (4625, "High", "Failed Logon", "Windows Event 4625: An account failed to log on - possible brute-force or credential stuffing."),
            (4648, "Medium", "Logon With Explicit Creds", "Windows Event 4648: A logon was attempted with explicit credentials - possible lateral movement."),
            (4672, "Medium", "Special Privileges Assigned", "Windows Event 4672: Special privileges assigned to new logon - elevated session started."),
            (4698, "High", "Scheduled Task Created", "Windows Event 4698: A scheduled task was created - common persistence mechanism."),
            (4720, "High", "User Account Created", "Windows Event 4720: A new user account was created - verify this is authorized."),
            (4728, "High", "Member Added to Admin Group", "Windows Event 4728: A user was added to a privileged global group - review immediately."),
            (4732, "High", "Member Added to Local Admin", "Windows Event 4732: A user was added to a local privileged group."),
            (4756, "High", "Member Added to Universal Group", "Windows Event 4756: A member was added to a security-enabled universal group."),
            (4768, "Medium", "Kerberos TGT Requested", "Windows Event 4768: Kerberos TGT requested - monitor for AS-REP roasting."),
            (4769, "High", "Kerberos Service Ticket", "Windows Event 4769: Kerberos service ticket requested - monitor for Kerberoasting."),
            (4776, "Medium", "NTLM Auth Attempt", "Windows Event 4776: NTLM credential validation attempted - check for pass-the-hash."),
            (5140, "Medium", "Network Share Accessed", "Windows Event 5140: A network share object was accessed - review for unauthorized lateral movement."),
            (7045, "Critical", "New Service Installed", "Windows Event 7045: A new service was installed - common malware persistence technique."),
            (1102, "Critical", "Audit Log Cleared", "Windows Event 1102: The audit log was cleared - possible evidence destruction."),
            (4616, "Medium", "System Time Changed", "Windows Event 4616: System time was changed - may indicate log tampering."),
            (4657, "Medium", "Registry Value Modified", "Windows Event 4657: A registry value was modified - check for persistence or configuration tampering."),
        ];

        let mut alerts = Vec::new();
        for event in events {
            for &(rule_id, sev_label, title, detail_prefix) in RULES {
                if event.event_id == rule_id {
                    alerts.push(Alert {
                        id: 0,
                        kind: AlertKind::SystemAnomaly,
                        severity: severity_from_label(sev_label),
                        title: format!("{} (EID {})", title, event.event_id),
                        detail: format!(
                            "{} | Log: {} | {}",
                            detail_prefix,
                            event.log_name,
                            truncate_for_alert(&event.message, 200)
                        ),
                        package_name: None,
                        package_ecosystem: None,
                        ip_address: None,
                        cve_ids: vec![],
                        event_title: Some(format!("EID {}", event.event_id)),
                        created_at: Utc::now().to_rfc3339(),
                        acked: false,
                    });
                    break;
                }
            }
        }
        dedup_alerts(alerts)
    }

    fn from_unix_events(events: &[WinEvent]) -> Vec<Alert> {
        const RULES: &[LocalEventRule] = &[
            LocalEventRule {
                severity: "Critical",
                title: "Rootkit or kernel stealth indicator",
                detail: "Local logs mention rootkit, kernel hook, artifact hiding, or LD_PRELOAD-style stealth behavior.",
                sources: &["kernel", "audit", "journald", "systemd", "launchd", "securityd"],
                messages: &[
                    "rootkit",
                    "syscall hook",
                    "kernel hook",
                    "hidden process",
                    "hidden file",
                    "ld.so.preload",
                    "diamorphine",
                    "reptile",
                    "drovorub",
                    "skidmap",
                ],
            },
            LocalEventRule {
                severity: "High",
                title: "Kernel module or extension activity",
                detail: "Local logs indicate kernel module/kext load or unload behavior requiring rootkit persistence review.",
                sources: &["kernel", "audit", "journald", "systemd", "launchd", "syspolicyd"],
                messages: &[
                    "modprobe",
                    "insmod",
                    "rmmod",
                    "kextload",
                    "kextunload",
                    "kernel module",
                    "loadable kernel module",
                    ".ko",
                ],
            },
            LocalEventRule {
                severity: "Critical",
                title: "Kernel panic or crash",
                detail: "Kernel reported panic/oops/crash behavior; investigate host stability and possible exploitation.",
                sources: &["kernel", "journald"],
                messages: &["kernel panic", "kernel oops", "segfault", "blocked for more than"],
            },
            LocalEventRule {
                severity: "High",
                title: "System service failure",
                detail: "systemd/launchd reported a failed or abnormal service state.",
                sources: &["systemd", "launchd", ".service"],
                messages: &[
                    "failed to start",
                    "entered failed state",
                    "main process exited",
                    "exited with abnormal code",
                ],
            },
            LocalEventRule {
                severity: "High",
                title: "Authentication failure",
                detail: "Local auth logs show failed login, invalid user, or sudo authentication failure.",
                sources: &["sshd", "sudo", "securityd", "authorization"],
                messages: &[
                    "failed password",
                    "authentication failure",
                    "invalid user",
                    "not in sudoers",
                    "authorization denied",
                ],
            },
            LocalEventRule {
                severity: "High",
                title: "Audit policy or journal tampering",
                detail: "Local audit/journal logs indicate possible evidence tampering or corrupted audit storage.",
                sources: &["audit", "auditd", "journald", "systemd-journald"],
                messages: &[
                    "audit log cleared",
                    "journal file",
                    "corrupt",
                    "failed to rotate",
                    "vacuum",
                ],
            },
            LocalEventRule {
                severity: "Medium",
                title: "Network service anomaly",
                detail: "networkd/NetworkManager reported link, DHCP, route, DNS, or connectivity failures.",
                sources: &["systemd-networkd", "networkmanager", "networkd", "kernel"],
                messages: &[
                    "link is down",
                    "dhcp",
                    "dns",
                    "route",
                    "unreachable",
                    "network is unreachable",
                    "carrier lost",
                ],
            },
            LocalEventRule {
                severity: "Medium",
                title: "Mandatory access control denial",
                detail: "Local security controls denied an operation; review for exploit attempts or policy drift.",
                sources: &[
                    "kernel",
                    "audit",
                    "sandboxd",
                    "syspolicyd",
                    "xprotect",
                    "gatekeeper",
                ],
                messages: &[
                    "avc denied",
                    "apparmor=\"denied\"",
                    "operation not permitted",
                    "deny",
                    "blocked",
                    "malware",
                ],
            },
        ];

        let mut alerts = Vec::new();
        for event in events {
            let source = event.log_name.to_ascii_lowercase();
            let message = event.message.to_ascii_lowercase();
            for rule in RULES {
                if rule.sources.iter().any(|term| source.contains(term))
                    && rule.messages.iter().any(|term| message.contains(term))
                {
                    alerts.push(Alert {
                        id: 0,
                        kind: AlertKind::SystemAnomaly,
                        severity: severity_from_label(rule.severity),
                        title: format!("{} ({})", rule.title, event.log_name),
                        detail: format!(
                            "{} | Log: {} | {}",
                            rule.detail,
                            event.log_name,
                            truncate_for_alert(&event.message, 200)
                        ),
                        package_name: None,
                        package_ecosystem: None,
                        ip_address: None,
                        cve_ids: vec![],
                        event_title: Some(event.log_name.clone()),
                        created_at: Utc::now().to_rfc3339(),
                        acked: false,
                    });
                    break;
                }
            }
        }
        dedup_alerts(alerts)
    }
}

fn truncate_for_alert(message: &str, max_chars: usize) -> String {
    message.chars().take(max_chars).collect()
}

fn dedup_alerts(mut alerts: Vec<Alert>) -> Vec<Alert> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Alert> = HashMap::new();
    alerts.sort_by_key(|a| std::cmp::Reverse(a.severity.score()));
    for alert in alerts {
        let key = match &alert.kind {
            AlertKind::CveMatch => format!(
                "cve:{}:{}",
                alert.package_ecosystem.as_deref().unwrap_or(""),
                alert.package_name.as_deref().unwrap_or("")
            ),
            AlertKind::IpBlacklist => format!("ip:{}", alert.ip_address.as_deref().unwrap_or("")),
            _ => alert.title.clone(),
        };
        map.entry(key).or_insert(alert);
    }
    let mut out: Vec<Alert> = map.into_values().collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.severity.score()));
    out
}
