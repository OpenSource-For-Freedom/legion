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
    /// High-confidence DPRK (Contagious Interview) workstation indicator.
    DprkIndicator,
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
            AlertKind::DprkIndicator => write!(f, "DPRK Indicator"),
        }
    }
}

/// A detector "scope" used for *reconciling* alerts (auto-resolution).
///
/// Each scan recomputes the complete current set of findings for a detector.
/// Reconciling replaces that detector's unacked alerts with the fresh set, so a
/// finding that no longer holds (peer gone, file no longer matches, IP off the
/// blacklist) simply disappears instead of lingering forever. Scopes are matched
/// against the alert [`Alert::source`] string via SQL `LIKE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertScope {
    /// YARA file matches (`source = "YARA"`).
    Yara,
    /// Heuristic scorer: process provenance, threat-intel peer, count spike.
    Heuristic,
    /// High-signal baseline drift (`source = "Baseline drift"`).
    Drift,
    /// Botnet C2 / blocklist correlation on active connections.
    AbuseIntel,
    /// Package ↔ OSV/CVE correlation.
    PackageCve,
    /// Direct OSV vulnerability findings on scanned packages
    /// (`source = "OSV vulnerability"`).
    PackageVuln,
    /// DPRK workstation indicators. Reconciled so an artifact that has been
    /// cleaned up stops alerting.
    Dprk,
}

impl AlertScope {
    /// SQL `LIKE` pattern matching the `source` of alerts in this scope. Exact
    /// strings match literally; a trailing `%` matches a family of sources.
    pub fn source_like(self) -> &'static str {
        match self {
            AlertScope::Yara => "YARA",
            AlertScope::Heuristic => "Heuristic:%",
            AlertScope::Drift => "Baseline drift",
            // Trailing % so the scope keeps matching rows written before the
            // source was corrected from the wrong provider name, and any
            // future blocklist, rather than orphaning them unreconciled.
            AlertScope::AbuseIntel => "Threat intel (%",
            AlertScope::PackageCve => "Package/OSV correlation",
            AlertScope::PackageVuln => "OSV vulnerability",
            AlertScope::Dprk => crate::dprk::DPRK_SOURCE,
        }
    }
}

pub fn severity_from_label(label: &str) -> Severity {
    match label.trim().to_ascii_lowercase().as_str() {
        // "error" is syslog severity 3 (below critical) - an ordinary error-level
        // log line should not become a Critical alert. "alert"/"emergency" are
        // syslog 1/0 and legitimately stay Critical.
        "critical" | "crit" | "emergency" | "alert" | "fault" => Severity::Critical,
        "high" | "error" | "err" => Severity::High,
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
    /// File or path that triggered the alert (YARA target, suspicious executable
    /// path, …). `None` for non-file alerts (IP, package, event). Shown per alert.
    #[serde(default)]
    pub file_path: Option<String>,
    /// Human label for the detector that raised the alert ("YARA", "Threat
    /// intel", "Heuristic baseline", "OS event log", …). Surfaced in the log.
    #[serde(default)]
    pub source: String,
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
                            // The lockfile/manifest the package was found in — the
                            // alert's true origin on disk.
                            file_path: scanned.path.clone(),
                            source: "Package/OSV correlation".into(),
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
                // An active connection to a listed botnet C2 is critical on its
                // own merits. Severity used to be derived from `abuse_score`,
                // which for this feed was a number Legion invented.
                // A confirmed connection to a listed botnet C2 is High-severity at
                // minimum. The feed's abuse_score may only RAISE it to Critical,
                // never bury it: a listed C2 with a modest score (e.g. 20) used to
                // become Low/Info via from_score and could be filtered out
                // downstream, silently de-prioritizing a real detection.
                let severity = match entry.abuse_score {
                    Some(score) if score >= 90 => Severity::Critical,
                    Some(_) => Severity::High,
                    None => Severity::Critical,
                };
                // Say what the feed actually publishes. The old text rendered
                // "country: unknown, abuse score: 100/100" — a hardcoded
                // placeholder and a fabricated metric, both reading like
                // findings.
                let mut facts: Vec<String> = Vec::new();
                if let Some(malware) = entry.malware.as_deref() {
                    facts.push(format!("botnet: {malware}"));
                }
                if let Some(status) = entry.c2_status.as_deref() {
                    facts.push(format!("C2 status: {status}"));
                }
                if let Some(score) = entry.abuse_score {
                    facts.push(format!("abuse score: {score}/100"));
                }
                if let Some(country) = entry.country.as_deref() {
                    facts.push(format!("country: {country}"));
                }
                if let Some(seen) = entry.last_reported.as_deref() {
                    facts.push(format!("last seen: {seen}"));
                }
                let detail = if facts.is_empty() {
                    format!(
                        "Active connection to {}, listed by {}.",
                        entry.ip, blacklist.source
                    )
                } else {
                    format!(
                        "Active connection to {}, listed by {} ({}).",
                        entry.ip,
                        blacklist.source,
                        facts.join(", ")
                    )
                };
                alerts.push(Alert {
                    id: 0,
                    kind: AlertKind::IpBlacklist,
                    severity,
                    title: format!("Blacklisted IP: {}", entry.ip),
                    detail,
                    package_name: None,
                    package_ecosystem: None,
                    ip_address: Some(entry.ip.clone()),
                    cve_ids: vec![],
                    event_title: None,
                    created_at: Utc::now().to_rfc3339(),
                    acked: false,
                    file_path: None,
                    // Name the feed that actually produced this, rather than a
                    // hardcoded provider Legion never queried.
                    source: format!("Threat intel ({})", blacklist.source),
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
                file_path: Some(m.target.clone()),
                source: "YARA".into(),
            });
        }
        alerts
    }

    /// Convert OSV vulnerability findings into deduped alerts so known-vulnerable
    /// dependencies show up in the primary Alerts view, not just the threat panel
    /// (QA 2026-07 F2). Deduped by package+version+first-CVE.
    /// Escalate alerts whose CVE is in CISA's Known Exploited Vulnerabilities
    /// catalog: not "someone could exploit this", but "this is being exploited
    /// in the wild right now".
    ///
    /// This is the highest-signal, lowest-false-positive escalation available,
    /// and it was being thrown away. `kev_cross_ref` was written, correct, and
    /// had zero callers: KEV was fetched and stored by `/api/feeds/refresh` and
    /// then never joined to package findings, so an operator was never told that
    /// one of their dependencies was under active attack. It is a pure join on
    /// CVE id, so it invents nothing and cannot produce a false positive that
    /// the underlying OSV finding did not already have.
    ///
    /// Returns the number of alerts escalated.
    pub fn apply_kev(alerts: &mut [Alert], xrefs: &[crate::threat_intel::KevCrossRef]) -> usize {
        use std::collections::HashMap;
        // CVE -> the cross-ref carrying it, so the alert can say *why*.
        let by_cve: HashMap<&str, &crate::threat_intel::KevCrossRef> =
            xrefs.iter().map(|x| (x.cve_id.as_str(), x)).collect();

        let mut escalated = 0;
        for alert in alerts.iter_mut() {
            let Some(hit) = alert
                .cve_ids
                .iter()
                .find_map(|id| by_cve.get(id.as_str()).copied())
            else {
                continue;
            };
            // Scope the escalation to the package the KEV entry was matched
            // against, so a shared CVE id cannot bleed onto an unrelated alert.
            if alert
                .package_name
                .as_deref()
                .is_some_and(|p| !p.eq_ignore_ascii_case(&hit.package))
            {
                continue;
            }
            alert.severity = Severity::Critical;
            let ransom = if hit.ransomware {
                " Known use in ransomware campaigns."
            } else {
                ""
            };
            alert.detail = format!(
                "ACTIVELY EXPLOITED — {} is in CISA's Known Exploited Vulnerabilities catalog \
                 (added {}).{ransom} Patch this first: exploitation is confirmed in the wild, \
                 not theoretical.\n\n{}",
                hit.cve_id, hit.date_added, alert.detail
            );
            escalated += 1;
        }
        escalated
    }

    pub fn from_osv(findings: &[crate::threat_intel::OsvFinding]) -> Vec<Alert> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut alerts = Vec::new();
        for f in findings {
            let ver = f.version.clone().unwrap_or_default();
            let cve = f.cve_ids.first().cloned().unwrap_or_default();
            let key = format!("{}|{ver}|{cve}", f.package);
            if !seen.insert(key) {
                continue;
            }
            // An OSV `MAL-` advisory is not a vulnerability in a legitimate
            // package: it is a report that the package IS malware. Rating it by
            // the CVSS-ish label (usually absent → Medium) buried confirmed
            // malicious code among ordinary patch chores.
            let malicious = crate::threat_intel::is_malicious_advisory(&f.osv_id);
            let severity = if malicious {
                Severity::Critical
            } else {
                f.severity
                    .as_deref()
                    .map(severity_from_label)
                    .unwrap_or(Severity::Medium)
            };

            // All advisory identifiers, surfaced on the alert (so the detail row
            // shows RUSTSEC/CVE/GHSA ids, not an empty list).
            let mut ids: Vec<String> = Vec::new();
            if !f.osv_id.is_empty() {
                ids.push(f.osv_id.clone());
            }
            ids.extend(f.cve_ids.iter().cloned());
            ids.extend(f.ghsa_ids.iter().cloned());
            ids.dedup();

            // Build a useful detail even when OSV has no prose summary.
            let mut detail = String::new();
            if !f.summary.trim().is_empty() && f.summary != "No description" {
                detail.push_str(f.summary.trim());
            }
            if !ids.is_empty() {
                if !detail.is_empty() {
                    detail.push_str(" — ");
                }
                detail.push_str(&ids.join(", "));
            }
            if let Some(fix) = &f.fixed_version {
                detail.push_str(&format!(" · fixed in {fix}"));
            }
            if !f.osv_id.is_empty() {
                detail.push_str(&format!(" · https://osv.dev/{}", f.osv_id));
            }
            if detail.is_empty() {
                detail = "known vulnerability advisory".into();
            }

            let fix_hint = f
                .fixed_version
                .as_ref()
                .map(|v| format!(" → fix {v}"))
                .unwrap_or_default();
            let ver_suffix = if ver.is_empty() {
                String::new()
            } else {
                format!(" {ver}")
            };
            alerts.push(Alert {
                id: 0,
                kind: if malicious {
                    AlertKind::SuspiciousPackage
                } else {
                    AlertKind::CveMatch
                },
                severity,
                title: if malicious {
                    format!("Malicious package: {}{ver_suffix}", f.package)
                } else {
                    format!("Vulnerable package: {}{ver_suffix}{fix_hint}", f.package)
                },
                detail: if malicious {
                    format!(
                        "OSV reports this package as malicious code, not a bug in a \
                         legitimate package. Remove it and audit any secrets the \
                         host could reach.\n\n{detail}"
                    )
                } else {
                    detail
                },
                package_name: Some(f.package.clone()),
                package_ecosystem: Some(f.ecosystem.clone()),
                ip_address: None,
                cve_ids: ids,
                event_title: None,
                created_at: Utc::now().to_rfc3339(),
                acked: false,
                file_path: None,
                source: "OSV vulnerability".into(),
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
                file_path: None,
                source: "Baseline drift".into(),
            })
            .collect()
    }

    pub fn from_local_events(events: &[WinEvent]) -> Vec<Alert> {
        // Drop Legion/HARDN's own scanner status narration ("Checking kernel
        // modules...", "219 kernel modules loaded") before correlating: it
        // otherwise matched the kernel-module / tamper rules and produced
        // self-inflicted alerts from the tool's own telemetry loop.
        // is_scanner_status_noise() was written for exactly this but was never
        // wired in.
        let filtered: Vec<WinEvent> = events
            .iter()
            .filter(|e| !e.is_scanner_status_noise())
            .cloned()
            .collect();
        let mut alerts = Self::from_win_events(&filtered);
        alerts.extend(Self::from_unix_events(&filtered));
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
                        file_path: None,
                        source: format!("OS event log: {}", event.log_name),
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
                sources: &["kernel", "audit", "journald", "systemd"],
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
                title: "Kernel module activity",
                detail: "Local logs indicate kernel module load or unload behavior requiring rootkit persistence review.",
                sources: &["kernel", "audit", "journald", "systemd"],
                messages: &[
                    "modprobe",
                    "insmod",
                    "rmmod",
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
                // "segfault" and "blocked for more than" were removed: a normal
                // crashing userland process logs "foo[123]: segfault at ..." (source
                // "kernel") and a hung-task I/O stall logs "blocked for more than
                // 120 seconds" on effectively every busy host, so both fired a
                // Critical kernel-panic alert as a false positive. They are handled
                // by the Medium rule below instead.
                messages: &["kernel panic", "kernel oops", "BUG:"],
            },
            LocalEventRule {
                severity: "Medium",
                title: "Process crash or hung task",
                detail: "A process segfaulted or a task was blocked on I/O for an extended period; usually a stability issue, occasionally a sign of exploitation attempts if repeated.",
                sources: &["kernel", "journald"],
                messages: &["segfault", "blocked for more than"],
            },
            LocalEventRule {
                severity: "High",
                title: "System service failure",
                detail: "systemd reported a failed or abnormal service state.",
                sources: &["systemd", ".service"],
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
                sources: &["kernel", "audit"],
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
                        file_path: None,
                        source: format!("OS event log: {}", event.log_name),
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
