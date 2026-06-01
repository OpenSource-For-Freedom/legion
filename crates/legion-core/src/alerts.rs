//! Alert engine: correlates scan results and IP connections against threat feeds
//! to produce actionable security alerts.

use crate::{
    feeds::{AbuseIpPayload, CyberEvent},
    scanner::ScannedPackage,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Types ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical, // score ≥ 90
    High,     // 70-89
    Medium,   // 40-69
    Low,      // 10-39
    Info,     // 0-9
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
    CveMatch,           // installed package matches enrichment.affected_packages
    IpBlacklist,        // active connection to AbuseIPDB blacklisted IP
    SuspiciousPackage,  // package name appears in event title/summary (heuristic)
    SystemAnomaly,      // high resource usage / anomalous process
}

impl std::fmt::Display for AlertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertKind::CveMatch => write!(f, "CVE Match"),
            AlertKind::IpBlacklist => write!(f, "IP Blacklist"),
            AlertKind::SuspiciousPackage => write!(f, "Suspicious Pkg"),
            AlertKind::SystemAnomaly => write!(f, "System Anomaly"),
        }
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

// ─────────────────────────────── Engine ─────────────────────────────────────

pub struct AlertEngine;

impl AlertEngine {
    /// Cross-reference installed packages with cyber-event affected_packages.
    /// Returns a list of alerts (unsaved, id=0).
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
                    // Match ecosystem variants: "crates" == "crates.io", "pypi" == "pip" etc.
                    let eco_match = eco_lower == scanned_eco
                        || (eco_lower == "crates.io" && scanned_eco == "crates")
                        || (eco_lower == "pypi" && scanned_eco == "pypi")
                        || (eco_lower == "npm" && scanned_eco == "npm");

                    if eco_match
                        && scanned.name.to_lowercase()
                            == affected_pkg.name.to_lowercase()
                    {
                        let cves = enrichment
                            .cve_ids
                            .clone()
                            .unwrap_or_default();
                        let severity =
                            Severity::from_score(event.severity.unwrap_or(50.0));

                        let detail = format!(
                            "Package '{}' ({}) found in cyber event '{}'. CVEs: {}. Techniques: {}",
                            scanned.name,
                            scanned.ecosystem_str(),
                            event.title,
                            if cves.is_empty() { "none listed".to_owned() } else { cves.join(", ") },
                            enrichment.attack_techniques
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

        // Deduplicate: same package → keep highest severity
        dedup_alerts(alerts)
    }

    /// Cross-reference active IP connections against the AbuseIPDB blacklist.
    pub fn check_ips(active_ips: &[String], blacklist: &AbuseIpPayload) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for conn_ip in active_ips {
            if let Some(entry) = blacklist.ips.iter().find(|e| e.ip == *conn_ip) {
                let score = entry.abuse_score.unwrap_or(100);
                let severity = Severity::from_score(score as f64);

                alerts.push(Alert {
                    id: 0,
                    kind: AlertKind::IpBlacklist,
                    severity,
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
}

/// Keep one alert per (kind, package/ip) pair — highest severity wins.
fn dedup_alerts(mut alerts: Vec<Alert>) -> Vec<Alert> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Alert> = HashMap::new();
    alerts.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));
    for alert in alerts {
        let key = match &alert.kind {
            AlertKind::CveMatch => format!(
                "cve:{}:{}",
                alert.package_ecosystem.as_deref().unwrap_or(""),
                alert.package_name.as_deref().unwrap_or("")
            ),
            AlertKind::IpBlacklist => {
                format!("ip:{}", alert.ip_address.as_deref().unwrap_or(""))
            }
            _ => alert.title.clone(),
        };
        map.entry(key).or_insert(alert);
    }
    let mut out: Vec<Alert> = map.into_values().collect();
    out.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));
    out
}
