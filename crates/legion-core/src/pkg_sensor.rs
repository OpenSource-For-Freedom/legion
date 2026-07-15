//! Continual package-attack sensor.
//!
//! A small, always-on watcher that raises a high-confidence **pop-up alert** the
//! moment a *confirmed-malicious* dependency appears in the host's package trees
//! (npm, PyPI, crates, ...). It is deliberately:
//!
//! * **Alert-only** — it never quarantines or modifies anything yet. A false
//!   quarantine could break a working system, so the destructive response stays a
//!   separate, later opt-in.
//! * **Zero-false-positive by construction** — it fires ONLY on exact
//!   name+ecosystem matches in the curated malicious-package list
//!   ([`crate::ai_detector`]). Signals that merely *suggest* risk (a brand-new
//!   package, an install script, a novel peer) are intentionally excluded here,
//!   so an alert always means "this exact package is known-malicious."
//!
//! The runtime poll loop lives in the web binary (it owns the tokio runtime and
//! the DB handle); this module holds the pure detection + de-duplication logic
//! and a best-effort desktop pop-up, all unit-testable.

use std::collections::BTreeSet;

use chrono::Utc;

use crate::ai_detector::{AiDetector, AiThreatKind};
use crate::alerts::{Alert, AlertKind, Severity};
use crate::scanner::ScannedPackage;

/// A confirmed-malicious package detected by the sensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaliciousHit {
    pub name: String,
    pub ecosystem: String,
    pub version: Option<String>,
    /// Human-readable reason, taken verbatim from the curated list.
    pub detail: String,
    /// MITRE ATLAS technique id, when known.
    pub atlas_id: Option<String>,
}

impl MaliciousHit {
    /// Stable identity for de-duplication across polling ticks.
    fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.ecosystem,
            self.name,
            self.version.as_deref().unwrap_or("")
        )
    }
}

/// Confirmed-malicious detections only (exact name+ecosystem match against the
/// curated list). This is the zero-false-positive core: vulnerable-but-legitimate
/// SDKs, inventory notes, and every heuristic are deliberately filtered out, so a
/// returned hit always means the package is on the known-malicious list.
pub fn confirmed_malicious(packages: &[ScannedPackage]) -> Vec<MaliciousHit> {
    AiDetector::scan_packages(packages)
        .into_iter()
        .filter(|t| t.kind == AiThreatKind::MaliciousAiPackage)
        .map(|t| MaliciousHit {
            name: t.package.unwrap_or_default(),
            ecosystem: t.ecosystem.unwrap_or_default(),
            version: t.version,
            detail: t.detail,
            atlas_id: t.atlas_id,
        })
        .collect()
}

/// Render a detection as a Critical dashboard alert.
pub fn to_alert(hit: &MaliciousHit) -> Alert {
    let detail = match &hit.atlas_id {
        Some(id) => format!("{} [{}]", hit.detail, id),
        None => hit.detail.clone(),
    };
    Alert {
        id: 0,
        kind: AlertKind::SuspiciousPackage,
        severity: Severity::Critical,
        title: format!(
            "Malicious package detected: {} ({})",
            hit.name, hit.ecosystem
        ),
        detail,
        package_name: Some(hit.name.clone()),
        package_ecosystem: Some(hit.ecosystem.clone()),
        ip_address: None,
        cve_ids: vec![],
        event_title: None,
        created_at: Utc::now().to_rfc3339(),
        acked: false,
        file_path: None,
        source: "Package attack sensor".to_string(),
    }
}

/// Best-effort desktop pop-up. Never blocks and never fails the caller: if no
/// notifier is available the detection still lands as a dashboard alert.
pub fn desktop_popup(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args(["--urgency=critical", "--app-name=Legion", title, body])
            .spawn();
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Native pop-up on Windows/macOS is future work; the dashboard alert is
        // always raised regardless of platform.
        let _ = (title, body);
    }
}

/// Tracks which malicious packages have already been surfaced so the pop-up fires
/// once per (ecosystem, name, version) rather than on every poll.
#[derive(Default)]
pub struct PackageSensor {
    alerted: BTreeSet<String>,
}

impl PackageSensor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Given the current package inventory, return only the confirmed-malicious
    /// hits not seen before, recording them so they are not re-reported.
    pub fn new_hits(&mut self, packages: &[ScannedPackage]) -> Vec<MaliciousHit> {
        let mut fresh = Vec::new();
        for hit in confirmed_malicious(packages) {
            if self.alerted.insert(hit.key()) {
                fresh.push(hit);
            }
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Ecosystem, ScannedPackage};

    fn pkg(eco: Ecosystem, name: &str, ver: &str) -> ScannedPackage {
        ScannedPackage {
            ecosystem: eco,
            name: name.to_string(),
            version: Some(ver.to_string()),
            path: None,
        }
    }

    #[test]
    fn legitimate_packages_never_alert() {
        // Ordinary, well-known packages must produce ZERO hits — the whole point
        // is no false positives that could break a system. Note `openai` is the
        // REAL SDK, not a typosquat, so it must not fire here.
        let pkgs = vec![
            pkg(Ecosystem::Npm, "left-pad", "1.3.0"),
            pkg(Ecosystem::Npm, "react", "18.2.0"),
            pkg(Ecosystem::Npm, "openai", "4.0.0"),
        ];
        assert!(confirmed_malicious(&pkgs).is_empty());
    }

    #[test]
    fn known_malicious_package_is_detected() {
        // A curated typosquat (openai-node on npm) must be caught.
        let pkgs = vec![pkg(Ecosystem::Npm, "openai-node", "9.9.9")];
        let hits = confirmed_malicious(&pkgs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "openai-node");
        assert_eq!(hits[0].ecosystem, "npm");
    }

    #[test]
    fn a_detection_only_pops_once() {
        // The continual poll must not re-alert the same package on every tick.
        let mut sensor = PackageSensor::new();
        let pkgs = vec![pkg(Ecosystem::Npm, "openai-node", "9.9.9")];
        let first = sensor.new_hits(&pkgs);
        let second = sensor.new_hits(&pkgs);
        assert_eq!(first.len(), 1);
        assert!(
            second.is_empty(),
            "same package must not re-alert on the next poll"
        );
    }
}
