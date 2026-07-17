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
    /// Stable identity for de-duplication across polling ticks *and* restarts.
    ///
    /// Deliberately `ecosystem|name`, with no version: the curated list matches
    /// on name and ecosystem alone, so the version never changes the verdict and
    /// including it would page again for the same known-bad package on every
    /// version bump. It also keeps the key derivable from a stored alert, which
    /// records the package and ecosystem but not the version — that is what lets
    /// the dedup survive a restart.
    pub fn key(&self) -> String {
        alert_key(&self.ecosystem, &self.name)
    }
}

/// The dedup identity for a package, shared by live hits and rows rehydrated
/// from the database so the two cannot drift apart.
pub fn alert_key(ecosystem: &str, name: &str) -> String {
    format!("{}|{}", ecosystem.to_lowercase(), name.to_lowercase())
}

/// Confirmed-malicious detections only (exact name+ecosystem match against the
/// curated list). This is the zero-false-positive core: vulnerable-but-legitimate
/// SDKs, inventory notes, and every heuristic are deliberately filtered out, so a
/// returned hit always means the package is on the known-malicious list.
///
/// Filtering on the kind alone is NOT sufficient. `MaliciousAiPackage` also
/// carries an advisory tier of "unofficial / unaudited wrapper" judgements, and
/// several of those are legitimate open-source projects someone may have
/// installed deliberately (`chatgpt-wrapper`, `claude-api`, `langchain-js`).
/// Paging Critical on those is exactly the false positive this sensor must never
/// produce, so gate on `confirmed_malicious` too.
pub fn confirmed_malicious(packages: &[ScannedPackage]) -> Vec<MaliciousHit> {
    AiDetector::scan_packages(packages)
        .into_iter()
        .filter(|t| t.kind == AiThreatKind::MaliciousAiPackage && t.confirmed_malicious)
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

    /// Build a sensor that already considers `keys` reported.
    ///
    /// Seeded from the alerts already in the database, so a restart does not
    /// re-pop every malicious package the operator has already been told about.
    /// Without this the dedup lived only in memory: relaunching Legion fired the
    /// whole backlog again, and `save_alerts` would insert a fresh unacked row
    /// beside an alert the operator had already acked.
    pub fn with_seen<I: IntoIterator<Item = String>>(keys: I) -> Self {
        Self {
            alerted: keys.into_iter().collect(),
        }
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
    fn unofficial_but_legitimate_packages_never_page() {
        // The curated list blends two claims: "this is malware" and "this is an
        // unofficial wrapper". The second is a policy opinion, and several of
        // these are real, legitimate open-source projects a developer may have
        // installed on purpose. Paging Critical on them is a false positive that
        // could have an operator rip out working software, so the sensor must
        // stay silent even though the detector still surfaces them as advisories.
        for (eco, name) in [
            (Ecosystem::Pip, "chatgpt-wrapper"),
            (Ecosystem::Pip, "claude-api"),
            (Ecosystem::Pip, "huggingface"),
            (Ecosystem::Npm, "langchain-js"),
        ] {
            let pkgs = vec![pkg(eco, name, "1.0.0")];
            assert!(
                confirmed_malicious(&pkgs).is_empty(),
                "{name} is unofficial, not known-malicious — it must never page"
            );
            // ...but it must still be *reported* somewhere: silence in the
            // sensor must not mean the advisory was dropped entirely.
            assert!(
                !AiDetector::scan_packages(&pkgs).is_empty(),
                "{name} should still surface as a dashboard advisory"
            );
        }
    }

    #[test]
    fn every_hit_the_sensor_pages_on_is_flagged_confirmed() {
        // Guards the invariant directly rather than by example: nothing the
        // sensor emits may come from the advisory tier.
        let all: Vec<ScannedPackage> = ["openai-node", "chatgpt-wrapper", "openai", "claude-api"]
            .iter()
            .map(|n| pkg(Ecosystem::Npm, n, "1.0.0"))
            .chain(
                ["chatgpt", "gpt3", "claude-api", "openai"]
                    .iter()
                    .map(|n| pkg(Ecosystem::Pip, n, "1.0.0")),
            )
            .collect();
        for hit in confirmed_malicious(&all) {
            assert!(
                AiDetector::is_confirmed_malicious(&hit.name, &hit.ecosystem),
                "sensor paged on {} ({}), which is not on the confirmed list",
                hit.name,
                hit.ecosystem
            );
        }
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
    fn a_seeded_sensor_does_not_re_pop_after_a_restart() {
        // The dedup used to live only in memory, so relaunching Legion fired a
        // critical desktop pop-up for every malicious package all over again —
        // including ones the operator had already acked. Seeding from the stored
        // alerts is what makes the dedup survive the process.
        let pkgs = vec![pkg(Ecosystem::Npm, "openai-node", "9.9.9")];
        let key = confirmed_malicious(&pkgs)[0].key();

        let mut restarted = PackageSensor::with_seen([key]);
        assert!(
            restarted.new_hits(&pkgs).is_empty(),
            "a package already reported before the restart must not re-pop"
        );

        // A different malicious package still pops: seeding must not deafen it.
        let mut other = PackageSensor::with_seen(["npm|openai-node".to_string()]);
        assert_eq!(
            other
                .new_hits(&[pkg(Ecosystem::Pip, "chatgpt", "1.0.0")])
                .len(),
            1
        );
    }

    #[test]
    fn dedup_key_ignores_version_but_not_ecosystem() {
        // The key must be derivable from a stored alert, which records package
        // and ecosystem but no version — otherwise the restart seed above can
        // never match. Same package at a new version is still the same known-bad
        // package; the same name in a different ecosystem is not.
        let a = &confirmed_malicious(&[pkg(Ecosystem::Npm, "openai-node", "1.0.0")])[0];
        let b = &confirmed_malicious(&[pkg(Ecosystem::Npm, "openai-node", "2.0.0")])[0];
        assert_eq!(a.key(), b.key());
        assert_eq!(a.key(), alert_key("npm", "openai-node"));
        assert_ne!(alert_key("npm", "chatgpt"), alert_key("pypi", "chatgpt"));
        // Case must not split the key: the DB may hold either casing.
        assert_eq!(
            alert_key("NPM", "OpenAI-Node"),
            alert_key("npm", "openai-node")
        );
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
