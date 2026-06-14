//! Heuristic baseline model.
//!
//! On first launch Legion captures a *baseline* snapshot of the host — running
//! process names, active remote IPs, installed packages and the set of YARA
//! rules that already fire on disk. The snapshot is persisted as the heuristic
//! model. Every subsequent scan captures the same shape and diffs it against the
//! baseline, surfacing **drift** (new processes, new outbound peers, newly
//! installed packages and — most importantly — YARA rules that match now but did
//! not at baseline).
//!
//! This module is OS-agnostic: process/connection collection comes from the
//! cross-platform [`crate::telemetry`] helpers and `sysinfo`, package inventory
//! from [`crate::scanner`], and file signatures from the [`crate::yara`] engine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

use crate::alerts::{Alert, AlertEngine, Severity};
use crate::scanner::PackageScanner;
use crate::yara::{YaraManager, YaraMatch};
use crate::{telemetry, Database};

/// A point-in-time fingerprint of the host used as the heuristic model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub os: String,
    pub created_at: String,
    pub process_names: Vec<String>,
    pub remote_ips: Vec<String>,
    /// `"ecosystem:name"` identifiers.
    pub packages: Vec<String>,
    /// Names of YARA rules that matched at capture time.
    pub yara_rules_hit: Vec<String>,
    pub proc_count: usize,
}

impl Baseline {
    /// Capture the current host state. `yara_hits` is the result of the YARA
    /// scan performed by the caller (so the engine is built only once).
    pub fn capture(scan_root: &Path, yara_hits: &[YaraMatch]) -> Self {
        let process_names = collect_process_names();
        let proc_count = process_names.len();
        let remote_ips = sorted_unique(telemetry::active_remote_ips());

        let scan = PackageScanner::scan(scan_root);
        let packages = sorted_unique(
            scan.packages
                .iter()
                .map(|p| format!("{}:{}", p.ecosystem_str(), p.name))
                .collect(),
        );

        let yara_rules_hit = sorted_unique(yara_hits.iter().map(|m| m.rule.clone()).collect());

        Self {
            os: crate::yara::current_os().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            process_names,
            remote_ips,
            packages,
            yara_rules_hit,
            proc_count,
        }
    }
}

/// A single deviation from the baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drift {
    /// "NewProcess" | "NewRemoteIp" | "NewPackage" | "NewYaraRule"
    pub kind: String,
    /// Severity label aligned with [`crate::alerts::Severity`].
    pub severity: String,
    pub detail: String,
}

/// Diff `current` against the stored `baseline`, returning all deviations.
pub fn compare(baseline: &Baseline, current: &Baseline) -> Vec<Drift> {
    let mut drifts = Vec::new();

    let base_procs: BTreeSet<&String> = baseline.process_names.iter().collect();
    for p in &current.process_names {
        if !base_procs.contains(p) {
            drifts.push(Drift {
                kind: "NewProcess".into(),
                severity: "Low".into(),
                detail: format!("New process not present at baseline: {p}"),
            });
        }
    }

    let base_ips: BTreeSet<&String> = baseline.remote_ips.iter().collect();
    for ip in &current.remote_ips {
        if !base_ips.contains(ip) {
            drifts.push(Drift {
                kind: "NewRemoteIp".into(),
                severity: "Medium".into(),
                detail: format!("New outbound connection peer since baseline: {ip}"),
            });
        }
    }

    let base_pkgs: BTreeSet<&String> = baseline.packages.iter().collect();
    for pkg in &current.packages {
        if !base_pkgs.contains(pkg) {
            drifts.push(Drift {
                kind: "NewPackage".into(),
                severity: "Low".into(),
                detail: format!("New package installed since baseline: {pkg}"),
            });
        }
    }

    let base_rules: BTreeSet<&String> = baseline.yara_rules_hit.iter().collect();
    for rule in &current.yara_rules_hit {
        if !base_rules.contains(rule) {
            drifts.push(Drift {
                kind: "NewYaraRule".into(),
                severity: "High".into(),
                detail: format!("YARA rule '{rule}' now matches but did not at baseline"),
            });
        }
    }

    drifts
}

/// Result of [`run`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanOutcome {
    /// True when this run *established* the baseline (first launch).
    pub baseline_created: bool,
    pub yara_matches: Vec<YaraMatch>,
    pub drifts: Vec<Drift>,
    /// Number of alerts saved (YARA hits + drift).
    pub alerts_saved: usize,
    pub rules_loaded: usize,
    pub warnings: Vec<String>,
}

/// Run a full heuristic scan against `scan_root`:
///   1. build the YARA engine for this OS and scan the configured paths,
///   2. capture the current host fingerprint,
///   3. on first launch, persist it as the baseline; otherwise diff against it,
///   4. persist YARA matches and raise alerts for matches + drift.
pub fn run(db: &Database, mgr: &YaraManager, scan_root: &Path) -> anyhow::Result<ScanOutcome> {
    let (engine, warnings) = mgr.build_engine();
    let rules_loaded = engine.rule_count();

    let max_bytes = mgr.config.max_file_size_bytes();
    let max_files = mgr.config.max_files_per_scan;
    let yara_matches = engine.scan_paths(&mgr.scan_paths(), max_bytes, max_files);

    if !yara_matches.is_empty() {
        db.save_yara_matches(&yara_matches)?;
    }

    let current = Baseline::capture(scan_root, &yara_matches);

    let (baseline_created, reference, drifts) = if db.has_baseline()? {
        let baseline = db.get_latest_baseline()?.unwrap_or_default();
        let drifts = compare(&baseline, &current);
        (false, baseline, drifts)
    } else {
        db.save_baseline(&current)?;
        // On first run the reference IS the just-captured snapshot, so the
        // heuristic "new public peer" rule self-suppresses (nothing is new yet).
        (true, current.clone(), Vec::new())
    };

    // Build the alert set from three sources, favouring *real* observations over
    // raw drift volume:
    //   1. YARA matches.
    //   2. Cross-OS heuristic scoring (execution provenance, malicious/new public
    //      peers, process-count spike) — the meaningful behavioural signal.
    //   3. Only high-signal drift (e.g. a newly-firing YARA rule); lower drift
    //      stays an observation in `drifts` instead of flooding the alert list
    //      with one entry per new process/package.
    let mut alerts: Vec<Alert> = AlertEngine::from_yara_matches(&yara_matches);
    alerts.extend(crate::heuristics::score_host(db, &reference, &current.remote_ips));
    alerts.extend(
        AlertEngine::from_drifts(&drifts)
            .into_iter()
            .filter(|a| matches!(a.severity, Severity::High | Severity::Critical)),
    );
    let alerts_saved = alerts.len();
    if !alerts.is_empty() {
        db.save_alerts(&alerts)?;
    }

    Ok(ScanOutcome {
        baseline_created,
        yara_matches,
        drifts,
        alerts_saved,
        rules_loaded,
        warnings,
    })
}

// ───────────────────────────────── helpers ──────────────────────────────────

fn collect_process_names() -> Vec<String> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    let names: Vec<String> = sys
        .processes()
        .values()
        .map(|p| {
            p.name()
                .to_string_lossy()
                .to_lowercase()
                .trim_end_matches(".exe")
                .to_string()
        })
        .collect();
    sorted_unique(names)
}

fn sorted_unique(items: Vec<String>) -> Vec<String> {
    let set: BTreeSet<String> = items.into_iter().filter(|s| !s.is_empty()).collect();
    set.into_iter().collect()
}
