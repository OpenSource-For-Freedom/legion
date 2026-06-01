//! Cross-ecosystem package scanner.
//!
//! Supported ecosystems: Cargo (Cargo.lock), npm (package-lock.json), pip (pip list).
//! The scanner walks the given directory tree and extracts installed package coordinates.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pip,
    System,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Cargo => write!(f, "crates"),
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Pip => write!(f, "pypi"),
            Ecosystem::System => write!(f, "system"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub path: Option<String>,
}

impl ScannedPackage {
    pub fn ecosystem_str(&self) -> String {
        self.ecosystem.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub packages: Vec<ScannedPackage>,
    pub scanned_at: String,
    pub errors: Vec<String>,
}

impl ScanResult {
    pub fn cargo_count(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| p.ecosystem == Ecosystem::Cargo)
            .count()
    }
    pub fn npm_count(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| p.ecosystem == Ecosystem::Npm)
            .count()
    }
    pub fn pip_count(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| p.ecosystem == Ecosystem::Pip)
            .count()
    }
}

// ─────────────────────────── Cargo.lock Parser ──────────────────────────────
fn scan_cargo_lock(lock_path: &Path) -> Result<Vec<ScannedPackage>> {
    let text = std::fs::read_to_string(lock_path)?;
    // Minimal TOML parsing — only need [[package]] sections.
    // Use toml_edit or manual parse; here we parse with serde via the `toml` crate.
    // Since we don't want to add toml as a dep, we parse line-by-line (fast, no dep).
    let mut packages = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_ver: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (cur_name.take(), cur_ver.take()) {
                packages.push(ScannedPackage {
                    ecosystem: Ecosystem::Cargo,
                    name: n,
                    version: Some(v),
                    path: Some(lock_path.to_string_lossy().into_owned()),
                });
            }
        } else if let Some(rest) = line.strip_prefix("name = ") {
            cur_name = Some(rest.trim_matches('"').to_owned());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            cur_ver = Some(rest.trim_matches('"').to_owned());
        }
    }
    // Last package
    if let (Some(n), Some(v)) = (cur_name, cur_ver) {
        packages.push(ScannedPackage {
            ecosystem: Ecosystem::Cargo,
            name: n,
            version: Some(v),
            path: Some(lock_path.to_string_lossy().into_owned()),
        });
    }
    Ok(packages)
}

// ─────────────────────────── npm package-lock Parser ────────────────────────

fn scan_npm_lock(lock_path: &Path) -> Result<Vec<ScannedPackage>> {
    let text = std::fs::read_to_string(lock_path)?;
    let json: serde_json::Value = serde_json::from_str(&text)?;

    let mut packages = Vec::new();

    // package-lock v2/v3 has "packages" key; v1 has "dependencies"
    if let Some(pkgs) = json.get("packages").and_then(|v| v.as_object()) {
        for (key, val) in pkgs {
            if key.is_empty() {
                continue; // skip root
            }
            let name = key.trim_start_matches("node_modules/").to_owned();
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());
            packages.push(ScannedPackage {
                ecosystem: Ecosystem::Npm,
                name,
                version,
                path: Some(lock_path.to_string_lossy().into_owned()),
            });
        }
    } else if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
        for (name, val) in deps {
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());
            packages.push(ScannedPackage {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                version,
                path: Some(lock_path.to_string_lossy().into_owned()),
            });
        }
    }
    Ok(packages)
}

// ────────────────────────────── pip Scanner ─────────────────────────────────

/// Runs `pip list --format=json` and parses the output.
fn scan_pip() -> Result<Vec<ScannedPackage>> {
    let output = Command::new("pip")
        .args(["list", "--format=json"])
        .output()
        .or_else(|_| {
            Command::new("pip3")
                .args(["list", "--format=json"])
                .output()
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "pip list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let list: Vec<HashMap<String, String>> = serde_json::from_str(&text)?;

    Ok(list
        .into_iter()
        .map(|mut m| ScannedPackage {
            ecosystem: Ecosystem::Pip,
            name: m.remove("name").unwrap_or_default().to_lowercase(),
            version: m.remove("version"),
            path: None,
        })
        .collect())
}

// ────────────────────────────── Scanner ─────────────────────────────────────

/// Walk a directory tree collecting all supported lock-files.
pub struct PackageScanner;

impl PackageScanner {
    /// Scan a directory for Cargo.lock and package-lock.json files, and
    /// query the system pip installation. Returns a combined ScanResult.
    pub fn scan(root: &Path) -> ScanResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut packages = Vec::new();
        let mut errors = Vec::new();

        // Walk directory for lock files
        Self::walk(root, &mut packages, &mut errors);

        // System-wide pip
        match scan_pip() {
            Ok(pip_pkgs) => packages.extend(pip_pkgs),
            Err(e) => errors.push(format!("pip: {e}")),
        }

        ScanResult {
            packages,
            scanned_at: now,
            errors,
        }
    }

    fn walk(dir: &Path, packages: &mut Vec<ScannedPackage>, errors: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip common noise dirs
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | "node_modules" | ".git" | "__pycache__") {
                    continue;
                }
                Self::walk(&path, packages, errors);
            } else {
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                match fname {
                    "Cargo.lock" => match scan_cargo_lock(&path) {
                        Ok(pkgs) => {
                            tracing::debug!("Cargo.lock: {} packages at {:?}", pkgs.len(), path);
                            packages.extend(pkgs);
                        }
                        Err(e) => errors.push(format!("Cargo.lock {:?}: {e}", path)),
                    },
                    "package-lock.json" => match scan_npm_lock(&path) {
                        Ok(pkgs) => {
                            tracing::debug!(
                                "package-lock.json: {} packages at {:?}",
                                pkgs.len(),
                                path
                            );
                            packages.extend(pkgs);
                        }
                        Err(e) => errors.push(format!("package-lock.json {:?}: {e}", path)),
                    },
                    _ => {}
                }
            }
        }
    }
}
