//! Cross-ecosystem package scanner.
//!
//! Supported ecosystems: Cargo (Cargo.lock), npm (package-lock.json), pip (pip list).
//! The scanner walks the given directory tree and extracts installed package coordinates.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    let output = run_pip_list()?;

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

fn run_pip_list() -> Result<Output> {
    if crate::privilege::is_elevated() {
        return run_pip_list_elevated();
    }
    run_pip_list_unprivileged()
}

fn run_pip_list_elevated() -> Result<Output> {
    #[cfg(target_os = "windows")]
    {
        let mut tried: Vec<String> = Vec::new();

        // Prefer a known system launcher path over PATH lookup.
        let py_launcher = Path::new("C:\\Windows\\py.exe");
        if py_launcher.is_file() {
            tried.push(py_launcher.display().to_string());
            if let Ok(out) = Command::new(py_launcher)
                .args(["-3", "-m", "pip", "list", "--format=json"])
                .output()
            {
                return Ok(out);
            }
        }

        for dir in windows_python_dirs() {
            let py = dir.join("python.exe");
            if py.is_file() {
                tried.push(py.display().to_string());
                if let Ok(out) = Command::new(&py)
                    .args(["-m", "pip", "list", "--format=json"])
                    .output()
                {
                    return Ok(out);
                }
            }
            let pip = dir.join("Scripts").join("pip.exe");
            if pip.is_file() {
                tried.push(pip.display().to_string());
                if let Ok(out) = Command::new(&pip).args(["list", "--format=json"]).output() {
                    return Ok(out);
                }
            }
        }

        anyhow::bail!(
            "elevated scan refused PATH-based pip execution on Windows; no trusted interpreter found (tried: {})",
            if tried.is_empty() {
                "none".to_string()
            } else {
                tried.join(", ")
            }
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Under root/elevated context, execute only known absolute system paths.
        let mut tried: Vec<String> = Vec::new();
        for pip in [
            Path::new("/usr/bin/pip3"),
            Path::new("/usr/local/bin/pip3"),
            Path::new("/usr/bin/pip"),
            Path::new("/usr/local/bin/pip"),
        ] {
            if pip.is_file() {
                tried.push(pip.display().to_string());
                if let Ok(out) = Command::new(pip).args(["list", "--format=json"]).output() {
                    return Ok(out);
                }
            }
        }

        for py in [
            Path::new("/usr/bin/python3"),
            Path::new("/usr/local/bin/python3"),
        ] {
            if py.is_file() {
                tried.push(py.display().to_string());
                if let Ok(out) = Command::new(py)
                    .args(["-m", "pip", "list", "--format=json"])
                    .output()
                {
                    return Ok(out);
                }
            }
        }

        anyhow::bail!(
            "elevated scan refused PATH-based pip execution; no trusted interpreter found (tried: {})",
            if tried.is_empty() {
                "none".to_string()
            } else {
                tried.join(", ")
            }
        );
    }
}

fn run_pip_list_unprivileged() -> Result<Output> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("py")
            .args(["-3", "-m", "pip", "list", "--format=json"])
            .output()
        {
            return Ok(out);
        }
        if let Ok(out) = Command::new("python")
            .args(["-m", "pip", "list", "--format=json"])
            .output()
        {
            return Ok(out);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        for pip in [
            Path::new("/usr/bin/pip3"),
            Path::new("/usr/local/bin/pip3"),
            Path::new("/usr/bin/pip"),
            Path::new("/usr/local/bin/pip"),
        ] {
            if pip.is_file() {
                if let Ok(out) = Command::new(pip).args(["list", "--format=json"]).output() {
                    return Ok(out);
                }
            }
        }

        for py in [
            Path::new("/usr/bin/python3"),
            Path::new("/usr/local/bin/python3"),
        ] {
            if py.is_file() {
                if let Ok(out) = Command::new(py)
                    .args(["-m", "pip", "list", "--format=json"])
                    .output()
                {
                    return Ok(out);
                }
            }
        }
    }

    // Compatibility fallback when only PATH-resolved tools are available.
    Command::new("pip")
        .args(["list", "--format=json"])
        .output()
        .or_else(|_| {
            Command::new("pip3")
                .args(["list", "--format=json"])
                .output()
        })
        .or_else(|_| {
            Command::new("python3")
                .args(["-m", "pip", "list", "--format=json"])
                .output()
        })
        .map_err(Into::into)
}

#[cfg(target_os = "windows")]
fn windows_python_dirs() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Programs").join("Python"));
    }
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        roots.push(PathBuf::from(pf));
    }
    if let Some(pf86) = std::env::var_os("ProgramFiles(x86)") {
        roots.push(PathBuf::from(pf86));
    }

    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        if root.ends_with("Python") {
            if let Ok(entries) = std::fs::read_dir(&root) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        out.push(entry.path());
                    }
                }
            }
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.to_ascii_lowercase().starts_with("python") {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

// ────────────────────────────── Scanner ─────────────────────────────────────

/// Walk a directory tree collecting all supported lock-files.
pub struct PackageScanner;

impl PackageScanner {
    /// Scan a directory for Cargo.lock and package-lock.json files, and
    /// query the system pip installation. Returns a combined ScanResult.
    pub fn scan(root: &Path) -> ScanResult {
        Self::scan_roots(std::slice::from_ref(&root.to_path_buf()))
    }

    /// Scan every fixed drive / mount point on the host (see
    /// [`crate::fsroots::system_scan_roots`]) for lock-files — the whole-system
    /// package inventory. Removable and network filesystems are skipped.
    pub fn scan_system() -> ScanResult {
        Self::scan_roots(&crate::fsroots::system_scan_roots())
    }

    /// Scan each of `roots` for lock-files and combine with the system pip list.
    pub fn scan_roots(roots: &[PathBuf]) -> ScanResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut packages = Vec::new();
        let mut errors = Vec::new();

        for root in roots {
            Self::walk(root, &mut packages, &mut errors, 0);
        }

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

    fn walk(
        dir: &Path,
        packages: &mut Vec<ScannedPackage>,
        errors: &mut Vec<String>,
        depth: usize,
    ) {
        // Bound recursion depth so a deep tree (or a symlink loop that slipped
        // through) cannot exhaust the stack (audit CORE-4).
        const MAX_DEPTH: usize = 64;
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Use symlink_metadata so we never follow a symlink — following one
            // could escape the scan root or create an unbounded loop (audit CORE-4).
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                // Skip OS pseudo-trees, system noise, and build/VCS dirs so a
                // whole-drive walk stays safe and bounded.
                if crate::fsroots::is_excluded_scan_dir(&path) {
                    continue;
                }
                Self::walk(&path, packages, errors, depth + 1);
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
