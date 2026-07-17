pub mod ai_detector;
pub mod alerts;
pub mod baseline;
pub mod db;
pub mod feeds;
pub mod fsroots;
pub mod heuristics;
pub mod http;
pub mod integrity;
pub mod privilege;
pub mod quarantine;
pub mod runner;
pub mod scanner;
pub mod soar;
pub mod telemetry;
pub mod threat_intel;
pub mod yara;

pub use ai_detector::{AiDetector, AiThreat, AiThreatKind};
pub use alerts::{Alert, AlertEngine, AlertKind, Severity};
pub use baseline::{Baseline, Drift, ScanOutcome};
pub use db::Database;
pub use feeds::{AbuseIpEntry, AbuseIpPayload, CyberEvent, FeedManager};
pub use heuristics::{evaluate as evaluate_heuristics, score_host, ProcObservation};
pub use privilege::{ensure_elevated, ensure_elevated_unless, is_elevated, Elevation};
pub use quarantine::{QuarantineEntry, QuarantineManager};
pub use runner::{RunnerCommandPlan, RunnerHost, RunnerManager, RunnerStatus};
pub use scanner::{Ecosystem, PackageScanner, ScanResult, ScannedPackage};
pub use telemetry::{DockerInfo, SystemStats, WinEvent};
pub use threat_intel::{KevCrossRef, KevEntry, OsvFinding};
pub use yara::{UpdateReport, YaraConfig, YaraEngine, YaraManager, YaraMatch};

/// Default data directory, platform-aware.
pub fn data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(base).join("legion")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(base)
            .join(".local")
            .join("share")
            .join("legion")
    }
}

/// Restrict a file to owner read/write (`0600`) on Unix, and to the current user
/// only (inherited ACEs stripped) on Windows. Best-effort: errors are swallowed
/// so a permission tweak never breaks startup.
pub fn harden_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        restrict_to_owner_windows(path, "(F)");
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
}

/// Restrict a directory to owner access only (`0700` Unix / current-user-only
/// with inheritance on Windows). Best-effort; errors swallowed.
pub fn harden_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        // (OI)(CI) so new children under the store inherit the owner-only ACL.
        restrict_to_owner_windows(path, "(OI)(CI)(F)");
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
}

/// Windows owner-only lockdown, the ACL parity for Unix `0600`/`0700`: break ACL
/// inheritance and grant the given rights to the current user only, so the
/// quarantine store / secrets are not readable by other standard local accounts.
/// Best-effort via `icacls` (no FFI); any failure is ignored. `grant` is an
/// icacls permission spec, e.g. `"(F)"` for a file or `"(OI)(CI)(F)"` for a dir.
#[cfg(windows)]
fn restrict_to_owner_windows(path: &std::path::Path, grant: &str) {
    let Some(p) = path.to_str() else {
        return;
    };
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() {
        return;
    }
    let _ = std::process::Command::new("icacls")
        .args([p, "/inheritance:r", "/grant:r", &format!("{user}:{grant}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}
