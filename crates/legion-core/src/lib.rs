pub mod ai_detector;
pub mod alerts;
pub mod baseline;
pub mod db;
pub mod feeds;
pub mod http;
pub mod integrity;
pub mod privilege;
pub mod quarantine;
pub mod runner;
pub mod scanner;
pub mod telemetry;
pub mod threat_intel;
pub mod yara;

pub use ai_detector::{AiDetector, AiThreat, AiThreatKind};
pub use alerts::{Alert, AlertEngine, AlertKind, Severity};
pub use baseline::{Baseline, Drift, ScanOutcome};
pub use db::Database;
pub use feeds::{AbuseIpEntry, AbuseIpPayload, CyberEvent, FeedManager};
pub use privilege::{ensure_elevated, is_elevated, Elevation};
pub use quarantine::{QuarantineEntry, QuarantineManager};
pub use runner::{RunnerCommandPlan, RunnerHost, RunnerManager, RunnerStatus};
pub use scanner::{Ecosystem, PackageScanner, ScanResult, ScannedPackage};
pub use telemetry::{DockerInfo, SystemStats, WinEvent};
pub use threat_intel::{KevCrossRef, KevEntry, OsvFinding, ThreatFoxIoc};
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

/// Restrict a file to owner read/write (`0600`) on Unix. No-op on other
/// platforms (Windows inherits the user-profile ACL). Best-effort: errors are
/// swallowed so a permission tweak never breaks startup.
pub fn harden_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Restrict a directory to owner access only (`0700`) on Unix. No-op elsewhere.
pub fn harden_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
