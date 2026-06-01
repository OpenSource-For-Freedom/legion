pub mod ai_detector;
pub mod alerts;
pub mod db;
pub mod feeds;
pub mod quarantine;
pub mod scanner;
pub mod telemetry;
pub mod threat_intel;

pub use ai_detector::{AiDetector, AiThreat, AiThreatKind};
pub use alerts::{Alert, AlertEngine, AlertKind, Severity};
pub use db::Database;
pub use feeds::{AbuseIpEntry, AbuseIpPayload, CyberEvent, FeedManager};
pub use quarantine::{QuarantineEntry, QuarantineManager};
pub use scanner::{Ecosystem, PackageScanner, ScannedPackage, ScanResult};
pub use telemetry::{DockerInfo, SystemStats, WinEvent};
pub use threat_intel::{KevCrossRef, KevEntry, OsvFinding, ThreatFoxIoc};

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
