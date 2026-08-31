pub mod ai_detector;
pub mod alerts;
pub mod baseline;
pub mod db;
pub mod dprk;
pub mod feeds;
pub mod fsroots;
pub mod heuristics;
pub mod http;
pub mod integrity;
pub mod pkg_sensor;
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
pub use dprk::{DprkFinding, DPRK_SOURCE};
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

/// Machine-wide store for large, **non-secret** artifacts: model weights and the
/// `llama-server` runtime.
///
/// [`data_dir`] follows `HOME`, which becomes `/root` the moment Legion
/// self-elevates. Everything under it is therefore per-account — fine for the
/// database and the session token, wasteful for a 1.1 GB GGUF: the same model
/// was downloaded once per user, and the copy staged while elevated was
/// invisible to an unelevated run.
///
/// These artifacts are public downloads verified by SHA-256, not secrets, so
/// they are deliberately world-readable and are **not** passed through
/// [`harden_dir`]. Root stages them once; an unelevated run reads the same copy.
pub fn shared_store_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(base).join("legion")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/var/lib/legion")
    }
}

/// Whether `dir` can be created or already accepts writes from this process.
fn store_is_writable(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    // `create_dir_all` succeeds on an existing read-only dir, so probe a write.
    //
    // The probe name must be unique per call. A single fixed name meant two
    // concurrent callers shared one file: on Windows the second `write` hits a
    // sharing violation against the first caller's handle (or the first caller's
    // `remove_file` lands between the second's write and its own cleanup), and
    // the loser concludes a perfectly writable shared store is read-only. That
    // is not a cosmetic race — it silently sends one artifact to the machine-wide
    // store and the next to the per-user directory, so the model and the runtime
    // that must load it can end up in different roots.
    static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let probe = dir.join(format!(
        ".legion-write-probe-{}-{}",
        std::process::id(),
        PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolve where a large artifact lives, preferring an existing copy.
///
/// `rel` is a path relative to the store root (e.g. `models/foo.gguf`).
///
/// 1. An existing copy in the shared store wins, even when that store is not
///    writable by this process — an unelevated run must be able to *read* what
///    root staged rather than re-downloading gigabytes.
/// 2. Then an existing copy in the per-user dir, so installs that predate the
///    shared store keep working untouched.
/// 3. Otherwise the shared store if we can write to it, else the per-user dir.
pub fn resolve_store_path(rel: &std::path::Path) -> std::path::PathBuf {
    resolve_store_path_in(&shared_store_dir(), &data_dir(), rel)
}

/// Testable core of [`resolve_store_path`], with both roots injected.
fn resolve_store_path_in(
    shared_root: &std::path::Path,
    user_root: &std::path::Path,
    rel: &std::path::Path,
) -> std::path::PathBuf {
    let shared = shared_root.join(rel);
    if shared.exists() {
        return shared;
    }
    let user = user_root.join(rel);
    if user.exists() {
        return user;
    }
    if store_is_writable(shared_root) {
        // World-readable so an unelevated run can read what root staged. These
        // are hash-verified public artifacts, not secrets.
        set_world_readable_dir(shared_root);
        shared
    } else {
        user
    }
}

/// Make a directory traversable and readable by every local account (`0755`).
/// Intentionally the opposite of [`harden_dir`]: see [`shared_store_dir`].
fn set_world_readable_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    {
        // Windows inherits the permissive ProgramData ACL, which is what we want.
        let _ = path;
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

#[cfg(test)]
mod store_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn an_existing_shared_copy_wins_even_when_unwritable() {
        // The case that motivated this: root stages the 1.1 GB model into the
        // machine-wide store, then an unelevated run must READ that copy rather
        // than re-downloading it into its own home. Unwritable must not mean
        // unusable.
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let rel = Path::new("models").join("m.gguf");

        std::fs::create_dir_all(shared.path().join("models")).unwrap();
        std::fs::write(shared.path().join(&rel), b"weights").unwrap();

        let got = resolve_store_path_in(shared.path(), user.path(), &rel);
        assert_eq!(got, shared.path().join(&rel));
    }

    #[test]
    fn an_existing_user_copy_is_kept() {
        // Installs that predate the shared store must not be orphaned into a
        // silent re-download.
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let rel = Path::new("models").join("m.gguf");

        std::fs::create_dir_all(user.path().join("models")).unwrap();
        std::fs::write(user.path().join(&rel), b"weights").unwrap();

        let got = resolve_store_path_in(shared.path(), user.path(), &rel);
        assert_eq!(got, user.path().join(&rel));
    }

    #[test]
    fn a_fresh_install_prefers_the_shared_store_when_writable() {
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let rel = Path::new("models").join("m.gguf");
        let got = resolve_store_path_in(shared.path(), user.path(), &rel);
        assert_eq!(got, shared.path().join(&rel), "writable shared store wins");
    }

    #[test]
    fn a_fresh_install_falls_back_when_the_shared_store_is_unwritable() {
        // Unelevated first run on a box with no /var/lib/legion: must degrade to
        // the per-user dir rather than failing.
        let user = tempfile::tempdir().unwrap();
        let rel = Path::new("models").join("m.gguf");
        // A path under a file cannot be created as a directory.
        let blocker = tempfile::NamedTempFile::new().unwrap();
        let unwritable = blocker.path().join("legion");

        let got = resolve_store_path_in(&unwritable, user.path(), &rel);
        assert_eq!(got, user.path().join(&rel));
    }

    #[test]
    fn store_writability_probes_an_actual_write() {
        // create_dir_all succeeds on an existing read-only directory, so
        // existence alone is not evidence we can stage into it.
        let dir = tempfile::tempdir().unwrap();
        assert!(store_is_writable(dir.path()));
        // No probe file may be left behind, whatever it was named.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(leftovers.is_empty(), "probe left behind: {leftovers:?}");

        let blocker = tempfile::NamedTempFile::new().unwrap();
        assert!(!store_is_writable(&blocker.path().join("nope")));
    }

    #[test]
    fn concurrent_writability_probes_all_agree() {
        // Every caller probing the same writable directory at the same time must
        // get the same answer. With a single shared probe filename they did not:
        // one thread's cleanup or open handle made another read the directory as
        // read-only, and the two then resolved the same artifact to different
        // store roots.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || (0..25).all(|_| store_is_writable(&root)))
            })
            .collect();
        for t in threads {
            assert!(
                t.join().unwrap(),
                "a writable directory was reported read-only under concurrency"
            );
        }
    }

    #[test]
    fn concurrent_resolution_picks_one_root() {
        // The consequence the probe race actually had: resolve_store_path_in
        // handing back two different roots for the same relative path.
        let shared = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let (sp, up) = (shared.path().to_path_buf(), user.path().to_path_buf());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (sp, up) = (sp.clone(), up.clone());
                std::thread::spawn(move || {
                    let rel = std::path::Path::new("runtime").join("llama-test");
                    (0..25)
                        .map(|_| resolve_store_path_in(&sp, &up, &rel))
                        .collect::<std::collections::HashSet<_>>()
                })
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        for t in threads {
            seen.extend(t.join().unwrap());
        }
        assert_eq!(
            seen.len(),
            1,
            "resolution diverged across threads: {seen:?}"
        );
    }
}
