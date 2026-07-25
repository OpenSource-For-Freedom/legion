//! Whole-system scan support: drive/mount enumeration and scan exclusions.
//!
//! These helpers let the package scanner and the YARA engine cover *every* fixed
//! drive and folder on the host while staying safe and bounded — OS
//! pseudo-filesystems, recycle bins, and high-noise build/cache directories are
//! skipped so a full-drive walk neither loops nor wastes time on irrelevant
//! trees. Removable (USB) and network filesystems are left out: a host scan
//! should cover the machine, not external media or remote shares.

use std::path::{Path, PathBuf};

/// Network filesystem names to skip (best-effort, matched case-insensitively).
const NETWORK_FS: &[&str] = &["nfs", "nfs4", "cifs", "smbfs", "smb", "fuse.sshfs", "9p"];

/// Enumerate the fixed (non-removable, non-network) drive roots / mount points.
///
/// Windows resolves to each fixed drive root (`C:\`, `D:\`, …); Linux to each
/// mounted local filesystem (`/`, `/home`, …). Falls back to drive-letter
/// probing (Windows) or `/` (Unix) when disk enumeration returns nothing.
pub fn system_scan_roots() -> Vec<PathBuf> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut roots: Vec<PathBuf> = Vec::new();
    for disk in disks.list() {
        if disk.is_removable() {
            continue;
        }
        let fs = disk.file_system().to_string_lossy().to_ascii_lowercase();
        if NETWORK_FS.contains(&fs.as_str()) {
            continue;
        }
        let mount = disk.mount_point().to_path_buf();
        if !roots.contains(&mount) {
            roots.push(mount);
        }
    }
    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        roots = fallback_roots();
    }
    roots
}

#[cfg(target_os = "windows")]
fn fallback_roots() -> Vec<PathBuf> {
    ('A'..='Z')
        .map(|c| PathBuf::from(format!("{c}:\\")))
        .filter(|p| p.exists())
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn fallback_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Absolute pseudo / system trees never worth scanning (matched after
/// normalising backslashes to `/` and lowercasing).
const ABS_DENY: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    // Package-manager metadata, not executable content. `dpkg.status` is a
    // catalogue of software DESCRIPTIONS, so malware-keyword rules match the
    // prose ("reverse shell", "curl | sh") and report the package database as a
    // critical finding.
    "/var/backups",
    "/var/lib/dpkg",
    "/var/lib/apt",
];

/// System trees matched anywhere in the path (huge, low-signal OS internals).
const SUBSTR_DENY: &[&str] = &[
    // Dependency caches, matched by their full path so an ordinary project
    // directory that happens to be called "cache" or "registry" is unaffected.
    //
    // These hold third-party source the developer never wrote, and scanning
    // them produced real false positives: iconv-lite's generated charset tables
    // legitimately contain Private Use Area codepoints (that is what they map),
    // and a query-string library's test fixtures contain deliberate encoding
    // oddities. Neither is the developer's own code, which is what the
    // injection campaigns actually target.
    "/.bun/install/cache",
    "/.cargo/registry",
    "/.npm/_cacache",
    "/.gradle/caches",
    "/.m2/repository",
    "/windows/winsxs",
    "/windows/servicing",
    "/$recycle.bin",
    "/system volume information",
    "/windows.~bt",
    "/windows.~ws",
];

/// High-noise directory *names* skipped at any depth (build artifacts, VCS,
/// and Legion's own vendored toolchain — a compiler/libc trips behavioural
/// rules like crypto-miner / fileless-exec on normal linker/libc strings).
const NAME_DENY: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    // npm's content-addressable cache: third-party tarball contents, never the
    // developer's own source.
    "_cacache",
    ".pnpm-store",
    ".local-tools",
    // Legion's own rule/signature distribution dirs — their rule text (`.yar`,
    // rule `.json`) contains every malware indicator by design and self-matches.
    "rules-feed",
    "agents",
];

/// Legion's own runtime directories — its binary location and data dir (rules
/// cache, signature DB, config). A security scanner must never flag its own
/// files: the rule text itself contains every malware indicator by design, so
/// scanning them yields guaranteed false positives (QA 2026-07 F9). Computed
/// once and cached.
fn legion_own_dirs() -> &'static Vec<std::path::PathBuf> {
    use std::sync::OnceLock;
    static DIRS: OnceLock<Vec<std::path::PathBuf>> = OnceLock::new();
    DIRS.get_or_init(|| {
        let mut v = vec![crate::data_dir()];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                v.push(parent.to_path_buf());
            }
        }
        v.into_iter()
            .map(|p| p.canonicalize().unwrap_or(p))
            .collect()
    })
}

/// True when a directory should be skipped during a whole-system scan. Keeps a
/// full-drive walk safe (no `/proc` recursion / loops) and bounded (no WinSxS,
/// recycle bins, or build trees).
pub fn is_excluded_scan_dir(path: &Path) -> bool {
    if let Some(s) = path.to_str() {
        let lower = s.replace('\\', "/").to_ascii_lowercase();
        if ABS_DENY
            .iter()
            .any(|d| lower == *d || lower.starts_with(&format!("{d}/")))
        {
            return true;
        }
        if SUBSTR_DENY.iter().any(|d| lower.contains(d)) {
            return true;
        }
    }
    // Last path component, split on BOTH separators so a Windows-style path is
    // matched the same on any host (`Path::file_name` only honours the native
    // separator, so on Linux it would treat `C:\a\node_modules` as one component).
    let name = path
        .to_str()
        .unwrap_or("")
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if NAME_DENY.contains(&name.as_str()) {
        return true;
    }

    // Legion's own binary/data/rule directories — never scan ourselves.
    if let Ok(canon) = path.canonicalize() {
        if legion_own_dirs()
            .iter()
            .any(|d| canon == *d || canon.starts_with(d))
        {
            return true;
        }
    }
    false
}

/// Reveal `path` in the host's file manager so an analyst can jump straight to a
/// flagged file. On Windows the file is *selected* in Explorer; on Linux the
/// containing folder is opened (selecting a specific item is not portable across
/// file managers). No shell is invoked — the manager is launched with the path as
/// a direct argument. Errors if the path does not exist or the launch fails.
pub fn reveal_in_file_manager(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    // Existence check first: never hand a non-existent / dangling path to the OS,
    // and give the caller a clear error instead of a silent no-op.
    if std::fs::symlink_metadata(path).is_err() {
        return Err(Error::new(ErrorKind::NotFound, "path does not exist"));
    }
    #[cfg(target_os = "windows")]
    {
        // `explorer /select,<path>` opens the folder and highlights the item.
        std::process::Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn()?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let dir = if path.is_dir() {
            path
        } else {
            path.parent().unwrap_or(Path::new("/"))
        };
        std::process::Command::new("xdg-open").arg(dir).spawn()?;
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = path;
        Err(Error::new(
            ErrorKind::Unsupported,
            "reveal not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_pseudo_and_system_trees() {
        assert!(is_excluded_scan_dir(Path::new("/proc")));
        assert!(is_excluded_scan_dir(Path::new("/proc/1234")));
        assert!(is_excluded_scan_dir(Path::new("/sys/kernel")));
        assert!(is_excluded_scan_dir(Path::new("C:\\Windows\\WinSxS")));
        assert!(is_excluded_scan_dir(Path::new("D:\\$Recycle.Bin")));
        assert!(is_excluded_scan_dir(Path::new(
            "C:\\System Volume Information"
        )));
    }

    #[test]
    fn excludes_noise_dir_names_any_depth() {
        assert!(is_excluded_scan_dir(Path::new("/home/u/proj/.git")));
        assert!(is_excluded_scan_dir(Path::new(
            "C:\\code\\app\\node_modules"
        )));
        assert!(is_excluded_scan_dir(Path::new("/home/u/proj/target")));
    }

    #[test]
    fn keeps_ordinary_and_staging_dirs() {
        // /tmp and friends are prime staging spots — must NOT be excluded.
        assert!(!is_excluded_scan_dir(Path::new("/tmp")));
        assert!(!is_excluded_scan_dir(Path::new("/home/u/Downloads")));
        assert!(!is_excluded_scan_dir(Path::new("C:\\Users\\bob\\Desktop")));
        // "/proc" only as a real pseudo root, not a substring of another name.
        assert!(!is_excluded_scan_dir(Path::new("/home/u/process-logs")));
    }

    #[test]
    fn system_roots_are_nonempty() {
        // Whatever the host, enumeration (or the fallback) yields at least one root.
        assert!(!system_scan_roots().is_empty());
    }
}
