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
    // Generated catalogues, indexes and logs: text that LISTS command and
    // capability names rather than executing them, so behavioural rules match
    // the names. Observed live: AppArmor profiles under /var/lib/snapd name
    // `/etc/ld.so.preload` and `insmod` (LD-preload + kernel-module rules), the
    // command-not-found and man databases enumerate every binary, and the
    // systemd journal replays whatever was logged. None is a threat surface.
    "/var/lib/snapd",
    "/var/lib/command-not-found",
    "/var/cache/man",
    "/var/cache/snapd",
    "/var/log/journal",
    // Container engine data roots. These hold pulled IMAGE LAYERS and container
    // filesystems - entire third-party operating systems, each full of tools that
    // match the behavioural rules (reverse shells, miners, container-escape
    // helpers). Scanning inside them reports other people's container images as
    // host compromise. A running container's threat is a runtime concern (the
    // process/network sensors), not a walk of the image store. Rootless roots
    // under $HOME are covered by SUBSTR_DENY below.
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/containers",
    "/var/lib/podman",
];

/// Distribution-owned executable/library trees. These are populated only by the
/// package manager, are integrity-verifiable against it, and hold the OS's own
/// binaries and shared objects — `bash`, `fakeroot` and `eatmydata` legitimately
/// set `LD_PRELOAD`, the dynamic linker references `ld-linux`/`--library-path`,
/// and `kmod` names `insmod`, so a string-based content rule fires on the
/// platform itself. The threat Legion hunts (malicious npm/pip/cargo packages,
/// dropped payloads) lands in user-writable locations - $HOME, /tmp, /var/tmp,
/// /dev/shm, /opt, downloads, project trees - which stay in scope. In-place
/// tampering of a system binary is a job for package integrity verification, a
/// separate control, not a string match. Matched as a prefix (exact dir or a
/// child of it).
const SYSTEM_PKG_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    // Kernel source/headers (the `linux-headers-*` packages). Kconfig, Makefiles
    // and the in-tree selftests BUILD and TEST kernel modules, iptables rules and
    // `curl | sh` fetches by design, so every behavioural rule fires on them.
    "/usr/src",
];

/// Basenames of Legion's own executables. A security scanner must never inspect
/// its own binary: the rule corpus is compiled into it (every malware indicator
/// by design), and its process-management code carries strings like
/// `--library-path` and `LD_PRELOAD=`, so it self-matches the fileless-exec and
/// LD-preload rules. The running binary's directory is excluded via
/// [`legion_own_dirs`], but an installed copy at a DIFFERENT path (e.g. a dev
/// build scanning the `/usr/local/bin` install) is only caught by name.
const LEGION_BIN_NAMES: &[&str] = &["legion-web", "legion-cli", "legion-tui", "legion"];

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
    // Package-manager and toolchain caches: downloaded/extracted third-party
    // archives (uv/pip Python wheels, HuggingFace models, Playwright/Puppeteer
    // browsers, Go build cache, gstreamer plugin registry). Same third-party
    // status as the .cargo/.npm caches above - a `bandit`/`torch`/`aiohttp` wheel
    // extracted into ~/.cache/uv legitimately carries socket and exec strings.
    // Supply-chain risk here is the package sensor's job, not the content scan.
    "/.cache/uv/",
    "/.cache/pip/",
    "/.cache/pypoetry/",
    "/.cache/huggingface/",
    "/.cache/gstreamer",
    "/.cache/go-build",
    "/.cache/ms-playwright",
    "/.cache/puppeteer",
    "/.cache/yarn",
    // Language toolchains installed by version managers: the interpreter/runtime
    // itself is third-party (a CPython stdlib carries socket/exec sample code, an
    // installer script pipes curl to sh by design).
    "/.local/share/uv",
    "/.nvm/",
    "/.rustup/",
    "/.rbenv/",
    "/.pyenv/",
    "/.sdkman/",
    // Trash: files the user already DELETED are not a live threat surface.
    "/.local/share/trash",
    // Browser profile caches: downloaded web content (a page's JS trips the miner
    // and curl-pipe rules). Not the host's own executables.
    "/.cache/mozilla",
    "/.cache/google-chrome",
    "/.cache/chromium",
    "/.mozilla/firefox",
    // Editor DERIVED data: VS Code auto-saved local history (old versions of the
    // very scripts already scanned in place), plus per-workspace and global
    // storage. Re-scanning saved copies of a file double-counts it; these are not
    // independently-executed content.
    "/.config/code/user/history",
    "/.config/code/user/workspacestorage",
    "/.config/code/user/globalstorage",
    // Rootless container engine data roots under $HOME (Docker/Podman): image
    // layers and container filesystems, as with the /var/lib roots above.
    "/.local/share/docker",
    "/.local/share/containers",
    // Installed editor extensions and language-server payloads: third-party
    // vendored code (Python, PowerShell, debug adapters) that ships security
    // tooling and interpreter shims, so behavioural rules fire on it. Only the
    // extensions/server trees are skipped, not the user's own `.vscode/`
    // settings in a project.
    "/.vscode/extensions",
    "/.vscode-server",
    "/.vscode-oss/extensions",
    "/.cursor/extensions",
    "/.cursor-server",
    "/.windsurf/extensions",
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
    // Third-party dependency trees the developer never wrote. Supply-chain risk
    // in these is the PACKAGE SENSOR's job (match the package name against OSV /
    // known-malicious lists), not the content scanner's: string rules fire on
    // benign library code by the hundred (a `bandit` security linter literally
    // ships attack signatures, `httpx`/`urllib3` carry socket code, `pygments`
    // has reverse-shell syntax samples). Mirrors the existing node_modules /
    // .cargo / .npm exclusions for the Python and editor ecosystems.
    "site-packages",
    "dist-packages",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    // PyInstaller one-dir bundle payload (`<app>/_internal/…`). Holds the app's
    // BUNDLED third-party runtime - Qt, systemd, Python's own shared objects -
    // which the developer never wrote, exactly like node_modules. Those compiled
    // libraries legitimately contain socket/exec strings, so the command/script
    // behavioural rules fire on them (observed live 2026-08: a bundled
    // libQt6RemoteObjects.so hit Reverse_Shell_Oneliner, libsystemd.so hit
    // Fileless_Exec). A trojanised app is caught by scanning its own launcher and
    // scripts, not its vendored .so libraries.
    "_internal",
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
        if SYSTEM_PKG_DIRS
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

    // Legion's own executables by basename, wherever they live (a dev build must
    // not scan the `/usr/local/bin` install and self-match). AppImage bundles
    // carry the same corpus, so exclude any Legion-named `.appimage` too.
    if LEGION_BIN_NAMES.contains(&name.as_str())
        || (name.ends_with(".appimage") && name.contains("legion"))
    {
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
        // /usr/local/bin is a real threat surface (admin-installed binaries) and
        // must stay in scope even though /usr/bin does not.
        assert!(!is_excluded_scan_dir(Path::new(
            "/usr/local/bin/somebinary"
        )));
        // /etc holds real persistence targets (ld.so.preload, cron, systemd).
        assert!(!is_excluded_scan_dir(Path::new("/etc/cron.d/job")));
        assert!(!is_excluded_scan_dir(Path::new("/opt/app")));
        // NOTE: /dev/shm IS excluded (as all of /dev, a pseudo-fs). A dropper
        // SCRIPT that references /dev/shm is still caught wherever it lives; the
        // memory-backed file itself is out of the content-scan surface today.
        assert!(is_excluded_scan_dir(Path::new("/dev/shm/payload")));
    }

    #[test]
    fn excludes_distro_owned_binary_trees() {
        // String rules on the OS's own binaries produce only false positives
        // (bash/fakeroot set LD_PRELOAD, the linker names ld-linux).
        for p in [
            "/usr/bin/bash",
            "/bin/ls",
            "/usr/sbin/init",
            "/usr/lib/x86_64-linux-gnu/ld-linux.so.2",
            "/usr/share/fish/vendor_functions.d/insmod.fish",
            "/lib64/libc.so.6",
        ] {
            assert!(is_excluded_scan_dir(Path::new(p)), "should exclude {p}");
        }
    }

    #[test]
    fn excludes_third_party_dependency_trees() {
        // Python venvs / editor extensions are vendored third-party code; the
        // package sensor covers supply-chain risk there, not the content scan.
        for p in [
            // venv / site-packages / dist-packages are pruned by dir NAME (the
            // walk stops when it reaches the dir, before any child file).
            "/home/u/proj/.venv",
            "/home/u/proj/venv",
            "/home/u/proj/x/lib/python3.12/site-packages",
            "/usr/lib/python3/dist-packages",
            // Editor-extension trees match anywhere in the path (SUBSTR).
            "/home/u/.vscode/extensions/ms-python.python-2026.4.0/x.py",
            "/home/u/.cursor/extensions/some.ext/index.js",
        ] {
            assert!(is_excluded_scan_dir(Path::new(p)), "should exclude {p}");
        }
        // A user's own .vscode/settings.json in a project is NOT an extension tree.
        assert!(!is_excluded_scan_dir(Path::new(
            "/home/u/proj/.vscode/settings.json"
        )));
    }

    #[test]
    fn excludes_pyinstaller_bundled_runtime() {
        // The `_internal` payload dir is pruned during the walk (its vendored .so
        // libraries are third-party, like node_modules), so its whole subtree is
        // skipped before any child file is visited.
        assert!(is_excluded_scan_dir(Path::new(
            "/opt/darkelf-shadow/_internal"
        )));
        // An ordinary app dir beside it stays in scope.
        assert!(!is_excluded_scan_dir(Path::new("/opt/darkelf-shadow/bin")));
    }

    #[test]
    fn excludes_generated_catalogues_and_logs() {
        for p in [
            "/var/lib/snapd/apparmor/profiles/snap.foo",
            "/var/lib/command-not-found/commands.db",
            "/var/cache/man/index.db",
            "/var/log/journal/abc/user.journal",
        ] {
            assert!(is_excluded_scan_dir(Path::new(p)), "should exclude {p}");
        }
    }

    #[test]
    fn never_scans_its_own_binary_by_name_anywhere() {
        // A dev build (running from target/) must still skip the installed copy.
        assert!(is_excluded_scan_dir(Path::new("/usr/local/bin/legion-web")));
        assert!(is_excluded_scan_dir(Path::new("/home/u/legion-cli")));
        assert!(is_excluded_scan_dir(Path::new(
            "/home/u/Downloads/Legion-v1.1.35-x86_64.AppImage"
        )));
        // A same-prefixed but different binary is not us.
        assert!(!is_excluded_scan_dir(Path::new(
            "/usr/local/bin/legionnaire"
        )));
    }

    #[test]
    fn system_roots_are_nonempty() {
        // Whatever the host, enumeration (or the fallback) yields at least one root.
        assert!(!system_scan_roots().is_empty());
    }
}
