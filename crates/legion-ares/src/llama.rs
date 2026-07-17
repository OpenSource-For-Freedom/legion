//! llama.cpp server lifecycle: the runtime that actually serves the staged
//! Hugging Face GGUF.
//!
//! Legion stages a SHA-256-pinned GGUF from Hugging Face, but until this module
//! existed nothing ever loaded it — the weights were a write-only artifact and
//! every hunt silently fell back to `engine-only`. This module closes that gap
//! by managing a pinned `llama-server` build the same way the model itself is
//! managed: pinned release, SHA-256 verified, staged under the Legion data dir.
//!
//! Design notes:
//! * An operator-supplied `llama-server` on `PATH` always wins, so anyone who
//!   wants a CUDA/Vulkan/ROCm build just installs one and Legion uses it. The
//!   managed build is the portable CPU fallback so the product works out of the
//!   box on a stock machine.
//! * Extraction shells out to the system `tar`, matching how the rest of the
//!   workspace shells out (`icacls`, `netstat`, `tasklist`, `setx`). This is safe
//!   because the archive's SHA-256 is verified *before* extraction, so the bytes
//!   are already authenticated. Windows 10+ bundles bsdtar, which reads zip; the
//!   PowerShell `Expand-Archive` fallback covers older hosts.
//! * Detection and process spawning are synchronous and dependency-free, so this
//!   module needs no async runtime — the download lives in the web layer, which
//!   owns the Tokio runtime. This mirrors `bootstrap.rs`.

use std::path::{Path, PathBuf};

/// Pinned llama.cpp release. Bump together with the SHA-256s in [`asset_for_host`].
pub const LLAMA_BUILD: &str = "b10054";

const RELEASE_BASE: &str = "https://github.com/ggml-org/llama.cpp/releases/download";

/// A pinned, per-platform `llama-server` release archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerAsset {
    /// Release asset filename.
    pub archive: &'static str,
    /// SHA-256 of the archive, enforced before extraction.
    pub sha256: &'static str,
    /// Exact published size, used as the download cap.
    pub size_bytes: u64,
    /// True when the archive nests everything under a single top-level dir and
    /// therefore needs `--strip-components=1` (the Linux tarballs do; the
    /// Windows zips are flat).
    pub strip_top_level: bool,
}

impl ServerAsset {
    /// Full download URL for this asset.
    pub fn url(&self) -> String {
        format!("{RELEASE_BASE}/{LLAMA_BUILD}/{}", self.archive)
    }
}

/// The pinned archive for the current platform, or `None` where we ship no
/// managed build (the operator must supply `llama-server` on `PATH`).
///
/// Every arm is spelled out so an unsupported target returns `None` rather than
/// failing to compile.
pub fn asset_for_host() -> Option<ServerAsset> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(ServerAsset {
            archive: "llama-b10054-bin-ubuntu-x64.tar.gz",
            sha256: "dbfcbd71bafb5ff6ab57ed9a9f62c2a7522401986edf7f44b30a366ebcf86c71",
            size_bytes: 16_060_201,
            strip_top_level: true,
        })
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some(ServerAsset {
            archive: "llama-b10054-bin-win-cpu-x64.zip",
            sha256: "5801980ae267310e2f2cb4bd4d1795718ee7b600a2a17d0a9320a601c8979bde",
            size_bytes: 18_004_849,
            strip_top_level: false,
        })
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    {
        None
    }
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    }
}

/// Root of the managed runtime store: `<data_dir>/runtime`.
pub fn managed_root() -> PathBuf {
    legion_core::data_dir().join("runtime")
}

/// Directory holding the pinned build's binary and its shared libraries. The
/// whole directory must stay together: `llama-server` links against sibling
/// `libllama`/`libggml` objects and will not start without them.
pub fn managed_dir() -> PathBuf {
    managed_root().join(format!("llama-{LLAMA_BUILD}"))
}

/// Path the managed `llama-server` binary is staged to.
pub fn managed_binary() -> PathBuf {
    managed_dir().join(binary_name())
}

/// Locate a usable `llama-server`: an operator-supplied one on `PATH` first,
/// then the managed pinned build.
pub fn find_binary() -> Option<PathBuf> {
    let name = binary_name();
    if let Ok(path) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path.split(sep).filter(|d| !d.is_empty()) {
            let cand = Path::new(dir).join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    let managed = managed_binary();
    managed.is_file().then_some(managed)
}

/// Whether any `llama-server` is available to run right now.
pub fn is_installed() -> bool {
    find_binary().is_some()
}

/// Extract a verified archive into `dest`.
///
/// The caller MUST have verified the archive's SHA-256 first: extraction trusts
/// the bytes.
pub fn extract_archive(archive: &Path, dest: &Path, strip_top_level: bool) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    std::fs::create_dir_all(dest)?;

    let mut cmd = Command::new("tar");
    cmd.arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if strip_top_level {
        cmd.arg("--strip-components=1");
    }
    match cmd.status() {
        Ok(s) if s.success() => return Ok(()),
        // Fall through to the Windows-native path below; on Unix a tar failure
        // is terminal since there is no second extractor to try.
        Ok(s) => {
            #[cfg(not(windows))]
            return Err(std::io::Error::other(format!("tar exited with {s}")));
            #[cfg(windows)]
            tracing::warn!("tar exited with {s}; falling back to Expand-Archive");
        }
        Err(e) => {
            #[cfg(not(windows))]
            return Err(e);
            #[cfg(windows)]
            tracing::warn!("tar unavailable ({e}); falling back to Expand-Archive");
        }
    }

    #[cfg(windows)]
    {
        // Older Windows without bundled bsdtar. Expand-Archive handles zip only,
        // which is exactly what we ship on this platform.
        let q = |s: &str| s.replace('\'', "''");
        let ps = format!(
            "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
            q(&archive.display().to_string()),
            q(&dest.display().to_string()),
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "Expand-Archive exited with {status}"
            )));
        }
        Ok(())
    }
}

/// Make the staged binary and its helper objects executable. No-op on Windows,
/// where executability is not a file mode.
pub fn make_executable(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if path.is_file() {
                let mut perms = std::fs::metadata(&path)?.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Launch `llama-server` against a staged GGUF as a detached background process.
///
/// `alias` is reported verbatim by the server at `/v1/models`, which is what
/// lets Legion's exact-name status check match the tier it staged.
///
/// The server is bound to loopback and its bundled web UI is disabled: this
/// process exists to answer Legion's own API calls, nothing else.
pub fn spawn_server(
    model: &Path,
    host: &str,
    port: u16,
    ctx: u32,
    gpu_layers: u32,
    alias: &str,
) -> std::io::Result<PathBuf> {
    let bin = find_binary().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "llama-server not found on PATH or in the managed runtime dir",
        )
    })?;
    if !model.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("staged model not found at {}", model.display()),
        ));
    }
    spawn_server_at(&bin, model, host, port, ctx, gpu_layers, alias)?;
    Ok(bin)
}

#[allow(clippy::too_many_arguments)]
fn spawn_server_at(
    bin: &Path,
    model: &Path,
    host: &str,
    port: u16,
    ctx: u32,
    gpu_layers: u32,
    alias: &str,
) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(bin);
    cmd.arg("--model")
        .arg(model)
        .arg("--host")
        .arg(host)
        .arg("--port")
        .arg(port.to_string())
        .arg("--ctx-size")
        .arg(ctx.to_string())
        .arg("--n-gpu-layers")
        .arg(gpu_layers.to_string())
        .arg("--alias")
        .arg(alias)
        // Legion is the only client; do not serve llama.cpp's own web UI.
        .arg("--no-webui")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS — no console flash, survives us.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    let child = cmd.spawn()?;
    // Reap the child when it exits. Dropping the handle does not wait() on
    // Unix, so a stopped server would sit as a <defunct> zombie for as long as
    // Legion runs — and restarting the runtime would stack up more.
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Ok(())
}

/// Terminate any local `llama-server`. Idempotent: returns `Ok(())` whether or
/// not a process was found.
pub fn stop_server() -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/F", "/IM", "llama-server.exe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        // Exit code 128 means "no matching process" — that's fine.
        if !status.success() && status.code() != Some(128) {
            return Err(std::io::Error::other(format!(
                "taskkill exited with {:?}",
                status.code()
            )));
        }
    }

    #[cfg(unix)]
    {
        // -x so we match the exact process name and never our own command line.
        let _ = Command::new("pkill")
            .args(["-x", "llama-server"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_layout_is_build_pinned() {
        let dir = managed_dir();
        assert!(dir.ends_with(format!("llama-{LLAMA_BUILD}")));
        assert!(managed_binary().starts_with(&dir));
        assert!(managed_dir().starts_with(managed_root()));
    }

    #[test]
    fn binary_name_matches_platform() {
        if cfg!(windows) {
            assert_eq!(binary_name(), "llama-server.exe");
        } else {
            assert_eq!(binary_name(), "llama-server");
        }
    }

    #[test]
    fn host_asset_is_pinned_and_well_formed() {
        // Every platform we ship a managed build for must carry a real pin: a
        // 64-hex SHA-256 and a non-zero cap. An empty sha would silently
        // downgrade the download to trust-the-transport.
        if let Some(asset) = asset_for_host() {
            assert_eq!(asset.sha256.len(), 64, "sha256 must be 64 hex chars");
            assert!(
                asset.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "sha256 must be hex"
            );
            assert!(asset.size_bytes > 0, "size cap must be set");
            assert!(asset.url().starts_with("https://"), "download must be TLS");
            assert!(asset.url().contains(LLAMA_BUILD), "url must match the pin");
        }
    }

    #[test]
    fn linux_archive_strips_its_top_level_dir() {
        // The Linux tarball nests under llama-<build>/ and the Windows zip is
        // flat. Getting this backwards silently produces a binary one level too
        // deep, which find_binary would then miss.
        if let Some(asset) = asset_for_host() {
            if asset.archive.ends_with(".tar.gz") {
                assert!(asset.strip_top_level);
            }
            if asset.archive.ends_with(".zip") {
                assert!(!asset.strip_top_level);
            }
        }
    }
}
