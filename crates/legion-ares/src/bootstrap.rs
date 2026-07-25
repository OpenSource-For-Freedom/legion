//! Ollama lifecycle helpers: locate the local Ollama binary, start its server
//! if it is installed but not running, and report what the operator must do
//! (install it) when it is missing entirely.
//!
//! Detection and process spawning are synchronous and dependency-free so this
//! module needs no async runtime. The online check + start orchestration lives
//! in the web layer (`legion-web`), which owns the Tokio runtime.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where to send operators who do not yet have Ollama installed.
pub const DOWNLOAD_URL: &str = "https://ollama.com/download";

/// Lifecycle state of the local Ollama server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OllamaState {
    /// Server is reachable and answering.
    Running,
    /// Server was not running; we launched it and it came online.
    Started,
    /// Binary is present but the server is not reachable (start failed or is
    /// still warming up). The operator can retry the start.
    Installed,
    /// No Ollama binary found anywhere we looked — the operator must install it.
    NotInstalled,
}

impl OllamaState {
    /// True when chat/hunt requests can be served right now.
    pub fn is_online(self) -> bool {
        matches!(self, OllamaState::Running | OllamaState::Started)
    }
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "ollama.exe"
    } else {
        "ollama"
    }
}

/// Known per-platform install locations, checked after `PATH`.
fn known_locations() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    {
        // Standard per-user installer writes here (no UAC required).
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            v.push(Path::new(&local).join(r"Programs\Ollama\ollama.exe"));
        }
        // Some setups write to USERPROFILE\AppData\Local when LOCALAPPDATA isn't set.
        if let Ok(up) = std::env::var("USERPROFILE") {
            v.push(Path::new(&up).join(r"AppData\Local\Programs\Ollama\ollama.exe"));
        }
        // System-wide installer.
        if let Ok(pf) = std::env::var("ProgramFiles") {
            v.push(Path::new(&pf).join(r"Ollama\ollama.exe"));
        }
        // winget package cache location (WinGet-installed).
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            v.push(
                Path::new(&local)
                    .join(r"Microsoft\WinGet\Packages\Ollama.Ollama_Microsoft.Winget.Source_8wekyb3d8bbwe\ollama.exe"),
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        v.push(PathBuf::from("/usr/local/bin/ollama"));
        v.push(PathBuf::from("/usr/bin/ollama"));
        v.push(PathBuf::from("/bin/ollama"));
        // Snap / Flatpak / manual install.
        if let Ok(home) = std::env::var("HOME") {
            v.push(Path::new(&home).join(".local/bin/ollama"));
        }
    }
    v
}

/// Silently install Ollama using the platform's package manager.
///
/// * Windows — uses `winget install --id Ollama.Ollama --silent`.  The
///   per-user installer requires no UAC prompt.
/// * Linux — uses the official one-liner (`curl … | sh`) only when
///   `curl` is available; refuses to pipe as root.
///
/// Returns `Ok(())` on a successful install, or an `Err` describing
/// why the install could not be attempted or failed.
// The body is split into mutually exclusive `#[cfg]` blocks, each ending the
// function for its platform, so the trailing `return` is unavoidable on whichever
// block is active. Allow the resulting lint rather than fight the cfg split.
#[allow(clippy::needless_return)]
pub fn auto_install() -> std::io::Result<()> {
    #[cfg(windows)]
    use std::process::Command;

    #[cfg(windows)]
    {
        use std::process::Stdio;
        let status = Command::new("winget")
            .args([
                "install",
                "--id",
                "Ollama.Ollama",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            // winget exit 0x8a150011 means "already installed" — treat as OK.
            let code = status.code().unwrap_or(-1);
            if code != -2_046_906_351i32 {
                return Err(std::io::Error::other(format!(
                    "winget install Ollama.Ollama exited with {code}"
                )));
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // Refuse to auto-install as root to avoid piping-as-root risks.
        if legion_core::is_elevated() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing auto-install as root; install Ollama manually",
            ));
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "auto-install not supported on this Linux variant; install from https://ollama.com/download",
        ));
    }
}

/// Locate the Ollama executable: first on `PATH`, then in known install dirs.
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
    known_locations().into_iter().find(|c| c.is_file())
}

/// Whether an Ollama binary is installed on this host.
pub fn is_installed() -> bool {
    find_binary().is_some()
}

/// Launch `ollama serve` as a detached background process. Returns the binary
/// that was started, or an error if no binary was found / spawn failed.
///
/// The child is fully detached (no inherited stdio, no console window on
/// Windows) so it outlives this process and never blocks the dashboard.
pub fn spawn_server() -> std::io::Result<PathBuf> {
    let bin = find_binary().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ollama binary not found on PATH or in known install locations",
        )
    })?;
    spawn_server_at(&bin)?;
    Ok(bin)
}

fn spawn_server_at(bin: &Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(bin);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // GPU memory optimizations so a more capable model (and longer context)
    // stays fully resident on a small GPU instead of spilling to CPU — the cause
    // of the minutes-slow replies. Flash attention plus q8_0 KV-cache
    // quantization roughly halve KV-cache memory with negligible quality loss
    // (q8_0 is the conservative cache type). Only applied when Legion starts
    // Ollama itself, and never overrides an explicit operator setting.
    if std::env::var_os("OLLAMA_FLASH_ATTENTION").is_none() {
        cmd.env("OLLAMA_FLASH_ATTENTION", "1");
    }
    if std::env::var_os("OLLAMA_KV_CACHE_TYPE").is_none() {
        cmd.env("OLLAMA_KV_CACHE_TYPE", "q8_0");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS — no console flash, survives us.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    // Same inherited-root problem as llama-server, and the same fix. Ollama is
    // a long-lived HTTP server with no authentication; it needs GPU access, not
    // uid 0. Legion self-elevates, so without this it would run as root purely
    // because of who its parent happened to be.
    #[cfg(unix)]
    if let Some(user) = crate::llama::drop_service_privileges(&mut cmd, bin, None) {
        tracing::info!("ollama: dropping server to unprivileged account '{user}'");
    }

    cmd.spawn().map(|_child| ())
}

/// Terminate the local Ollama server process. Uses the platform-native approach
/// so the child shuts down cleanly rather than being orphaned. Returns `Ok(())`
/// whether or not a process was found (idempotent).
pub fn stop_server() -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    {
        // taskkill /F /IM ollama.exe — kills every instance owned by any user
        // that this process has permission to terminate (loopback-only, so in
        // practice just the one we started).
        let status = Command::new("taskkill")
            .args(["/F", "/IM", "ollama.exe"])
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
        // Send SIGTERM; if the process is gone already, pkill exits 1 — ignore.
        let _ = Command::new("pkill")
            .args(["-x", "ollama"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(())
}
