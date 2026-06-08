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
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            v.push(Path::new(&local).join(r"Programs\Ollama\ollama.exe"));
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            v.push(Path::new(&pf).join(r"Ollama\ollama.exe"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        v.push(PathBuf::from("/usr/local/bin/ollama"));
        v.push(PathBuf::from("/opt/homebrew/bin/ollama"));
        v.push(PathBuf::from(
            "/Applications/Ollama.app/Contents/Resources/ollama",
        ));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        v.push(PathBuf::from("/usr/local/bin/ollama"));
        v.push(PathBuf::from("/usr/bin/ollama"));
        v.push(PathBuf::from("/bin/ollama"));
    }
    v
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
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS — no console flash, survives us.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    cmd.spawn().map(|_child| ())
}
