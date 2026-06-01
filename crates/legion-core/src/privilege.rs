//! Cross-platform privilege detection and OS-native elevation.
//!
//! Legion relies on the operating system's own access-control model rather than
//! an in-app login: sensitive telemetry (the Windows Security event log, the
//! full process table, raw sockets) requires administrative rights, so on launch
//! the interactive front-ends ask the OS to elevate through its **native** prompt
//! — UAC on Windows, a polkit/`pkexec` dialog or `sudo` on Linux, and an
//! `osascript` "administrator privileges" dialog on macOS.
//!
//! This module never elevates silently and never hangs a non-interactive
//! session: elevation is skipped when already privileged, when opted out
//! (`--no-elevate` / `LEGION_NO_ELEVATE`), in CI, or when no interactive prompt
//! channel is available.

use std::io::IsTerminal;
use std::process::Command;

/// Result of an [`ensure_elevated`] attempt.
#[derive(Debug)]
pub enum Elevation {
    /// The process is already running with administrative rights.
    AlreadyElevated,
    /// A privileged relaunch was started; the caller should exit this process.
    Relaunched,
    /// Elevation was intentionally not attempted (with a human-readable reason).
    Skipped(String),
    /// Elevation was attempted but failed/declined (with a reason).
    Failed(String),
}

/// True when the current process holds administrative privileges
/// (root on Unix, an elevated/Administrator token on Windows).
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // Avoid a libc dependency: `id -u` reports the effective uid.
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        // `net session` enumerates sessions and only succeeds for admins.
        Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Whether elevation prompts are suppressed by environment.
fn opted_out() -> Option<String> {
    if std::env::var_os("LEGION_NO_ELEVATE").is_some() {
        return Some("LEGION_NO_ELEVATE set".into());
    }
    if std::env::var_os("CI").is_some() {
        return Some("CI environment".into());
    }
    None
}

/// If the process is not already elevated, relaunch it through the OS-native
/// elevation prompt and (for prompts that run the child to completion) wait on
/// it. Returns [`Elevation`] describing what happened; on [`Elevation::Relaunched`]
/// the caller should exit promptly.
///
/// `reason` is shown to the user to explain why elevation is requested.
pub fn ensure_elevated(reason: &str) -> Elevation {
    if is_elevated() {
        return Elevation::AlreadyElevated;
    }
    if let Some(why) = opted_out() {
        return Elevation::Skipped(why);
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return Elevation::Failed(format!("cannot locate executable: {e}")),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    eprintln!("legion: requesting administrator privileges — {reason}");

    #[cfg(target_os = "windows")]
    {
        relaunch_windows(&exe, &args)
    }
    #[cfg(target_os = "macos")]
    {
        relaunch_macos(&exe, &args)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        relaunch_linux(&exe, &args)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Elevation::Skipped("unsupported platform".into())
    }
}

#[cfg(target_os = "windows")]
fn relaunch_windows(exe: &std::path::Path, args: &[String]) -> Elevation {
    // PowerShell Start-Process -Verb RunAs triggers the UAC prompt. It returns
    // immediately; the elevated process runs independently, so the caller exits.
    let exe_str = exe.to_string_lossy().replace('\'', "''");
    let mut cmd = format!("Start-Process -FilePath '{exe_str}'");
    if !args.is_empty() {
        let quoted: Vec<String> = args
            .iter()
            .map(|a| format!("'{}'", a.replace('\'', "''")))
            .collect();
        cmd.push_str(&format!(" -ArgumentList {}", quoted.join(",")));
    }
    cmd.push_str(" -Verb RunAs");

    match Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .status()
    {
        Ok(s) if s.success() => Elevation::Relaunched,
        Ok(s) => Elevation::Failed(format!("UAC relaunch exited with {s}")),
        Err(e) => Elevation::Failed(format!("powershell unavailable: {e}")),
    }
}

#[cfg(target_os = "macos")]
fn relaunch_macos(exe: &std::path::Path, args: &[String]) -> Elevation {
    // osascript shows the native administrator dialog and runs the command to
    // completion, so we supervise the elevated child for the process lifetime.
    let mut shell = shell_quote(&exe.to_string_lossy());
    for a in args {
        shell.push(' ');
        shell.push_str(&shell_quote(a));
    }
    let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    match Command::new("osascript").args(["-e", &script]).status() {
        Ok(s) if s.success() => Elevation::Relaunched,
        Ok(_) => Elevation::Failed("administrator prompt cancelled".into()),
        Err(e) => Elevation::Failed(format!("osascript unavailable: {e}")),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn relaunch_linux(exe: &std::path::Path, args: &[String]) -> Elevation {
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();

    // Prefer a graphical polkit prompt; fall back to sudo on a terminal.
    if has_display && which("pkexec") {
        return run_and_supervise("pkexec", exe, args);
    }
    if std::io::stdin().is_terminal() && which("sudo") {
        return run_and_supervise("sudo", exe, args);
    }
    Elevation::Skipped(
        "no interactive elevation channel (no DISPLAY for pkexec, no TTY for sudo)".into(),
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_and_supervise(tool: &str, exe: &std::path::Path, args: &[String]) -> Elevation {
    match Command::new(tool).arg(exe).args(args).status() {
        Ok(s) if s.success() => Elevation::Relaunched,
        Ok(s) => Elevation::Failed(format!("{tool} exited with {s}")),
        Err(e) => Elevation::Failed(format!("{tool} unavailable: {e}")),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn shell_quote(s: &str) -> String {
    // POSIX single-quote escaping for the inner shell command.
    format!("'{}'", s.replace('\'', "'\\''"))
}
