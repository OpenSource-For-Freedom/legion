//! Cross-platform privilege detection and OS-native elevation.
//!
//! Legion relies on the operating system's own access-control model rather than
//! an in-app login: sensitive telemetry (the Windows Security event log, the
//! full process table, raw sockets) requires administrative rights, so on launch
//! the interactive front-ends ask the OS to elevate through its **native** prompt
//! — UAC on Windows, and a polkit/`pkexec` dialog or `sudo` on Linux.
//!
//! This module never elevates silently and never hangs a non-interactive
//! session: elevation is skipped when already privileged, when opted out
//! (`--no-elevate` / `LEGION_NO_ELEVATE`), in CI, or when no interactive prompt
//! channel is available.

use std::process::Command;

fn one_prompt_mode_enabled() -> bool {
    if std::env::var_os("LEGION_ONE_PROMPT_MODE").is_some() {
        return true;
    }

    let mut markers: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(unix)]
    {
        markers.push(std::path::PathBuf::from("/etc/legion/one_prompt_mode"));
        markers.push(std::path::PathBuf::from("/etc/legion/no_runtime_elevation"));
        if let Some(home) = std::env::var_os("HOME") {
            markers.push(std::path::PathBuf::from(home).join(".config/legion/one_prompt_mode"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            markers.push(std::path::PathBuf::from(pd).join("Legion/one_prompt_mode"));
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            markers.push(std::path::PathBuf::from(appdata).join("legion/one_prompt_mode"));
        }
    }

    markers.into_iter().any(|p| p.is_file())
}

/// Outcome of a one-shot elevated action launched via [`run_elevated_wait`].
#[derive(Debug, PartialEq, Eq)]
pub enum ElevatedRun {
    /// The elevated helper ran to completion and exited 0.
    Completed,
    /// The user declined the OS elevation prompt (UAC/polkit cancelled).
    Cancelled,
    /// The helper launched but exited non-zero, or elevation failed.
    Failed(String),
    /// No interactive elevation channel is available on this platform/session.
    Unsupported(String),
}

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

/// Whether elevation prompts are suppressed.
///
/// `flag` carries an explicit caller opt-out (the `--no-elevate` command-line
/// flag). It is checked first and on its own: previously only the environment
/// was consulted, so `--no-elevate` parsed fine and then did nothing, and every
/// caller of that flag — including `restart.ps1`, which passes it specifically
/// to avoid a second UAC prompt — got prompted anyway.
fn opted_out(flag: bool) -> Option<String> {
    if flag {
        return Some("--no-elevate passed".into());
    }
    if one_prompt_mode_enabled() {
        return Some("installer one-prompt mode enabled".into());
    }
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
///
/// Equivalent to [`ensure_elevated_unless`] with no explicit opt-out.
pub fn ensure_elevated(reason: &str) -> Elevation {
    ensure_elevated_unless(reason, false)
}

/// [`ensure_elevated`], but `skip` (from `--no-elevate`) suppresses the prompt
/// outright. Callers that expose the flag must use this: the environment-only
/// check cannot see a command-line flag.
pub fn ensure_elevated_unless(reason: &str, skip: bool) -> Elevation {
    if is_elevated() {
        return Elevation::AlreadyElevated;
    }
    if let Some(why) = opted_out(skip) {
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
    #[cfg(target_os = "linux")]
    {
        relaunch_linux(&exe, &args)
    }
    // Spelled out rather than `not(any(unix, windows))`: macOS is `unix` but not
    // `linux`, so that form leaves it with no matching arm at all.
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (&exe, &args);
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

#[cfg(target_os = "linux")]
fn relaunch_linux(exe: &std::path::Path, args: &[String]) -> Elevation {
    use std::io::IsTerminal;

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

#[cfg(target_os = "linux")]
fn run_and_supervise(tool: &str, exe: &std::path::Path, args: &[String]) -> Elevation {
    match Command::new(tool).arg(exe).args(args).status() {
        Ok(s) if s.success() => Elevation::Relaunched,
        Ok(s) => Elevation::Failed(format!("{tool} exited with {s}")),
        Err(e) => Elevation::Failed(format!("{tool} unavailable: {e}")),
    }
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// Run a privileged helper action through the OS-native elevation prompt and
/// **block until it finishes**, returning whether it completed, was cancelled,
/// or failed.
///
/// Unlike [`ensure_elevated`], this always shows a fresh prompt (UAC / polkit)
/// for the specific action — it is the per-action elevation path used
/// by, e.g., saving privileged configuration. `exe` is the helper executable
/// (typically the current binary re-invoked with a privileged subcommand) and
/// `args` are its arguments. `reason` explains the request to the user where the
/// platform supports a custom message.
pub fn run_elevated_wait(exe: &std::path::Path, args: &[String], reason: &str) -> ElevatedRun {
    // No flag here: this is the per-action path, and the web layer already gates
    // it on `--no-elevate` via its `elevate_writes` setting before calling.
    if let Some(why) = opted_out(false) {
        return ElevatedRun::Unsupported(why);
    }
    let _ = reason;
    #[cfg(target_os = "windows")]
    {
        run_elevated_windows(exe, args)
    }
    #[cfg(target_os = "linux")]
    {
        run_elevated_unix(exe, args)
    }
    // See `ensure_elevated_unless`: `not(any(unix, windows))` would leave macOS
    // with no arm at all.
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (exe, args);
        ElevatedRun::Unsupported("unsupported platform".into())
    }
}

#[cfg(target_os = "windows")]
fn run_elevated_windows(exe: &std::path::Path, args: &[String]) -> ElevatedRun {
    // Start-Process -Verb RunAs shows the UAC consent prompt. -Wait -PassThru
    // lets us recover the child's exit code; a declined prompt makes Start-Process
    // throw, which we map to ERROR_CANCELLED (1223).
    let exe_str = exe.to_string_lossy().replace('\'', "''");
    let mut start = format!("Start-Process -FilePath '{exe_str}'");
    if !args.is_empty() {
        let quoted: Vec<String> = args
            .iter()
            .map(|a| format!("'{}'", a.replace('\'', "''")))
            .collect();
        start.push_str(&format!(" -ArgumentList {}", quoted.join(",")));
    }
    start.push_str(" -Verb RunAs -Wait -PassThru");
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ $p = {start}; exit $p.ExitCode }} catch {{ exit 1223 }}"
    );

    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
    {
        Ok(s) if s.success() => ElevatedRun::Completed,
        Ok(s) if s.code() == Some(1223) => ElevatedRun::Cancelled,
        Ok(s) => ElevatedRun::Failed(format!("elevated helper exited with {s}")),
        Err(e) => ElevatedRun::Failed(format!("powershell unavailable: {e}")),
    }
}

#[cfg(target_os = "linux")]
fn run_elevated_unix(exe: &std::path::Path, args: &[String]) -> ElevatedRun {
    use std::io::IsTerminal;
    let has_display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    let tool = if has_display && which("pkexec") {
        "pkexec"
    } else if std::io::stdin().is_terminal() && which("sudo") {
        "sudo"
    } else {
        return ElevatedRun::Unsupported(
            "no interactive elevation channel (no DISPLAY for pkexec, no TTY for sudo)".into(),
        );
    };
    match Command::new(tool).arg(exe).args(args).status() {
        Ok(s) if s.success() => ElevatedRun::Completed,
        // pkexec uses 126 (dismissed) / 127 (auth failed); sudo uses 1.
        Ok(s) if matches!(s.code(), Some(126) | Some(127) | Some(1)) => ElevatedRun::Cancelled,
        Ok(s) => ElevatedRun::Failed(format!("{tool} exited with {s}")),
        Err(e) => ElevatedRun::Failed(format!("{tool} unavailable: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flag_opts_out_on_its_own() {
        // The regression this guards: `--no-elevate` was parsed but never
        // reached this decision, so the flag was inert and the app self-elevated
        // anyway. The flag must suppress elevation by itself, without depending
        // on any environment variable being set.
        let why = opted_out(true).expect("--no-elevate must suppress elevation");
        assert!(why.contains("--no-elevate"), "reason was {why:?}");
    }

    #[test]
    fn ensure_elevated_unless_reports_skipped_for_the_flag() {
        // On an already-elevated host (CI often runs as root) AlreadyElevated
        // legitimately short-circuits first, so the flag path is unobservable.
        if is_elevated() {
            return;
        }
        match ensure_elevated_unless("test", true) {
            Elevation::Skipped(why) => assert!(why.contains("--no-elevate"), "reason was {why:?}"),
            other => panic!("expected Skipped for --no-elevate, got {other:?}"),
        }
    }

    #[test]
    fn plain_ensure_elevated_does_not_opt_out_by_itself() {
        // `ensure_elevated` must keep its old behaviour: no implicit opt-out.
        // (Environment-based opt-outs are still honoured; this only asserts the
        // flag defaults to false rather than silently suppressing prompts.)
        assert!(opted_out(false).is_none() || std::env::var_os("CI").is_some());
    }
}
