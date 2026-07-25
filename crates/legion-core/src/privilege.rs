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
    /// **Refused**: the executable that would have been run as root is
    /// modifiable by a non-root user, so elevating it would hand root to
    /// whoever can write it.
    ///
    /// Distinct from [`Elevation::Skipped`] on purpose. Skipped means "we chose
    /// not to ask"; this means "asking would have been a vulnerability". The
    /// caller must surface it as an error, never continue quietly, and never
    /// prompt anyway.
    RefusedUntrustedExe(String),
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

/// Why an executable is not safe to run as root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedReason {
    /// The path could not be resolved (broken symlink, race, permissions).
    Unresolvable(String),
    /// The file or a parent directory is not owned by root.
    NotRootOwned { path: String, uid: u32 },
    /// The file or a parent directory is group- or world-writable.
    Writable { path: String, mode: u32 },
    /// The path lives somewhere a user controls by definition.
    UntrustedLocation { path: String, why: &'static str },
}

impl UntrustedReason {
    /// Operator-facing explanation, including what to do about it.
    pub fn message(&self) -> String {
        let detail = match self {
            UntrustedReason::Unresolvable(e) => {
                format!("the executable path could not be resolved ({e})")
            }
            UntrustedReason::NotRootOwned { path, uid } => {
                format!("{path} is owned by uid {uid}, not root")
            }
            UntrustedReason::Writable { path, mode } => {
                format!("{path} is writable by non-root users (mode {mode:04o})")
            }
            UntrustedReason::UntrustedLocation { path, why } => {
                format!("{path} is {why}")
            }
        };
        format!(
            "Refusing to run Legion as root from an untrusted path: {detail}.\n\
             \n\
             Anything able to write that file or its directory would be executed \
             as root at the next launch, and the administrator prompt would still \
             say \"Legion\". Install to a root-owned location first:\n\
             \n\
             \tsudo legion-web install\n\
             \n\
             then start Legion from there. Running unelevated is also fine — you \
             lose privileged telemetry (system event logs, the full process \
             table) and nothing else."
        )
    }
}

/// Locations whose contents are, by construction, under a user's control.
#[cfg(unix)]
fn untrusted_location(path: &std::path::Path) -> Option<&'static str> {
    let p = path.to_string_lossy();
    // An AppImage is extracted fresh on every launch into a user-writable
    // directory, so its contents can never be trusted for elevation no matter
    // what the file modes look like at the instant we check.
    for var in ["APPIMAGE", "APPDIR"] {
        if let Some(v) = std::env::var_os(var) {
            let v = v.to_string_lossy().to_string();
            if !v.is_empty() && (p.starts_with(&v) || p == v) {
                return Some(
                    "inside an AppImage mount or extraction root, which is re-created per launch",
                );
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy().to_string();
        if !home.is_empty() && home != "/" && p.starts_with(&home) {
            return Some("inside a user home directory");
        }
    }
    for prefix in ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"] {
        if p.starts_with(prefix) {
            return Some("in a world-writable temporary directory");
        }
    }
    None
}

/// Whether `exe` is safe to execute as root.
///
/// **The invariant: never elevate a binary a non-root user can modify.**
///
/// Legion self-elevates by handing `current_exe()` to pkexec. Run from an
/// AppImage, that is the runtime-extracted copy under `~/.cache`, in a
/// user-writable directory — so any code running as the user (a malicious
/// dependency, an editor extension, a browser exploit) can overwrite it and
/// wait to be handed root at the next launch. The polkit prompt does not help:
/// the user authorises "Legion" and something else runs.
///
/// Checking the file alone is not enough. A **user-writable parent directory**
/// permits `rename(2)` over a root-owned file, so every ancestor up to `/` is
/// checked as well.
#[cfg(unix)]
pub fn exe_trusted_for_root(exe: &std::path::Path) -> Result<(), UntrustedReason> {
    use std::os::unix::fs::MetadataExt;

    // Resolve symlinks first: a trusted-looking path may point somewhere else,
    // and the kernel executes the target, not the name.
    let real = exe
        .canonicalize()
        .map_err(|e| UntrustedReason::Unresolvable(format!("{}: {e}", exe.display())))?;

    if let Some(why) = untrusted_location(&real) {
        return Err(UntrustedReason::UntrustedLocation {
            path: real.display().to_string(),
            why,
        });
    }

    // The file, then every directory above it to the root.
    let mut cur: Option<&std::path::Path> = Some(real.as_path());
    while let Some(path) = cur {
        let md = std::fs::symlink_metadata(path)
            .map_err(|e| UntrustedReason::Unresolvable(format!("{}: {e}", path.display())))?;
        if md.uid() != 0 {
            return Err(UntrustedReason::NotRootOwned {
                path: path.display().to_string(),
                uid: md.uid(),
            });
        }
        let mode = md.mode() & 0o7777;
        // Group- or world-writable. A sticky world-writable directory (/tmp) is
        // still rejected: sticky stops deletion of others' files, not the
        // creation of new ones on a path we are about to execute.
        if mode & 0o022 != 0 {
            return Err(UntrustedReason::Writable {
                path: path.display().to_string(),
                mode,
            });
        }
        cur = path.parent();
    }
    Ok(())
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

    // Never elevate a binary a non-root user can modify. Checked here, before
    // any platform arm and before any prompt, so there is no path to pkexec
    // that skips it. Refusal is the default: we do not warn and continue, and
    // we do not prompt anyway.
    #[cfg(unix)]
    if let Err(reason) = exe_trusted_for_root(&exe) {
        return Elevation::RefusedUntrustedExe(reason.message());
    }

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
    // Same invariant as the startup path. This helper is normally the current
    // binary re-invoked with a privileged subcommand, so it inherits exactly the
    // same exposure and must not be exempt.
    #[cfg(unix)]
    if let Err(r) = exe_trusted_for_root(exe) {
        return ElevatedRun::Failed(r.message());
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

#[cfg(all(test, unix))]
mod exe_trust_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // These exercise the decision logic against real paths. Cases needing
    // root-owned files use /usr/bin, which is root:root 0755 on any sane host;
    // if that is not true the host is already compromised and the test is moot.

    #[test]
    fn a_root_owned_trusted_path_is_accepted() {
        // Criterion 2: a proper install must still elevate.
        for candidate in ["/usr/bin/env", "/bin/sh", "/usr/bin/true"] {
            let p = std::path::Path::new(candidate);
            if !p.exists() {
                continue;
            }
            assert!(
                exe_trusted_for_root(p).is_ok(),
                "{candidate} should be trusted: {:?}",
                exe_trusted_for_root(p)
            );
            return;
        }
        panic!("no root-owned system binary found to test against");
    }

    #[test]
    fn a_user_writable_file_is_rejected() {
        // Criterion 3, and the actual vulnerability: the AppImage's extracted
        // copy under ~/.cache is owned and writable by the user, and pkexec was
        // being handed exactly that.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("legion-web");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = exe_trusted_for_root(&exe).unwrap_err();
        // A tempdir lives under /tmp, so location or ownership both legitimately
        // reject it — what matters is that it is refused, with a reason.
        assert!(
            matches!(
                err,
                UntrustedReason::NotRootOwned { .. }
                    | UntrustedReason::Writable { .. }
                    | UntrustedReason::UntrustedLocation { .. }
            ),
            "{err:?}"
        );
        assert!(
            err.message().contains("legion-web install"),
            "must tell the operator how to fix it"
        );
    }

    #[test]
    fn a_root_owned_file_in_a_user_writable_directory_is_rejected() {
        // The subtle case, and the one this host actually exhibits:
        // /home/tim/.cache/legion is drwxrwxr-x tim:tim. Even a root-owned
        // binary inside it can be swapped via rename(2), so checking the file
        // alone would pass something that is trivially replaceable.
        //
        // Verified structurally: a path whose PARENT is writable must be
        // rejected even when the leaf itself looks fine.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("writable");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        let exe = sub.join("legion-web");
        std::fs::write(&exe, b"x").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            exe_trusted_for_root(&exe).is_err(),
            "a writable ancestor must reject the whole path"
        );
    }

    #[test]
    fn a_symlink_from_a_trusted_path_to_an_untrusted_target_is_rejected() {
        // The name is not what executes. A symlink sitting somewhere respectable
        // that points into a user-writable file must be judged by its target.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = dir.path().join("looks-legit");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = exe_trusted_for_root(&link).unwrap_err();
        // canonicalize() resolved to the target, so the reported path is the
        // target and not the innocuous-looking link name.
        let msg = err.message();
        assert!(
            !msg.contains("looks-legit"),
            "the symlink must be resolved before judging: {msg}"
        );
    }

    #[test]
    fn an_appimage_extraction_root_is_rejected_regardless_of_modes() {
        // Criterion 5's $APPIMAGE case. An AppImage is re-extracted on every
        // launch into a user-writable directory, so its contents can never be
        // trusted no matter how the modes look at the instant we check them.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("legion-web");
        std::fs::write(&exe, b"x").unwrap();

        let prev = std::env::var_os("APPIMAGE");
        std::env::set_var("APPIMAGE", dir.path());
        let err = exe_trusted_for_root(&exe).unwrap_err();
        match prev {
            Some(v) => std::env::set_var("APPIMAGE", v),
            None => std::env::remove_var("APPIMAGE"),
        }

        assert!(
            matches!(err, UntrustedReason::UntrustedLocation { .. }),
            "an $APPIMAGE path must be refused on location alone: {err:?}"
        );
        assert!(err.message().contains("AppImage"), "{}", err.message());
    }

    #[test]
    fn a_home_directory_path_is_rejected() {
        // The observed vulnerability lived at ~/.cache/legion/legion-web.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("legion-web");
        std::fs::write(&exe, b"x").unwrap();

        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", dir.path());
        let err = exe_trusted_for_root(&exe).unwrap_err();
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        assert!(
            matches!(err, UntrustedReason::UntrustedLocation { .. }),
            "{err:?}"
        );
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
