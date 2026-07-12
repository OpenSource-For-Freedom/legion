//! Cross-platform installer, in Rust.
//!
//! Replaces the parallel shell installers (`scripts/install.ps1`,
//! `scripts/install.sh`, `restart.ps1`) with one implementation that runs
//! natively on Windows and Linux — no PowerShell/bash interpreter, no second
//! copy of the same logic to drift, and it reuses the workspace's own
//! `data_dir` / `harden_dir` code. Because this ships *inside* `legion-web`, the
//! binary self-installs (it copies the running executable into place) rather than
//! re-downloading itself, so there is no unverified `curl | sh`-to-root step.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Options for [`run`], mapped from the `install` subcommand flags.
pub struct InstallOptions {
    pub bin_dir: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub no_path: bool,
    pub no_desktop: bool,
}

/// Install the running `legion-web` binary into a bin dir + set up the data dir,
/// PATH, and a desktop/menu entry.
pub fn run(opts: InstallOptions) -> Result<()> {
    let exe = std::env::current_exe().context("cannot locate the running executable")?;
    let bin_dir = validate_install_dir(opts.bin_dir.unwrap_or_else(default_bin_dir))
        .context("invalid bin dir: must be an absolute path without parent traversal")?;
    let data_dir = opts.data_dir.unwrap_or_else(legion_core::data_dir);

    std::fs::create_dir_all(&bin_dir).with_context(|| format!("create bin dir {bin_dir:?}"))?;
    let dest = bin_dir.join(exe_name());
    if exe != dest {
        std::fs::copy(&exe, &dest).with_context(|| format!("copy binary to {dest:?}"))?;
    }
    make_executable(&dest)?;

    std::fs::create_dir_all(&data_dir).with_context(|| format!("create data dir {data_dir:?}"))?;
    legion_core::harden_dir(&data_dir);

    if !opts.no_path {
        if let Err(e) = add_to_path(&bin_dir) {
            eprintln!("note: could not update PATH automatically: {e}");
        }
    }
    if !opts.no_desktop {
        if let Err(e) = install_desktop_entry(&dest) {
            eprintln!("note: could not install desktop entry: {e}");
        }
    }

    println!("Legion installed:");
    println!("  app:      {}", dest.display());
    println!("  data dir: {}", data_dir.display());
    println!("  run:      {} (opens http://localhost:3000)", exe_name());
    Ok(())
}

/// Stop any running dashboard instance, then relaunch the installed binary.
/// Replaces `restart.ps1` (user-facing stop/relaunch; the dev rebuild-and-restart
/// stays a dev script).
pub fn restart() -> Result<()> {
    let stopped = stop_running_instances();
    println!("stopped {stopped} running legion-web process(es)");
    let dest = default_bin_dir().join(exe_name());
    let target = if dest.exists() {
        dest
    } else {
        std::env::current_exe()?
    };
    std::process::Command::new(&target)
        .spawn()
        .with_context(|| format!("relaunch {target:?}"))?;
    println!("relaunched {}", target.display());
    Ok(())
}

/// Kill every running `legion-web` process except this one. Uses `sysinfo` so the
/// same code works on Linux and Windows.
fn stop_running_instances() -> usize {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let me = std::process::id();
    let sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    let mut n = 0;
    for (pid, proc_) in sys.processes() {
        if pid.as_u32() == me {
            continue;
        }
        let name = proc_.name();
        if (name == exe_name() || name == "legion-web") && proc_.kill() {
            n += 1;
        }
    }
    n
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "legion-web.exe"
    } else {
        "legion-web"
    }
}

fn validate_install_dir(path: PathBuf) -> Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!("path must be absolute");
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        anyhow::bail!("path must not contain parent directory components");
    }
    Ok(path)
}

fn safe_absolute_base_from_os(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return None;
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return None;
    }
    Some(path)
}

fn default_bin_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // Per-user, no elevation required.
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("legion").join("bin");
        }
        PathBuf::from(r"C:\Program Files\Legion")
    }
    #[cfg(not(windows))]
    {
        // System-wide when root, else the user-local bin dir (no sudo needed).
        if is_root() {
            PathBuf::from("/usr/local/bin")
        } else if let Some(home) = std::env::var_os("HOME") {
            if let Some(home) = safe_absolute_base_from_os(home) {
                home.join(".local").join("bin")
            } else {
                PathBuf::from("/usr/local/bin")
            }
        } else {
            PathBuf::from("/usr/local/bin")
        }
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    // /proc/self is owned by the process UID; 0 == root. No libc needed.
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {path:?}"))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Persist the bin dir on the user's PATH.
#[cfg(unix)]
fn add_to_path(bin_dir: &Path) -> Result<()> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home else {
        anyhow::bail!("HOME not set");
    };
    let line = format!("export PATH=\"$PATH:{}\"\n", bin_dir.display());
    let marker = format!("$PATH:{}", bin_dir.display());
    for rc in [".profile", ".bashrc", ".zshrc"] {
        let path = home.join(rc);
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(&marker) {
            continue;
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(format!("\n# Added by `legion-web install`\n{line}").as_bytes());
        }
    }
    Ok(())
}

/// Persist the bin dir on the user's PATH via `setx` (a native Windows command,
/// not PowerShell). A `winreg`-based edit would avoid the 1024-char `setx`
/// limit; tracked as a follow-up.
#[cfg(windows)]
fn add_to_path(bin_dir: &Path) -> Result<()> {
    let cur = std::env::var("PATH").unwrap_or_default();
    let entry = bin_dir.display().to_string();
    if cur.split(';').any(|p| p == entry) {
        return Ok(());
    }
    let new = if cur.is_empty() {
        entry
    } else {
        format!("{cur};{entry}")
    };
    let status = std::process::Command::new("setx")
        .arg("PATH")
        .arg(new)
        .status()
        .context("run setx")?;
    if !status.success() {
        anyhow::bail!("setx exited with {status}");
    }
    Ok(())
}

/// Write a freedesktop `.desktop` launcher into the user's applications dir.
#[cfg(unix)]
fn install_desktop_entry(exe: &Path) -> Result<()> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home else {
        anyhow::bail!("HOME not set");
    };
    let apps = home.join(".local/share/applications");
    std::fs::create_dir_all(&apps)?;
    let desktop = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Legion\n\
         GenericName=Security Monitor\n\
         Comment=Local SIEM/SOAR security dashboard (http://localhost:3000)\n\
         Exec={}\n\
         Terminal=false\n\
         Categories=System;Security;Monitor;\n\
         Keywords=SIEM;security;CVE;threat;monitor;legion;ares;\n\
         StartupWMClass=legion-web\n",
        exe.display()
    );
    std::fs::write(apps.join("legion.desktop"), desktop)?;
    Ok(())
}

/// On Windows a Start-menu shortcut is a `.lnk`, which needs COM (`IShellLink`)
/// or the `winreg`/`mslnk` crate to create without PowerShell. Left as a
/// follow-up so the prototype stays dependency-free.
#[cfg(windows)]
fn install_desktop_entry(_exe: &Path) -> Result<()> {
    println!("note: Start-menu shortcut not yet created (tracked follow-up)");
    Ok(())
}
