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
    let bin_dir_real = std::fs::canonicalize(&bin_dir)
        .with_context(|| format!("canonicalize bin dir {bin_dir:?}"))?;
    let dest = bin_dir_real.join(exe_name());
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
    // Create the unprivileged account the model server drops to. Done here, in
    // an explicit operator-run install step, rather than silently at runtime:
    // adding a system account is a real change to the machine and should not be
    // a side effect of launching a dashboard.
    #[cfg(unix)]
    if let Err(e) = ensure_model_user() {
        eprintln!("note: could not create the model service account: {e}");
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
    // Route the (env-derived) default bin dir through the same validator as
    // `run` before we exec the installed binary, so the path is guarded.
    let installed = validate_install_dir(default_bin_dir())
        .map(|d| d.join(exe_name()))
        .ok()
        .filter(|d| d.exists());
    let target = match installed {
        Some(d) => d,
        None => std::env::current_exe()?,
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
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        anyhow::bail!("path must not contain parent directory components");
    }
    Ok(path)
}

fn safe_absolute_base_from_os(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return None;
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    Some(path)
}

fn default_bin_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // Per-user, no elevation required. Route the env-derived base through the
        // same absolute/no-`..` sanitizer as the Unix HOME path.
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            if let Some(local) = safe_absolute_base_from_os(local) {
                return local.join("legion").join("bin");
            }
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

/// Create a per-user Start-Menu shortcut (`.lnk`) via PowerShell's WScript.Shell
/// (no COM/FFI dependency, matching how the rest of the Windows code shells out).
/// Best-effort; a failure is surfaced but the caller treats install as advisory.
#[cfg(windows)]
fn install_desktop_entry(exe: &Path) -> Result<()> {
    let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) else {
        anyhow::bail!("APPDATA not set");
    };
    let programs = appdata.join(r"Microsoft\Windows\Start Menu\Programs");
    std::fs::create_dir_all(&programs)?;
    let lnk = programs.join("Legion.lnk");
    let target = exe.display().to_string();
    let workdir = exe
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    // Single-quoted PS strings take backslashes literally; escape any embedded
    // single quote by doubling it so odd install paths can't break the script.
    let q = |s: &str| s.replace('\'', "''");
    let ps = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');\
         $s.TargetPath='{target}';\
         $s.WorkingDirectory='{workdir}';\
         $s.Description='Local SIEM/SOAR security dashboard (http://localhost:3000)';\
         $s.IconLocation='{target},0';$s.Save()",
        lnk = q(&lnk.display().to_string()),
        target = q(&target),
        workdir = q(&workdir),
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .context("run powershell to create Start-Menu shortcut")?;
    if !status.success() {
        anyhow::bail!("powershell shortcut creation exited with {status}");
    }
    println!("Start-Menu shortcut created: {}", lnk.display());
    Ok(())
}

/// Create the unprivileged system account the model server runs as.
///
/// Legion self-elevates to read privileged telemetry, and every child it spawns
/// inherits root — including `llama-server`, which needs none of it: it reads
/// two files and binds a loopback port. Running an inference server that parses
/// gigabytes of third-party weights with full system authority is a poor trade.
///
/// No home directory and no login shell: this account exists to own a process,
/// not to be used.
#[cfg(unix)]
fn ensure_model_user() -> Result<()> {
    let user = legion_ares::llama::MODEL_SERVER_USER;
    if legion_ares::llama::resolve_user(user).is_some() {
        println!("  model service account '{user}' already exists");
        return Ok(());
    }
    if !legion_core::is_elevated() {
        anyhow::bail!(
            "not running as root; create it manually with: \
             sudo useradd --system --no-create-home --shell /usr/sbin/nologin {user}"
        );
    }
    let status = std::process::Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "Legion model server",
            user,
        ])
        .status()
        .context("run useradd")?;
    // Exit 9 is "user already exists", which is success for our purposes.
    if !status.success() && status.code() != Some(9) {
        anyhow::bail!("useradd exited with {status}");
    }
    println!("  created model service account '{user}' (no home, no shell)");

    // GPU device nodes belong to render/video. Without membership the dropped
    // server loses Vulkan and silently falls back to CPU, which reads as "the
    // model got slow" rather than "the privilege drop cost you the GPU".
    for group in ["render", "video"] {
        if legion_ares::llama::resolve_group(group).is_none() {
            continue; // group does not exist on this distro
        }
        let st = std::process::Command::new("usermod")
            .args(["-aG", group, user])
            .status();
        match st {
            Ok(s) if s.success() => {
                println!("  added '{user}' to the '{group}' group (GPU access)")
            }
            _ => eprintln!(
                "note: could not add '{user}' to '{group}'; GPU offload may fall back to CPU"
            ),
        }
    }
    Ok(())
}
