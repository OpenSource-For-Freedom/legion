//! Legion Runner integration helpers.
//!
//! Legion Runner is Linux-only. On Windows, Legion can manage it through WSL
//! when a Linux distribution with systemd is available. This module keeps token
//! handling out of the web UI: provisioning still happens in a shell where the
//! operator exports `LEGIONR_TOKEN`.

use serde::{Deserialize, Serialize};
use std::process::Command;

pub const LEGION_RUNNER_REPO: &str = "https://github.com/OpenSource-For-Freedom/Legion_runner";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerHost {
    Linux,
    WindowsWsl,
    WindowsNoWsl,
    Unsupported,
}

impl RunnerHost {
    pub fn supported(&self) -> bool {
        matches!(self, RunnerHost::Linux | RunnerHost::WindowsWsl)
    }

    pub fn label(&self) -> &'static str {
        match self {
            RunnerHost::Linux => "linux",
            RunnerHost::WindowsWsl => "windows_wsl",
            RunnerHost::WindowsNoWsl => "windows_no_wsl",
            RunnerHost::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerStatus {
    pub host: RunnerHost,
    pub supported: bool,
    pub linux_only: bool,
    pub wsl_available: bool,
    pub systemd_available: bool,
    pub legionr_available: bool,
    pub service_active: bool,
    pub repo_url: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerCommandPlan {
    pub install: Vec<String>,
    pub provision: Vec<String>,
    pub harden: Vec<String>,
    pub launch: Vec<String>,
    pub doctor: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct RunnerManager;

impl RunnerManager {
    pub fn status() -> RunnerStatus {
        status_for_host(detect_host())
    }

    pub fn command_plan(host: &RunnerHost) -> RunnerCommandPlan {
        command_plan_for_host(host)
    }

    pub fn doctor() -> std::io::Result<String> {
        // F2 (QA 2026-07): don't exec `legionr` when it isn't installed — that
        // surfaced as a generic 500. Report status cleanly instead, mirroring
        // what `status()` already detects.
        let st = Self::status();
        if !st.legionr_available {
            return Ok(format!(
                "Legion Runner is not installed.\n\
                 host: {} | systemd: {} | service active: {}\n\
                 Install it from {} (see the Runner tab for the exact commands).",
                if st.linux_only { "linux" } else { "other" },
                st.systemd_available,
                st.service_active,
                st.repo_url,
            ));
        }
        run_runner_command(&["legionr", "doctor"])
    }

    pub fn launch_service() -> std::io::Result<String> {
        run_runner_command(&["systemctl", "start", "legionr@default"])
    }

    pub fn stop_service() -> std::io::Result<String> {
        run_runner_command(&["systemctl", "stop", "legionr@default"])
    }
}

pub fn detect_host() -> RunnerHost {
    if cfg!(target_os = "linux") {
        return RunnerHost::Linux;
    }
    if cfg!(target_os = "windows") {
        if command_success("wsl", &["-e", "sh", "-lc", "test -r /proc/version"]) {
            return RunnerHost::WindowsWsl;
        }
        return RunnerHost::WindowsNoWsl;
    }
    RunnerHost::Unsupported
}

pub fn status_for_host(host: RunnerHost) -> RunnerStatus {
    let wsl_available = matches!(host, RunnerHost::WindowsWsl);
    let (systemd_available, legionr_available, service_active) = match host {
        RunnerHost::Linux => (
            command_success("systemctl", &["--version"]),
            command_success("legionr", &["--version"]),
            command_success("systemctl", &["is-active", "--quiet", "legionr@default"]),
        ),
        RunnerHost::WindowsWsl => (
            command_success(
                "wsl",
                &["-e", "sh", "-lc", "command -v systemctl >/dev/null 2>&1"],
            ),
            command_success(
                "wsl",
                &["-e", "sh", "-lc", "command -v legionr >/dev/null 2>&1"],
            ),
            command_success(
                "wsl",
                &[
                    "-e",
                    "sh",
                    "-lc",
                    "systemctl is-active --quiet legionr@default",
                ],
            ),
        ),
        _ => (false, false, false),
    };
    let supported = host.supported();
    let message = match host {
        RunnerHost::Linux if service_active => "Legion Runner service is active".to_string(),
        RunnerHost::Linux if legionr_available => {
            "Legion Runner CLI is installed; service is not active".to_string()
        }
        RunnerHost::Linux => {
            "Linux host detected; install and provision Legion Runner before launch".to_string()
        }
        RunnerHost::WindowsWsl if service_active => {
            "Legion Runner is active inside WSL".to_string()
        }
        RunnerHost::WindowsWsl => {
            "WSL is available; install and launch Legion Runner inside WSL".to_string()
        }
        RunnerHost::WindowsNoWsl => {
            "Legion Runner is Linux-only; install WSL with systemd to manage it from Windows"
                .to_string()
        }
        RunnerHost::Unsupported => "Legion Runner requires Linux or Windows with WSL".to_string(),
    };

    RunnerStatus {
        host,
        supported,
        linux_only: true,
        wsl_available,
        systemd_available,
        legionr_available,
        service_active,
        repo_url: LEGION_RUNNER_REPO.to_string(),
        message,
    }
}

pub fn command_plan_for_host(host: &RunnerHost) -> RunnerCommandPlan {
    if matches!(host, RunnerHost::WindowsNoWsl) {
        return RunnerCommandPlan {
            install: vec![
                "wsl --install".to_string(),
                "wsl --set-default-version 2".to_string(),
                "wsl -e bash -lc \"git clone https://github.com/OpenSource-For-Freedom/Legion_runner.git\"".to_string(),
                "wsl -e bash -lc \"cd Legion_runner && sudo ./scripts/install.sh\"".to_string(),
            ],
            provision: vec![
                "wsl -e bash -lc \"export LEGIONR_TOKEN=<github_pat_with_runner_admin>\"".to_string(),
                "wsl -e bash -lc \"sudo -u legionr -E legionr provision <owner/repo-or-org> --config /etc/legion-runner/default.json --container podman --link http://127.0.0.1:3000\"".to_string(),
            ],
            harden: vec!["wsl -e bash -lc \"cd Legion_runner && sudo ./scripts/harden.sh\"".to_string()],
            launch: vec![
                "wsl -e bash -lc \"sudo systemctl enable --now legionr@default\"".to_string(),
                "wsl -e bash -lc \"journalctl -u legionr@default -f\"".to_string(),
            ],
            doctor: vec![
                "wsl -e bash -lc \"legionr doctor\"".to_string(),
                "wsl -e bash -lc \"legionr status\"".to_string(),
            ],
        };
    }

    let prefix = match host {
        RunnerHost::WindowsWsl => "wsl -e bash -lc \"",
        _ => "",
    };
    let suffix = if prefix.is_empty() { "" } else { "\"" };
    let wrap = |cmd: &str| format!("{prefix}{cmd}{suffix}");

    RunnerCommandPlan {
        install: vec![
            wrap("git clone https://github.com/OpenSource-For-Freedom/Legion_runner.git"),
            wrap("cd Legion_runner && sudo ./scripts/install.sh"),
        ],
        provision: vec![
            wrap("export LEGIONR_TOKEN=<github_pat_with_runner_admin>"),
            wrap("sudo -u legionr -E legionr provision <owner/repo-or-org> --config /etc/legion-runner/default.json --container podman --link http://127.0.0.1:3000"),
        ],
        harden: vec![wrap("cd Legion_runner && sudo ./scripts/harden.sh")],
        launch: vec![
            wrap("sudo systemctl enable --now legionr@default"),
            wrap("journalctl -u legionr@default -f"),
        ],
        doctor: vec![wrap("legionr doctor"), wrap("legionr status")],
    }
}

fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_runner_command(args: &[&str]) -> std::io::Result<String> {
    let host = detect_host();
    if !host.supported() {
        return Ok("Legion Runner requires Linux or Windows with WSL".to_string());
    }
    let output = if matches!(host, RunnerHost::WindowsWsl) {
        let joined = args.join(" ");
        Command::new("wsl")
            .args(["-e", "bash", "-lc", &joined])
            .output()?
    } else {
        let (program, rest) = args.split_first().expect("runner command cannot be empty");
        Command::new(program).args(rest).output()?
    };
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if text.trim().is_empty() {
        text = format!("command exited with status {}", output.status);
    }
    Ok(text)
}
