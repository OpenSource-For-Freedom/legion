//! Poncho Mythos autonomous agent loop — per-OS command and control.
//!
//! This module defines a persistent background agent that:
//!
//!   1. Detects the runtime OS lane (Windows / Linux / macOS / WSL / Container).
//!   2. Dispatches a curated set of **read-only** OS probes for that lane every
//!      tick interval (default 5 minutes).
//!   3. Runs the Mythos neural scorer on the live probe output.
//!   4. Automatically escalates to a full LLM hunt when the Mythos score crosses
//!      the `elevated` or `critical` threshold.
//!   5. Publishes its state to a shared `AgentLoopState` struct the dashboard
//!      can poll at any time.
//!
//! All probes are **read-only** — no files are written, no processes are
//! modified, and no network connections are opened by the probe commands
//! themselves (the Ollama call is still loopback-only and policy-gated).

use crate::config::PonchoConfig;
use crate::mythos::MythosNeuralHunter;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ─────────────────────── OS Lane ────────────────────────────────────────────

/// The runtime OS lane Poncho is operating in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsLane {
    WindowsKernel,
    LinuxKernel,
    MacosKernel,
    WslBridge,
    Container,
    Generic,
}

impl OsLane {
    pub fn label(&self) -> &'static str {
        match self {
            OsLane::WindowsKernel => "windows-kernel",
            OsLane::LinuxKernel => "linux-kernel",
            OsLane::MacosKernel => "macos-kernel",
            OsLane::WslBridge => "wsl-bridge",
            OsLane::Container => "container",
            OsLane::Generic => "generic-local",
        }
    }

    pub fn detect() -> Self {
        let target_os = std::env::consts::OS;

        // Container first — /.dockerenv or kubepods cgroup beats the base OS.
        let is_container = std::path::Path::new("/.dockerenv").exists()
            || std::fs::read_to_string("/proc/1/cgroup")
                .map(|s| {
                    let s = s.to_ascii_lowercase();
                    s.contains("docker") || s.contains("kubepods") || s.contains("containerd")
                })
                .unwrap_or(false);
        if is_container {
            return OsLane::Container;
        }

        // WSL: Linux kernel that reports Microsoft in /proc/version.
        let is_wsl = target_os == "linux"
            && std::fs::read_to_string("/proc/version")
                .map(|v| {
                    let v = v.to_ascii_lowercase();
                    v.contains("microsoft") || v.contains("wsl")
                })
                .unwrap_or(false);
        if is_wsl {
            return OsLane::WslBridge;
        }

        match target_os {
            "windows" => OsLane::WindowsKernel,
            "linux" => OsLane::LinuxKernel,
            "macos" => OsLane::MacosKernel,
            _ => OsLane::Generic,
        }
    }
}

// ─────────────────────── Probe definition ───────────────────────────────────

/// A single read-only diagnostic probe: a command with fixed args.
struct Probe {
    /// Human-readable label for logs and dashboard.
    label: &'static str,
    /// Executable (searched on PATH for the target OS).
    program: &'static str,
    /// Arguments passed to the program.
    args: &'static [&'static str],
    /// Maximum bytes of stdout we retain (prevents OOM on chatty commands).
    max_bytes: usize,
}

/// Run a probe and return (label, truncated_stdout, stderr_hint).
fn run_probe(p: &Probe) -> ProbeResult {
    let result = Command::new(p.program)
        .args(p.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output();

    match result {
        Ok(out) => {
            let raw = String::from_utf8_lossy(&out.stdout);
            let text = if raw.len() > p.max_bytes {
                format!(
                    "{}…[{} bytes truncated]",
                    &raw[..p.max_bytes],
                    raw.len() - p.max_bytes
                )
            } else {
                raw.to_string()
            };
            let stderr = if out.status.success() {
                None
            } else {
                Some(
                    String::from_utf8_lossy(&out.stderr)
                        .chars()
                        .take(200)
                        .collect(),
                )
            };
            ProbeResult {
                label: p.label.to_string(),
                text,
                stderr,
                ok: out.status.success(),
            }
        }
        Err(e) => ProbeResult {
            label: p.label.to_string(),
            text: String::new(),
            stderr: Some(format!("{e}")),
            ok: false,
        },
    }
}

/// Per-lane probe tables — **read-only** commands only.
fn probes_for_lane(lane: &OsLane) -> Vec<Probe> {
    match lane {
        OsLane::WindowsKernel => vec![
            Probe {
                label: "processes",
                program: "tasklist",
                args: &["/FO", "CSV", "/NH"],
                max_bytes: 8192,
            },
            Probe {
                label: "services",
                program: "sc",
                args: &["query", "state=", "all"],
                max_bytes: 8192,
            },
            Probe {
                label: "network-connections",
                program: "netstat",
                args: &["-ano"],
                max_bytes: 6144,
            },
            Probe {
                label: "drivers-loaded",
                program: "driverquery",
                args: &["/FO", "CSV", "/NH"],
                max_bytes: 6144,
            },
            Probe {
                label: "scheduled-tasks",
                program: "schtasks",
                args: &["/query", "/FO", "CSV", "/NH"],
                max_bytes: 6144,
            },
            Probe {
                label: "autorun-hklm",
                program: "reg",
                args: &[
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                ],
                max_bytes: 3072,
            },
            Probe {
                label: "autorun-hkcu",
                program: "reg",
                args: &[
                    "query",
                    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                ],
                max_bytes: 3072,
            },
            Probe {
                label: "event-security-recent",
                program: "wevtutil",
                args: &[
                    "qe",
                    "Security",
                    "/c:20",
                    "/rd:true",
                    "/f:text",
                    "/q:*[System[(Level=1 or Level=2)]]",
                ],
                max_bytes: 6144,
            },
            Probe {
                label: "event-system-errors",
                program: "wevtutil",
                args: &[
                    "qe",
                    "System",
                    "/c:20",
                    "/rd:true",
                    "/f:text",
                    "/q:*[System[(Level=1 or Level=2)]]",
                ],
                max_bytes: 6144,
            },
        ],

        OsLane::WslBridge => vec![
            Probe {
                label: "processes",
                program: "ps",
                args: &["aux", "--no-headers"],
                max_bytes: 8192,
            },
            Probe {
                label: "network-connections",
                program: "ss",
                args: &["-tupn"],
                max_bytes: 6144,
            },
            Probe {
                label: "kernel-modules",
                program: "lsmod",
                args: &[],
                max_bytes: 4096,
            },
            Probe {
                label: "ld-preload",
                program: "cat",
                args: &["/etc/ld.so.preload"],
                max_bytes: 1024,
            },
            Probe {
                label: "failed-units",
                program: "systemctl",
                args: &["list-units", "--failed", "--no-pager", "--no-legend"],
                max_bytes: 3072,
            },
            Probe {
                label: "journal-errors",
                program: "journalctl",
                args: &["-n", "50", "-p", "err", "--no-pager"],
                max_bytes: 6144,
            },
            // WSL bridge: also query Windows tasklist across the boundary.
            Probe {
                label: "windows-processes",
                program: "/mnt/c/Windows/System32/tasklist.exe",
                args: &["/FO", "CSV", "/NH"],
                max_bytes: 4096,
            },
        ],

        OsLane::LinuxKernel => vec![
            Probe {
                label: "processes",
                program: "ps",
                args: &["aux", "--no-headers"],
                max_bytes: 8192,
            },
            Probe {
                label: "network-connections",
                program: "ss",
                args: &["-tupn"],
                max_bytes: 6144,
            },
            Probe {
                label: "kernel-modules",
                program: "lsmod",
                args: &[],
                max_bytes: 4096,
            },
            Probe {
                label: "ld-preload",
                program: "cat",
                args: &["/etc/ld.so.preload"],
                max_bytes: 1024,
            },
            Probe {
                label: "failed-units",
                program: "systemctl",
                args: &["list-units", "--failed", "--no-pager", "--no-legend"],
                max_bytes: 3072,
            },
            Probe {
                label: "journal-errors",
                program: "journalctl",
                args: &["-n", "50", "-p", "err", "--no-pager"],
                max_bytes: 6144,
            },
            Probe {
                label: "auditd-status",
                program: "auditctl",
                args: &["-s"],
                max_bytes: 1024,
            },
            Probe {
                label: "suid-sgid-scan",
                program: "find",
                args: &["/usr/bin", "/usr/sbin", "-perm", "-4000", "-o", "-perm", "-2000"],
                max_bytes: 2048,
            },
        ],

        OsLane::MacosKernel => vec![
            Probe {
                label: "processes",
                program: "ps",
                args: &["aux"],
                max_bytes: 8192,
            },
            Probe {
                label: "network-connections",
                program: "netstat",
                args: &["-an"],
                max_bytes: 6144,
            },
            Probe {
                label: "launch-daemons",
                program: "launchctl",
                args: &["list"],
                max_bytes: 6144,
            },
            Probe {
                label: "kexts-loaded",
                program: "kextstat",
                args: &["-l", "-n", "com.apple"],
                max_bytes: 4096,
            },
            Probe {
                label: "system-extensions",
                program: "systemextensionsctl",
                args: &["list"],
                max_bytes: 3072,
            },
            Probe {
                label: "sip-status",
                program: "csrutil",
                args: &["status"],
                max_bytes: 512,
            },
            Probe {
                label: "gatekeeper-status",
                program: "spctl",
                args: &["--status"],
                max_bytes: 256,
            },
        ],

        OsLane::Container => vec![
            Probe {
                label: "processes",
                program: "ps",
                args: &["aux"],
                max_bytes: 6144,
            },
            Probe {
                label: "network-connections",
                program: "ss",
                args: &["-tupn"],
                max_bytes: 4096,
            },
            Probe {
                label: "cgroup",
                program: "cat",
                args: &["/proc/1/cgroup"],
                max_bytes: 1024,
            },
            Probe {
                label: "capabilities",
                program: "cat",
                args: &["/proc/self/status"],
                max_bytes: 2048,
            },
            Probe {
                label: "ld-preload",
                program: "cat",
                args: &["/etc/ld.so.preload"],
                max_bytes: 512,
            },
        ],

        OsLane::Generic => vec![
            Probe {
                label: "processes",
                program: "ps",
                args: &["aux"],
                max_bytes: 6144,
            },
        ],
    }
}

// ─────────────────────── Probe result + tick record ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub label: String,
    pub text: String,
    pub stderr: Option<String>,
    pub ok: bool,
}

/// A single autonomous agent tick — all probe results plus scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTick {
    pub tick_id: u64,
    pub timestamp: String,
    pub lane: String,
    pub probes_run: usize,
    pub probes_ok: usize,
    pub mythos_score: f32,
    pub mythos_posture: String,
    pub signals: Vec<String>,
    /// Whether this tick triggered an automatic LLM hunt escalation.
    pub auto_hunt_triggered: bool,
    /// Probe results (trimmed for wire size — labels only in summary, full in detail).
    pub probe_summary: Vec<String>,
}

// ─────────────────────── Shared loop state ──────────────────────────────────

/// Snapshot of the autonomous agent loop shared with the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLoopState {
    pub running: bool,
    pub lane: String,
    pub tick_interval_secs: u64,
    /// Last completed tick (None until the first tick finishes).
    pub last_tick: Option<AgentTick>,
    /// Ring buffer of the last N ticks (newest first).
    pub recent_ticks: Vec<AgentTick>,
    /// Number of automatic escalations triggered since process start.
    pub auto_escalations: u64,
    /// Next scheduled tick (ISO 8601 timestamp, None if not started).
    pub next_tick_at: Option<String>,
}

impl Default for AgentLoopState {
    fn default() -> Self {
        Self {
            running: false,
            lane: OsLane::detect().label().to_string(),
            tick_interval_secs: 300,
            last_tick: None,
            recent_ticks: Vec::new(),
            auto_escalations: 0,
            next_tick_at: None,
        }
    }
}

/// Shared handle to the agent loop state.
pub type LoopStateHandle = Arc<Mutex<AgentLoopState>>;

// ─────────────────────── Mythos probe scorer ────────────────────────────────

/// Score the raw probe output using keyword signal extraction. This runs
/// entirely locally (no LLM) and is the first escalation gate.
fn score_probe_output(results: &[ProbeResult]) -> (f32, Vec<String>) {
    let mut score: f32 = 0.0;
    let mut signals: Vec<String> = Vec::new();

    for r in results {
        if !r.ok && r.label != "ld-preload" {
            // Expected-absent probes (ld.so.preload not existing) are not bad.
            if r.stderr.as_deref().map(|s| !s.contains("No such file")).unwrap_or(true) {
                score += 0.04;
                signals.push(format!("probe {} failed", r.label));
            }
        }
        let text = r.text.to_ascii_lowercase();
        let label = r.label.as_str();

        match label {
            "kernel-modules" | "kexts-loaded" => {
                let sus: &[&str] = &[
                    "diamorphine",
                    "reptile",
                    "drovorub",
                    "skidmap",
                    "azazel",
                    "rootfoo",
                    "suckit",
                    "bdvl",
                    "khook",
                ];
                for s in sus {
                    if text.contains(s) {
                        score += 0.35;
                        signals.push(format!("known rootkit module {} in {}", s, label));
                    }
                }
            }
            "ld-preload" => {
                if !text.is_empty() && !text.trim().is_empty() {
                    score += 0.30;
                    signals.push("ld.so.preload is non-empty — possible rootkit hooking".into());
                }
            }
            "autorun-hklm" | "autorun-hkcu" => {
                let sus: &[&str] = &[
                    "temp\\", "appdata\\local\\temp", "\\tmp\\", "powershell -enc",
                    "powershell -e ", "cmd /c ", "wscript", "cscript", "regsvr32",
                    "mshta", "certutil -decode", "bitsadmin",
                ];
                for s in sus {
                    if text.contains(s) {
                        score += 0.20;
                        signals.push(format!("suspicious autorun entry: contains '{}'", s));
                    }
                }
            }
            "scheduled-tasks" => {
                let sus: &[&str] = &[
                    "powershell -enc",
                    "\\temp\\",
                    "\\tmp\\",
                    "mshta",
                    "wscript",
                    "certutil",
                    "bitsadmin",
                ];
                for s in sus {
                    if text.contains(s) {
                        score += 0.18;
                        signals.push(format!(
                            "suspicious scheduled task pattern: contains '{}'",
                            s
                        ));
                    }
                }
            }
            "drivers-loaded" => {
                let sus: &[&str] = &[
                    "not found",
                    "\\temp\\",
                    "unsigned",
                    "no pad",
                    "test sign",
                    "disable integrity",
                ];
                for s in sus {
                    if text.contains(s) {
                        score += 0.15;
                        signals.push(format!("suspicious driver state: '{}'", s));
                    }
                }
            }
            "sip-status" => {
                if text.contains("disabled") {
                    score += 0.22;
                    signals.push("macOS SIP is disabled".into());
                }
            }
            "gatekeeper-status" => {
                if text.contains("disabled") {
                    score += 0.15;
                    signals.push("macOS Gatekeeper is disabled".into());
                }
            }
            "event-security-recent" | "event-system-errors" => {
                let sus: &[&str] = &[
                    "audit log was cleared",
                    "eventlog service stopped",
                    "unexpected shutdown",
                    "security account manager",
                    "credential manager",
                    "token hijack",
                    "driver installation",
                    "new service was installed",
                    "kerberos pre-authentication failed",
                    "4625",
                    "4720",
                    "7045",
                    "1102",
                ];
                for s in sus {
                    if text.contains(s) {
                        score += 0.12;
                        signals.push(format!("security event pattern '{}' in {}", s, label));
                    }
                }
            }
            "network-connections" => {
                // Multiple unusual high ports in ESTABLISHED state is worth noting.
                let established = text
                    .lines()
                    .filter(|l| l.contains("established") || l.contains("ESTABLISHED"))
                    .count();
                if established > 80 {
                    score += 0.08;
                    signals.push(format!(
                        "high established connection count: {}",
                        established
                    ));
                }
            }
            "capabilities" => {
                // Docker container running with broad capabilities.
                let cap_lines: Vec<_> = text
                    .lines()
                    .filter(|l| l.starts_with("capeff") || l.starts_with("capbnd"))
                    .collect();
                for cl in cap_lines {
                    if cl.contains("ffffffffffffffff") {
                        score += 0.28;
                        signals.push("container running with full capabilities (cap_eff all)".into());
                    }
                }
            }
            "failed-units" => {
                let count = text.lines().filter(|l| !l.trim().is_empty()).count();
                if count > 3 {
                    score += 0.06;
                    signals.push(format!("{} failed systemd units", count));
                }
            }
            "auditd-status" => {
                if text.contains("enabled 0") || text.contains("disabled") {
                    score += 0.14;
                    signals.push("auditd is disabled — audit telemetry gap".into());
                }
            }
            "suid-sgid-scan" => {
                let count = text.lines().filter(|l| !l.trim().is_empty()).count();
                if count > 15 {
                    score += 0.08;
                    signals.push(format!("high SUID/SGID file count: {}", count));
                }
            }
            _ => {}
        }
    }

    signals.sort();
    signals.dedup();
    signals.truncate(10);
    let score = score.min(1.0_f32);
    (score, signals)
}

// ─────────────────────── Agent loop ─────────────────────────────────────────

/// Callback type invoked by the agent loop when it decides to escalate to an
/// LLM hunt. The caller (main.rs) provides a closure that drives the actual
/// LLM call so that `agent.rs` has no Ollama/reqwest dependency.
pub type HuntCallback =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// Configuration for the autonomous agent loop.
#[derive(Clone)]
pub struct AgentLoopConfig {
    /// How often to run a probe tick.
    pub tick_interval: Duration,
    /// Mythos score threshold above which an automatic hunt is triggered.
    pub escalation_threshold: f32,
    /// Maximum number of ticks to keep in the ring buffer.
    pub history_depth: usize,
    /// Minimum seconds between automatic hunt escalations (cooldown).
    pub escalation_cooldown_secs: u64,
}

impl Default for AgentLoopConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(300), // 5 min
            escalation_threshold: 0.45,              // "elevated" posture
            history_depth: 20,
            escalation_cooldown_secs: 600, // 10 min between auto-hunts
        }
    }
}

/// Run the Poncho Mythos autonomous agent loop. This is a long-running async
/// task that should be spawned once via `tokio::spawn`.
pub async fn run_agent_loop(
    cfg: Arc<Mutex<PonchoConfig>>,
    state: LoopStateHandle,
    loop_cfg: AgentLoopConfig,
    on_hunt: HuntCallback,
) {
    let lane = OsLane::detect();
    let mut tick_id: u64 = 0;
    let mut auto_escalations: u64 = 0;
    let mut last_escalation_at: Option<std::time::Instant> = None;
    let history_depth = loop_cfg.history_depth;

    // Mark the loop as running.
    {
        let mut s = state.lock().unwrap();
        s.running = true;
        s.lane = lane.label().to_string();
        s.tick_interval_secs = loop_cfg.tick_interval.as_secs();
    }

    tracing::info!(
        "poncho agent loop starting — lane={} interval={}s",
        lane.label(),
        loop_cfg.tick_interval.as_secs()
    );

    loop {
        // Schedule the next tick timestamp before sleeping.
        {
            let next_at = (Utc::now()
                + chrono::Duration::seconds(loop_cfg.tick_interval.as_secs() as i64))
            .to_rfc3339();
            state.lock().unwrap().next_tick_at = Some(next_at);
        }

        tokio::time::sleep(loop_cfg.tick_interval).await;

        tick_id += 1;
        let ts = Utc::now().to_rfc3339();

        tracing::debug!("poncho agent tick {} — lane={}", tick_id, lane.label());

        // Run probes in a blocking thread so we never block the async runtime.
        let lane_clone = lane.clone();
        let probe_results =
            tokio::task::spawn_blocking(move || -> Vec<ProbeResult> {
                let probes = probes_for_lane(&lane_clone);
                probes.iter().map(run_probe).collect()
            })
            .await
            .unwrap_or_default();

        let probes_run = probe_results.len();
        let probes_ok = probe_results.iter().filter(|r| r.ok).count();

        // Score with the keyword scorer first (no LLM needed).
        let (probe_score, mut probe_signals) = score_probe_output(&probe_results);

        // Collect a probe summary (label + first line of output).
        let probe_summary: Vec<String> = probe_results
            .iter()
            .map(|r| {
                let first = r
                    .text
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or(if r.ok { "(empty)" } else { "(failed)" });
                format!("[{}] {}", r.label, first.chars().take(80).collect::<String>())
            })
            .collect();

        // Also fetch the current Mythos neural assessment.
        let mythos_score;
        let mythos_posture;
        {
            // Quick snapshot of DB-resident SIEM data for the neural scorer.
            // We only need the signals that MythosNeuralHunter reads, not the
            // full KnowledgeContext (that would require a DB handle here).
            // We run from the probe text as synthetic events so no DB needed.
            let synthetic_events: Vec<legion_core::WinEvent> = probe_results
                .iter()
                .map(|r| legion_core::WinEvent {
                    time: ts.clone(),
                    event_id: 0,
                    level: if r.ok { "Information".to_string() } else { "Warning".to_string() },
                    log_name: r.label.clone(),
                    message: r.text.chars().take(512).collect(),
                })
                .collect();

            let mythos = MythosNeuralHunter::assess(
                &[],          // alerts: no DB handle in agent loop
                &synthetic_events,
                &[],          // yara: not re-running here
                &[],          // rule_hits: not re-running here
            );
            // Blend probe keyword score with Mythos score.
            let blended = ((mythos.score + probe_score) / 2.0).min(1.0);
            mythos_score = blended;
            mythos_posture = if blended >= 0.75 {
                "critical"
            } else if blended >= 0.45 {
                "elevated"
            } else if blended >= 0.20 {
                "watch"
            } else {
                "baseline"
            }
            .to_string();
            probe_signals.extend(mythos.signals);
            probe_signals.sort();
            probe_signals.dedup();
            probe_signals.truncate(10);
        }

        // Decide whether to escalate.
        let should_escalate = mythos_score >= loop_cfg.escalation_threshold
            && last_escalation_at
                .map(|t| {
                    t.elapsed().as_secs() >= loop_cfg.escalation_cooldown_secs
                })
                .unwrap_or(true);

        if should_escalate {
            auto_escalations += 1;
            last_escalation_at = Some(std::time::Instant::now());
            tracing::warn!(
                "poncho agent escalating to hunt — score={:.2} posture={} tick={}",
                mythos_score,
                mythos_posture,
                tick_id
            );
            // Drive the hunt callback asynchronously but don't block the loop.
            let cb = Arc::clone(&on_hunt);
            tokio::spawn(async move {
                cb().await;
            });
        }

        // Fetch updated config (interval may have changed via dashboard).
        let new_interval = cfg
            .lock()
            .ok()
            .map(|_c| loop_cfg.tick_interval)
            .unwrap_or(loop_cfg.tick_interval);
        let _ = new_interval; // used if dynamic interval support added later

        let tick = AgentTick {
            tick_id,
            timestamp: ts,
            lane: lane.label().to_string(),
            probes_run,
            probes_ok,
            mythos_score,
            mythos_posture,
            signals: probe_signals,
            auto_hunt_triggered: should_escalate,
            probe_summary,
        };

        // Publish state.
        {
            let mut s = state.lock().unwrap();
            s.last_tick = Some(tick.clone());
            s.auto_escalations = auto_escalations;
            // Push newest first.
            s.recent_ticks.insert(0, tick);
            s.recent_ticks.truncate(history_depth);
            s.next_tick_at = Some(
                (Utc::now()
                    + chrono::Duration::seconds(loop_cfg.tick_interval.as_secs() as i64))
                .to_rfc3339(),
            );
        }
    }
}
