//! Cross-platform system telemetry using the `sysinfo` crate.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemStats {
    pub cpu_pct: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub proc_count: usize,
    pub net_rx_kb: u64,
    pub net_tx_kb: u64,
    pub load_avg_1: f64,
}

impl SystemStats {
    pub fn mem_pct(&self) -> f32 {
        if self.mem_total_mb == 0 {
            return 0.0;
        }
        (self.mem_used_mb as f32 / self.mem_total_mb as f32) * 100.0
    }
}

/// Collect a snapshot of system statistics.
pub fn collect() -> SystemStats {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_pct = sys.global_cpu_usage();
    let mem_used_mb = sys.used_memory() / (1024 * 1024);
    let mem_total_mb = sys.total_memory() / (1024 * 1024);
    let proc_count = sys.processes().len();

    // Network I/O – raw cumulative bytes (caller computes rate via delta)
    let (net_rx_kb, net_tx_kb) = {
        let networks = sysinfo::Networks::new_with_refreshed_list();
        let rx: u64 = networks.values().map(|d| d.received()).sum();
        let tx: u64 = networks.values().map(|d| d.transmitted()).sum();
        (rx / 1024, tx / 1024)
    };

    // Load average (not available on Windows – returns 0.0)
    let load_avg = System::load_average();
    let load_avg_1 = load_avg.one;

    SystemStats {
        cpu_pct,
        mem_used_mb,
        mem_total_mb,
        proc_count,
        net_rx_kb,
        net_tx_kb,
        load_avg_1,
    }
}

/// Collect active TCP connection remote IPs using platform-specific approach.
/// Falls back to an empty list if the command is unavailable.
pub fn active_remote_ips() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        collect_ips_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        collect_ips_unix()
    }
}

#[cfg(target_os = "windows")]
fn collect_ips_windows() -> Vec<String> {
    use std::process::Command;
    let output = Command::new("netstat")
        .args(["-n", "-p", "TCP"])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: vec![],
            stderr: vec![],
        });
    parse_netstat(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "windows"))]
fn collect_ips_unix() -> Vec<String> {
    use std::process::Command;
    let output = Command::new("ss")
        .args(["-tn", "state", "established"])
        .output()
        .or_else(|_| Command::new("netstat").args(["-tn"]).output())
        .unwrap_or_else(|_| std::process::Output {
            status: unsafe { std::mem::zeroed() },
            stdout: vec![],
            stderr: vec![],
        });
    parse_netstat(&String::from_utf8_lossy(&output.stdout))
}

fn parse_netstat(output: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in output.lines() {
        // Match lines with ESTABLISHED connections; extract remote IP
        if !line.to_uppercase().contains("ESTABLISHED") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // netstat: TCP local_addr remote_addr state
        if parts.len() >= 3 {
            let remote = parts[parts.len() - 2]; // second to last before "ESTABLISHED"
            if let Some(ip) = remote.rsplit_once(':') {
                let ip_str = ip.0.trim_matches('[').trim_matches(']').to_owned();
                if !ip_str.starts_with("127.") && !ip_str.starts_with("0.0") {
                    ips.push(ip_str);
                }
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

// ─────────────────────── Raw network bytes (for rate calc) ──────────────────

/// Returns raw cumulative (rx_bytes, tx_bytes) across all interfaces.
/// The caller diffs consecutive calls to compute a KB/s rate.
pub fn collect_net_raw() -> (u64, u64) {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let rx: u64 = networks.values().map(|d| d.received()).sum();
    let tx: u64 = networks.values().map(|d| d.transmitted()).sum();
    (rx, tx)
}

// ─────────────────────── Windows Event Log ──────────────────────────────────

/// A single Windows Event Log entry (Security / System / Application).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinEvent {
    pub time: String,
    pub event_id: u32,
    pub level: String,
    pub log_name: String,
    pub message: String,
}

/// Collect recent events from Windows Security, System, and Application logs.
/// Returns an empty vec on non-Windows or if the log is inaccessible.
pub fn collect_win_events(max: usize) -> Vec<WinEvent> {
    #[cfg(target_os = "windows")]
    {
        win_events_windows(max)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = max;
        vec![]
    }
}

#[cfg(target_os = "windows")]
fn win_events_windows(max: usize) -> Vec<WinEvent> {
    use std::process::Command;

    // Query Security, System, Application; sort newest-first; trim message to 200 chars.
    let script = format!(
        r#"$e=@();foreach($l in 'Security','System','Application'){{try{{$e+=Get-WinEvent -LogName $l -MaxEvents 25 -ErrorAction SilentlyContinue}}catch{{}}}};$r=@($e|Sort-Object TimeCreated -Descending|Select-Object -First {max}|ForEach-Object{{$msg=if($_.Message){{($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(200,$_.Message.Length))}}else{{''}};[PSCustomObject]@{{t=$_.TimeCreated.ToString('s');i=$_.Id;l=if($_.LevelDisplayName){{$_.LevelDisplayName}}else{{'Info'}};g=$_.LogName;m=$msg}}}});if($r.Count -gt 0){{$r|ConvertTo-Json -Compress}}else{{'[]'}}"#,
        max = max
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();

    let Ok(out) = output else { return vec![] };
    let text = String::from_utf8_lossy(&out.stdout);
    parse_win_events(text.trim())
}

#[cfg(target_os = "windows")]
fn parse_win_events(json: &str) -> Vec<WinEvent> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let arr: Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return vec![],
    };

    arr.into_iter()
        .map(|obj| WinEvent {
            time: obj["t"].as_str().unwrap_or("").to_string(),
            event_id: obj["i"].as_u64().unwrap_or(0) as u32,
            level: obj["l"].as_str().unwrap_or("Information").to_string(),
            log_name: obj["g"].as_str().unwrap_or("").to_string(),
            message: obj["m"]
                .as_str()
                .unwrap_or("")
                .trim()
                .replace('\r', "")
                .replace('\n', " "),
        })
        .collect()
}

// ─────────────────────── Docker Monitoring ──────────────────────────────────

/// A Docker container with live resource stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerInfo {
    pub name: String,
    pub image: String,
    /// running | exited | paused | restarting | created
    pub state: String,
    /// Human-readable uptime ("Up 2 hours", "Exited (0) 3 days ago")
    pub status: String,
    pub cpu_pct: String,
    pub mem_usage: String,
    pub net_in: String,
    pub net_out: String,
    pub ports: String,
}

/// Collect Docker container list + live stats. Returns empty vec if Docker is
/// not installed or the daemon is not running.
pub fn collect_docker() -> Vec<DockerInfo> {
    collect_docker_inner().unwrap_or_default()
}

fn collect_docker_inner() -> Result<Vec<DockerInfo>, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // List all containers (running + stopped).
    let ps = Command::new("docker")
        .args([
            "ps", "-a", "--no-trunc", "--format",
            r#"{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","state":"{{.State}}","status":"{{.Status}}","ports":"{{.Ports}}"}"#,
        ])
        .output();

    let Ok(ps_out) = ps else {
        return Ok(vec![]);
    };
    if !ps_out.status.success() {
        return Ok(vec![]);
    }

    let ps_text = String::from_utf8_lossy(&ps_out.stdout);
    let mut containers: Vec<DockerInfo> = ps_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            Some(DockerInfo {
                name: v["name"]
                    .as_str()
                    .unwrap_or("")
                    .trim_start_matches('/')
                    .to_string(),
                image: v["image"].as_str().unwrap_or("").to_string(),
                state: v["state"].as_str().unwrap_or("").to_string(),
                status: v["status"].as_str().unwrap_or("").to_string(),
                cpu_pct: "—".into(),
                mem_usage: "—".into(),
                net_in: "—".into(),
                net_out: "—".into(),
                ports: v["ports"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    if containers.is_empty() {
        return Ok(containers);
    }

    // Fetch live stats for running containers only.
    let running_names: Vec<String> = containers
        .iter()
        .filter(|c| c.state == "running")
        .map(|c| c.name.clone())
        .collect();

    if !running_names.is_empty() {
        let mut stats_cmd = Command::new("docker");
        stats_cmd.args([
            "stats",
            "--no-stream",
            "--format",
            r#"{"name":"{{.Name}}","cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}","net":"{{.NetIO}}"}"#,
        ]);
        for n in &running_names {
            stats_cmd.arg(n);
        }

        if let Ok(out) = stats_cmd.output() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut map: HashMap<String, (String, String, String, String)> = HashMap::new();

            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let name = v["name"]
                        .as_str()
                        .unwrap_or("")
                        .trim_start_matches('/')
                        .to_string();
                    let cpu = v["cpu"].as_str().unwrap_or("—").to_string();
                    let mem = v["mem"].as_str().unwrap_or("—").to_string();
                    let net = v["net"].as_str().unwrap_or("—").to_string();
                    let parts: Vec<&str> = net.splitn(2, '/').collect();
                    let ni = parts.first().unwrap_or(&"—").trim().to_string();
                    let no = parts.get(1).unwrap_or(&"—").trim().to_string();
                    map.insert(name, (cpu, mem, ni, no));
                }
            }

            for c in &mut containers {
                if let Some((cpu, mem, ni, no)) = map.get(&c.name) {
                    c.cpu_pct = cpu.clone();
                    c.mem_usage = mem.clone();
                    c.net_in = ni.clone();
                    c.net_out = no.clone();
                }
            }
        }
    }

    Ok(containers)
}
