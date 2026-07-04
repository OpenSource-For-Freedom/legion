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
    #[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn collect_ips_unix() -> Vec<String> {
    use std::process::Command;
    // Prefer ss (iproute2). NOTE: `state established` removes the State column
    // from the output, so it has no "ESTABLISHED" text and the peer address is
    // the LAST field — `parse_netstat` (written for netstat) cannot read it.
    // Parse ss output with its own parser; fall back to netstat otherwise.
    if let Ok(out) = Command::new("ss")
        .args(["-tn", "state", "established"])
        .output()
    {
        if out.status.success() {
            let ips = parse_ss(&String::from_utf8_lossy(&out.stdout));
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    if let Ok(out) = Command::new("netstat").args(["-tn"]).output() {
        return parse_netstat(&String::from_utf8_lossy(&out.stdout));
    }
    Vec::new()
}

/// Extract the remote IP from an `IP:port` peer field, handling IPv6 (`[::1]:443`)
/// and dropping loopback / unspecified addresses. Returns `None` when there is no
/// routable peer.
#[cfg(all(unix, not(target_os = "macos")))]
fn peer_ip(addr: &str) -> Option<String> {
    let (ip, _port) = addr.rsplit_once(':')?;
    let ip = ip.trim_matches('[').trim_matches(']');
    if ip.is_empty() || ip == "*" || ip == "::1" || ip.starts_with("127.") || ip.starts_with("0.0")
    {
        return None;
    }
    Some(ip.to_owned())
}

/// Parse `ss -tn state established` output. Every non-header row is an
/// established connection (the state filter drops the State column), and the
/// peer address is the final whitespace-separated field.
#[cfg(all(unix, not(target_os = "macos")))]
fn parse_ss(output: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        // Skip the header row(s).
        if line.contains("Peer Address") || parts[0] == "Recv-Q" || parts[0] == "State" {
            continue;
        }
        if let Some(ip) = peer_ip(parts[parts.len() - 1]) {
            ips.push(ip);
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
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
    // Use the *cumulative* per-interface counters (total since the interface came
    // up), not `received()`/`transmitted()` which report bytes since the previous
    // refresh — those are 0 on a freshly created `Networks` (single refresh, no
    // interval), which made rx/tx read 0 on every OS. The caller diffs successive
    // cumulative samples to derive the KB/s rate. Cross-platform via sysinfo
    // (Linux /sys, Windows iphlpapi).
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let rx: u64 = networks.values().map(|d| d.total_received()).sum();
    let tx: u64 = networks.values().map(|d| d.total_transmitted()).sum();
    (rx, tx)
}

// ─────────────────────── Local System Event Logs ────────────────────────────

/// A single local system event entry.
///
/// Windows sources are Security / System / Application. Linux sources are
/// journald/systemd/network/auth/kernel events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinEvent {
    pub time: String,
    pub event_id: u32,
    pub level: String,
    pub log_name: String,
    pub message: String,
}

impl WinEvent {
    /// True when this event is a security scanner's own status narration —
    /// a Legion component (`legion-*`) or the HARDN suite daemon — rather than
    /// observed host activity. Scanner progress lines legitimately contain
    /// hunting vocabulary ("Checking kernel modules...", "219 kernel modules
    /// loaded") that keyword rules and the posture scorer would count as
    /// kernel-tamper indicators, so a protected host would otherwise report a
    /// critical posture from its own telemetry loop. Both conditions are
    /// required — a scanner source unit AND a status-phrase shape — so events
    /// that merely mention a scanner, and scanner lines describing real
    /// detections, are still evaluated.
    pub fn is_scanner_status_noise(&self) -> bool {
        let source = self.log_name.to_ascii_lowercase();
        if !(source.starts_with("legion-") || source.starts_with("hardn")) {
            return false;
        }
        let msg = self.message.trim().to_ascii_lowercase();
        msg.starts_with("checking ")
            || msg.contains("running full monitoring checks")
            || msg.contains("kernel modules loaded")
            || msg.contains("listening sockets found")
            || msg.contains("active systemd services")
            || msg.contains("iptables rules configured")
            || msg.contains("creating legion baseline")
    }
}

/// Collect recent local security/system events for the current OS.
///
/// This preserves the existing `WinEvent` response shape used by the dashboard
/// while making the lower event panel and correlation engine platform-local.
pub fn collect_local_events(max: usize) -> Vec<WinEvent> {
    #[cfg(target_os = "windows")]
    {
        win_events_windows(max)
    }
    #[cfg(target_os = "linux")]
    {
        linux_journal_events(max)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = max;
        vec![]
    }
}

/// Backward-compatible alias for older callers. Prefer `collect_local_events`.
pub fn collect_win_events(max: usize) -> Vec<WinEvent> {
    collect_local_events(max)
}

#[cfg(target_os = "linux")]
fn linux_journal_events(max: usize) -> Vec<WinEvent> {
    use std::process::Command;

    let limit = max.saturating_mul(3).max(max).to_string();
    let output = Command::new("journalctl")
        .args(["--no-pager", "--output=json", "--since=-24h", "-n", &limit])
        .output();

    let Ok(out) = output else { return vec![] };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut events = parse_linux_journal_events(&text);
    events.truncate(max);
    events
}

fn priority_label(priority: u64) -> &'static str {
    match priority {
        0 => "Emergency",
        1 => "Alert",
        2 => "Critical",
        3 => "Error",
        4 => "Warning",
        5 => "Notice",
        7 => "Debug",
        _ => "Information",
    }
}

fn clean_event_message(message: &str, max_chars: usize) -> String {
    message
        .trim()
        .replace('\r', "")
        .replace('\n', " ")
        .chars()
        .take(max_chars)
        .collect()
}

fn parse_json_objects(input: &str) -> Vec<serde_json::Value> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input.trim()) {
        return match value {
            serde_json::Value::Array(items) => items,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => vec![],
        };
    }

    input
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .collect()
}

pub(crate) fn parse_linux_journal_events(json_lines: &str) -> Vec<WinEvent> {
    let mut events: Vec<WinEvent> = parse_json_objects(json_lines)
        .into_iter()
        .map(|obj| {
            let priority = obj["PRIORITY"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                .or_else(|| obj["PRIORITY"].as_u64())
                .unwrap_or(6);
            let unit = obj["_SYSTEMD_UNIT"]
                .as_str()
                .or_else(|| obj["SYSLOG_IDENTIFIER"].as_str())
                .or_else(|| obj["_COMM"].as_str())
                .unwrap_or("journald");
            let time = obj["__REALTIME_TIMESTAMP"]
                .as_str()
                .map(journal_timestamp_to_iso)
                .unwrap_or_default();
            WinEvent {
                time,
                event_id: priority as u32,
                level: priority_label(priority).to_string(),
                log_name: unit.to_string(),
                message: clean_event_message(obj["MESSAGE"].as_str().unwrap_or(""), 300),
            }
        })
        .collect();
    events.sort_by(|a, b| b.time.cmp(&a.time));
    events
}

fn journal_timestamp_to_iso(micros: &str) -> String {
    let Ok(us) = micros.parse::<i64>() else {
        return String::new();
    };
    let secs = us / 1_000_000;
    let nanos = ((us % 1_000_000).max(0) as u32) * 1_000;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
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
            message: clean_event_message(obj["m"].as_str().unwrap_or(""), 300),
        })
        .collect()
}

#[doc(hidden)]
pub fn parse_linux_journal_events_for_testing(json_lines: &str) -> Vec<WinEvent> {
    parse_linux_journal_events(json_lines)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn parse_ss_extracts_remote_peers_and_filters_loopback() {
        // `ss -tn state established` output: no State column, peer is the last field.
        let out = "\
Recv-Q Send-Q  Local Address:Port     Peer Address:Port
0      0           127.0.0.1:3000        127.0.0.1:53944
0      0      192.168.90.230:35246   160.79.104.10:443
0      0      192.168.90.230:41896   160.79.104.10:443
0      0      192.168.90.230:55012      8.8.8.8:443
0      0           [::1]:6000             [::1]:40222
0      0      [2001:db8::5]:443    [2606:4700::1111]:443
";
        let ips = parse_ss(out);
        // Deduped, loopback (127.x / ::1) dropped; LAN + public peers kept.
        assert!(ips.contains(&"160.79.104.10".to_string()));
        assert!(ips.contains(&"8.8.8.8".to_string()));
        assert!(ips.contains(&"2606:4700::1111".to_string()));
        assert!(!ips.iter().any(|i| i.starts_with("127.") || i == "::1"));
        // 160.79.104.10 appears twice in input but is deduped.
        assert_eq!(ips.iter().filter(|i| *i == "160.79.104.10").count(), 1);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn peer_ip_handles_ipv4_ipv6_and_loopback() {
        assert_eq!(peer_ip("1.2.3.4:443").as_deref(), Some("1.2.3.4"));
        assert_eq!(
            peer_ip("[2606:4700::1111]:443").as_deref(),
            Some("2606:4700::1111")
        );
        assert_eq!(peer_ip("127.0.0.1:22"), None);
        assert_eq!(peer_ip("[::1]:80"), None);
        assert_eq!(peer_ip("garbage"), None);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parse_netstat_windows_format() {
        // `netstat -n -p TCP` on Windows: State column present (peer is 2nd-to-last).
        let out = "\
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    192.168.1.5:50321      93.184.216.34:443      ESTABLISHED
  TCP    127.0.0.1:5354         127.0.0.1:49670        ESTABLISHED
  TCP    192.168.1.5:50322      140.82.112.3:443       ESTABLISHED
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
";
        let ips = parse_netstat(out);
        assert!(ips.contains(&"93.184.216.34".to_string()));
        assert!(ips.contains(&"140.82.112.3".to_string()));
        assert!(!ips.iter().any(|i| i.starts_with("127."))); // loopback dropped
        assert!(!ips.contains(&"0.0.0.0".to_string())); // LISTENING line skipped
    }
}
