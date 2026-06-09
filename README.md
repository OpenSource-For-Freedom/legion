# Legion 

An Agentic Local security monitor for your machine. Scans packages for CVEs, flags connections to known-malicious IPs, detects typosquatted and vulnerable AI SDK packages, scans files with continuously-updated YARA rules, models a heuristic baseline of the host, and pulls live threat intel from CISA KEV and more. 
- the goal is an open source NIST/SOC application to enrich all of these new Dev attacks. 
![Legion dashboard](assets/legion.png)
![Poncho agent tab](assets/agent.png)
Browser dashboard at http://localhost:3000.

## Project status

Current state:

- Web dashboard is live and running on localhost.
- Package scan summary now reports discovered Cargo, npm, and pip packages correctly.
- Windows Event Viewer events are now correlated into alerts for threat-relevant event IDs.
- YARA scanning, baseline drift detection, OSV correlation, and live feed pulls are active.
- PONCHO agent tab is integrated into the web UI.
- PONCHO supports local model install, update, model scanning, rule evaluation, chat, and full hunt mode.
- DeepSeek models are blocked by policy.
- Poncho test suite is passing.

Included views:

- Main dashboard screenshot: `assets/legion.png`
- PONCHO agent screenshot: `assets/agent.png`

## Requirements

- Rust 1.78 or newer: https://rustup.rs
- Make: included on Linux/macOS, on Windows install via `choco install make` or use `winget install GnuWin32.Make`
- No other runtime dependencies. SQLite is bundled.

## Start

```powershell
cd F:\dev\legion
make legion
```

Opens the browser dashboard at http://localhost:3000 automatically.

Scan root defaults to `F:\dev`. To change it, edit `SCAN_ROOT` in the Makefile or run the binary directly:

```powershell
.\target\debug\legion-web.exe --scan-root C:\your\code --port 3000
```

## All make targets

```
make legion         Build and launch web dashboard (port 3000)
make web            Same as make legion
make tui-launch     Build and launch TUI dashboard (terminal)
make release        Build release binaries
make test           Run all tests
make test-poncho    Run Poncho agent unit tests
make clean          Clean build artifacts
make feeds          Pull CISA KEV, ThreatFox, and AbuseIPDB feeds
make scan           Scan F:\dev for CVE-affected packages
make alerts         Print active alerts
make status         Print system and alert summary
make stop           Stop running web dashboard
```

## CLI

```
legion scan [PATH]                        Scan packages for CVE matches
legion alerts [--acked] [--json]          List alerts
legion ack <ID>                           Acknowledge alert by ID
legion quarantine list                    List quarantined packages
legion quarantine add <ECO> <NAME>        Add package to quarantine
legion quarantine release <ID>            Remove from quarantine
legion quarantine remediate <ECO> <NAME>  Print removal command
legion feeds refresh                      Pull all threat feeds
legion feeds status                       Show feed cache stats
legion status                             Print system and alert summary
legion yara scan [PATH]                   Scan a path with the OS rule set
legion yara update                        Fetch latest rules for this OS
legion yara rules                         Show loaded rule count + warnings
legion baseline run [PATH]                Capture baseline (first) / diff (after)
legion baseline show                      Show stored baseline summary
```

## YARA scanning & heuristic baseline

Legion ships a dependency-free, pure-Rust YARA-compatible engine so the same
binary scans files on Linux, macOS and Windows with no external libraries.

- **Continuously updated rules.** Rules are fetched per-OS from the GitHub-hosted
  rules feed configured in `yara_config.json` (`rules_repo`, default
  [`rules-feed/`](rules-feed/) on `main`) and cached under `<data_dir>/rules/<os>/`.
  A baseline rule set is compiled into the binary as an offline / first-launch
  fallback, so detection works before the first update. Run `legion yara update`
  (or `POST /api/yara/update`) to pull the latest rules. To host the feed in a
  separate repo, copy the `rules-feed/` layout and update `rules_repo`.
- **Per-OS configuration.** `yara_config.json` declares, for each of `linux`,
  `macos` and `windows`, the `rule_files` to assemble and the `scan_paths` to
  walk. A copy is written to `<data_dir>/yara_config.json` on first run and can
  be edited there.
- **Heuristic baseline.** On first launch (any of the CLI `scan`, the TUI, or the
  web server) Legion captures a baseline fingerprint of the host — running
  processes, outbound peers, installed packages and the YARA rules that already
  match. This is the heuristic model. Every later scan re-captures the same shape
  and reports **drift**: new processes, new outbound peers, newly installed
  packages, and — highest priority — YARA rules that match now but did not at
  baseline. Drift and YARA hits are raised as alerts.

## Web API

All endpoints are on http://localhost:3000.

```
GET  /api/status            System telemetry, alert counts, scan summary
GET  /api/alerts            Active (unacked) alerts
POST /api/alerts/:id/ack    Acknowledge alert
POST /api/scan              Run package scan + AI detection
POST /api/feeds/refresh     Pull CISA KEV, ThreatFox, AbuseIPDB
GET  /api/feeds/status      Feed cache row counts
GET  /api/threats           AI threat detections + OSV findings
GET  /api/winevents         Windows Event Log (requires admin)
GET  /api/docker            Docker container list
GET  /api/connections       Active remote TCP IPs
POST /api/yara/scan         Run YARA scan + baseline comparison
POST /api/yara/update       Fetch latest YARA rules for this OS
GET  /api/baseline          Heuristic baseline summary
GET  /api/audit             Recent security audit-log entries

GET  /api/agent/status      PONCHO agent health, model, rules, chat state
GET  /api/agent/models      Available and installed local models
POST /api/agent/install     Install a local model through Ollama
POST /api/agent/update      Update an installed local model
POST /api/agent/scan-model  Scan a model manifest for suspicious content
GET  /api/agent/config      Read current PONCHO config
POST /api/agent/config      Save PONCHO config
GET  /api/agent/rules       Loaded PONCHO rule sets and active hits
POST /api/agent/chat        Chat with PONCHO using Legion context
POST /api/agent/hunt        Run a full blue-team hunt
GET  /api/agent/history     Current in-memory chat history
POST /api/agent/clear       Clear chat history
```

## PONCHO agent

PONCHO is the integrated blue-team threat hunter for Legion.

What it does:

- Hunts local, OWASP, NIST, CIS, development, and system vulnerabilities.
- Uses Legion alerts, package inventory, OSV findings, YARA matches, baseline drift, Windows events, Docker state, and active connections as its knowledge base.
- Supports local model management from the AGENT tab.
- Can install, update, and scan approved local models.
- Blocks DeepSeek models by policy.
- Uses read-only internet search for CVE and threat enrichment.
- Runs with read-only analysis intent and does not modify scanned code.

Current approved model list includes:

- qwen3:8b
- qwen3:4b
- qwen3:1.7b
- qwen2.5-coder:7b
- llama3.1:8b
- mistral:7b
- gemma3:4b
- phi4-mini:3.8b
- af-intel-analyst:v1

## Security model

Legion delegates access control to the operating system rather than an in-app
login. See [SECURITY.md](SECURITY.md) and the control mapping in
[COMPLIANCE.md](COMPLIANCE.md) (OWASP Top 10 / NIST 800-53 / SOC 2).

- **Loopback by default.** `legion-web` binds `127.0.0.1` (plain HTTP, on-host
  only), rejects non-loopback `Host` headers (DNS-rebinding guard), and emits no
  CORS headers. It also sets a strict security-header set, limits request bodies,
  and rate-limits. Override the bind only behind an authenticated reverse proxy:
  `legion-web --host 0.0.0.0` (logs a warning and disables the rebinding guard).
- **OS elevation prompt.** On launch, `legion-web` requests administrator rights
  via the native prompt (UAC / polkit / `osascript`) so it can read privileged
  telemetry. Skip with `--no-elevate` or `LEGION_NO_ELEVATE=1`. The TUI prints an
  elevation hint instead of relaunching (it shares your terminal).
- **Owner-only data.** The database, config, and cached rules are created
  `0600`/`0700` on Unix.
- **Audit trail.** Sensitive actions are recorded to an `audit_log` table and
  structured logs; read recent entries at `GET /api/audit`.

## Data location

| Platform | Path |
|----------|------|
| Windows  | `%APPDATA%\legion\legion.db` |
| Linux    | `~/.local/share/legion/legion.db` |
| macOS    | `~/.local/share/legion/legion.db` |

## TUI keys

| Key   | Action |
|-------|--------|
| `r`   | Full refresh (feeds + scan) |
| `s`   | Scan packages |
| `a`   | Acknowledge selected alert |
| `j/k` | Navigate alerts |
| `q`   | Quit |

## License

MIT
