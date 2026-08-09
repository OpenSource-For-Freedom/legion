//! Detection benchmark: a labeled corpus run against REAL legion-core detection
//! code, reporting recall (real threats caught) and false-positive rate (benign
//! artifacts flagged), per category. Each case guards a specific audit fix, so a
//! future change cannot silently reopen a false positive or a missed alert.
//!
//! SAFETY: no live malware, ever. Every "flag" case is a SYNTHETIC artifact (a
//! crafted process/command/event/package) that reproduces only the signal the
//! detector keys on. The corpus is read-only ground truth: flipping an expected
//! label is a claim about reality and must be justified in the note.
//!
//! Run the scoreboard directly with:
//!   cargo test -p legion-core --test detection_benchmark -- --nocapture

use std::path::Path;

use legion_core::ai_detector::{is_version_before, AiDetector};
use legion_core::alerts::severity_from_label;
use legion_core::dprk;
use legion_core::{
    AbuseIpEntry, AbuseIpPayload, AlertEngine, Ecosystem, ScannedPackage, Severity, WinEvent,
    YaraEngine,
};

fn pkg(eco: Ecosystem, name: &str, ver: &str) -> ScannedPackage {
    ScannedPackage {
        ecosystem: eco,
        name: name.into(),
        version: Some(ver.into()),
        path: None,
    }
}

fn win_event(log: &str, msg: &str) -> WinEvent {
    WinEvent {
        time: String::new(),
        event_id: 0,
        level: String::new(),
        log_name: log.into(),
        message: msg.into(),
    }
}

struct Case {
    id: &'static str,
    category: &'static str,
    /// true = a real threat that MUST be flagged; false = benign, must stay quiet.
    expect_flag: bool,
    /// what the real detector actually did.
    got_flag: bool,
    note: &'static str,
}

fn corpus() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    macro_rules! case {
        ($id:expr, $cat:expr, $expect:expr, $got:expr, $note:expr) => {
            cases.push(Case {
                id: $id,
                category: $cat,
                expect_flag: $expect,
                got_flag: $got,
                note: $note,
            });
        };
    }

    // ── AI-SDK package detection ─────────────────────────────────────────────
    // langchain-experimental used a "0.0.0" fix sentinel; is_version_before(v,
    // "0.0.0") is never true, so the Critical rule fired for NO installed version.
    let langchain =
        AiDetector::scan_packages(&[pkg(Ecosystem::Pip, "langchain-experimental", "0.3.4")]);
    case!(
        "ai-langchain-experimental",
        "ai",
        true,
        !langchain.is_empty(),
        "langchain-experimental at a real version must be flagged (0.0.0 sentinel matched nothing)"
    );
    let benign_pkg = AiDetector::scan_packages(&[pkg(Ecosystem::Npm, "left-pad", "1.3.0")]);
    case!(
        "ai-benign-quiet",
        "ai",
        false,
        !benign_pkg.is_empty(),
        "an ordinary non-AI package must not be flagged"
    );

    // ── version comparison is numeric, not substring ─────────────────────────
    case!(
        "ver-vulnerable",
        "ai",
        true,
        is_version_before("7.5.1", "7.5.10"),
        "7.5.1 is genuinely before 7.5.10"
    );
    case!(
        "ver-patched-quiet",
        "ai",
        false,
        is_version_before("7.5.10", "7.5.1"),
        "patched 7.5.10 must NOT compare as before 7.5.1 (no substring drift)"
    );

    // ── DPRK: VS Code TasksJacker ────────────────────────────────────────────
    let curl_task = r#"{"tasks":[{"command":"curl","args":["http://x/y"],"runOptions":{"runOn":"folderOpen"}}]}"#;
    case!(
        "dprk-vscode-curl",
        "dprk",
        true,
        dprk::scan_vscode_tasks(Path::new("/x/.vscode/tasks.json"), curl_task).is_some(),
        "a folderOpen task that runs curl is a TasksJacker payload"
    );
    let base64_task = r#"{"tasks":[{"command":"node","args":["scripts/gen-base64-assets.js"],"runOptions":{"runOn":"folderOpen"}}]}"#;
    case!(
        "dprk-vscode-base64-benign",
        "dprk",
        false,
        dprk::scan_vscode_tasks(Path::new("/x/.vscode/tasks.json"), base64_task).is_some(),
        "a benign task whose arg merely contains 'base64' must not be flagged"
    );

    // ── DPRK: interpreter running from staging dir ───────────────────────────
    let deno_proc = vec![(
        "deno".to_string(),
        "deno run /home/u/.n2/beacon.js".to_string(),
    )];
    case!(
        "dprk-deno-staging",
        "dprk",
        true,
        !dprk::scan_process_cmdlines(&deno_proc).is_empty(),
        "a deno process executing from .n2/ staging must be flagged"
    );
    let clean_proc = vec![(
        "node".to_string(),
        "node /home/u/project/index.js".to_string(),
    )];
    case!(
        "dprk-clean-node",
        "dprk",
        false,
        !dprk::scan_process_cmdlines(&clean_proc).is_empty(),
        "an ordinary node process must not be flagged"
    );

    // ── network: confirmed C2 must not be down-rated below High ──────────────
    let blacklist = AbuseIpPayload {
        ok: true,
        configured: true,
        generated_at: String::new(),
        source: "test".into(),
        ips: vec![AbuseIpEntry {
            ip: "45.9.9.9".into(),
            country: None,
            abuse_score: Some(20),
            last_reported: None,
            malware: Some("Emotet".into()),
            c2_status: Some("online".into()),
        }],
    };
    let c2 = AlertEngine::check_ips(&["45.9.9.9".to_string()], &blacklist);
    let c2_high_or_worse = c2
        .iter()
        .any(|a| matches!(a.severity, Severity::High | Severity::Critical));
    case!(
        "c2-low-score-floored",
        "network",
        true,
        c2_high_or_worse,
        "a listed C2 with a modest abuse_score (20) must stay >= High, not drop to Low/Info"
    );

    // ── events: userland segfault is Medium, not a Critical kernel panic ──────
    let seg = AlertEngine::from_local_events(&[win_event(
        "kernel",
        "app[123]: segfault at 0 ip 000000 sp 000000 error 4",
    )]);
    let seg_medium_no_critical = seg.iter().any(|a| matches!(a.severity, Severity::Medium))
        && !seg.iter().any(|a| matches!(a.severity, Severity::Critical));
    case!(
        "segfault-medium-not-critical",
        "events",
        true,
        seg_medium_no_critical,
        "a userland segfault surfaces as Medium, never a Critical kernel-panic false positive"
    );

    // ── events: Legion's own status narration must not self-alert ────────────
    let noise = AlertEngine::from_local_events(&[win_event(
        "legion-monitor",
        "Checking kernel modules...",
    )]);
    case!(
        "scanner-noise-quiet",
        "events",
        false,
        !noise.is_empty(),
        "Legion's own 'Checking kernel modules...' status line must not raise an alert"
    );

    // ── events: syslog 'error' must not be Critical ──────────────────────────
    case!(
        "severity-error-not-critical",
        "events",
        false,
        severity_from_label("error") == Severity::Critical,
        "an ordinary syslog error-level label must not map to Critical"
    );

    // ── yara: an empty rule feed compiles to zero rules (drives the reject) ──
    let (real_engine, _) = YaraEngine::compile(&[(
        "t.yar",
        "rule t { strings: $a = \"malware\" condition: $a }",
    )]);
    case!(
        "yara-real-rule-loads",
        "yara",
        true,
        real_engine.rule_count() >= 1,
        "a valid rule file compiles to >= 1 rule"
    );
    let (empty_engine, _) = YaraEngine::compile(&[("empty.yar", "   \n# comment only\n")]);
    case!(
        "yara-empty-zero-rules",
        "yara",
        false,
        empty_engine.rule_count() >= 1,
        "an empty/comment-only feed must compile to 0 rules so the reject guard triggers"
    );

    cases
}

#[test]
fn detection_benchmark_no_missed_alerts_or_false_positives() {
    use std::collections::BTreeMap;

    let cases = corpus();
    assert!(
        !cases.is_empty(),
        "benchmark ran 0 cases: a gate that tests nothing is not a pass"
    );

    // (tp, fn, fp, tn) per category
    let mut per: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    let mut missed: Vec<&Case> = Vec::new();
    let mut false_pos: Vec<&Case> = Vec::new();

    for c in &cases {
        let slot = per.entry(c.category).or_default();
        match (c.expect_flag, c.got_flag) {
            (true, true) => slot[0] += 1,
            (true, false) => {
                slot[1] += 1;
                missed.push(c);
            }
            (false, true) => {
                slot[2] += 1;
                false_pos.push(c);
            }
            (false, false) => slot[3] += 1,
        }
    }

    let pct = |n: usize, d: usize| -> String {
        if d == 0 {
            "n/a".to_string()
        } else {
            format!("{:.1}%", (n as f64) * 100.0 / (d as f64))
        }
    };

    println!("\n==================== LEGION DETECTION BENCHMARK ====================");
    println!(
        "{:<12}{:>10}{:>10}{:>5}{:>5}{:>5}{:>5}",
        "category", "recall", "fp-rate", "tp", "fn", "fp", "tn"
    );
    let (mut tp, mut fnn, mut fp, mut tn) = (0, 0, 0, 0);
    for (cat, s) in &per {
        tp += s[0];
        fnn += s[1];
        fp += s[2];
        tn += s[3];
        println!(
            "{:<12}{:>10}{:>10}{:>5}{:>5}{:>5}{:>5}",
            cat,
            pct(s[0], s[0] + s[1]),
            pct(s[2], s[2] + s[3]),
            s[0],
            s[1],
            s[2],
            s[3]
        );
    }
    println!(
        "{:<12}{:>10}{:>10}{:>5}{:>5}{:>5}{:>5}",
        "OVERALL",
        pct(tp, tp + fnn),
        pct(fp, fp + tn),
        tp,
        fnn,
        fp,
        tn
    );
    println!("cases={} (guarding audit fixes)", cases.len());
    println!("====================================================================\n");

    for c in &missed {
        println!("MISSED ALERT: {} ({}) - {}", c.id, c.category, c.note);
    }
    for c in &false_pos {
        println!("FALSE POSITIVE: {} ({}) - {}", c.id, c.category, c.note);
    }

    assert!(
        missed.is_empty(),
        "{} missed alert(s): {:?}",
        missed.len(),
        missed.iter().map(|c| c.id).collect::<Vec<_>>()
    );
    assert!(
        false_pos.is_empty(),
        "{} false positive(s): {:?}",
        false_pos.len(),
        false_pos.iter().map(|c| c.id).collect::<Vec<_>>()
    );
}
