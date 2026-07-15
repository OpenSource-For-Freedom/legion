//! Legion CLI – package & IP security monitor
//!
//! Subcommands:
//!   scan [PATH]                    Scan packages in PATH (default: current dir)
//!   watch [--interval N]           Run continuous background scans
//!   alerts [--acked]               List active (or acknowledged) alerts
//!   ack <ID>                       Acknowledge an alert
//!   quarantine list                List quarantined packages
//!   quarantine add <ECOSYSTEM> <NAME> [VERSION]
//!   quarantine release <ID>        Release a quarantine entry
//!   status                         Summary of feeds, alerts, packages
//!   feeds refresh                  Pull latest threat feeds and persist them

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};

use legion_core::{
    alerts::AlertEngine, baseline, data_dir, feeds::FeedManager, quarantine::QuarantineManager,
    scanner::PackageScanner, yara::YaraManager, Database,
};

// ─────────────────────────────── CLI Definition ─────────────────────────────

#[derive(Parser)]
#[command(
    name = "legion",
    about = "Legion SIEM/SOAR – local machine & server security monitor",
    long_about = None,
    version
)]
struct Cli {
    /// Set log verbosity (error|warn|info|debug|trace).
    #[arg(long, global = true, default_value = "warn", env = "LEGION_LOG")]
    log: String,

    /// Override database path.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan packages in a directory for CVE matches.
    Scan {
        /// Directory to scan. Omit to inventory packages across every fixed drive.
        path: Option<PathBuf>,
    },

    /// Run continuous scans on an interval.
    Watch {
        /// Scan interval in seconds.
        #[arg(short, long, default_value = "300")]
        interval: u64,

        /// Directory to scan. Omit to scan every fixed drive each pass.
        path: Option<PathBuf>,
    },

    /// List alerts.
    Alerts {
        /// Also show acknowledged alerts.
        #[arg(long)]
        acked: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Acknowledge an alert by ID.
    Ack {
        /// Alert ID to acknowledge.
        id: i64,
    },

    /// Manage the package quarantine list.
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCmd,
    },

    /// Show summary status.
    Status,

    /// Refresh threat feeds from the DEFCON Database.
    Feeds {
        #[command(subcommand)]
        cmd: FeedsCmd,
    },

    /// YARA file scanning and dynamic rule management.
    Yara {
        #[command(subcommand)]
        cmd: YaraCmd,
    },

    /// Heuristic baseline (captured on first launch, diffed thereafter).
    Baseline {
        #[command(subcommand)]
        cmd: BaselineCmd,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List all quarantine entries.
    List,
    /// Add a package to quarantine.
    Add {
        ecosystem: String,
        name: String,
        version: Option<String>,
        #[arg(short, long, default_value = "manual")]
        reason: String,
    },
    /// Release (un-flag) a quarantine entry.
    Release { id: i64 },
    /// Show remediation command for a quarantined package.
    Remediate { ecosystem: String, name: String },
}

#[derive(Subcommand)]
enum FeedsCmd {
    /// Refresh all feeds.
    Refresh,
    /// Show feed cache stats.
    Status,
}

#[derive(Subcommand)]
enum YaraCmd {
    /// Scan a path with the active rule set for this OS.
    Scan {
        /// File or directory to scan (default: configured scan paths).
        path: Option<PathBuf>,
    },
    /// Fetch the latest rules for this OS from the configured rules repo.
    Update,
    /// Show how many rules are loaded and any parse warnings.
    Rules,
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Run a heuristic scan: capture baseline on first run, diff thereafter.
    Run {
        /// Directory to inventory for packages (default: current dir).
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show the stored baseline summary.
    Show,
}

// ─────────────────────────────── Entry Point ────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match legion_core::ensure_elevated(
        "Legion needs administrator rights at startup to scan and inspect privileged telemetry.",
    ) {
        legion_core::Elevation::AlreadyElevated => {}
        legion_core::Elevation::Relaunched => return Ok(()),
        legion_core::Elevation::Skipped(why) => {
            tracing::warn!("startup elevation skipped: {why}");
        }
        legion_core::Elevation::Failed(why) => {
            return Err(anyhow!("administrator approval required: {why}"));
        }
    }

    // Logging
    fmt()
        .with_env_filter(EnvFilter::new(&cli.log))
        .without_time()
        .init();

    // Database
    let db_path = cli.db.unwrap_or_else(|| data_dir().join("legion.db"));
    let db = Database::open(&db_path)?;

    match cli.command {
        // ── scan ────────────────────────────────────────────────────────────
        Commands::Scan { path } => {
            cmd_scan(&db, path.as_deref()).await?;
        }

        // ── watch ───────────────────────────────────────────────────────────
        Commands::Watch { interval, path } => {
            let target = path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "all fixed drives".to_string());
            println!("Watching {target} every {interval}s (Ctrl+C to stop)");
            loop {
                cmd_scan(&db, path.as_deref()).await?;
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
            }
        }

        // ── alerts ──────────────────────────────────────────────────────────
        Commands::Alerts { acked, json } => {
            let filter = if acked { None } else { Some(false) };
            let alerts = db.get_alerts(filter)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&alerts)?);
            } else {
                print_alerts(&alerts);
            }
        }

        // ── ack ─────────────────────────────────────────────────────────────
        Commands::Ack { id } => {
            db.ack_alert(id)?;
            println!("Alert {id} acknowledged.");
        }

        // ── quarantine ───────────────────────────────────────────────────────
        Commands::Quarantine { cmd } => match cmd {
            QuarantineCmd::List => {
                let qm = QuarantineManager::new(db);
                let entries = qm.list()?;
                if entries.is_empty() {
                    println!("No quarantine entries.");
                } else {
                    println!(
                        "{:<5} {:<10} {:<30} {:<12} STATUS",
                        "ID", "ECOSYSTEM", "NAME", "VERSION"
                    );
                    for e in &entries {
                        let status = if e.is_active() { "ACTIVE" } else { "released" };
                        println!(
                            "{:<5} {:<10} {:<30} {:<12} {}",
                            e.id,
                            e.ecosystem,
                            e.name,
                            e.version.as_deref().unwrap_or("-"),
                            status
                        );
                    }
                }
            }
            QuarantineCmd::Add {
                ecosystem,
                name,
                version,
                reason,
            } => {
                let qm = QuarantineManager::new(db);
                let id = qm.quarantine(&ecosystem, &name, version.as_deref(), &reason)?;
                println!("Quarantined {ecosystem}/{name} (id={id})");
                println!(
                    "Remediation: {}",
                    QuarantineManager::remediation_cmd(&ecosystem, &name, None).remove
                );
            }
            QuarantineCmd::Release { id } => {
                let qm = QuarantineManager::new(db);
                qm.release(id)?;
                println!("Quarantine entry {id} released.");
            }
            QuarantineCmd::Remediate { ecosystem, name } => {
                let rem = QuarantineManager::remediation_cmd(&ecosystem, &name, None);
                if let Some(update) = rem.update {
                    println!("{update}");
                }
                println!("{}", rem.remove);
            }
        },

        // ── status ───────────────────────────────────────────────────────────
        Commands::Status => {
            let events = db.count_events()?;
            let active = db.count_active_alerts()?;
            let stats = legion_core::telemetry::collect();
            println!("LEGION SIEM — STATUS");
            println!("────────────────────────────────────");
            println!("  DB:             {}", db_path.display());
            println!("  Cyber events:   {events}");
            println!("  Active alerts:  {active}");
            println!("  CPU:            {:.1}%", stats.cpu_pct);
            println!(
                "  Memory:         {} / {} MB",
                stats.mem_used_mb, stats.mem_total_mb
            );
            println!("  Processes:      {}", stats.proc_count);
        }

        // ── feeds ────────────────────────────────────────────────────────────
        Commands::Feeds { cmd } => match cmd {
            FeedsCmd::Refresh => {
                cmd_feeds_refresh(&db).await?;
            }
            FeedsCmd::Status => {
                let n = db.count_events()?;
                println!("Cached cyber events: {n}");
            }
        },

        // ── yara ─────────────────────────────────────────────────────────────
        Commands::Yara { cmd } => match cmd {
            YaraCmd::Scan { path } => {
                let mgr = YaraManager::load(data_dir());
                let (engine, warnings) = mgr.build_engine();
                for w in &warnings {
                    eprintln!("  warn: {w}");
                }
                let roots = match path {
                    Some(p) => vec![p],
                    None => mgr.scan_paths(),
                };
                println!(
                    "YARA: {} rule(s) loaded, scanning {} path(s)...",
                    engine.rule_count(),
                    roots.len()
                );
                let matches = engine.scan_paths(
                    &roots,
                    mgr.config.max_file_size_bytes(),
                    mgr.config.effective_max_files(),
                );
                if matches.is_empty() {
                    println!("  No YARA matches.");
                } else {
                    db.save_yara_matches(&matches)?;
                    let alerts = AlertEngine::from_yara_matches(&matches);
                    if !alerts.is_empty() {
                        db.save_alerts(&alerts)?;
                    }
                    println!("  {} match(es):", matches.len());
                    for m in &matches {
                        println!("    [{}] {} — {}", m.severity, m.rule, m.target);
                    }
                }
            }
            YaraCmd::Update => {
                let mgr = YaraManager::load(data_dir());
                println!(
                    "Updating YARA rules for {} ...",
                    legion_core::yara::current_os()
                );
                let report = mgr.update_rules().await;
                println!("  fetched: {}, failed: {}", report.fetched, report.failed);
                for f in &report.files {
                    println!("    + {f}");
                }
                for e in &report.errors {
                    eprintln!("    warn: {e}");
                }
            }
            YaraCmd::Rules => {
                let mgr = YaraManager::load(data_dir());
                let (engine, warnings) = mgr.build_engine();
                println!(
                    "YARA rules loaded for {}: {}",
                    legion_core::yara::current_os(),
                    engine.rule_count()
                );
                for w in &warnings {
                    eprintln!("  warn: {w}");
                }
            }
        },

        // ── baseline ───────────────────────────────────────────────────────────
        Commands::Baseline { cmd } => match cmd {
            BaselineCmd::Run { path } => {
                let mgr = YaraManager::load(data_dir());
                let outcome = baseline::run(&db, &mgr, &path)?;
                print_baseline_outcome(&outcome);
            }
            BaselineCmd::Show => {
                if let Some(b) = db.get_latest_baseline()? {
                    println!("Baseline ({}) captured {}", b.os, b.created_at);
                    println!("  processes: {}", b.process_names.len());
                    println!("  remote IPs: {}", b.remote_ips.len());
                    println!("  packages: {}", b.packages.len());
                    println!("  YARA rules hit: {}", b.yara_rules_hit.len());
                } else {
                    println!(
                        "No baseline captured yet. Run `legion baseline run` or `legion scan`."
                    );
                }
            }
        },
    }

    Ok(())
}

// ─────────────────────────────── Helpers ────────────────────────────────────

async fn cmd_scan(db: &Database, path: Option<&Path>) -> Result<()> {
    // 1. Package inventory. With an explicit path, scope the scan to it;
    //    otherwise inventory every fixed drive on the host.
    let scan = match path {
        Some(p) => {
            println!("Scanning {} for packages...", p.display());
            PackageScanner::scan(p)
        }
        None => {
            println!("Scanning all fixed drives for packages...");
            PackageScanner::scan_system()
        }
    };
    println!(
        "  Packages found: {} cargo, {} npm, {} pip",
        scan.cargo_count(),
        scan.npm_count(),
        scan.pip_count()
    );
    if !scan.errors.is_empty() {
        for err in &scan.errors {
            eprintln!("  warn: {err}");
        }
    }
    db.save_scan(&scan.packages)?;

    // 2. Load cached events (or fetch if none)
    let events = {
        let cached = db.count_events()?;
        if cached == 0 {
            println!("  No cached events — pulling feed...");
            let fm = FeedManager::new()?;
            let evs = fm.fetch_cyber_events().await?;
            db.upsert_events(&evs)?;
            evs
        } else {
            // Use cached data for fast offline scan
            // For full refresh run: legion feeds refresh
            vec![]
        }
    };

    // 3. Correlate
    let alerts = AlertEngine::correlate(&scan.packages, &events);
    if alerts.is_empty() {
        println!("  No CVE matches found.");
    } else {
        println!("  {} alert(s) generated:", alerts.len());
        db.save_alerts(&alerts)?;
        print_alerts(&alerts);
    }

    // 4. Heuristic baseline + YARA. On first launch this establishes the
    //    baseline (the heuristic model); subsequent scans diff against it.
    let mgr = YaraManager::load(data_dir());
    let outcome = match path {
        Some(p) => baseline::run_scoped(db, &mgr, p),
        None => baseline::run(db, &mgr, Path::new(".")),
    };
    match outcome {
        Ok(outcome) => print_baseline_outcome(&outcome),
        Err(e) => eprintln!("  warn: baseline/yara scan failed: {e}"),
    }

    Ok(())
}

fn print_baseline_outcome(outcome: &legion_core::ScanOutcome) {
    for w in &outcome.warnings {
        eprintln!("  warn: yara rule: {w}");
    }
    if outcome.baseline_created {
        println!(
            "  Baseline established ({} YARA rules loaded). Future scans compare against it.",
            outcome.rules_loaded
        );
    } else {
        println!(
            "  Baseline comparison: {} drift item(s), {} YARA match(es).",
            outcome.drifts.len(),
            outcome.yara_matches.len()
        );
    }
    for m in &outcome.yara_matches {
        if m.severity != "Info" {
            println!("    YARA [{}] {} — {}", m.severity, m.rule, m.target);
        }
    }
    for d in &outcome.drifts {
        println!("    DRIFT [{}] {}", d.severity, d.detail);
    }
}

async fn cmd_feeds_refresh(db: &Database) -> Result<()> {
    let fm = FeedManager::new()?;

    print!("Fetching cyber events... ");
    let events = fm.fetch_cyber_events().await?;
    let n = db.upsert_events(&events)?;
    println!("{n} events cached.");

    print!("Fetching AbuseIPDB blacklist... ");
    match fm.fetch_abuseips().await {
        Ok(payload) => {
            db.upsert_ips(&payload.ips)?;
            println!("{} IPs cached.", payload.ips.len());
        }
        Err(e) => eprintln!("warn: {e}"),
    }

    Ok(())
}

fn print_alerts(alerts: &[legion_core::alerts::Alert]) {
    if alerts.is_empty() {
        println!("No alerts.");
        return;
    }
    println!(
        "{:<5} {:<6} {:<16} {:<40} CREATED",
        "ID", "SEV", "TYPE", "TITLE"
    );
    println!("{}", "─".repeat(100));
    for a in alerts {
        println!(
            "{:<5} {:<6} {:<16} {:<40} {}",
            a.id,
            a.severity.label(),
            a.kind_str(),
            truncate(&a.title, 38),
            &a.created_at[..19],
        );
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
