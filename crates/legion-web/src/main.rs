//! Legion Web – browser-based SIEM dashboard served over HTTP.
//!
//! Usage:
//!   legion-web [--port 3000] [--scan-root .] [--db <path>]

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{fmt, EnvFilter};

use legion_core::{
    ai_detector::AiDetector, alerts::AlertEngine, baseline, data_dir, feeds::FeedManager,
    scanner::PackageScanner, telemetry, threat_intel, yara::YaraManager, AiThreat, Database,
    DockerInfo, OsvFinding, WinEvent,
};

// ─────────────────────────────── CLI args ───────────────────────────────────

#[derive(Parser)]
#[command(name = "legion-web", about = "Legion SIEM – browser dashboard")]
struct Args {
    /// HTTP port to listen on.
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Root directory to scan for packages.
    #[arg(short, long, default_value = ".")]
    scan_root: PathBuf,

    /// Override database path.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Do not open browser automatically.
    #[arg(long)]
    no_open: bool,
}

// ─────────────────────────────── Shared state ───────────────────────────────

/// Stores the previous network sample for delta (rate) calculation.
struct NetSample {
    rx_bytes: u64,
    tx_bytes: u64,
    at: Instant,
}

#[derive(Clone)]
struct AppState {
    db: Database,
    scan_root: PathBuf,
    /// Previous raw network byte counters — used to compute KB/s rates.
    net_prev: Arc<Mutex<Option<NetSample>>>,
}

// ─────────────────────────────── Error type ─────────────────────────────────

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

type AResult<T> = std::result::Result<T, AppError>;

// ─────────────────────────────── Response types ─────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    cpu_pct: f32,
    mem_used_mb: u64,
    mem_total_mb: u64,
    proc_count: usize,
    net_rx_kb: u64,
    net_tx_kb: u64,
    load_avg_1: f64,
    // Alerts
    alerts_total: i64,
    alerts_critical: i64,
    ip_threats: i64,
    // Scan summary
    cargo_pkgs: i64,
    npm_pkgs: i64,
    pip_pkgs: i64,
    last_scan: String,
    // Feed cache
    feeds_events: i64,
    feeds_ips: i64,
}

#[derive(Serialize)]
struct WinEventsResponse {
    events: Vec<WinEvent>,
    admin_required: bool,
}

#[derive(Serialize)]
struct ScanResponse {
    alerts_generated: usize,
    cargo: usize,
    npm: usize,
    pip: usize,
    ai_findings: usize,
    osv_findings: usize,
    yara_matches: usize,
    baseline_created: bool,
    drift: usize,
}

#[derive(Serialize)]
struct YaraScanResponse {
    rules_loaded: usize,
    yara_matches: usize,
    baseline_created: bool,
    drift: usize,
    warnings: usize,
}

#[derive(Serialize)]
struct BaselineResponse {
    captured: bool,
    os: String,
    created_at: String,
    processes: usize,
    remote_ips: usize,
    packages: usize,
    yara_rules_hit: usize,
}

#[derive(Serialize)]
struct FeedResponse {
    events: usize,
    ips: usize,
    kev: usize,
    threatfox: usize,
}

#[derive(Serialize)]
struct ThreatsResponse {
    ai_threats: Vec<AiThreat>,
    osv_findings: Vec<OsvFinding>,
    ai_critical: usize,
    ai_high: usize,
    osv_total: usize,
    kev_total: i64,
    threatfox_total: i64,
}

// ─────────────────────────────── Handlers ───────────────────────────────────

/// Serve the embedded HTML dashboard.
async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

/// GET /api/status — telemetry + alert counts + scan summary.
async fn api_status(State(s): State<Arc<AppState>>) -> AResult<Json<StatusResponse>> {
    // Collect CPU/mem/proc stats and raw net bytes concurrently.
    let (stats_res, net_res) = tokio::join!(
        tokio::task::spawn_blocking(telemetry::collect),
        tokio::task::spawn_blocking(telemetry::collect_net_raw),
    );
    let stats = stats_res?;
    let (rx_raw, tx_raw): (u64, u64) = net_res?;

    // Compute KB/s net rate from delta against previous sample.
    let now = Instant::now();
    let (net_rx_kb, net_tx_kb) = {
        let mut prev = s.net_prev.lock().unwrap();
        let rate = if let Some(ref p) = *prev {
            let elapsed = now.duration_since(p.at).as_secs_f64().max(0.5);
            let rx_diff: u64 = rx_raw.saturating_sub(p.rx_bytes);
            let tx_diff: u64 = tx_raw.saturating_sub(p.tx_bytes);
            (
                (rx_diff as f64 / elapsed / 1024.0) as u64,
                (tx_diff as f64 / elapsed / 1024.0) as u64,
            )
        } else {
            (0, 0)
        };
        *prev = Some(NetSample {
            rx_bytes: rx_raw,
            tx_bytes: tx_raw,
            at: now,
        });
        rate
    };

    let alerts_total = s.db.count_active_alerts()?;
    let ip_threats = s.db.count_alerts_by_kind("IP Blacklist")?;

    let all_active = s.db.get_alerts(Some(false))?;
    let alerts_critical = all_active
        .iter()
        .filter(|a| matches!(a.severity, legion_core::alerts::Severity::Critical))
        .count() as i64;

    let scan = s.db.get_scan_summary()?;
    let feeds_events = s.db.count_events()?;
    let feeds_ips = s.db.count_cached_ips().unwrap_or(0);

    Ok(Json(StatusResponse {
        cpu_pct: stats.cpu_pct,
        mem_used_mb: stats.mem_used_mb,
        mem_total_mb: stats.mem_total_mb,
        proc_count: stats.proc_count,
        net_rx_kb,
        net_tx_kb,
        load_avg_1: stats.load_avg_1,
        alerts_total,
        alerts_critical,
        ip_threats,
        cargo_pkgs: scan.cargo,
        npm_pkgs: scan.npm,
        pip_pkgs: scan.pip,
        last_scan: scan.last_scan.unwrap_or_else(|| "never".into()),
        feeds_events,
        feeds_ips,
    }))
}

/// GET /api/docker — container list with live stats.
async fn api_docker() -> AResult<Json<Vec<DockerInfo>>> {
    let containers = tokio::task::spawn_blocking(telemetry::collect_docker).await?;
    Ok(Json(containers))
}

/// GET /api/connections — active remote TCP IPs.
async fn api_connections() -> AResult<Json<Vec<String>>> {
    let ips = tokio::task::spawn_blocking(telemetry::active_remote_ips).await?;
    Ok(Json(ips))
}

/// GET /api/winevents — recent Windows Security / System / Application log entries.
async fn api_win_events() -> AResult<Json<WinEventsResponse>> {
    let events = tokio::task::spawn_blocking(|| telemetry::collect_win_events(75)).await?;
    let admin_required = events.is_empty();
    Ok(Json(WinEventsResponse {
        events,
        admin_required,
    }))
}

/// GET /api/alerts — all unacked alerts.
async fn api_alerts(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<Vec<legion_core::alerts::Alert>>> {
    let alerts = s.db.get_alerts(Some(false))?;
    Ok(Json(alerts))
}

/// POST /api/alerts/:id/ack
async fn api_ack(Path(id): Path<i64>, State(s): State<Arc<AppState>>) -> AResult<StatusCode> {
    s.db.ack_alert(id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/feeds/refresh — pull all feeds: cyber events, AbuseIPDB, CISA KEV, ThreatFox.
async fn api_feeds_refresh(State(s): State<Arc<AppState>>) -> AResult<Json<FeedResponse>> {
    let fm = FeedManager::new()?;

    // Run all feed fetches concurrently
    let (evs_res, ips_res, kev_res, tf_res) = tokio::join!(
        fm.fetch_cyber_events(),
        fm.fetch_abuseips(),
        threat_intel::fetch_kev(),
        threat_intel::fetch_threatfox(3),
    );

    let ev_count = match evs_res {
        Ok(evs) => {
            let n = evs.len();
            s.db.upsert_events(&evs)?;
            n
        }
        Err(e) => {
            tracing::warn!("cyber events fetch failed: {e}");
            0
        }
    };
    let ip_count = match ips_res {
        Ok(payload) => {
            let n = payload.ips.len();
            s.db.upsert_ips(&payload.ips)?;
            n
        }
        Err(e) => {
            tracing::warn!("AbuseIPDB fetch failed: {e}");
            0
        }
    };
    let kev_count = match kev_res {
        Ok(entries) => {
            let n = entries.len();
            s.db.save_kev_entries(&entries)?;
            n
        }
        Err(e) => {
            tracing::warn!("CISA KEV fetch failed: {e}");
            0
        }
    };
    let tf_count = match tf_res {
        Ok(iocs) => {
            let n = iocs.len();
            s.db.save_threatfox_iocs(&iocs)?;
            n
        }
        Err(e) => {
            tracing::warn!("ThreatFox fetch failed: {e}");
            0
        }
    };

    Ok(Json(FeedResponse {
        events: ev_count,
        ips: ip_count,
        kev: kev_count,
        threatfox: tf_count,
    }))
}

/// POST /api/scan — scan packages, run AI detection, correlate alerts, query OSV.
async fn api_scan(State(s): State<Arc<AppState>>) -> AResult<Json<ScanResponse>> {
    let db = s.db.clone();
    let root = s.scan_root.clone();

    // Phase 1: blocking scan + AI detection + alert correlation
    let (packages, alerts, ai_threats, cargo, npm, pip) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let scan = PackageScanner::scan(&root);
            let cargo = scan.cargo_count();
            let npm = scan.npm_count();
            let pip = scan.pip_count();
            db.save_scan(&scan.packages)?;

            // AI detection: packages + running processes
            let mut ai = AiDetector::scan_packages(&scan.packages);
            ai.extend(AiDetector::scan_processes());
            if !ai.is_empty() {
                db.save_ai_detections(&ai)?;
            }

            let events = db.get_events()?;
            let alerts = AlertEngine::correlate(&scan.packages, &events);
            if !alerts.is_empty() {
                db.save_alerts(&alerts)?;
            }

            Ok((scan.packages, alerts, ai, cargo, npm, pip))
        })
        .await??;

    let alert_count = alerts.len();
    let ai_count = ai_threats.len();

    // Phase 2: async OSV query (background — doesn't block the response)
    let db2 = s.db.clone();
    let pkgs = packages.clone();
    tokio::spawn(async move {
        match threat_intel::query_osv(&pkgs).await {
            Ok(findings) if !findings.is_empty() => {
                let n = findings.len();
                if let Err(e) = db2.save_osv_vulns(&findings) {
                    tracing::warn!("OSV save failed: {e}");
                } else {
                    tracing::info!("OSV: {n} findings cached");
                }
            }
            Err(e) => tracing::warn!("OSV query failed: {e}"),
            _ => {}
        }
    });

    let osv_total = s.db.count_osv_vulns().unwrap_or(0) as usize;

    // Phase 3: heuristic baseline + YARA scan (blocking). Establishes the
    // baseline on first run, diffs against it thereafter.
    let db3 = s.db.clone();
    let root3 = s.scan_root.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mgr = YaraManager::load(data_dir());
        baseline::run(&db3, &mgr, &root3)
    })
    .await?
    .unwrap_or_default();

    Ok(Json(ScanResponse {
        alerts_generated: alert_count,
        cargo,
        npm,
        pip,
        ai_findings: ai_count,
        osv_findings: osv_total,
        yara_matches: outcome.yara_matches.len(),
        baseline_created: outcome.baseline_created,
        drift: outcome.drifts.len(),
    }))
}

/// POST /api/yara/scan — build the OS rule set, scan configured paths, and run
/// the baseline comparison.
async fn api_yara_scan(State(s): State<Arc<AppState>>) -> AResult<Json<YaraScanResponse>> {
    let db = s.db.clone();
    let root = s.scan_root.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mgr = YaraManager::load(data_dir());
        baseline::run(&db, &mgr, &root)
    })
    .await??;

    Ok(Json(YaraScanResponse {
        rules_loaded: outcome.rules_loaded,
        yara_matches: outcome.yara_matches.len(),
        baseline_created: outcome.baseline_created,
        drift: outcome.drifts.len(),
        warnings: outcome.warnings.len(),
    }))
}

/// POST /api/yara/update — fetch the latest rules for this OS from the repo.
async fn api_yara_update() -> AResult<Json<legion_core::UpdateReport>> {
    let mgr = YaraManager::load(data_dir());
    let report = mgr.update_rules().await;
    Ok(Json(report))
}

/// GET /api/baseline — summary of the stored heuristic baseline.
async fn api_baseline(State(s): State<Arc<AppState>>) -> AResult<Json<BaselineResponse>> {
    match s.db.get_latest_baseline()? {
        Some(b) => Ok(Json(BaselineResponse {
            captured: true,
            os: b.os,
            created_at: b.created_at,
            processes: b.process_names.len(),
            remote_ips: b.remote_ips.len(),
            packages: b.packages.len(),
            yara_rules_hit: b.yara_rules_hit.len(),
        })),
        None => Ok(Json(BaselineResponse {
            captured: false,
            os: legion_core::yara::current_os().to_string(),
            created_at: String::new(),
            processes: 0,
            remote_ips: 0,
            packages: 0,
            yara_rules_hit: 0,
        })),
    }
}

/// GET /api/threats — return cached AI detections + OSV findings + feed counts.
async fn api_threats(State(s): State<Arc<AppState>>) -> AResult<Json<ThreatsResponse>> {
    let ai_threats = s.db.get_ai_detections().unwrap_or_default();
    let osv_findings = s.db.get_osv_vulns().unwrap_or_default();
    let kev_total = s.db.count_kev_entries().unwrap_or(0);
    let tf_total = s.db.count_threatfox_iocs().unwrap_or(0);

    let ai_critical = ai_threats
        .iter()
        .filter(|t| t.severity == "Critical")
        .count();
    let ai_high = ai_threats.iter().filter(|t| t.severity == "High").count();
    let osv_total = osv_findings.len();

    Ok(Json(ThreatsResponse {
        ai_threats,
        osv_findings,
        ai_critical,
        ai_high,
        osv_total,
        kev_total,
        threatfox_total: tf_total,
    }))
}

/// GET /api/feeds/status
async fn api_feeds_status(State(s): State<Arc<AppState>>) -> AResult<Json<serde_json::Value>> {
    let events = s.db.count_events()?;
    Ok(Json(serde_json::json!({ "events": events })))
}

// ─────────────────────────────── Main ───────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    fmt()
        .with_env_filter(EnvFilter::new("warn"))
        .without_time()
        .init();

    let db_path = args.db.unwrap_or_else(|| data_dir().join("legion.db"));
    let db = Database::open(&db_path)?;

    let state = Arc::new(AppState {
        db,
        scan_root: args.scan_root.canonicalize().unwrap_or(args.scan_root),
        net_prev: Arc::new(Mutex::new(None)),
    });

    // On launch, establish the heuristic baseline first if one does not yet
    // exist for this OS, so later scans have something to compare against.
    {
        let db = state.db.clone();
        let root = state.scan_root.clone();
        tokio::task::spawn_blocking(move || {
            if db.has_baseline().unwrap_or(false) {
                return;
            }
            let mgr = YaraManager::load(data_dir());
            match baseline::run(&db, &mgr, &root) {
                Ok(o) => {
                    tracing::info!("baseline established: {} YARA rules loaded", o.rules_loaded)
                }
                Err(e) => tracing::warn!("baseline capture failed: {e}"),
            }
        });
    }

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/status", get(api_status))
        .route("/api/alerts", get(api_alerts))
        .route("/api/alerts/:id/ack", post(api_ack))
        .route("/api/feeds/refresh", post(api_feeds_refresh))
        .route("/api/feeds/status", get(api_feeds_status))
        .route("/api/scan", post(api_scan))
        .route("/api/winevents", get(api_win_events))
        .route("/api/docker", get(api_docker))
        .route("/api/connections", get(api_connections))
        .route("/api/threats", get(api_threats))
        .route("/api/yara/scan", post(api_yara_scan))
        .route("/api/yara/update", post(api_yara_update))
        .route("/api/baseline", get(api_baseline))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&addr).await?;
    let url = format!("http://localhost:{}", args.port);

    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║  LEGION SIEM/SOAR  — Web Dashboard   ║");
    println!("  ╠══════════════════════════════════════╣");
    println!("  ║  {}  ║", url);
    println!("  ║  Ctrl+C to stop                      ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    if !args.no_open {
        let _ = open::that(&url);
    }

    axum::serve(listener, app).await?;
    Ok(())
}
