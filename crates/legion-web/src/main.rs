//! Legion Web – browser-based SIEM dashboard served over HTTP.
//!
//! Usage:
//!   legion-web [--port 3000] [--scan-root .] [--db <path>]

use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

use legion_core::{
    ai_detector::AiDetector,
    alerts::{severity_from_label, Alert, AlertEngine, AlertKind},
    baseline, data_dir,
    feeds::FeedManager,
    privilege,
    runner::{RunnerCommandPlan, RunnerManager, RunnerStatus},
    scanner::PackageScanner,
    telemetry, threat_intel,
    yara::YaraManager,
    AiThreat, Database, DockerInfo, OsvFinding, WinEvent,
};
use legion_poncho::{
    bootstrap, ChatMessage, KnowledgeContext, ModelRegistry, ModelScanResult, OllamaState,
    PonchoChat, PonchoConfig, RuleHit, RuleSet,
};

// ─────────────────────────────── CLI args ───────────────────────────────────

#[derive(Parser)]
#[command(name = "legion-web", about = "Legion SIEM – browser dashboard")]
struct Args {
    /// HTTP port to listen on.
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Address to bind. Defaults to loopback; only change this if you front the
    /// dashboard with your own authenticated reverse proxy.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Root directory to scan for packages.
    #[arg(short, long, default_value = ".")]
    scan_root: PathBuf,

    /// Override database path.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Do not open browser automatically.
    #[arg(long)]
    no_open: bool,

    /// Do not request OS administrator elevation at startup.
    #[arg(long)]
    no_elevate: bool,

    /// Internal: privileged helper invoked via UAC to persist the PONCHO config
    /// from the given JSON file, then exit. Not for direct use.
    #[arg(long, hide = true)]
    apply_poncho_config: Option<PathBuf>,
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
    /// Poncho agent config (persisted to data_dir/poncho.json).
    poncho_config: Arc<Mutex<PonchoConfig>>,
    /// In-memory chat history (session-scoped, not persisted).
    chat_history: Arc<Mutex<Vec<ChatMessage>>>,
    /// Most recent PONCHO hunt report, surfaced on the dashboard. Session-scoped.
    last_hunt: Arc<Mutex<Option<legion_poncho::HuntReport>>>,
    /// When true, privileged config writes elevate through a UAC-prompting
    /// helper; when false they are written in-process (dev / `--no-elevate`).
    elevate_writes: bool,
    /// Per-process bearer token gating every `/api/*` route. Delivered to the
    /// browser as a SameSite=Strict cookie and accepted as `Authorization:
    /// Bearer` / `X-Legion-Token` for same-user CLI clients (audit WEB-1).
    session_token: String,
}

// ─────────────────────────────── Error type ─────────────────────────────────

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log the full error server-side; return a generic message to the client
        // so internal paths / schema / errors are not leaked (OWASP A09/A01).
        tracing::error!(target: "legion.web", "request failed: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

type AResult<T> = std::result::Result<T, AppError>;

// ─────────────────────────── Security middleware ────────────────────────────

/// Add hardening response headers to every reply (OWASP A05 / NIST SC-18).
/// The CSP keeps `'unsafe-inline'` because the dashboard is a single embedded
/// file with inline scripts/styles; all dynamic data is HTML-escaped client-side
/// before insertion, and no external origins are permitted.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut header::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; img-src 'self' data: https://cdn.simpleicons.org; style-src 'self' 'unsafe-inline'; \
         script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::CACHE_CONTROL, "no-store");
    set(
        h,
        header::HeaderName::from_static("permissions-policy"),
        "geolocation=(), microphone=(), camera=(), usb=()",
    );
    set(
        h,
        header::HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        h,
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    resp
}

/// Reject requests whose `Host` header is not a loopback name. Combined with the
/// loopback bind this defeats DNS-rebinding attacks against the local dashboard
/// (a remote page resolving an attacker domain to 127.0.0.1). Skipped when the
/// operator has deliberately bound a non-loopback address.
async fn host_guard(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip any :port and brackets from IPv6 literals.
    let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let bare = bare.trim_start_matches('[').trim_end_matches(']');
    let ok = matches!(bare, "localhost" | "127.0.0.1" | "::1")
        || bare
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        tracing::warn!(target: "legion.web", "rejected request with non-loopback Host: {host:?}");
        (StatusCode::FORBIDDEN, "forbidden").into_response()
    }
}

/// Minimal dependency-free fixed-window rate limiter (global). Loopback-only, so
/// this exists to blunt accidental request storms / local fuzzing rather than
/// distributed abuse. Allows `MAX` requests per `WINDOW`.
#[derive(Clone)]
struct RateLimiter {
    inner: Arc<Mutex<(Instant, u32)>>,
}

impl RateLimiter {
    const MAX: u32 = 600;
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }

    fn allow(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.0.elapsed() > Self::WINDOW {
            *g = (Instant::now(), 0);
        }
        g.1 += 1;
        g.1 <= Self::MAX
    }
}

async fn rate_limit(State(rl): State<RateLimiter>, req: Request, next: Next) -> Response {
    if rl.allow() {
        next.run(req).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response()
    }
}

// ─────────────────────────────── Authentication ─────────────────────────────

/// Generate the per-session API token: a `LEGION_API_TOKEN` override if set and
/// non-empty, otherwise 32 bytes of OS CSPRNG rendered as hex.
fn generate_session_token() -> String {
    if let Ok(t) = std::env::var("LEGION_API_TOKEN") {
        if !t.is_empty() {
            return t;
        }
    }
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS RNG unavailable for session token");
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Constant-time byte comparison so token checks do not leak length/prefix via
/// timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Pull the presented token from `Authorization: Bearer`, `X-Legion-Token`, or
/// the `legion_session` cookie (whichever is present first).
fn presented_token(req: &Request) -> Option<String> {
    let h = req.headers();
    if let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") {
            return Some(t.trim().to_string());
        }
    }
    if let Some(v) = h
        .get(header::HeaderName::from_static("x-legion-token"))
        .and_then(|v| v.to_str().ok())
    {
        return Some(v.trim().to_string());
    }
    if let Some(v) = h.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in v.split(';') {
            if let Some(t) = part.trim().strip_prefix("legion_session=") {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Require a valid session token on every `/api/*` route. Without it, any local
/// process that can reach the loopback port could drive privileged actions
/// (audit WEB-1).
async fn require_auth(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let ok = presented_token(&req)
        .map(|p| ct_eq(p.as_bytes(), s.session_token.as_bytes()))
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

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
struct AuditEntry {
    ts: String,
    actor: String,
    action: String,
    detail: String,
    source: String,
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
}

#[derive(Serialize)]
struct ThreatsResponse {
    ai_threats: Vec<AiThreat>,
    osv_findings: Vec<OsvFinding>,
    ai_critical: usize,
    ai_high: usize,
    osv_total: usize,
    kev_total: i64,
}

#[derive(Serialize)]
struct RunnerCommandResponse {
    ok: bool,
    output: String,
}

// ─────────────────────────────── Handlers ───────────────────────────────────

/// Serve the embedded HTML dashboard, installing the session token as a
/// SameSite=Strict, HttpOnly cookie so the page's same-origin `fetch()` calls
/// authenticate automatically while cross-site requests cannot carry it
/// (audit WEB-1 / WEB-4).
async fn serve_dashboard(State(s): State<Arc<AppState>>) -> Response {
    let cookie = format!(
        "legion_session={}; Path=/; SameSite=Strict; HttpOnly; Max-Age=86400",
        s.session_token
    );
    (
        [(header::SET_COOKIE, cookie)],
        Html(include_str!("dashboard.html")),
    )
        .into_response()
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

/// GET /api/winevents — recent local OS event log entries.
async fn api_win_events() -> AResult<Json<WinEventsResponse>> {
    let events = tokio::task::spawn_blocking(|| telemetry::collect_local_events(75)).await?;
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
    s.db.audit("operator", "alert.ack", &format!("alert {id}"), "web");
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/feeds/refresh — pull all feeds: cyber events, AbuseIPDB, and CISA KEV.
async fn api_feeds_refresh(State(s): State<Arc<AppState>>) -> AResult<Json<FeedResponse>> {
    s.db.audit(
        "operator",
        "feeds.refresh",
        "threat feed pull requested",
        "web",
    );
    let fm = FeedManager::new()?;
    let mut ip_payload = None;

    // Run all feed fetches concurrently
    let (evs_res, ips_res, kev_res) = tokio::join!(
        fm.fetch_cyber_events(),
        fm.fetch_abuseips(),
        threat_intel::fetch_kev(),
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
            ip_payload = Some(payload);
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
    if let Some(payload) = ip_payload {
        let active_ips = tokio::task::spawn_blocking(telemetry::active_remote_ips).await?;
        if !active_ips.is_empty() {
            let ip_alerts = AlertEngine::check_ips(&active_ips, &payload);
            if !ip_alerts.is_empty() {
                s.db.save_alerts(&ip_alerts)?;
            }
        }
    }

    Ok(Json(FeedResponse {
        events: ev_count,
        ips: ip_count,
        kev: kev_count,
    }))
}

/// POST /api/scan — scan packages, run AI detection, correlate alerts, query OSV.
async fn api_scan(State(s): State<Arc<AppState>>) -> AResult<Json<ScanResponse>> {
    s.db.audit(
        "operator",
        "scan.run",
        "package + YARA + baseline scan",
        "web",
    );
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

            // CVE correlation against feed events
            let events = db.get_events()?;
            let mut alerts = AlertEngine::correlate(&scan.packages, &events);

            // Local OS event logs -> alerts (Windows IDs plus Linux/macOS patterns)
            let win_events = telemetry::collect_local_events(200);
            if !win_events.is_empty() {
                let win_alerts = AlertEngine::from_local_events(&win_events);
                alerts.extend(win_alerts);
            }

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
async fn api_yara_update(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<legion_core::UpdateReport>> {
    s.db.audit(
        "operator",
        "yara.update",
        "rule feed update requested",
        "web",
    );
    let mgr = YaraManager::load(data_dir());
    let report = mgr.update_rules().await;
    s.db.audit(
        "system",
        "yara.update.done",
        &format!("fetched {} failed {}", report.fetched, report.failed),
        "web",
    );
    Ok(Json(report))
}

/// GET /api/audit — recent security audit-log entries (newest first).
async fn api_audit(State(s): State<Arc<AppState>>) -> AResult<Json<Vec<AuditEntry>>> {
    let rows = s.db.recent_audit(200)?;
    let out = rows
        .into_iter()
        .map(|(ts, actor, action, detail, source)| AuditEntry {
            ts,
            actor,
            action,
            detail,
            source,
        })
        .collect();
    Ok(Json(out))
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
    }))
}

/// GET /api/feeds/status
async fn api_feeds_status(State(s): State<Arc<AppState>>) -> AResult<Json<serde_json::Value>> {
    let events = s.db.count_events()?;
    Ok(Json(serde_json::json!({ "events": events })))
}

/// GET /api/runner/status — Linux/WSL readiness for Legion Runner.
async fn api_runner_status() -> AResult<Json<RunnerStatus>> {
    Ok(Json(RunnerManager::status()))
}

/// GET /api/runner/commands — setup and launch commands for Linux or WSL.
async fn api_runner_commands() -> AResult<Json<RunnerCommandPlan>> {
    let status = RunnerManager::status();
    Ok(Json(RunnerManager::command_plan(&status.host)))
}

/// POST /api/runner/doctor — run `legionr doctor` on Linux/WSL.
async fn api_runner_doctor(State(s): State<Arc<AppState>>) -> AResult<Json<RunnerCommandResponse>> {
    s.db.audit(
        "operator",
        "runner.doctor",
        "Legion Runner doctor requested",
        "web",
    );
    let output = tokio::task::spawn_blocking(RunnerManager::doctor).await??;
    Ok(Json(RunnerCommandResponse { ok: true, output }))
}

/// POST /api/runner/launch — start the pre-provisioned legionr@default service.
async fn api_runner_launch(State(s): State<Arc<AppState>>) -> AResult<Json<RunnerCommandResponse>> {
    s.db.audit(
        "operator",
        "runner.launch",
        "Legion Runner service start requested",
        "web",
    );
    let output = tokio::task::spawn_blocking(RunnerManager::launch_service).await??;
    Ok(Json(RunnerCommandResponse { ok: true, output }))
}

/// POST /api/runner/stop — stop the legionr@default service.
async fn api_runner_stop(State(s): State<Arc<AppState>>) -> AResult<Json<RunnerCommandResponse>> {
    s.db.audit(
        "operator",
        "runner.stop",
        "Legion Runner service stop requested",
        "web",
    );
    let output = tokio::task::spawn_blocking(RunnerManager::stop_service).await??;
    Ok(Json(RunnerCommandResponse { ok: true, output }))
}

// ─────────────────────────── Poncho agent helpers ───────────────────────────

/// Resolve the `agents/` directory next to the working directory.
fn agents_dir() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("agents")
}

fn load_poncho_rules(cfg: &PonchoConfig) -> Vec<RuleSet> {
    let dir = agents_dir();
    let all = legion_poncho::load_rule_sets(&dir);
    // Filter by which frameworks are enabled
    all.into_iter()
        .filter(|rs| match rs.framework.as_str() {
            "OWASP" => cfg.rules_enabled.owasp,
            "NIST" => cfg.rules_enabled.nist,
            "CIS" => cfg.rules_enabled.cis,
            "DEV" => cfg.rules_enabled.dev,
            "SYSTEM" => cfg.rules_enabled.system,
            _ => true,
        })
        .collect()
}

// ─────────────────────────── Poncho request bodies ──────────────────────────

#[derive(Deserialize)]
struct AgentInstallBody {
    tag: String,
}

#[derive(Deserialize)]
struct AgentChatBody {
    message: String,
}

// ─────────────────────────── Poncho response types ──────────────────────────

#[derive(Serialize)]
struct AgentStatusResponse {
    online: bool,
    os: AgentOsProfile,
    /// Whether an Ollama binary is installed locally (even if not running).
    ollama_installed: bool,
    /// Where to send the operator to install Ollama if it is missing.
    ollama_download_url: String,
    model: String,
    fallback_model: String,
    ollama_host: String,
    rules_loaded: usize,
    rule_hits: usize,
    hunt_ran: bool,
    search_enabled: bool,
    chat_messages: usize,
}

#[derive(Serialize)]
struct AgentOsProfile {
    build_platform: String,
    family: String,
    platform: String,
    version: String,
    kernel: String,
    arch: String,
    lane: String,
}

fn detect_agent_os_profile() -> AgentOsProfile {
    let target_os = std::env::consts::OS;
    let is_wsl = target_os == "linux"
        && std::fs::read_to_string("/proc/version")
            .map(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("microsoft") || value.contains("wsl")
            })
            .unwrap_or(false);
    let platform = if is_wsl {
        "wsl".to_string()
    } else {
        target_os.to_string()
    };
    let lane = match platform.as_str() {
        "windows" => "windows-kernel",
        "wsl" | "linux" => "linux-kernel",
        "macos" => "macos-kernel",
        _ => "generic-local",
    }
    .to_string();
    AgentOsProfile {
        build_platform: target_os.to_string(),
        family: if is_wsl { "linux/wsl" } else { target_os }.to_string(),
        platform,
        version: sysinfo::System::long_os_version()
            .or_else(sysinfo::System::os_version)
            .unwrap_or_else(|| "unknown".to_string()),
        kernel: sysinfo::System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        arch: std::env::consts::ARCH.to_string(),
        lane,
    }
}

#[derive(Serialize)]
struct AgentRulesResponse {
    rule_sets: Vec<RuleSetSummary>,
    hits: Vec<RuleHit>,
}

#[derive(Serialize)]
struct RuleSetSummary {
    framework: String,
    version: String,
    rule_count: usize,
    hit_count: usize,
}

// ─────────────────────────── Ollama lifecycle ───────────────────────────────

/// Ensure the local Ollama server is running, starting it if it is installed
/// but down. Polls up to ~12s for the freshly-launched server to come online.
///
/// Returns the resulting [`OllamaState`]: `Running` if it was already up,
/// `Started` if we launched it successfully, `Installed` if a binary exists but
/// the server did not respond, or `NotInstalled` if no binary was found.
async fn ensure_ollama(host: &str) -> OllamaState {
    let registry = ModelRegistry::new(host);
    if registry.is_online().await {
        return OllamaState::Running;
    }
    match bootstrap::spawn_server() {
        Ok(bin) => {
            tracing::info!("starting Ollama server: {}", bin.display());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return OllamaState::NotInstalled;
        }
        Err(e) => {
            tracing::warn!("failed to launch Ollama: {e}");
            return OllamaState::Installed;
        }
    }
    // Give the server a moment to bind, then poll for readiness.
    for _ in 0..12 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if registry.is_online().await {
            return OllamaState::Started;
        }
    }
    OllamaState::Installed
}

// ─────────────────────────── Poncho handlers ────────────────────────────────

/// GET /api/agent/status
async fn api_agent_status(State(s): State<Arc<AppState>>) -> AResult<Json<AgentStatusResponse>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    let hist_len = s.chat_history.lock().unwrap().len();
    let hunt_ran = s.last_hunt.lock().unwrap().is_some();
    let registry = ModelRegistry::new(&cfg.ollama_host);
    let online = registry.is_online().await;
    let rule_sets = load_poncho_rules(&cfg);
    let rules_loaded: usize = rule_sets.iter().map(|rs| rs.rules.len()).sum();
    // Quick rule evaluation against cached DB data
    let (rule_hits,) = {
        let db = s.db.clone();
        let cfg2 = cfg.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = KnowledgeContext::collect(&db, &cfg2, &rule_sets);
            (ctx.rule_hits.len(),)
        })
        .await?
    };
    Ok(Json(AgentStatusResponse {
        online,
        os: detect_agent_os_profile(),
        ollama_installed: bootstrap::is_installed(),
        ollama_download_url: legion_poncho::OLLAMA_DOWNLOAD_URL.to_string(),
        model: cfg.model,
        fallback_model: cfg.fallback_model,
        ollama_host: cfg.ollama_host,
        rules_loaded,
        rule_hits,
        hunt_ran,
        search_enabled: cfg.search_enabled,
        chat_messages: hist_len,
    }))
}

/// POST /api/agent/ollama/start — start the local Ollama server if installed.
async fn api_agent_ollama_start(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<serde_json::Value>> {
    let host = s.poncho_config.lock().unwrap().ollama_host.clone();
    let state = ensure_ollama(&host).await;
    s.db.audit(
        "operator",
        "agent.ollama.start",
        &format!("{state:?}"),
        "web",
    );
    let message = match state {
        OllamaState::Running => "Ollama is already running.".to_string(),
        OllamaState::Started => "Ollama started successfully.".to_string(),
        OllamaState::Installed => {
            "Ollama is installed but did not come online — try starting it manually.".to_string()
        }
        OllamaState::NotInstalled => format!(
            "Ollama is not installed. Download it from {}",
            legion_poncho::OLLAMA_DOWNLOAD_URL
        ),
    };
    Ok(Json(serde_json::json!({
        "ok": state.is_online(),
        "state": state,
        "installed": state != OllamaState::NotInstalled,
        "download_url": legion_poncho::OLLAMA_DOWNLOAD_URL,
        "message": message,
    })))
}

/// GET /api/agent/models
async fn api_agent_models(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<Vec<legion_poncho::ModelInfo>>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    let registry = ModelRegistry::new(&cfg.ollama_host);
    let models = registry.list_models().await.unwrap_or_default();
    Ok(Json(models))
}

/// POST /api/agent/install  body: { "tag": "qwen3:8b" }
async fn api_agent_install(
    State(s): State<Arc<AppState>>,
    Json(body): Json<AgentInstallBody>,
) -> AResult<Json<serde_json::Value>> {
    // Validate tag is not blocked before touching anything
    if ModelRegistry::is_blocked(&body.tag) {
        return Ok(Json(serde_json::json!({
            "ok": false,
            "error": format!("model '{}' is blocked by Poncho policy", body.tag)
        })));
    }
    let cfg = s.poncho_config.lock().unwrap().clone();
    s.db.audit(
        "operator",
        "agent.install",
        &format!("model pull: {}", body.tag),
        "web",
    );
    let registry = ModelRegistry::new(&cfg.ollama_host);
    match registry.install_model(&body.tag).await {
        Ok(()) => {
            s.db.audit("system", "agent.install.ok", &body.tag, "web");
            // Trust-on-first-use digest pin so a later content swap is detectable
            // (audit PON-1). Best-effort: never fail the install on a pin error.
            match registry.pin_current(&data_dir(), &body.tag).await {
                Ok(Some(d)) => {
                    s.db.audit("system", "agent.pin", &format!("{}={}", body.tag, d), "web")
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("digest pin failed for {}: {e}", body.tag),
            }
            Ok(Json(serde_json::json!({ "ok": true, "tag": body.tag })))
        }
        Err(e) => Ok(Json(
            serde_json::json!({ "ok": false, "error": e.to_string() }),
        )),
    }
}

/// POST /api/agent/update  body: { "tag": "qwen3:8b" }
async fn api_agent_update(
    State(s): State<Arc<AppState>>,
    Json(body): Json<AgentInstallBody>,
) -> AResult<Json<serde_json::Value>> {
    if ModelRegistry::is_blocked(&body.tag) {
        return Ok(Json(serde_json::json!({
            "ok": false,
            "error": format!("model '{}' is blocked", body.tag)
        })));
    }
    let cfg = s.poncho_config.lock().unwrap().clone();
    s.db.audit(
        "operator",
        "agent.update",
        &format!("model update: {}", body.tag),
        "web",
    );
    let registry = ModelRegistry::new(&cfg.ollama_host);
    match registry.update_model(&body.tag).await {
        Ok(()) => {
            // An update legitimately changes the digest, so re-pin (audit PON-1).
            match registry.pin_current(&data_dir(), &body.tag).await {
                Ok(Some(d)) => s.db.audit(
                    "system",
                    "agent.repin",
                    &format!("{}={}", body.tag, d),
                    "web",
                ),
                Ok(None) => {}
                Err(e) => tracing::warn!("digest re-pin failed for {}: {e}", body.tag),
            }
            Ok(Json(serde_json::json!({ "ok": true, "tag": body.tag })))
        }
        Err(e) => Ok(Json(
            serde_json::json!({ "ok": false, "error": e.to_string() }),
        )),
    }
}

/// POST /api/agent/scan-model  body: { "tag": "qwen3:8b" }
async fn api_agent_scan_model(
    State(s): State<Arc<AppState>>,
    Json(body): Json<AgentInstallBody>,
) -> AResult<Json<ModelScanResult>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    s.db.audit("operator", "agent.scan_model", &body.tag, "web");
    let registry = ModelRegistry::new(&cfg.ollama_host);
    let result = registry
        .scan_model(&body.tag)
        .await
        .unwrap_or_else(|e| ModelScanResult {
            tag: body.tag.clone(),
            blocked: false,
            clean: false,
            warnings: vec![e.to_string()],
        });
    Ok(Json(result))
}

/// GET /api/agent/config
async fn api_agent_config_get(State(s): State<Arc<AppState>>) -> AResult<Json<PonchoConfig>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    Ok(Json(cfg))
}

/// POST /api/agent/config  — save + validate config.
///
/// Persisting the config is a privileged action: it re-launches a short-lived
/// elevated helper which triggers a fresh OS admin prompt (UAC / polkit /
/// osascript) each time. The save only commits if the operator approves.
async fn api_agent_config_save(
    State(s): State<Arc<AppState>>,
    Json(new_cfg): Json<PonchoConfig>,
) -> AResult<Json<serde_json::Value>> {
    // Validate no blocked models (cheap, unprivileged) before prompting.
    if let Err(e) = new_cfg.validate() {
        return Ok(Json(
            serde_json::json!({ "ok": false, "error": e.to_string() }),
        ));
    }

    if s.elevate_writes {
        // Blocks on the OS elevation prompt — run off the async runtime.
        let cfg = new_cfg.clone();
        let outcome = tokio::task::spawn_blocking(move || elevated_persist_config(&cfg)).await?;
        match outcome {
            Ok(privilege::ElevatedRun::Completed) => {
                // Helper wrote the file elevated; reload it into memory.
                *s.poncho_config.lock().unwrap() = PonchoConfig::load(&data_dir());
            }
            Ok(privilege::ElevatedRun::Cancelled) => {
                s.db.audit(
                    "operator",
                    "agent.config.save.cancelled",
                    "UAC declined",
                    "web",
                );
                return Ok(Json(serde_json::json!({
                    "ok": false,
                    "cancelled": true,
                    "error": "Administrator approval was cancelled — configuration unchanged."
                })));
            }
            Ok(privilege::ElevatedRun::Unsupported(why)) => {
                // No elevation channel (e.g. headless): fall back to a direct write.
                tracing::warn!("elevation unsupported ({why}); writing config in-process");
                if let Err(e) = new_cfg.save(&data_dir()) {
                    return Ok(Json(
                        serde_json::json!({ "ok": false, "error": e.to_string() }),
                    ));
                }
                *s.poncho_config.lock().unwrap() = new_cfg.clone();
            }
            Ok(privilege::ElevatedRun::Failed(why)) => {
                return Ok(Json(serde_json::json!({ "ok": false, "error": why })));
            }
            Err(e) => {
                return Ok(Json(
                    serde_json::json!({ "ok": false, "error": e.to_string() }),
                ));
            }
        }
    } else {
        // Development / --no-elevate: write directly, no prompt.
        if let Err(e) = new_cfg.save(&data_dir()) {
            return Ok(Json(
                serde_json::json!({ "ok": false, "error": e.to_string() }),
            ));
        }
        *s.poncho_config.lock().unwrap() = new_cfg.clone();
    }

    s.db.audit(
        "operator",
        "agent.config.save",
        &format!("model={}", new_cfg.model),
        "web",
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Persist the PONCHO config through the OS elevation prompt. Stages the
/// proposed config in the protected data dir, then re-invokes this executable
/// elevated with `--apply-poncho-config <file>` and waits for it to finish.
fn elevated_persist_config(cfg: &PonchoConfig) -> Result<privilege::ElevatedRun> {
    let exe = std::env::current_exe()?;
    let mut staged = data_dir();
    std::fs::create_dir_all(&staged).ok();
    staged.push("poncho.pending.json");
    std::fs::write(&staged, serde_json::to_vec_pretty(cfg)?)?;
    legion_core::harden_file(&staged);

    let args = vec![
        "--apply-poncho-config".to_string(),
        staged.to_string_lossy().to_string(),
    ];
    let outcome = privilege::run_elevated_wait(
        &exe,
        &args,
        "Legion needs administrator approval to change the PONCHO agent configuration.",
    );
    let _ = std::fs::remove_file(&staged);
    Ok(outcome)
}

/// Elevated helper entrypoint (`--apply-poncho-config`): read the staged config
/// and persist it with hardened permissions, then exit. Runs with admin rights.
fn apply_poncho_config_helper(path: &std::path::Path) -> Result<()> {
    // This runs elevated, so the path handed on argv is untrusted: confine it to
    // the protected data directory and to the expected staged filename before
    // reading, so a crafted `--apply-poncho-config /attacker/file` cannot have us
    // write attacker-controlled content with admin rights (audit WEB-2).
    let expected_dir = data_dir().canonicalize().unwrap_or_else(|_| data_dir());
    let canon = path.canonicalize()?;
    if !canon.starts_with(&expected_dir) {
        anyhow::bail!("refusing to apply config from outside the protected data directory");
    }
    if canon.file_name() != Some(std::ffi::OsStr::new("poncho.pending.json")) {
        anyhow::bail!("refusing to apply config from an unexpected filename");
    }
    let data = std::fs::read_to_string(&canon)?;
    let cfg: PonchoConfig = serde_json::from_str(&data)?;
    cfg.validate()?;
    cfg.save(&data_dir())?;
    Ok(())
}

/// GET /api/agent/rules  — return all loaded rule sets + current hits
async fn api_agent_rules(State(s): State<Arc<AppState>>) -> AResult<Json<AgentRulesResponse>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    let rule_sets = load_poncho_rules(&cfg);
    let db = s.db.clone();
    let cfg2 = cfg.clone();
    let rs_clone = rule_sets.clone();
    let hits = tokio::task::spawn_blocking(move || {
        let ctx = KnowledgeContext::collect(&db, &cfg2, &rs_clone);
        ctx.rule_hits
    })
    .await?;

    let summaries: Vec<RuleSetSummary> = rule_sets
        .iter()
        .map(|rs| {
            let hit_count = hits.iter().filter(|h| h.framework == rs.framework).count();
            RuleSetSummary {
                framework: rs.framework.clone(),
                version: rs.version.clone(),
                rule_count: rs.rules.len(),
                hit_count,
            }
        })
        .collect();

    Ok(Json(AgentRulesResponse {
        rule_sets: summaries,
        hits,
    }))
}

/// POST /api/agent/chat  body: { "message": "..." }
async fn api_agent_chat(
    State(s): State<Arc<AppState>>,
    Json(body): Json<AgentChatBody>,
) -> AResult<Json<legion_poncho::ChatResponse>> {
    // Sanitise input
    let user_msg = body.message.trim().to_string();
    if user_msg.is_empty() {
        return Err(anyhow::anyhow!("empty message").into());
    }
    if user_msg.len() > 4096 {
        return Err(anyhow::anyhow!("message exceeds 4096 byte limit").into());
    }
    let cfg = s.poncho_config.lock().unwrap().clone();
    let history = s.chat_history.lock().unwrap().clone();
    let db = s.db.clone();
    let cfg2 = cfg.clone();
    let rule_sets = load_poncho_rules(&cfg);

    // Phase 1: build knowledge context (blocking syscalls)
    let ctx =
        tokio::task::spawn_blocking(move || KnowledgeContext::collect(&db, &cfg2, &rule_sets))
            .await?;

    // Phase 2: call Ollama (async HTTP)
    let chat = PonchoChat::new(cfg.clone());
    let resp = chat.respond(&history, &user_msg, &ctx).await?;

    // Phase 3: update in-memory history
    {
        let mut h = s.chat_history.lock().unwrap();
        h.push(ChatMessage {
            role: "user".to_string(),
            content: user_msg,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
        h.push(ChatMessage {
            role: "assistant".to_string(),
            content: resp.content.clone(),
            timestamp: resp.timestamp.clone(),
        });
        // Trim to 2× limit + 4 guard
        let cap = cfg.chat_history_limit * 2 + 4;
        if h.len() > cap {
            let excess = h.len() - cap;
            h.drain(..excess);
        }
    }

    s.db.audit(
        "operator",
        "agent.chat",
        &format!("model={}", resp.model_used),
        "web",
    );
    Ok(Json(resp))
}

/// POST /api/agent/hunt  — full structured blue-team hunt
async fn api_agent_hunt(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<legion_poncho::HuntReport>> {
    let cfg = s.poncho_config.lock().unwrap().clone();
    let db = s.db.clone();
    let cfg2 = cfg.clone();
    let rule_sets = load_poncho_rules(&cfg);

    let ctx =
        tokio::task::spawn_blocking(move || KnowledgeContext::collect(&db, &cfg2, &rule_sets))
            .await?;

    let chat = PonchoChat::new(cfg.clone());
    let report = chat.hunt(&ctx).await?;
    s.db.audit(
        "operator",
        "agent.hunt",
        &format!(
            "model={} hits={}",
            report.model_used,
            report.rule_hits.len()
        ),
        "web",
    );

    // Promote the hunt's Critical/High rule hits to SIEM alerts so they surface
    // in the top KPI counters, alert log, and correlation matrix — not just the
    // agent panel. Re-running a hunt refreshes them (see replace_agent_alerts).
    let now = chrono::Utc::now().to_rfc3339();
    let agent_alerts: Vec<Alert> = report
        .rule_hits
        .iter()
        .filter_map(|h| {
            let sev_label = match h.severity.to_ascii_lowercase().as_str() {
                "critical" => "Critical",
                "high" => "High",
                _ => return None, // only escalate Critical/High to the SIEM
            };
            let detail = if h.remediation.is_empty() {
                h.evidence.clone()
            } else {
                format!("{} — Remediation: {}", h.evidence, h.remediation)
            };
            Some(Alert {
                id: 0,
                kind: AlertKind::SystemAnomaly,
                severity: severity_from_label(sev_label),
                title: format!("PONCHO: {} {}", h.rule_id, h.title),
                detail,
                package_name: None,
                package_ecosystem: None,
                ip_address: None,
                cve_ids: Vec::new(),
                event_title: Some(format!("{} {}", h.framework.to_uppercase(), h.rule_id)),
                created_at: now.clone(),
                acked: false,
            })
        })
        .collect();
    if let Err(e) = s.db.replace_agent_alerts(&agent_alerts) {
        tracing::warn!("failed to persist agent alerts: {e}");
    }

    // Cache for the dashboard's hunt-analysis panel.
    *s.last_hunt.lock().unwrap() = Some(report.clone());
    Ok(Json(report))
}

/// GET /api/agent/hunt/latest — most recent hunt report (null if none yet).
async fn api_agent_hunt_latest(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<Option<legion_poncho::HuntReport>>> {
    let report = s.last_hunt.lock().unwrap().clone();
    Ok(Json(report))
}

/// GET /api/agent/history  — return session chat history
async fn api_agent_history(State(s): State<Arc<AppState>>) -> AResult<Json<Vec<ChatMessage>>> {
    let h = s.chat_history.lock().unwrap().clone();
    Ok(Json(h))
}

/// POST /api/agent/clear  — clear session chat history
async fn api_agent_clear(State(s): State<Arc<AppState>>) -> AResult<StatusCode> {
    s.chat_history.lock().unwrap().clear();
    s.db.audit("operator", "agent.clear", "chat history cleared", "web");
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────── Main ───────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Privileged helper path: when re-invoked through the OS elevation prompt
    // (UAC / polkit / osascript), persist the PONCHO config and exit. This runs
    // elevated and does nothing else — it is the per-action elevation target.
    if let Some(path) = args.apply_poncho_config.as_ref() {
        return apply_poncho_config_helper(path);
    }

    match privilege::ensure_elevated(
        "Legion needs administrator rights at startup to read privileged telemetry.",
    ) {
        privilege::Elevation::AlreadyElevated => {}
        privilege::Elevation::Relaunched => return Ok(()),
        privilege::Elevation::Skipped(why) => {
            tracing::warn!("startup elevation skipped: {why}");
        }
        privilege::Elevation::Failed(why) => {
            return Err(anyhow::anyhow!("administrator approval required: {why}"));
        }
    }

    fmt()
        .with_env_filter(EnvFilter::new("warn"))
        .without_time()
        .init();

    // Access control is still delegated to the OS, but the dashboard now asks
    // for startup elevation so the browser package has privileged telemetry
    // available immediately. Sensitive mutations still use a short-lived
    // elevated helper for fresh prompts when saving agent config.
    let elevate_writes = !args.no_elevate;

    let db_path = args.db.unwrap_or_else(|| data_dir().join("legion.db"));
    let db = Database::open(&db_path)?;
    match db.clear_agent_alerts() {
        Ok(n) if n > 0 => tracing::info!("cleared {n} stale PONCHO alerts from previous session"),
        Ok(_) => {}
        Err(e) => tracing::warn!("failed to clear stale PONCHO alerts: {e}"),
    }

    let poncho_config = Arc::new(Mutex::new(PonchoConfig::load(&data_dir())));
    let chat_history: Arc<Mutex<Vec<ChatMessage>>> = Arc::new(Mutex::new(Vec::new()));

    let session_token = generate_session_token();

    let state = Arc::new(AppState {
        db,
        scan_root: args.scan_root.canonicalize().unwrap_or(args.scan_root),
        net_prev: Arc::new(Mutex::new(None)),
        poncho_config,
        chat_history,
        last_hunt: Arc::new(Mutex::new(None)),
        elevate_writes,
        session_token,
    });

    // Persist the token to an owner-only file so same-user CLI clients can read
    // it; other local users cannot (OS-delegated access control). Best-effort.
    let token_path = data_dir().join("session.token");
    if std::fs::write(&token_path, &state.session_token).is_ok() {
        legion_core::harden_file(&token_path);
    }

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

    // Bring the PONCHO agent online: start the local Ollama server if it is
    // installed but not running. If it is not installed, the dashboard surfaces
    // an install prompt — we only log here and never block startup on it.
    {
        let host = state.poncho_config.lock().unwrap().ollama_host.clone();
        tokio::spawn(async move {
            match ensure_ollama(&host).await {
                OllamaState::Running => tracing::info!("Ollama already running"),
                OllamaState::Started => tracing::info!("Ollama started by Legion"),
                OllamaState::Installed => {
                    tracing::warn!("Ollama installed but not reachable at {host}")
                }
                OllamaState::NotInstalled => tracing::warn!(
                    "Ollama not installed — PONCHO chat disabled until installed from {}",
                    legion_poncho::OLLAMA_DOWNLOAD_URL
                ),
            }
        });
    }

    // All `/api/*` routes sit behind the session-token gate; the dashboard page
    // itself ("/") is served unauthenticated so the browser can obtain the
    // cookie, then every API call it makes carries it (audit WEB-1).
    let api = Router::new()
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
        .route("/api/runner/status", get(api_runner_status))
        .route("/api/runner/commands", get(api_runner_commands))
        .route("/api/runner/doctor", post(api_runner_doctor))
        .route("/api/runner/launch", post(api_runner_launch))
        .route("/api/runner/stop", post(api_runner_stop))
        .route("/api/yara/scan", post(api_yara_scan))
        .route("/api/yara/update", post(api_yara_update))
        .route("/api/baseline", get(api_baseline))
        .route("/api/audit", get(api_audit))
        // ── Poncho agent ──────────────────────────────────────────────────
        .route("/api/agent/status", get(api_agent_status))
        .route("/api/agent/ollama/start", post(api_agent_ollama_start))
        .route("/api/agent/models", get(api_agent_models))
        .route("/api/agent/install", post(api_agent_install))
        .route("/api/agent/update", post(api_agent_update))
        .route("/api/agent/scan-model", post(api_agent_scan_model))
        .route("/api/agent/config", get(api_agent_config_get))
        .route("/api/agent/config", post(api_agent_config_save))
        .route("/api/agent/rules", get(api_agent_rules))
        .route("/api/agent/chat", post(api_agent_chat))
        .route("/api/agent/hunt", post(api_agent_hunt))
        .route("/api/agent/hunt/latest", get(api_agent_hunt_latest))
        .route("/api/agent/history", get(api_agent_history))
        .route("/api/agent/clear", post(api_agent_clear))
        // Session-token gate on every API route (applied only to the routes in
        // this sub-router, not the dashboard page).
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .merge(api)
        // No CORS layer: same-origin only. Browsers block cross-origin reads by
        // default, so we do not emit Access-Control-Allow-* headers at all.
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state.clone());

    // Loopback DNS-rebinding guard, applied only when bound to loopback.
    let bound_loopback = args
        .host
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(args.host == "localhost");
    let app = if bound_loopback {
        app.layer(middleware::from_fn(host_guard))
    } else {
        app
    };

    // Global rate limiter (its own state).
    let limiter = RateLimiter::new();
    let app = app.layer(middleware::from_fn_with_state(limiter, rate_limit));

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).await?;
    let url = format!("http://{}:{}", args.host, args.port);

    if !bound_loopback {
        tracing::warn!(
            "binding non-loopback address {addr} — the dashboard has no built-in \
             authentication; only do this behind an authenticated reverse proxy"
        );
    }

    state.db.audit(
        "system",
        "web.start",
        &format!("listening on {addr}"),
        "legion-web",
    );

    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║  LEGION SIEM/SOAR  — Web Dashboard   ║");
    println!("  ╠══════════════════════════════════════╣");
    println!("  ║  {}  ║", url);
    println!("  ║  Ctrl+C to stop                      ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();
    println!("  API token (for CLI clients): {}", state.session_token);
    println!("  also written to: {}", token_path.display());
    println!("  the browser dashboard authenticates automatically.");
    println!();

    if !args.no_open {
        let _ = open::that(&url);
    }

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn ct_eq_matches_only_identical_bytes() {
        assert!(ct_eq(b"abc123", b"abc123"));
        assert!(!ct_eq(b"abc123", b"abc124"));
        assert!(!ct_eq(b"abc", b"abcd")); // differing lengths
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn generated_token_is_64_hex_chars() {
        // Clear any override so we exercise the CSPRNG path.
        std::env::remove_var("LEGION_API_TOKEN");
        let t = generate_session_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn req_with(header_name: &'static str, value: &str) -> Request {
        Request::builder()
            .header(header_name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn presented_token_reads_bearer_header() {
        let r = req_with("authorization", "Bearer tok-abc");
        assert_eq!(presented_token(&r).as_deref(), Some("tok-abc"));
    }

    #[test]
    fn presented_token_reads_custom_header() {
        let r = req_with("x-legion-token", "tok-xyz");
        assert_eq!(presented_token(&r).as_deref(), Some("tok-xyz"));
    }

    #[test]
    fn presented_token_reads_session_cookie() {
        let r = req_with("cookie", "other=1; legion_session=tok-cookie; foo=bar");
        assert_eq!(presented_token(&r).as_deref(), Some("tok-cookie"));
    }

    #[test]
    fn presented_token_absent_when_no_credentials() {
        let r = Request::builder().body(Body::empty()).unwrap();
        assert!(presented_token(&r).is_none());
    }
}
