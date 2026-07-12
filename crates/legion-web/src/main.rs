//! Legion Web – browser-based SIEM dashboard served over HTTP.
//!
//! Usage:
//!   legion-web [--port 3000] [--scan-root .] [--db <path>]

use anyhow::Result;
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Instant,
};

mod install;
mod peercred;
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

use legion_ares::{
    bootstrap, AgentLoopConfig, AgentLoopState, AgentTick, AresChat, AresConfig, ChatMessage,
    HuntCallback, KnowledgeContext, LoopStateHandle, ModelManifest, ModelRegistry, OllamaState,
    RuleHit, RuleSet,
};
use legion_core::{
    ai_detector::AiDetector,
    alerts::{severity_from_label, Alert, AlertEngine, AlertKind, AlertScope},
    baseline, data_dir,
    feeds::FeedManager,
    privilege,
    runner::{RunnerCommandPlan, RunnerManager, RunnerStatus},
    scanner::PackageScanner,
    telemetry, threat_intel,
    yara::YaraManager,
    AiThreat, Database, DockerInfo, OsvFinding, WinEvent,
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

    /// Allow binding the dashboard to a non-loopback host. This is unsafe
    /// unless you place Legion behind an authenticated reverse proxy.
    #[arg(long)]
    allow_insecure_bind: bool,

    /// Internal: privileged helper invoked via UAC to persist the ARES config
    /// from the given JSON file, then exit. Not for direct use.
    #[arg(long, hide = true)]
    apply_ares_config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Subcommands. With none, `legion-web` runs the dashboard (default).
#[derive(Subcommand)]
enum Command {
    /// Install Legion into a bin dir + data dir, with PATH and desktop
    /// integration. Cross-platform Rust replacement for install.sh/install.ps1.
    Install {
        /// Where to place the `legion-web` binary (default: OS-appropriate).
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        /// Data directory to create and lock down (default: OS data dir).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Do not modify the user's PATH.
        #[arg(long)]
        no_path: bool,
        /// Do not install a desktop/menu entry.
        #[arg(long)]
        no_desktop: bool,
    },
    /// Stop a running dashboard instance and relaunch it (replaces restart.ps1).
    Restart,
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
    /// Ares agent config (persisted to data_dir/ares.json).
    ares_config: Arc<Mutex<AresConfig>>,
    /// In-memory chat history (session-scoped, not persisted).
    chat_history: Arc<Mutex<Vec<ChatMessage>>>,
    /// Most recent ARES hunt report, surfaced on the dashboard. Session-scoped.
    last_hunt: Arc<Mutex<Option<legion_ares::HuntReport>>>,
    /// Shared state of the autonomous Ares agent loop.
    agent_loop_state: LoopStateHandle,
    /// Detected host hardware and the model chosen for it (populated once at
    /// startup by the provisioning task). Surfaced on the agent page so the
    /// operator sees what was selected and why.
    hardware: Arc<Mutex<Option<legion_ares::HardwareProfile>>>,
    model_selection: Arc<Mutex<Option<legion_ares::ModelSelection>>>,
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

fn lock_api<'a, T>(m: &'a Mutex<T>, name: &'static str) -> AResult<MutexGuard<'a, T>> {
    m.lock()
        .map_err(|_| AppError(anyhow::anyhow!("state lock poisoned: {name}")))
}

// ─────────────────────────── Security middleware ────────────────────────────

/// Add hardening response headers to every reply (OWASP A05 / NIST SC-18).
/// The CSP keeps `'unsafe-inline'` because the dashboard is a single embedded
/// file with inline scripts/styles; all dynamic data is HTML-escaped client-side
/// before insertion. No external origins are permitted — the OS badge icons are
/// served same-origin from `/icons/:slug` (see `serve_os_icon`), so `img-src`
/// needs only `'self'` and `data:`.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    // Only the single-file HTML dashboard carries inline scripts/styles and so
    // needs `'unsafe-inline'`; every other response (JSON APIs, SVG icons) has no
    // inline content and gets a strict, script-free policy (audit 2026-07 M5).
    // Fully dropping `script-src 'unsafe-inline'` on the dashboard itself requires
    // refactoring its ~54 inline event handlers to delegated listeners (a nonce
    // disables `'unsafe-inline'` in CSP3, which would break them) — tracked
    // follow-up, browser-verified.
    let is_html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("text/html"))
        .unwrap_or(false);
    let h = resp.headers_mut();
    let set = |h: &mut header::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    let csp = if is_html {
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
         script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    } else {
        "default-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'none'; \
         connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; \
         form-action 'self'"
    };
    set(h, header::CONTENT_SECURITY_POLICY, csp);
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
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(target: "legion.web", "rate limiter lock poisoned; allowing request");
                return true;
            }
        };
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

/// State for [`same_user_guard`]: the address we bound to (for matching the
/// connection in `/proc/net/tcp`), the set of UIDs allowed to reach the control
/// plane, and whether an undeterminable peer should be refused.
#[derive(Clone)]
struct PeerGuard {
    local: SocketAddr,
    authorized: Arc<HashSet<u32>>,
    strict: bool,
}

/// Refuse loopback connections that belong to a *different* local user (audit
/// 2026-07 H1). A socket bound to `127.0.0.1` is reachable by every local
/// account, so without this a different user could scrape the session cookie
/// from `GET /` and drive the privileged API. This runs outermost — before the
/// token gate — so a foreign user is rejected before any handler sees the
/// request. Same-user (and root, and the elevating human via `PKEXEC_UID`/
/// `SUDO_UID`) pass through unchanged, so the browser flow is untouched.
async fn same_user_guard(State(g): State<PeerGuard>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let Some(peer) = peer else {
        // No connection info (shouldn't happen with the connect-info service);
        // the token gate still protects /api/*.
        return next.run(req).await;
    };
    if !peer.ip().is_loopback() {
        // Non-loopback reach is governed by the bind policy + host_guard.
        return next.run(req).await;
    }
    match peercred::check(peer, g.local, &g.authorized) {
        peercred::PeerAuth::Allowed => next.run(req).await,
        peercred::PeerAuth::Denied { uid } => {
            tracing::warn!(
                target: "legion.web",
                "refused loopback connection from uid={uid} ({peer}): not the owning user"
            );
            (StatusCode::FORBIDDEN, "forbidden: cross-user access").into_response()
        }
        peercred::PeerAuth::Unknown => {
            if g.strict {
                tracing::warn!(
                    target: "legion.web",
                    "refused loopback connection from {peer}: peer uid undeterminable (strict)"
                );
                (StatusCode::FORBIDDEN, "forbidden").into_response()
            } else {
                next.run(req).await
            }
        }
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
/// (audit WEB-1 / WEB-4). Cross-*user* access to this route (which vends the
/// token) is blocked upstream by [`same_user_guard`] (audit 2026-07 H1).
async fn serve_dashboard(State(s): State<Arc<AppState>>) -> Response {
    let cookie = format!(
        "legion_session={}; Path=/; SameSite=Strict; HttpOnly; Max-Age=86400",
        s.session_token
    );
    // Render the top-bar OS badge server-side so it is correct on first paint,
    // independent of any later /api/agent/status fetch (which only runs on the
    // ARES tab). Without this the static default leaked WINDOWS on Linux hosts.
    let os = detect_agent_os_profile();
    let (os_slug, os_label) = match os.platform.as_str() {
        "windows" => ("gitforwindows", "WINDOWS"),
        "wsl" => ("linux", "WSL"),
        _ => ("linux", "LINUX"),
    };
    let html = include_str!("dashboard.html")
        .replace("__LEGION_OS_SLUG__", os_slug)
        .replace("__LEGION_OS_LABEL__", os_label);
    ([(header::SET_COOKIE, cookie)], Html(html)).into_response()
}

// OS-badge icons, embedded and served same-origin so the dashboard makes no
// third-party requests (previously fetched from cdn.simpleicons.org). White
// monochrome glyphs to match the dark top bar. Keeps `img-src 'self'` honest.
const ICON_LINUX: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#fff"><path d="M12 2c-2.1 0-3.4 1.8-3.4 4.1 0 1.2.2 2-.6 3C6.7 11 5 13 5 15.4c0 1 .5 1.6 1.2 1.9-.3.6-1 1.1-1.7 1.6-.6.4-.9.8-.9 1.3 0 .7.7 1.1 1.6 1.1.8 0 1.6-.2 2.3-.2.4 0 .6.1.8.4.4.5 1.3.8 2.6.8s2.2-.3 2.6-.8c.2-.3.4-.4.8-.4.7 0 1.5.2 2.3.2.9 0 1.6-.4 1.6-1.1 0-.5-.3-.9-.9-1.3-.7-.5-1.4-1-1.7-1.6.7-.3 1.2-.9 1.2-1.9 0-2.4-1.7-4.4-2.9-6-.8-1-.6-1.8-.6-3C15.4 3.8 14.1 2 12 2zm-1.9 4a.8 1.1 0 1 1 0 2.2.8 1.1 0 0 1 0-2.2zm3.8 0a.8 1.1 0 1 1 0 2.2.8 1.1 0 0 1 0-2.2zm-1.9 2.6c.8 0 1.6.4 1.6.9 0 .3-.3.5-.7.7l-.9.4-.9-.4c-.4-.2-.7-.4-.7-.7 0-.5.8-.9 1.6-.9z"/></svg>"##;
const ICON_WINDOWS: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#fff"><path d="M3 5.1 10.6 4v7.6H3zm0 7.4h7.6V20L3 18.9zM11.4 3.9 21 2.5v9.1h-9.6zm0 8.6H21v9.1l-9.6-1.4z"/></svg>"##;

/// Serve an OS-badge icon from same-origin (`GET /icons/:slug`), replacing the
/// former external CDN dependency. Unauthenticated like the dashboard page.
async fn serve_os_icon(Path(slug): Path<String>) -> Response {
    let svg = match slug.as_str() {
        "windows" | "gitforwindows" => ICON_WINDOWS,
        _ => ICON_LINUX, // linux, wsl, and any unknown slug
    };
    let ct = [(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml"),
    )];
    (ct, svg).into_response()
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
        let mut prev = lock_api(&s.net_prev, "net_prev")?;
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

#[derive(Deserialize)]
struct OpenPathBody {
    path: String,
}

/// POST /api/open — reveal a flagged file/folder in the OS file manager.
///
/// Token-gated like every `/api` route, and loopback-only, so only a same-user,
/// authenticated client (the dashboard) can drive it. The path must exist; it is
/// handed to the file manager as a direct argument (no shell), and the request is
/// recorded in the audit log.
async fn api_open(State(s): State<Arc<AppState>>, Json(body): Json<OpenPathBody>) -> Response {
    let path = std::path::PathBuf::from(&body.path);
    // L2: confine the reveal to files Legion actually flagged (a known alert
    // `file_path`) or paths inside the configured scan root — so a token-holding
    // client cannot use this as an arbitrary-path existence oracle / file-manager
    // launcher for any location on disk.
    let under_scan_root = path
        .canonicalize()
        .ok()
        .zip(s.scan_root.canonicalize().ok())
        .map(|(p, root)| p.starts_with(&root))
        .unwrap_or(false);
    if !under_scan_root && !s.db.alert_path_exists(&body.path) {
        s.db.audit("operator", "alert.open.denied", &body.path, "web");
        // F7 (QA 2026-07): a confinement refusal is a 403, not a 500.
        return (
            StatusCode::FORBIDDEN,
            "refusing to open a path that is not flagged or inside the scan root",
        )
            .into_response();
    }
    if let Err(e) = legion_core::fsroots::reveal_in_file_manager(&path) {
        tracing::warn!(target: "legion.web", "open {} failed: {e}", body.path);
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not open path").into_response();
    }
    s.db.audit("operator", "alert.open", &body.path, "web");
    StatusCode::NO_CONTENT.into_response()
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
        // Reconcile the blacklist scope against the *current* connections: a peer
        // that has gone away, or an IP no longer on the feed, auto-resolves.
        let ip_alerts = AlertEngine::check_ips(&active_ips, &payload);
        s.db.reconcile_alerts(&[AlertScope::AbuseIntel], &ip_alerts)?;
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

    // Phase 1: blocking scan + AI detection + alert correlation. The package
    // inventory covers every fixed drive on the host, not just the scan root.
    let (packages, alert_count, ai_threats, cargo, npm, pip) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let scan = PackageScanner::scan_system();
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

            // CVE correlation against feed events. Reconciled: a package that was
            // removed or patched (no longer correlates) auto-resolves.
            let events = db.get_events()?;
            let cve_alerts = AlertEngine::correlate(&scan.packages, &events);
            db.reconcile_alerts(&[AlertScope::PackageCve], &cve_alerts)?;

            // Local OS event logs -> alerts (Windows IDs plus Linux patterns).
            // These are *point-in-time* events, not current-state findings, so they
            // are appended (deduped) rather than reconciled — an event that scrolls
            // out of the read window must not silently disappear from history.
            let win_events = telemetry::collect_local_events(200);
            let event_alerts = AlertEngine::from_local_events(&win_events);
            if !event_alerts.is_empty() {
                db.save_alerts(&event_alerts)?;
            }

            let alert_total = cve_alerts.len() + event_alerts.len();
            Ok((scan.packages, alert_total, ai, cargo, npm, pip))
        })
        .await??;

    let ai_count = ai_threats.len();

    // Phase 2: async OSV query (background — doesn't block the response)
    let db2 = s.db.clone();
    let pkgs = packages.clone();
    // Packages actually used by the monitored project(s): those inventoried from
    // a lockfile located under the scan root. Vuln ALERTS are limited to these so
    // the queue reflects what this system depends on, not every advisory-affected
    // crate sitting in a machine-wide package cache (QA 2026-07, user choice).
    let scan_root_canon = s
        .scan_root
        .canonicalize()
        .unwrap_or_else(|_| s.scan_root.clone());
    let in_scope: HashSet<String> = packages
        .iter()
        .filter(|p| {
            p.path
                .as_ref()
                .map(|pt| std::path::Path::new(pt).starts_with(&scan_root_canon))
                .unwrap_or(false)
        })
        .map(|p| p.name.to_ascii_lowercase())
        .collect();
    tokio::spawn(async move {
        match threat_intel::query_osv(&pkgs).await {
            Ok(findings) if !findings.is_empty() => {
                let n = findings.len();
                // Keep the full inventory in the threat panel...
                if let Err(e) = db2.save_osv_vulns(&findings) {
                    tracing::warn!("OSV save failed: {e}");
                } else {
                    tracing::info!("OSV: {n} findings cached");
                }
                // ...but only ALERT on in-use (in-scope) packages.
                let scoped: Vec<_> = findings
                    .iter()
                    .filter(|f| in_scope.contains(&f.package.to_ascii_lowercase()))
                    .cloned()
                    .collect();
                let osv_alerts = AlertEngine::from_osv(&scoped);
                if let Err(e) = db2.reconcile_alerts(&[AlertScope::PackageVuln], &osv_alerts) {
                    tracing::warn!("OSV alert reconcile failed: {e}");
                } else {
                    tracing::info!(
                        "OSV: {} findings, {} in-scope alerts raised",
                        n,
                        osv_alerts.len()
                    );
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

// ─────────────────────────── Ares agent helpers ───────────────────────────

/// Resolve the `agents/` directory next to the working directory.
fn agents_dir() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("agents")
}

fn load_ares_rules(cfg: &AresConfig) -> Vec<RuleSet> {
    let dir = agents_dir();
    let all = legion_ares::load_rule_sets(&dir);
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

// ─────────────────────────── Ares request bodies ──────────────────────────

#[derive(Deserialize)]
struct AgentChatBody {
    message: String,
}

// ─────────────────────────── Ares response types ──────────────────────────

#[derive(Serialize)]
struct AgentStatusResponse {
    online: bool,
    os: AgentOsProfile,
    /// Whether an Ollama binary is installed locally (even if not running).
    ollama_installed: bool,
    /// Where to send the operator to install Ollama if it is missing.
    ollama_download_url: String,
    model: String,
    /// Whether the primary model is installed in Ollama.
    model_installed: bool,
    fallback_model: String,
    /// Whether the fallback model is installed in Ollama.
    fallback_installed: bool,
    /// Active runtime backend (`openai_compat` or `ollama`).
    llm_runtime: String,
    /// Active model-host API base URL.
    llm_host: String,
    ollama_host: String,
    rules_loaded: usize,
    rule_hits: usize,
    hunt_ran: bool,
    search_enabled: bool,
    chat_messages: usize,
    /// Detected host hardware (None until the startup probe completes).
    hardware: Option<legion_ares::HardwareProfile>,
    /// The model tier chosen for the hardware, with the human-readable reason.
    model_selection: Option<legion_ares::ModelSelection>,
    /// Whether the model is chosen automatically from hardware (vs operator-pinned).
    model_auto: bool,
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
/// When the binary is not found we attempt a silent auto-install via the
/// platform package manager (winget on Windows) before giving
/// up, so first-run or fresh-OS setups work without manual steps.
///
/// Returns the resulting [`OllamaState`]: `Running` if it was already up,
/// `Started` if we launched it successfully, `Installed` if a binary exists but
/// the server did not respond, or `NotInstalled` if no binary was found even
/// after the auto-install attempt.
async fn ensure_ollama(host: &str) -> OllamaState {
    let registry = ModelRegistry::new(host);
    if registry.is_online().await {
        return OllamaState::Running;
    }

    // Attempt to start an already-installed server first.  If the binary is
    // missing, try a silent auto-install then retry.
    let spawn_result = bootstrap::spawn_server();
    match &spawn_result {
        Ok(bin) => {
            tracing::info!("starting Ollama server: {}", bin.display());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("Ollama binary not found — attempting silent auto-install");
            let installed = tokio::task::spawn_blocking(bootstrap::auto_install)
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
            match installed {
                Ok(()) => {
                    tracing::info!("Ollama auto-install succeeded; starting server");
                    match bootstrap::spawn_server() {
                        Ok(bin) => {
                            tracing::info!("Ollama server started: {}", bin.display());
                        }
                        Err(e) => {
                            tracing::warn!("Ollama auto-installed but server start failed: {e}");
                            return OllamaState::Installed;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Ollama auto-install failed: {e}. Download from {}",
                        legion_ares::OLLAMA_DOWNLOAD_URL
                    );
                    return OllamaState::NotInstalled;
                }
            }
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

#[derive(Deserialize)]
struct OpenAiModelsResponse {
    #[serde(default)]
    data: Vec<OpenAiModelInfo>,
}

#[derive(Deserialize)]
struct OpenAiModelInfo {
    id: String,
}

async fn fetch_openai_models(host: &str) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let url = format!("{}/v1/models", host.trim_end_matches('/'));
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("OpenAI-compatible /v1/models returned {}", resp.status());
    }
    let body: OpenAiModelsResponse = resp.json().await?;
    Ok(body.data.into_iter().map(|m| m.id).collect())
}

fn staged_model_path(primary: &str) -> std::path::PathBuf {
    let safe: String = primary
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    data_dir().join("models").join(format!("{safe}.gguf"))
}

fn openai_staged(primary: &str) -> bool {
    staged_model_path(primary).is_file()
}

fn pick_pullable_primary(preferred: &str) -> String {
    let manifest = ModelManifest::embedded();
    if manifest
        .tier(preferred)
        .is_some_and(|tier| tier.is_pullable())
    {
        return preferred.to_string();
    }
    for cand in ["legion-ares:qwen3-4b", "legion-ares:qwen3-1.7b"] {
        if manifest.tier(cand).is_some_and(|tier| tier.is_pullable()) {
            return cand.to_string();
        }
    }
    preferred.to_string()
}

fn fallback_for_primary(primary: &str) -> String {
    if let Some(suffix) = primary.strip_prefix("legion-ares:") {
        if let Some(idx) = suffix.rfind('-') {
            return format!("{}:{}", &suffix[..idx], &suffix[idx + 1..]);
        }
    }
    "qwen3:4b".to_string()
}

async fn stage_model_from_manifest(primary: &str) -> Result<String> {
    let manifest = ModelManifest::embedded();
    let model_version = manifest.model_version.clone();
    let tier = manifest
        .tier(primary)
        .ok_or_else(|| anyhow::anyhow!("no manifest tier entry for {primary}"))?;
    if !tier.is_pullable() {
        anyhow::bail!("manifest tier for {primary} is not pullable yet");
    }

    let path = staged_model_path(primary);
    let models_dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid staged model path"))?;
    std::fs::create_dir_all(models_dir)?;
    legion_core::harden_dir(models_dir);

    let state = legion_ares::model_state::ModelState::load(&data_dir());
    if path.is_file() && state.is_some_and(|s| s.is_current(primary, &tier.sha256)) {
        return Ok(format!(
            "{primary} staged and up to date ({})",
            manifest.model_version
        ));
    }

    let cap = if tier.size_bytes > 0 {
        (tier.size_bytes + 16 * 1024 * 1024) as usize
    } else {
        12 * 1024 * 1024 * 1024
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3600))
        .build()?;
    tracing::info!("ares: downloading staged model {primary} from {}", tier.url);
    let resp = client.get(&tier.url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("download of {} returned {}", tier.url, resp.status());
    }
    let integrity = legion_core::integrity::FeedIntegrity::Sha256(&tier.sha256);
    let bytes = legion_core::http::download_verified_to_file(resp, &path, cap, &integrity).await?;
    tracing::info!(
        "ares: staged + verified {bytes} bytes at {}",
        path.display()
    );

    let state = legion_ares::model_state::ModelState {
        tier: primary.to_string(),
        model_version,
        sha256: tier.sha256.clone(),
    };
    let _ = state.save(&data_dir());
    Ok(format!("{primary} pulled from Hugging Face and staged"))
}

async fn runtime_status(cfg: &AresConfig) -> (bool, bool, bool) {
    if cfg.runtime_is_ollama() {
        let registry = ModelRegistry::new(&cfg.ollama_host);
        let online = registry.is_online().await;
        let (model_installed, fallback_installed) = if online {
            tokio::join!(
                registry.is_model_installed(&cfg.model),
                registry.is_model_installed(&cfg.fallback_model),
            )
        } else {
            (false, false)
        };
        (online, model_installed, fallback_installed)
    } else {
        match fetch_openai_models(cfg.active_host()).await {
            Ok(models) => {
                let model_installed = models.iter().any(|m| m == &cfg.model);
                let fallback_installed = models.iter().any(|m| m == &cfg.fallback_model);
                (true, model_installed, fallback_installed)
            }
            Err(_) => {
                let model_staged = openai_staged(&cfg.model);
                let fallback_staged = openai_staged(&cfg.fallback_model);
                (false, model_staged, fallback_staged)
            }
        }
    }
}

// ─────────────────────────── Ares handlers ────────────────────────────────

/// GET /api/agent/status
async fn api_agent_status(State(s): State<Arc<AppState>>) -> AResult<Json<AgentStatusResponse>> {
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    let hist_len = lock_api(&s.chat_history, "chat_history")?.len();
    let hunt_ran = lock_api(&s.last_hunt, "last_hunt")?.is_some();
    let (online, model_installed, fallback_installed) = runtime_status(&cfg).await;
    let rule_sets = load_ares_rules(&cfg);
    let rules_loaded: usize = rule_sets.iter().map(|rs| rs.rules.len()).sum();
    let (rule_hits,) = {
        let db = s.db.clone();
        let cfg2 = cfg.clone();
        tokio::task::spawn_blocking(move || {
            let ctx = KnowledgeContext::collect(&db, &cfg2, &rule_sets);
            (ctx.rule_hits.len(),)
        })
        .await?
    };
    let active_host = cfg.active_host().to_string();
    Ok(Json(AgentStatusResponse {
        online,
        os: detect_agent_os_profile(),
        ollama_installed: bootstrap::is_installed(),
        ollama_download_url: legion_ares::OLLAMA_DOWNLOAD_URL.to_string(),
        model: cfg.model,
        model_installed,
        fallback_model: cfg.fallback_model,
        fallback_installed,
        llm_runtime: cfg.llm_runtime.clone(),
        llm_host: active_host,
        ollama_host: cfg.ollama_host,
        rules_loaded,
        rule_hits,
        hunt_ran,
        search_enabled: cfg.search_enabled,
        chat_messages: hist_len,
        hardware: lock_api(&s.hardware, "hardware")?.clone(),
        model_selection: lock_api(&s.model_selection, "model_selection")?.clone(),
        model_auto: cfg.model_auto,
    }))
}

/// POST /api/agent/ollama/start — start the local Ollama server if installed.
async fn api_agent_ollama_start(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<serde_json::Value>> {
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    if !cfg.runtime_is_ollama() {
        return Ok(Json(serde_json::json!({
            "ok": false,
            "state": "disabled",
            "installed": false,
            "download_url": legion_ares::OLLAMA_DOWNLOAD_URL,
            "message": "Ollama control is disabled because llm_runtime is not set to 'ollama'."
        })));
    }
    let host = cfg.ollama_host;
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
            legion_ares::OLLAMA_DOWNLOAD_URL
        ),
    };
    Ok(Json(serde_json::json!({
        "ok": state.is_online(),
        "state": state,
        "installed": state != OllamaState::NotInstalled,
        "download_url": legion_ares::OLLAMA_DOWNLOAD_URL,
        "message": message,
    })))
}

/// GET /api/agent/config
async fn api_agent_config_get(State(s): State<Arc<AppState>>) -> AResult<Json<AresConfig>> {
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    Ok(Json(cfg))
}

/// POST /api/agent/config  — save + validate config.
///
/// Persisting the config is a privileged action: it re-launches a short-lived
/// elevated helper which triggers a fresh OS admin prompt (UAC / polkit)
/// each time. The save only commits if the operator approves.
async fn api_agent_config_save(
    State(s): State<Arc<AppState>>,
    Json(new_cfg): Json<AresConfig>,
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
                *lock_api(&s.ares_config, "ares_config")? = AresConfig::load(&data_dir());
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
                *lock_api(&s.ares_config, "ares_config")? = new_cfg.clone();
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
        *lock_api(&s.ares_config, "ares_config")? = new_cfg.clone();
    }

    s.db.audit(
        "operator",
        "agent.config.save",
        &format!("model={}", new_cfg.model),
        "web",
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Persist the ARES config through the OS elevation prompt. Stages the
/// proposed config in the protected data dir, then re-invokes this executable
/// elevated with `--apply-ares-config <file>` and waits for it to finish.
fn elevated_persist_config(cfg: &AresConfig) -> Result<privilege::ElevatedRun> {
    let exe = std::env::current_exe()?;
    let mut staged = data_dir();
    std::fs::create_dir_all(&staged).ok();
    staged.push("ares.pending.json");
    std::fs::write(&staged, serde_json::to_vec_pretty(cfg)?)?;
    legion_core::harden_file(&staged);

    let args = vec![
        "--apply-ares-config".to_string(),
        staged.to_string_lossy().to_string(),
    ];
    let outcome = privilege::run_elevated_wait(
        &exe,
        &args,
        "Legion needs administrator approval to change the ARES agent configuration.",
    );
    let _ = std::fs::remove_file(&staged);
    Ok(outcome)
}

/// Elevated helper entrypoint (`--apply-ares-config`): read the staged config
/// and persist it with hardened permissions, then exit. Runs with admin rights.
fn apply_ares_config_helper(path: &std::path::Path) -> Result<()> {
    // This runs elevated, so the path handed on argv is untrusted: confine it to
    // the protected data directory and to the expected staged filename before
    // reading, so a crafted `--apply-ares-config /attacker/file` cannot have us
    // write attacker-controlled content with admin rights (audit WEB-2).
    let expected_dir = data_dir().canonicalize().unwrap_or_else(|_| data_dir());
    let canon = path.canonicalize()?;
    if !canon.starts_with(&expected_dir) {
        anyhow::bail!("refusing to apply config from outside the protected data directory");
    }
    if canon.file_name() != Some(std::ffi::OsStr::new("ares.pending.json")) {
        anyhow::bail!("refusing to apply config from an unexpected filename");
    }
    let data = std::fs::read_to_string(&canon)?;
    let cfg: AresConfig = serde_json::from_str(&data)?;
    cfg.validate()?;
    cfg.save(&data_dir())?;
    Ok(())
}

/// GET /api/agent/rules  — return all loaded rule sets + current hits
async fn api_agent_rules(State(s): State<Arc<AppState>>) -> AResult<Json<AgentRulesResponse>> {
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    let rule_sets = load_ares_rules(&cfg);
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
) -> AResult<Json<legion_ares::ChatResponse>> {
    // Sanitise input
    let user_msg = body.message.trim().to_string();
    if user_msg.is_empty() {
        return Err(anyhow::anyhow!("empty message").into());
    }
    if user_msg.len() > 4096 {
        return Err(anyhow::anyhow!("message exceeds 4096 byte limit").into());
    }
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    let history = lock_api(&s.chat_history, "chat_history")?.clone();
    let db = s.db.clone();
    let cfg2 = cfg.clone();
    let rule_sets = load_ares_rules(&cfg);

    // Phase 1: build knowledge context (blocking syscalls)
    let ctx =
        tokio::task::spawn_blocking(move || KnowledgeContext::collect(&db, &cfg2, &rule_sets))
            .await?;

    // Phase 2: call Ollama (async HTTP)
    let chat = AresChat::new(cfg.clone());
    let resp = chat.respond(&history, &user_msg, &ctx).await?;

    // Phase 3: update in-memory history
    {
        let mut h = lock_api(&s.chat_history, "chat_history")?;
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
async fn api_agent_hunt(State(s): State<Arc<AppState>>) -> AResult<Json<legion_ares::HuntReport>> {
    let cfg = lock_api(&s.ares_config, "ares_config")?.clone();
    let db = s.db.clone();
    let cfg2 = cfg.clone();
    let rule_sets = load_ares_rules(&cfg);

    let ctx =
        tokio::task::spawn_blocking(move || KnowledgeContext::collect(&db, &cfg2, &rule_sets))
            .await?;

    let chat = AresChat::new(cfg.clone());
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
                title: format!("ARES: {} {}", h.rule_id, h.title),
                detail,
                package_name: None,
                package_ecosystem: None,
                ip_address: None,
                cve_ids: Vec::new(),
                event_title: Some(format!("{} {}", h.framework.to_uppercase(), h.rule_id)),
                created_at: now.clone(),
                acked: false,
                file_path: None,
                source: format!("ARES agent ({})", h.framework.to_uppercase()),
            })
        })
        .collect();
    if let Err(e) = s.db.replace_agent_alerts(&agent_alerts) {
        tracing::warn!("failed to persist agent alerts: {e}");
    }

    // Cache for the dashboard's hunt-analysis panel.
    *lock_api(&s.last_hunt, "last_hunt")? = Some(report.clone());
    Ok(Json(report))
}

/// GET /api/agent/hunt/latest — most recent hunt report (null if none yet).
async fn api_agent_hunt_latest(
    State(s): State<Arc<AppState>>,
) -> AResult<Json<Option<legion_ares::HuntReport>>> {
    let report = lock_api(&s.last_hunt, "last_hunt")?.clone();
    Ok(Json(report))
}

/// GET /api/agent/history  — return session chat history
async fn api_agent_history(State(s): State<Arc<AppState>>) -> AResult<Json<Vec<ChatMessage>>> {
    let h = lock_api(&s.chat_history, "chat_history")?.clone();
    Ok(Json(h))
}

/// POST /api/agent/clear  — clear session chat history
async fn api_agent_clear(State(s): State<Arc<AppState>>) -> AResult<StatusCode> {
    lock_api(&s.chat_history, "chat_history")?.clear();
    s.db.audit("operator", "agent.clear", "chat history cleared", "web");
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/agent/loop/state — full autonomous loop state snapshot.
async fn api_agent_loop_state(State(s): State<Arc<AppState>>) -> AResult<Json<AgentLoopState>> {
    let st = lock_api(&s.agent_loop_state, "agent_loop_state")?.clone();
    Ok(Json(st))
}

/// GET /api/agent/loop/ticks — recent tick ring buffer (newest first).
async fn api_agent_loop_ticks(State(s): State<Arc<AppState>>) -> AResult<Json<Vec<AgentTick>>> {
    let ticks = lock_api(&s.agent_loop_state, "agent_loop_state")?
        .recent_ticks
        .clone();
    Ok(Json(ticks))
}

// ─────────────────────────────── Main ───────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Subcommands (install / restart) run and exit before any server setup.
    match args.command {
        Some(Command::Install {
            bin_dir,
            data_dir,
            no_path,
            no_desktop,
        }) => {
            return install::run(install::InstallOptions {
                bin_dir,
                data_dir,
                no_path,
                no_desktop,
            });
        }
        Some(Command::Restart) => return install::restart(),
        None => {}
    }

    // Privileged helper path: when re-invoked through the OS elevation prompt
    // (UAC / polkit), persist the ARES config and exit. This runs
    // elevated and does nothing else — it is the per-action elevation target.
    if let Some(path) = args.apply_ares_config.as_ref() {
        return apply_ares_config_helper(path);
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

    // Default to warnings, but keep the `legion.audit` target at info so the
    // structured audit-log mirror (AU-2/AU-3, mirrored for log forwarding) is
    // actually emitted; honor RUST_LOG when set for finer control.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,legion.audit=info")),
        )
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
        Ok(n) if n > 0 => tracing::info!("cleared {n} stale ARES alerts from previous session"),
        Ok(_) => {}
        Err(e) => tracing::warn!("failed to clear stale ARES alerts: {e}"),
    }

    let ares_config = Arc::new(Mutex::new(AresConfig::load(&data_dir())));
    let chat_history: Arc<Mutex<Vec<ChatMessage>>> = Arc::new(Mutex::new(Vec::new()));
    let agent_loop_state: LoopStateHandle = Arc::new(Mutex::new(AgentLoopState::default()));

    let session_token = generate_session_token();

    let state = Arc::new(AppState {
        db,
        scan_root: args.scan_root.canonicalize().unwrap_or(args.scan_root),
        net_prev: Arc::new(Mutex::new(None)),
        ares_config,
        chat_history,
        last_hunt: Arc::new(Mutex::new(None)),
        agent_loop_state,
        hardware: Arc::new(Mutex::new(None)),
        model_selection: Arc::new(Mutex::new(None)),
        elevate_writes,
        session_token,
    });

    // Persist the token to an owner-only file so same-user CLI clients can read
    // it; other local users cannot (OS-delegated access control). Best-effort.
    //
    // On Windows the process may be running elevated (admin) which causes
    // %APPDATA% to resolve to the *administrator* profile rather than the
    // interactive user's profile.  To keep the browser and the CLI able to find
    // the token, we first try the value of the non-elevated environment
    // variable (passed through by restart.ps1 as LEGION_USER_APPDATA), then
    // fall back to the standard data_dir().
    let token_path = {
        #[cfg(target_os = "windows")]
        {
            std::env::var("LEGION_USER_APPDATA")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|a| {
                    std::path::PathBuf::from(a)
                        .join("legion")
                        .join("session.token")
                })
                .unwrap_or_else(|| data_dir().join("session.token"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            data_dir().join("session.token")
        }
    };
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
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

    // Bring the ARES agent online. For the legacy Ollama runtime, start
    // `ollama serve` when needed. For OpenAI-compatible runtimes (for example
    // llama.cpp server), just probe reachability and skip Ollama lifecycle.
    // Track whether *we* started Ollama so we can stop it on exit.
    let ollama_started_by_us = Arc::new(AtomicBool::new(false));
    {
        let host = state
            .ares_config
            .lock()
            .map(|g| g.active_host().to_string())
            .unwrap_or_else(|_| "http://localhost:11434".to_string());
        let flag = ollama_started_by_us.clone();
        let prov_state = state.clone();
        tokio::spawn(async move {
            let use_ollama = prov_state
                .ares_config
                .lock()
                .map(|c| c.runtime_is_ollama())
                .unwrap_or(true);

            // Step 1: ensure the selected runtime is reachable.
            if use_ollama {
                let ollama_state = ensure_ollama(&host).await;
                match ollama_state {
                    OllamaState::Running => tracing::info!("Ollama already running"),
                    OllamaState::Started => {
                        flag.store(true, Ordering::Relaxed);
                        tracing::info!("Ollama started by Legion");
                    }
                    OllamaState::Installed => {
                        tracing::warn!("Ollama installed but not reachable at {host}");
                        return;
                    }
                    OllamaState::NotInstalled => {
                        tracing::warn!(
                            "Ollama not installed — ARES chat disabled until installed from {}",
                            legion_ares::OLLAMA_DOWNLOAD_URL
                        );
                        return;
                    }
                }
            } else if fetch_openai_models(&host).await.is_err() {
                tracing::warn!(
                    "OpenAI-compatible runtime not reachable at {host} — start your local model server"
                );
            }

            // Step 2: detect hardware and choose the model tier that stays
            // GPU-resident on this host (the fix for multi-minute responses).
            let hw = legion_ares::HardwareProfile::detect();
            let selection = legion_ares::select_model(&hw);
            tracing::info!(
                "ARES hardware: {} → {} ({})",
                hw.summary(),
                selection.primary,
                selection.reason
            );

            // In automatic mode the selection drives the active model; if the
            // operator has pinned a model (model_auto = false) we respect it and
            // only record what *would* have been chosen.
            let primary = {
                let mut cfg = match prov_state.ares_config.lock() {
                    Ok(c) => c,
                    Err(_) => {
                        tracing::warn!("ares_config lock poisoned during provisioning; skipping model selection update");
                        return;
                    }
                };
                if cfg.model_auto {
                    cfg.model = selection.primary.clone();
                    cfg.fallback_model = selection.fallback.clone();
                }
                cfg.model.clone()
            };
            if let Ok(mut h) = prov_state.hardware.lock() {
                *h = Some(hw);
            }
            if let Ok(mut ms) = prov_state.model_selection.lock() {
                *ms = Some(selection);
            }

            let pullable_primary = pick_pullable_primary(&primary);
            if pullable_primary != primary {
                tracing::warn!(
                    "ares: selected tier {primary} is not published; using pullable tier {pullable_primary}"
                );
                if let Ok(mut cfg) = prov_state.ares_config.lock() {
                    cfg.model = pullable_primary.clone();
                    cfg.fallback_model = fallback_for_primary(&pullable_primary);
                }
            }

            // Step 3: provision only in Ollama mode; OpenAI-compatible runtimes
            // are treated as externally managed model servers.
            if use_ollama {
                let registry = ModelRegistry::new(&host);
                let (changed, msg) = registry
                    .auto_provision_ares(&pullable_primary, &data_dir())
                    .await;
                if changed {
                    tracing::info!("Ares models provisioned: {msg}");
                } else {
                    tracing::info!("Ares model check: {msg}");
                }
            } else {
                match stage_model_from_manifest(&pullable_primary).await {
                    Ok(msg) => tracing::info!("Ares staged model: {msg}"),
                    Err(e) => tracing::warn!(
                        "Ares model staging failed for {pullable_primary}: {e} (runtime remains externally managed)"
                    ),
                }
            }
        });
    }

    // Launch the Ares autonomous agent loop.  This runs continuously
    // in the background: probing the OS lane, scoring with the neural hunter,
    // and escalating to a full LLM hunt when posture crosses the threshold.
    {
        let loop_state = state.agent_loop_state.clone();
        let loop_cfg_ref = state.ares_config.clone();
        let loop_app_state = state.clone();

        // The hunt callback: called by the agent loop when escalation fires.
        // Drives the same hunt pipeline as POST /api/agent/hunt.
        let hunt_cb: HuntCallback = Arc::new(move || {
            let s = loop_app_state.clone();
            Box::pin(async move {
                let cfg = match s.ares_config.lock() {
                    Ok(c) => c.clone(),
                    Err(_) => {
                        tracing::warn!("ares_config lock poisoned in auto-hunt; skipping tick");
                        return;
                    }
                };
                let db = s.db.clone();
                let cfg2 = cfg.clone();
                let rule_sets = load_ares_rules(&cfg);
                let ctx = match tokio::task::spawn_blocking(move || {
                    KnowledgeContext::collect(&db, &cfg2, &rule_sets)
                })
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("agent auto-hunt context failed: {e}");
                        return;
                    }
                };
                let chat = AresChat::new(cfg.clone());
                match chat.hunt(&ctx).await {
                    Ok(report) => {
                        tracing::warn!(
                            "ares agent auto-hunt complete: {} rule hits, model={}",
                            report.rule_hits.len(),
                            report.model_used
                        );
                        s.db.audit(
                            "agent",
                            "agent.auto_hunt",
                            &format!(
                                "model={} hits={}",
                                report.model_used,
                                report.rule_hits.len()
                            ),
                            "agent_loop",
                        );
                        if let Ok(mut lh) = s.last_hunt.lock() {
                            *lh = Some(report);
                        }
                    }
                    Err(e) => tracing::warn!("ares agent auto-hunt failed: {e}"),
                }
            })
        });

        tokio::spawn(legion_ares::run_agent_loop(
            loop_cfg_ref,
            loop_state,
            AgentLoopConfig::default(),
            hunt_cb,
        ));
    }

    // All `/api/*` routes sit behind the session-token gate; the dashboard page
    // itself ("/") is served unauthenticated so the browser can obtain the
    // cookie, then every API call it makes carries it (audit WEB-1).
    let api = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/alerts", get(api_alerts))
        .route("/api/alerts/:id/ack", post(api_ack))
        .route("/api/open", post(api_open))
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
        // ── Ares agent ──────────────────────────────────────────────────
        .route("/api/agent/status", get(api_agent_status))
        .route("/api/agent/ollama/start", post(api_agent_ollama_start))
        .route("/api/agent/config", get(api_agent_config_get))
        .route("/api/agent/config", post(api_agent_config_save))
        .route("/api/agent/rules", get(api_agent_rules))
        .route("/api/agent/chat", post(api_agent_chat))
        .route("/api/agent/hunt", post(api_agent_hunt))
        .route("/api/agent/hunt/latest", get(api_agent_hunt_latest))
        .route("/api/agent/history", get(api_agent_history))
        .route("/api/agent/clear", post(api_agent_clear))
        // ── Ares autonomous loop ────────────────────────────────────────
        .route("/api/agent/loop/state", get(api_agent_loop_state))
        .route("/api/agent/loop/ticks", get(api_agent_loop_ticks))
        // Session-token gate on every API route (applied only to the routes in
        // this sub-router, not the dashboard page).
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/icons/:slug", get(serve_os_icon))
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

    if !bound_loopback && !args.allow_insecure_bind {
        return Err(anyhow::anyhow!(
            "refusing non-loopback bind to {} without --allow-insecure-bind",
            args.host
        ));
    }

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

    // Same-user guard (audit 2026-07 H1): on a loopback bind, refuse
    // connections from a different local user so the session cookie vended by
    // `GET /` can't be scraped by any local account. Applied outermost so it
    // runs before the token gate. Escape hatches: `LEGION_DISABLE_PEERCRED`
    // turns it off; `LEGION_STRICT_PEERCRED` also refuses peers whose UID can't
    // be determined (e.g. IPv6 / non-Linux) instead of failing open.
    let peercred_disabled = std::env::var_os("LEGION_DISABLE_PEERCRED").is_some();
    let app = if bound_loopback && !peercred_disabled {
        let local = listener.local_addr().unwrap_or_else(|_| {
            addr.parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], args.port)))
        });
        let guard = PeerGuard {
            local,
            authorized: Arc::new(peercred::authorized_uids()),
            strict: std::env::var_os("LEGION_STRICT_PEERCRED").is_some(),
        };
        app.layer(middleware::from_fn_with_state(guard, same_user_guard))
    } else {
        app
    };

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
    println!(
        "  API token (for CLI clients) written to: {}",
        token_path.display()
    );
    println!("  the browser dashboard authenticates automatically.");
    println!();

    if !args.no_open {
        let _ = open::that(&url);
    }

    // `into_make_service_with_connect_info` populates `ConnectInfo<SocketAddr>`
    // so `same_user_guard` can identify the peer.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
        if ollama_started_by_us.load(Ordering::Relaxed) {
            tracing::info!("stopping Ollama (started by Legion)...");
            if let Err(e) = bootstrap::stop_server() {
                tracing::warn!("failed to stop Ollama: {e}");
            } else {
                tracing::info!("Ollama stopped");
            }
        }
    })
    .await?;
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
