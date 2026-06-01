//! Legion TUI – application state and async data refresh.

use anyhow::Result;
use legion_core::{
    alerts::{Alert, AlertEngine},
    feeds::FeedManager,
    quarantine::QuarantineManager,
    scanner::PackageScanner,
    telemetry::{self, SystemStats},
    Database,
};
use ratatui::widgets::TableState;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long to wait between automatic data refreshes.
const REFRESH_INTERVAL: Duration = Duration::from_secs(120);

// ─────────────────────────────── App State ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Alerts,
    #[allow(dead_code)]
    Telemetry,
    #[allow(dead_code)]
    Quarantine,
}

pub struct App {
    pub alerts: Vec<Alert>,
    pub stats: SystemStats,
    pub scan_info: ScanInfo,
    pub feed_info: FeedInfo,
    pub table_state: TableState,
    #[allow(dead_code)]
    pub selected_panel: Panel,
    pub status_msg: Option<String>,
    pub should_quit: bool,
    pub last_refresh: Instant,
    pub db: Database,
    pub scan_root: PathBuf,
}

#[derive(Default, Clone)]
pub struct FeedInfo {
    pub events_cached: i64,
    pub ips_cached: i64,
    pub quarantine_count: usize,
    pub active_connections: Vec<String>,
}

#[derive(Default, Clone)]
pub struct ScanInfo {
    pub cargo_count: usize,
    pub npm_count: usize,
    pub pip_count: usize,
    pub last_scan: Option<String>,
    #[allow(dead_code)]
    pub scan_errors: Vec<String>,
}

impl App {
    pub fn new(db: Database, scan_root: PathBuf) -> Self {
        Self {
            alerts: vec![],
            stats: SystemStats::default(),
            scan_info: ScanInfo::default(),
            feed_info: FeedInfo::default(),
            table_state: TableState::default(),
            selected_panel: Panel::Alerts,
            status_msg: Some("Press R to refresh, S to scan, Q to quit".into()),
            should_quit: false,
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            db,
            scan_root,
        }
    }

    /// Load alerts from DB and refresh system stats.
    pub fn refresh_fast(&mut self) -> Result<()> {
        self.alerts = self.db.get_alerts(Some(false))?;
        self.stats = telemetry::collect();
        self.feed_info.events_cached = self.db.count_events().unwrap_or(0);
        self.feed_info.ips_cached = self.db.count_cached_ips().unwrap_or(0);
        self.feed_info.quarantine_count = {
            let qm = QuarantineManager::new(self.db.clone());
            qm.list().map(|v| v.iter().filter(|e| e.is_active()).count()).unwrap_or(0)
        };
        self.feed_info.active_connections = telemetry::active_remote_ips();
        self.last_refresh = Instant::now();
        Ok(())
    }

    /// Full async refresh: pull feeds, scan packages, correlate.
    pub async fn full_refresh(&mut self) -> Result<()> {
        self.status_msg = Some("Refreshing feeds...".into());

        // Pull cyber feed
        let fm = FeedManager::new()?;
        let events = match fm.fetch_cyber_events().await {
            Ok(evs) => {
                let _ = self.db.upsert_events(&evs);
                evs
            }
            Err(e) => {
                self.status_msg = Some(format!("Feed error: {e}"));
                vec![]
            }
        };

        // Pull IP blacklist
        if let Ok(payload) = fm.fetch_abuseips().await {
            let _ = self.db.upsert_ips(&payload.ips);
        }

        self.status_msg = Some("Scanning packages...".into());

        // Scan packages
        let scan = PackageScanner::scan(&self.scan_root);
        let _ = self.db.save_scan(&scan.packages);

        self.scan_info = ScanInfo {
            cargo_count: scan.cargo_count(),
            npm_count: scan.npm_count(),
            pip_count: scan.pip_count(),
            last_scan: Some(
                chrono::Utc::now().format("%H:%M:%S UTC").to_string(),
            ),
            scan_errors: scan.errors.clone(),
        };

        // Correlate and save new alerts
        let new_alerts = AlertEngine::correlate(&scan.packages, &events);
        if !new_alerts.is_empty() {
            let _ = self.db.save_alerts(&new_alerts);
        }

        // Check IPs
        let active_ips = telemetry::active_remote_ips();
        if !active_ips.is_empty() {
            if let Ok(payload) = fm.fetch_abuseips().await {
                let ip_alerts = AlertEngine::check_ips(&active_ips, &payload);
                if !ip_alerts.is_empty() {
                    let _ = self.db.save_alerts(&ip_alerts);
                }
            }
        }

        // Reload alerts from DB
        self.alerts = self.db.get_alerts(Some(false))?;
        self.stats = telemetry::collect();
        self.last_refresh = Instant::now();
        self.status_msg = Some(format!(
            "Refreshed at {} — {} active alerts",
            chrono::Utc::now().format("%H:%M:%S"),
            self.alerts.len()
        ));

        Ok(())
    }

    pub fn should_auto_refresh(&self) -> bool {
        self.last_refresh.elapsed() >= REFRESH_INTERVAL
    }

    // ─── Navigation ────────────────────────────────────────────────────────

    pub fn next_alert(&mut self) {
        if self.alerts.is_empty() {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map(|s| (s + 1).min(self.alerts.len().saturating_sub(1)))
            .unwrap_or(0);
        self.table_state.select(Some(i));
    }

    pub fn prev_alert(&mut self) {
        if self.alerts.is_empty() {
            return;
        }
        let i = self
            .table_state
            .selected()
            .map(|s| s.saturating_sub(1))
            .unwrap_or(0);
        self.table_state.select(Some(i));
    }

    /// Acknowledge the currently selected alert.
    pub fn ack_selected(&mut self) -> Result<()> {
        if let Some(idx) = self.table_state.selected() {
            if let Some(alert) = self.alerts.get(idx) {
                self.db.ack_alert(alert.id)?;
                self.alerts.remove(idx);
                // Adjust selection
                if !self.alerts.is_empty() {
                    let new_idx = idx.min(self.alerts.len().saturating_sub(1));
                    self.table_state.select(Some(new_idx));
                } else {
                    self.table_state.select(None);
                }
                self.status_msg = Some(format!("Alert {idx} acknowledged"));
            }
        }
        Ok(())
    }
}
