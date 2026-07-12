//! SQLite persistence layer.
//!
//! Database lives at:
//!   Windows: %APPDATA%\legion\legion.db
//!   Linux: ~/.local/share/legion/legion.db

use crate::{
    ai_detector::{AiThreat, AiThreatKind},
    alerts::{Alert, AlertScope},
    baseline::Baseline,
    feeds::{AbuseIpEntry, CyberEvent},
    quarantine::QuarantineEntry,
    scanner::ScannedPackage,
    threat_intel::{KevEntry, OsvFinding},
    yara::YaraMatch,
};
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

// ─────────────────────────────── Database ───────────────────────────────────

/// A row from the audit log: `(ts, actor, action, detail, source)`.
pub type AuditRow = (String, String, String, String, String);

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) the database at `path`, initialising the schema.
    ///
    /// The data directory and database file are restricted to the owner on Unix
    /// (`0700` / `0600`) since they hold alert and threat-intelligence data.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            crate::harden_dir(parent);
        }
        let conn = Connection::open(path)?;
        crate::harden_file(path);
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        match db.prune_alerts() {
            Ok((legacy, aged)) if legacy + aged > 0 => {
                tracing::info!("alert hygiene: removed {legacy} legacy + {aged} aged-out alerts");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("alert hygiene failed: {e}"),
        }
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             -- Wait up to 10s for a held lock instead of failing instantly with
             -- SQLITE_BUSY. Without this, any concurrent writer (a second Legion
             -- instance, the CLI, or an overlapping background scan) makes writes
             -- error out immediately — surfacing as 'Scan failed'.
             PRAGMA busy_timeout = 10000;
             -- NORMAL is the recommended durability level under WAL and reduces
             -- fsync contention during large scan writes.
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS cyber_events (
                 id          TEXT PRIMARY KEY,
                 title       TEXT NOT NULL,
                 summary     TEXT,
                 severity    REAL,
                 date_start  TEXT,
                 tags        TEXT,
                 enrichment  TEXT,
                 fetched_at  TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS alerts (
                 id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind                TEXT NOT NULL,
                 severity            TEXT NOT NULL,
                 title               TEXT NOT NULL,
                 detail              TEXT,
                 package_name        TEXT,
                 package_ecosystem   TEXT,
                 ip_address          TEXT,
                 cve_ids             TEXT,
                 event_title         TEXT,
                 created_at          TEXT NOT NULL,
                 acked               INTEGER NOT NULL DEFAULT 0,
                 file_path           TEXT,
                 source              TEXT
             );

             CREATE INDEX IF NOT EXISTS idx_alerts_acked ON alerts(acked);

             CREATE TABLE IF NOT EXISTS scanned_packages (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ecosystem   TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 version     TEXT,
                 path        TEXT,
                 scanned_at  TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS quarantined (
                 id              INTEGER PRIMARY KEY AUTOINCREMENT,
                 ecosystem       TEXT NOT NULL,
                 name            TEXT NOT NULL,
                 version         TEXT,
                 reason          TEXT,
                 quarantined_at  TEXT NOT NULL,
                 released_at     TEXT
             );

             CREATE TABLE IF NOT EXISTS abuse_ips (
                 ip             TEXT PRIMARY KEY,
                 country        TEXT,
                 abuse_score    INTEGER,
                 last_reported  TEXT,
                 fetched_at     TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS osv_vulns (
                 osv_id      TEXT NOT NULL,
                 package     TEXT NOT NULL,
                 ecosystem   TEXT NOT NULL,
                 version     TEXT,
                 severity    TEXT,
                 summary     TEXT NOT NULL,
                 cve_ids     TEXT,
                 ghsa_ids    TEXT,
                 fixed_ver   TEXT,
                 published   TEXT,
                 fetched_at  TEXT NOT NULL,
                 PRIMARY KEY (osv_id, package, ecosystem)
             );

             CREATE TABLE IF NOT EXISTS kev_entries (
                 cve_id      TEXT PRIMARY KEY,
                 vendor      TEXT,
                 product     TEXT,
                 vuln_name   TEXT,
                 date_added  TEXT,
                 description TEXT,
                 ransomware  INTEGER NOT NULL DEFAULT 0,
                 fetched_at  TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS ai_detections (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind        TEXT NOT NULL,
                 severity    TEXT NOT NULL,
                 package     TEXT,
                 ecosystem   TEXT,
                 version     TEXT,
                 detail      TEXT NOT NULL,
                 atlas_id    TEXT,
                 detected_at TEXT NOT NULL,
                 acked       INTEGER NOT NULL DEFAULT 0
             );

             CREATE TABLE IF NOT EXISTS yara_matches (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 rule        TEXT NOT NULL,
                 tags        TEXT,
                 severity    TEXT NOT NULL,
                 description TEXT,
                 target      TEXT NOT NULL,
                 matched     TEXT,
                 detected_at TEXT NOT NULL,
                 acked       INTEGER NOT NULL DEFAULT 0
             );

             CREATE TABLE IF NOT EXISTS baselines (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 os          TEXT NOT NULL,
                 created_at  TEXT NOT NULL,
                 data        TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS audit_log (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts          TEXT NOT NULL,
                 actor       TEXT NOT NULL,
                 action      TEXT NOT NULL,
                 detail      TEXT,
                 source      TEXT
             );",
        )?;
        // Backfill columns on alerts tables created before file_path/source
        // existed. ALTER ADD COLUMN errors harmlessly if the column is already
        // present, so fresh (CREATE above) and upgraded DBs converge.
        for col in ["file_path", "source"] {
            let _ = conn.execute(&format!("ALTER TABLE alerts ADD COLUMN {col} TEXT"), []);
        }
        Ok(())
    }

    // ─── Audit log (tamper-evident security event trail) ─────────────────

    /// Append a security-relevant event to the audit log. Best-effort: a logging
    /// failure is reported via tracing but never aborts the caller's operation.
    pub fn audit(&self, actor: &str, action: &str, detail: &str, source: &str) {
        let ts = chrono::Utc::now().to_rfc3339();
        // Mirror to structured logs for SIEM/forwarder ingestion (NIST AU-2).
        tracing::info!(target: "legion.audit", actor, action, source, "{detail}");
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Err(e) = conn.execute(
            "INSERT INTO audit_log (ts, actor, action, detail, source) VALUES (?1,?2,?3,?4,?5)",
            params![ts, actor, action, detail, source],
        ) {
            tracing::warn!("audit log write failed: {e}");
        }
    }

    /// Most recent audit entries (newest first) as
    /// `(ts, actor, action, detail, source)` tuples.
    pub fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT ts, actor, action, COALESCE(detail,''), COALESCE(source,'')
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Whether `path` is recorded as the `file_path` of some alert. Used to
    /// confine the dashboard's "reveal in file manager" action to files Legion
    /// actually flagged, rather than any path on disk (audit 2026-07 L2).
    pub fn alert_path_exists(&self, path: &str) -> bool {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => e.into_inner(),
        };
        conn.query_row(
            "SELECT 1 FROM alerts WHERE file_path = ?1 LIMIT 1",
            [path],
            |_| Ok(()),
        )
        .is_ok()
    }

    // ─── Events ────────────────────────────────────────────────────────────

    pub fn upsert_events(&self, events: &[CyberEvent]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut count = 0usize;
        for ev in events {
            let tags = serde_json::to_string(&ev.tags).unwrap_or_default();
            let enrichment = serde_json::to_string(&ev.enrichment).unwrap_or_default();
            tx.execute(
                "INSERT OR REPLACE INTO cyber_events
                 (id, title, summary, severity, date_start, tags, enrichment, fetched_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    ev.id,
                    ev.title,
                    ev.summary,
                    ev.severity,
                    ev.date_start,
                    tags,
                    enrichment,
                    now,
                ],
            )?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn count_events(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM cyber_events", [], |r| r.get(0))?;
        Ok(n)
    }

    // ─── Alerts ────────────────────────────────────────────────────────────

    /// Startup alert hygiene. Returns `(legacy_removed, aged_removed)`.
    ///
    /// 1. **Legacy cruft.** Pre-refactor builds stored the [`AlertKind`] *Display*
    ///    string as the `source` ("Baseline Drift", "YARA Match", …). The current
    ///    engine writes detector-specific sources ("Baseline drift", "YARA",
    ///    "Heuristic: …") and reconciles them each scan, so these old rows are
    ///    never refreshed or resolved — they accumulate forever. Clear them.
    /// 2. **Retention.** Drop anything older than the hard window (30 days)
    ///    regardless of state, plus unacked `Low`/`Info` older than 14 days
    ///    (stale low-value noise — a still-valid finding is re-raised next scan).
    fn prune_alerts(&self) -> Result<(usize, usize)> {
        use chrono::{Duration, Utc};
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let legacy = conn.execute(
            "DELETE FROM alerts WHERE source IN
                ('Baseline Drift','YARA Match','IP Blacklist','CVE Match',
                 'Suspicious Pkg','System Anomaly')",
            [],
        )?;
        let cutoff_hard = (Utc::now() - Duration::days(30)).to_rfc3339();
        let cutoff_low = (Utc::now() - Duration::days(14)).to_rfc3339();
        let aged = conn.execute(
            "DELETE FROM alerts
             WHERE created_at < ?1
                OR (acked=0 AND severity IN ('Low','Info') AND created_at < ?2)",
            params![cutoff_hard, cutoff_low],
        )?;
        Ok((legacy, aged))
    }

    /// Reconcile the active (unacked) alerts for one or more detector scopes:
    /// in a single transaction, delete every unacked alert whose `source` falls
    /// in `scopes`, then insert `alerts`. The fresh set is authoritative, so any
    /// previously-active finding in those scopes that is absent now auto-resolves.
    /// Acked alerts are never touched. Returns the number of alerts inserted.
    ///
    /// Callers pass the scopes they fully recomputed this scan plus the alerts
    /// they produced; an empty `alerts` with non-empty `scopes` cleanly resolves
    /// all findings in those scopes (e.g. a scan that now comes back clean).
    pub fn reconcile_alerts(&self, scopes: &[AlertScope], alerts: &[Alert]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        for scope in scopes {
            tx.execute(
                "DELETE FROM alerts WHERE acked=0 AND source LIKE ?1",
                params![scope.source_like()],
            )?;
        }
        for a in alerts {
            let cve_json = serde_json::to_string(&a.cve_ids).unwrap_or_default();
            tx.execute(
                "INSERT INTO alerts
                 (kind, severity, title, detail, package_name, package_ecosystem,
                  ip_address, cve_ids, event_title, created_at, acked, file_path, source)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    a.kind_str(),
                    format!("{:?}", a.severity),
                    a.title,
                    a.detail,
                    a.package_name,
                    a.package_ecosystem,
                    a.ip_address,
                    cve_json,
                    a.event_title,
                    a.created_at,
                    a.acked as i32,
                    a.file_path,
                    a.source,
                ],
            )?;
        }
        tx.commit()?;
        Ok(alerts.len())
    }

    pub fn save_alerts(&self, alerts: &[Alert]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        for a in alerts {
            let cve_json = serde_json::to_string(&a.cve_ids).unwrap_or_default();
            tx.execute(
                "DELETE FROM alerts
                 WHERE acked=0
                   AND kind=?1
                   AND title=?2
                   AND COALESCE(package_name,'')=COALESCE(?3,'')
                   AND COALESCE(package_ecosystem,'')=COALESCE(?4,'')
                   AND COALESCE(ip_address,'')=COALESCE(?5,'')
                   AND COALESCE(cve_ids,'')=COALESCE(?6,'')
                   AND COALESCE(event_title,'')=COALESCE(?7,'')",
                params![
                    a.kind_str(),
                    a.title,
                    a.package_name,
                    a.package_ecosystem,
                    a.ip_address,
                    cve_json,
                    a.event_title,
                ],
            )?;
            tx.execute(
                "INSERT INTO alerts
                 (kind, severity, title, detail, package_name, package_ecosystem,
                  ip_address, cve_ids, event_title, created_at, acked, file_path, source)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    a.kind_str(),
                    format!("{:?}", a.severity),
                    a.title,
                    a.detail,
                    a.package_name,
                    a.package_ecosystem,
                    a.ip_address,
                    cve_json,
                    a.event_title,
                    a.created_at,
                    a.acked as i32,
                    a.file_path,
                    a.source,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Replace the set of unacked ARES agent-sourced alerts with a fresh batch.
    /// Agent findings are marked by a `ARES:` title prefix; each hunt clears the
    /// previous (unacked) agent alerts and inserts the current ones, so findings
    /// stay deduplicated and in sync with the latest hunt rather than accumulating.
    pub fn replace_agent_alerts(&self, alerts: &[Alert]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM alerts WHERE acked=0 AND title LIKE 'ARES:%'",
            [],
        )?;
        for a in alerts {
            let cve_json = serde_json::to_string(&a.cve_ids).unwrap_or_default();
            tx.execute(
                "INSERT INTO alerts
                 (kind, severity, title, detail, package_name, package_ecosystem,
                  ip_address, cve_ids, event_title, created_at, acked, file_path, source)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    a.kind_str(),
                    format!("{:?}", a.severity),
                    a.title,
                    a.detail,
                    a.package_name,
                    a.package_ecosystem,
                    a.ip_address,
                    cve_json,
                    a.event_title,
                    a.created_at,
                    a.acked as i32,
                    a.file_path,
                    a.source,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Clear unacked ARES agent-sourced alerts from previous web sessions.
    pub fn clear_agent_alerts(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = conn.execute(
            "DELETE FROM alerts WHERE acked=0 AND title LIKE 'ARES:%'",
            [],
        )?;
        Ok(deleted)
    }

    pub fn get_alerts(&self, acked_filter: Option<bool>) -> Result<Vec<Alert>> {
        use crate::alerts::{AlertKind, Severity};
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = match acked_filter {
            Some(true) => "SELECT * FROM alerts WHERE acked=1 ORDER BY id DESC",
            Some(false) => "SELECT * FROM alerts WHERE acked=0 ORDER BY id DESC",
            None => "SELECT * FROM alerts ORDER BY id DESC",
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(1)?;
            let sev_str: String = row.get(2)?;
            let cve_str: String = row.get(8).unwrap_or_default();
            let acked: i32 = row.get(11)?;

            let kind = match kind_str.as_str() {
                "CVE Match" => AlertKind::CveMatch,
                "IP Blacklist" => AlertKind::IpBlacklist,
                "Suspicious Pkg" => AlertKind::SuspiciousPackage,
                "YARA Match" => AlertKind::YaraMatch,
                "Baseline Drift" => AlertKind::BaselineDrift,
                _ => AlertKind::SystemAnomaly,
            };
            let severity = match sev_str.as_str() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Info,
            };
            let cve_ids: Vec<String> = serde_json::from_str(&cve_str).unwrap_or_default();

            // Columns added in a later migration; absent/NULL on older rows.
            let file_path: Option<String> = row.get::<_, Option<String>>(12).unwrap_or(None);
            let source: String = row
                .get::<_, Option<String>>(13)
                .unwrap_or(None)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| kind.to_string());

            Ok(Alert {
                id: row.get(0)?,
                kind,
                severity,
                title: row.get(3)?,
                detail: row.get(4).unwrap_or_default(),
                package_name: row.get(5)?,
                package_ecosystem: row.get(6)?,
                ip_address: row.get(7)?,
                cve_ids,
                event_title: row.get(9)?,
                created_at: row.get(10)?,
                acked: acked != 0,
                file_path,
                source,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn ack_alert(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("UPDATE alerts SET acked=1 WHERE id=?1", params![id])?;
        Ok(())
    }

    pub fn count_active_alerts(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM alerts WHERE acked=0", [], |r| {
            r.get(0)
        })?;
        Ok(n)
    }

    // ─── Scanned packages ──────────────────────────────────────────────────

    pub fn save_scan(&self, packages: &[ScannedPackage]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        for p in packages {
            tx.execute(
                "INSERT INTO scanned_packages (ecosystem, name, version, path, scanned_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![p.ecosystem_str(), p.name, p.version, p.path, now,],
            )?;
        }
        tx.execute(
            "DELETE FROM scanned_packages
             WHERE scanned_at NOT IN (
                 SELECT scanned_at FROM (
                     SELECT DISTINCT scanned_at
                     FROM scanned_packages
                     ORDER BY scanned_at DESC
                     LIMIT 10
                 )
             )",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    // ─── IP blacklist ───────────────────────────────────────────────────────

    pub fn upsert_ips(&self, ips: &[AbuseIpEntry]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        for ip in ips {
            tx.execute(
                "INSERT OR REPLACE INTO abuse_ips (ip, country, abuse_score, last_reported, fetched_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![ip.ip, ip.country, ip.abuse_score, ip.last_reported, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn is_ip_blacklisted(&self, ip: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM abuse_ips WHERE ip=?1",
            params![ip],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    // ─── Quarantine ────────────────────────────────────────────────────────

    pub fn quarantine_add(&self, entry: &QuarantineEntry) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO quarantined (ecosystem, name, version, reason, quarantined_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                entry.ecosystem,
                entry.name,
                entry.version,
                entry.reason,
                entry.quarantined_at,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn quarantine_list(&self) -> Result<Vec<QuarantineEntry>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt =
            conn.prepare("SELECT id, ecosystem, name, version, reason, quarantined_at, released_at FROM quarantined ORDER BY id DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(QuarantineEntry {
                id: row.get(0)?,
                ecosystem: row.get(1)?,
                name: row.get(2)?,
                version: row.get(3)?,
                reason: row.get(4)?,
                quarantined_at: row.get(5)?,
                released_at: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn quarantine_release(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE quarantined SET released_at=?1 WHERE id=?2",
            params![now, id],
        )?;
        Ok(())
    }

    // ─── Web helpers ───────────────────────────────────────────────────────

    /// Return package counts from the most recent scan batch + its timestamp.
    pub fn get_scan_summary(&self) -> Result<ScanSummary> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        let last_scan: Option<String> = conn
            .query_row("SELECT MAX(scanned_at) FROM scanned_packages", [], |r| {
                r.get(0)
            })
            .ok()
            .flatten();

        let (cargo, npm, pip) = if let Some(ref ts) = last_scan {
            let mut cargo = 0i64;
            let mut npm = 0i64;
            let mut pip = 0i64;
            let mut stmt = conn.prepare(
                "SELECT ecosystem, COUNT(*) FROM scanned_packages \
                 WHERE scanned_at = ?1 GROUP BY ecosystem",
            )?;
            let rows = stmt.query_map([ts], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows.flatten() {
                // ecosystem_str() outputs "crates", "npm", "pypi", "system"
                match row.0.as_str() {
                    "crates" | "Cargo" => cargo = row.1,
                    "npm" | "Npm" => npm = row.1,
                    "pypi" | "Pip" => pip = row.1,
                    _ => {}
                }
            }
            (cargo, npm, pip)
        } else {
            (0, 0, 0)
        };

        Ok(ScanSummary {
            cargo,
            npm,
            pip,
            last_scan,
        })
    }

    /// Load all cached cyber events from the database.
    pub fn get_events(&self) -> Result<Vec<CyberEvent>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, title, summary, severity, date_start, tags, enrichment \
             FROM cyber_events",
        )?;
        let rows = stmt.query_map([], |row| {
            let tags_str: String = row.get(5).unwrap_or_default();
            let enrich_str: String = row.get(6).unwrap_or_default();
            Ok(CyberEvent {
                id: row.get(0)?,
                title: row.get(1)?,
                summary: row.get(2)?,
                severity: row.get(3)?,
                date_start: row.get(4)?,
                tags: serde_json::from_str(&tags_str).ok(),
                enrichment: serde_json::from_str(&enrich_str).ok(),
                // Fields not stored in the DB — use harmless defaults
                source: String::new(),
                source_url: None,
                event_type: String::new(),
                risk_band: None,
                date_end: None,
                country: None,
                admin1: None,
                city: None,
                lat: None,
                lon: None,
                casualties: None,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Count unacked alerts of a specific kind string (e.g. "IP Blacklist").
    pub fn count_alerts_by_kind(&self, kind: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE acked=0 AND kind=?1",
            params![kind],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// Count total rows in the abuse_ips (AbuseIPDB) cache.
    pub fn count_cached_ips(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM abuse_ips", [], |r| r.get(0))?;
        Ok(n)
    }

    // ─── OSV vulnerability findings ───────────────────────────────────────

    pub fn save_osv_vulns(&self, vulns: &[OsvFinding]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        for v in vulns {
            let cves = serde_json::to_string(&v.cve_ids).unwrap_or_default();
            let ghsas = serde_json::to_string(&v.ghsa_ids).unwrap_or_default();
            tx.execute(
                "INSERT OR REPLACE INTO osv_vulns
                 (osv_id, package, ecosystem, version, severity, summary,
                  cve_ids, ghsa_ids, fixed_ver, published, fetched_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    v.osv_id,
                    v.package,
                    v.ecosystem,
                    v.version,
                    v.severity,
                    v.summary,
                    cves,
                    ghsas,
                    v.fixed_version,
                    v.published,
                    now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_osv_vulns(&self) -> Result<Vec<OsvFinding>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT osv_id, package, ecosystem, version, severity, summary,
                    cve_ids, ghsa_ids, fixed_ver, published
             FROM osv_vulns ORDER BY rowid DESC LIMIT 500",
        )?;
        let rows = stmt.query_map([], |row| {
            let cve_str: String = row.get(6).unwrap_or_default();
            let ghsa_str: String = row.get(7).unwrap_or_default();
            Ok(OsvFinding {
                osv_id: row.get(0)?,
                package: row.get(1)?,
                ecosystem: row.get(2)?,
                version: row.get(3)?,
                severity: row.get(4)?,
                summary: row.get(5)?,
                cve_ids: serde_json::from_str(&cve_str).unwrap_or_default(),
                ghsa_ids: serde_json::from_str(&ghsa_str).unwrap_or_default(),
                fixed_version: row.get(8)?,
                published: row.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn count_osv_vulns(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM osv_vulns", [], |r| r.get(0))?;
        Ok(n)
    }

    // ─── CISA KEV entries ─────────────────────────────────────────────────

    pub fn save_kev_entries(&self, entries: &[KevEntry]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        for e in entries {
            tx.execute(
                "INSERT OR REPLACE INTO kev_entries
                 (cve_id, vendor, product, vuln_name, date_added, description, ransomware, fetched_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    e.cve_id, e.vendor, e.product, e.vuln_name,
                    e.date_added, e.description, e.ransomware as i32, now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn count_kev_entries(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM kev_entries", [], |r| r.get(0))?;
        Ok(n)
    }

    // ─── AI threat detections ────────────────────────────────────────────

    pub fn save_ai_detections(&self, threats: &[AiThreat]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        for t in threats {
            tx.execute(
                "INSERT INTO ai_detections
                 (kind, severity, package, ecosystem, version, detail, atlas_id, detected_at, acked)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",
                params![
                    t.kind.to_string(),
                    t.severity,
                    t.package,
                    t.ecosystem,
                    t.version,
                    t.detail,
                    t.atlas_id,
                    t.detected_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_ai_detections(&self) -> Result<Vec<AiThreat>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Return the most recent scan batch (last 200 rows)
        let mut stmt = conn.prepare(
            "SELECT kind, severity, package, ecosystem, version, detail, atlas_id, detected_at
             FROM ai_detections ORDER BY id DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(0)?;
            let kind = match kind_str.as_str() {
                "Malicious AI Pkg" => AiThreatKind::MaliciousAiPackage,
                "Vulnerable AI SDK" => AiThreatKind::VulnerableAiSdk,
                "Agent Process" => AiThreatKind::AgentProcessDetected,
                _ => AiThreatKind::AiSdkInventory,
            };
            Ok(AiThreat {
                kind,
                severity: row.get(1)?,
                package: row.get(2)?,
                ecosystem: row.get(3)?,
                version: row.get(4)?,
                detail: row.get(5)?,
                atlas_id: row.get(6)?,
                detected_at: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // ─── YARA matches ────────────────────────────────────────────────────

    pub fn save_yara_matches(&self, matches: &[YaraMatch]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        // A scan recomputes the complete current YARA state, so replace the
        // table rather than appending — otherwise stale matches (e.g. from files
        // that no longer match, or before a rule/exclusion change) accumulate
        // forever and pollute the hunt/compliance view (QA 2026-07 F9).
        tx.execute("DELETE FROM yara_matches", [])?;
        for m in matches {
            let tags = serde_json::to_string(&m.tags).unwrap_or_default();
            let matched = serde_json::to_string(&m.matched_strings).unwrap_or_default();
            tx.execute(
                "INSERT INTO yara_matches
                 (rule, tags, severity, description, target, matched, detected_at, acked)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,0)",
                params![
                    m.rule,
                    tags,
                    m.severity,
                    m.description,
                    m.target,
                    matched,
                    m.detected_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_yara_matches(&self) -> Result<Vec<YaraMatch>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT rule, tags, severity, description, target, matched, detected_at
             FROM yara_matches ORDER BY id DESC LIMIT 500",
        )?;
        let rows = stmt.query_map([], |row| {
            let tags_str: String = row.get(1).unwrap_or_default();
            let matched_str: String = row.get(5).unwrap_or_default();
            Ok(YaraMatch {
                rule: row.get(0)?,
                tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                severity: row.get(2)?,
                description: row.get(3).unwrap_or_default(),
                target: row.get(4)?,
                matched_strings: serde_json::from_str(&matched_str).unwrap_or_default(),
                detected_at: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn count_yara_matches(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM yara_matches", [], |r| r.get(0))?;
        Ok(n)
    }

    // ─── Heuristic baseline ──────────────────────────────────────────────

    pub fn has_baseline(&self) -> Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM baselines WHERE os = ?1",
            params![crate::yara::current_os()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn save_baseline(&self, baseline: &Baseline) -> Result<()> {
        let data = serde_json::to_string(baseline)?;
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO baselines (os, created_at, data) VALUES (?1,?2,?3)",
            params![baseline.os, baseline.created_at, data],
        )?;
        Ok(())
    }

    /// Most recent baseline for the running OS.
    pub fn get_latest_baseline(&self) -> Result<Option<Baseline>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let data: Option<String> = conn
            .query_row(
                "SELECT data FROM baselines WHERE os = ?1 ORDER BY id DESC LIMIT 1",
                params![crate::yara::current_os()],
                |r| r.get(0),
            )
            .ok();
        match data {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
}

// ─────────────────────────────── ScanSummary ────────────────────────────────

#[derive(Debug, Default)]
pub struct ScanSummary {
    pub cargo: i64,
    pub npm: i64,
    pub pip: i64,
    pub last_scan: Option<String>,
}
