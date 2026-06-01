//! Package quarantine management.
//!
//! Quarantine records are stored in SQLite. Actual removal/isolation
//! of packages is deliberately deferred to the user since package
//! managers require elevated privileges in most environments.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A single quarantine record (mirrors the DB schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: i64,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub reason: Option<String>,
    pub quarantined_at: String,
    pub released_at: Option<String>,
}

impl QuarantineEntry {
    pub fn is_active(&self) -> bool {
        self.released_at.is_none()
    }
}

pub struct QuarantineManager {
    pub(crate) db: crate::db::Database,
}

impl QuarantineManager {
    pub fn new(db: crate::db::Database) -> Self {
        Self { db }
    }

    /// Add a package to quarantine.
    pub fn quarantine(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
        reason: &str,
    ) -> Result<i64> {
        let entry = QuarantineEntry {
            id: 0,
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            version: version.map(|s| s.to_owned()),
            reason: Some(reason.to_owned()),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            released_at: None,
        };
        let id = self.db.quarantine_add(&entry)?;
        tracing::warn!(
            "QUARANTINED {}/{} v{}: {}",
            ecosystem,
            name,
            version.unwrap_or("?"),
            reason
        );
        Ok(id)
    }

    /// List all quarantine entries (active and released).
    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        self.db.quarantine_list()
    }

    /// Mark a quarantine entry as released (package un-flagged).
    pub fn release(&self, id: i64) -> Result<()> {
        self.db.quarantine_release(id)?;
        tracing::info!("Quarantine entry {} released", id);
        Ok(())
    }

    /// Generate remediation commands for a quarantined package.
    pub fn remediation_cmd(ecosystem: &str, name: &str) -> String {
        match ecosystem {
            "crates" => format!("cargo remove {name}  # then remove from Cargo.lock"),
            "npm" => format!("npm uninstall {name}"),
            "pypi" => format!("pip uninstall -y {name}"),
            _ => format!("# Remove {name} manually from your {ecosystem} environment"),
        }
    }
}
