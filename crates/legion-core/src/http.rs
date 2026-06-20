//! Bounded HTTP body reads.
//!
//! A malicious or compromised feed (or a MITM on a connection) can return an
//! arbitrarily large response body. `reqwest`'s `.json()` / `.text()` buffer the
//! whole body with no size ceiling, so a hostile feed could exhaust memory
//! (audit finding CORE-1). These helpers stream the body and abort once a byte
//! cap is exceeded, honouring an advertised `Content-Length` for a fast reject.

use anyhow::{bail, Result};
use reqwest::Response;

/// Default ceiling for a single feed / rule-file response body: 32 MiB.
pub const DEFAULT_MAX_BODY: usize = 32 * 1024 * 1024;

/// True when `current + add` would exceed `max` (saturating, overflow-safe).
fn exceeds(current: usize, add: usize, max: usize) -> bool {
    current.saturating_add(add) > max
}

/// Read a response body into memory, rejecting any body larger than `max` bytes.
///
/// The advertised `Content-Length` (if any) is checked first for a cheap reject,
/// then the cap is enforced while streaming so a lying or absent header cannot
/// bypass it.
pub async fn read_capped(mut resp: Response, max: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max as u64 {
            bail!("response body too large: {len} bytes (cap {max})");
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if exceeds(buf.len(), chunk.len(), max) {
            bail!("response body exceeded {max} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a capped body, log its SHA-256 for auditability, and verify it against
/// the given integrity policy before returning (audit CORE-3). A non-`TlsOnly`
/// policy is fail-closed: a hash/signature mismatch returns an error and the
/// body is discarded.
pub async fn read_capped_verified(
    resp: Response,
    max: usize,
    integrity: &crate::integrity::FeedIntegrity<'_>,
    feed: &str,
) -> Result<Vec<u8>> {
    let bytes = read_capped(resp, max).await?;
    let sha = crate::integrity::sha256_hex(&bytes);
    tracing::debug!(target: "legion.feed", "{feed}: {} bytes sha256={sha}", bytes.len());
    crate::integrity::verify(&bytes, integrity)
        .map_err(|e| anyhow::anyhow!("{feed} integrity check failed: {e}"))?;
    Ok(bytes)
}

/// Stream a response body to `dest`, enforcing a byte cap and verifying the
/// finished file against `integrity` — **without buffering the whole body in
/// memory**. Suitable for large artifacts like model weights, where
/// [`read_capped`] would hold gigabytes in RAM. The SHA-256 is computed
/// incrementally as chunks arrive. On any failure (cap exceeded, hash mismatch,
/// IO error) the partial file is removed. Returns the number of bytes written.
pub async fn download_verified_to_file(
    mut resp: Response,
    dest: &std::path::Path,
    max: usize,
    integrity: &crate::integrity::FeedIntegrity<'_>,
) -> Result<u64> {
    use std::io::Write;
    if let Some(len) = resp.content_length() {
        if len > max as u64 {
            bail!("download too large: {len} bytes (cap {max})");
        }
    }
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut written: usize = 0;
    let mut file = std::fs::File::create(dest)?;

    let outcome: Result<u64> = async {
        while let Some(chunk) = resp.chunk().await? {
            if exceeds(written, chunk.len(), max) {
                bail!("download exceeded {max} bytes");
            }
            file.write_all(&chunk)?;
            ctx.update(&chunk);
            written = written.saturating_add(chunk.len());
        }
        file.flush()?;
        let digest = ctx.finish();
        let mut got = String::with_capacity(digest.as_ref().len() * 2);
        for b in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(got, "{b:02x}");
        }
        match integrity {
            crate::integrity::FeedIntegrity::Sha256(expected) => {
                if !got.eq_ignore_ascii_case(expected) {
                    bail!("download sha256 mismatch: expected {expected}, got {got}");
                }
            }
            crate::integrity::FeedIntegrity::TlsOnly => {}
            crate::integrity::FeedIntegrity::Ed25519 { .. } => {
                bail!("ed25519 integrity is not supported for streamed downloads");
            }
        }
        Ok(written as u64)
    }
    .await;

    if outcome.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    outcome
}

/// Read a capped body and deserialize it as JSON.
pub async fn json_capped<T: serde::de::DeserializeOwned>(resp: Response, max: usize) -> Result<T> {
    let bytes = read_capped(resp, max).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Read a capped body as UTF-8 text.
pub async fn text_capped(resp: Response, max: usize) -> Result<String> {
    let bytes = read_capped(resp, max).await?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceeds_detects_overflow_of_cap() {
        assert!(!exceeds(0, 10, 32));
        assert!(!exceeds(22, 10, 32));
        assert!(exceeds(23, 10, 32));
        // saturating add must not wrap to a small value and slip past the cap.
        assert!(exceeds(usize::MAX, 1, 32));
    }
}
