//! Cryptographic integrity verification for remote feeds (audit CORE-3).
//!
//! TLS already protects feed transport, but it does not bind a feed body to a
//! trusted *publisher*: a compromised CA, a MITM, or a breached origin can serve
//! a forged-but-well-formed feed that Legion would treat as ground truth and
//! fold into its baseline / alerts. This module adds publisher-level integrity:
//!
//! - **SHA-256** content hashing (for logging and pinned-snapshot checks).
//! - **Ed25519** detached-signature verification against a trusted public key,
//!   so a feed body can be cryptographically tied to whoever holds the signing
//!   key — independent of the TLS chain.
//!
//! Both primitives come from `ring`, which is already in the dependency tree.
//! Verification is fail-closed: when a policy other than [`FeedIntegrity::TlsOnly`]
//! is in force, a missing/forged signature or a hash mismatch rejects the body.

use anyhow::{bail, Result};
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = String::with_capacity(d.as_ref().len() * 2);
    for b in d.as_ref() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The integrity policy applied to a fetched feed body.
#[derive(Debug, Clone)]
pub enum FeedIntegrity<'a> {
    /// Transport TLS only — no publisher-level check. Used for third-party feeds
    /// (CISA KEV, OSV) that publish no signature or stable checksum.
    TlsOnly,
    /// Body must hash to exactly this lowercase-hex SHA-256 (pinned snapshot).
    Sha256(&'a str),
    /// Body must carry a valid Ed25519 detached signature, made by the holder of
    /// `public_key` (raw 32-byte key) over the exact body bytes.
    Ed25519 {
        public_key: &'a [u8],
        signature: &'a [u8],
    },
}

/// Verify `body` against `integrity`. `Ok(())` means the body may be trusted
/// under the given policy; an `Err` means it must be rejected.
pub fn verify(body: &[u8], integrity: &FeedIntegrity) -> Result<()> {
    match integrity {
        FeedIntegrity::TlsOnly => Ok(()),
        FeedIntegrity::Sha256(expected) => {
            let got = sha256_hex(body);
            if got.eq_ignore_ascii_case(expected) {
                Ok(())
            } else {
                bail!("feed sha256 mismatch: expected {expected}, got {got}");
            }
        }
        FeedIntegrity::Ed25519 {
            public_key,
            signature,
        } => UnparsedPublicKey::new(&signature::ED25519, *public_key)
            .verify(body, signature)
            .map_err(|_| anyhow::anyhow!("feed Ed25519 signature verification failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn sha256_known_answer() {
        // SHA-256("abc") — RFC 6234 test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_policy_accepts_match_rejects_tamper() {
        let body = b"threat-feed-body";
        let good = sha256_hex(body);
        assert!(verify(body, &FeedIntegrity::Sha256(&good)).is_ok());
        // Uppercase hex must also match (case-insensitive).
        assert!(verify(body, &FeedIntegrity::Sha256(&good.to_uppercase())).is_ok());
        // A single flipped byte must fail.
        assert!(verify(b"threat-feed-bodX", &FeedIntegrity::Sha256(&good)).is_err());
    }

    #[test]
    fn ed25519_roundtrip_and_tamper_detection() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = kp.public_key().as_ref().to_vec();

        let body = b"signed threat intelligence payload";
        let sig = kp.sign(body).as_ref().to_vec();

        // Valid signature over the exact body verifies.
        assert!(verify(
            body,
            &FeedIntegrity::Ed25519 {
                public_key: &public,
                signature: &sig,
            }
        )
        .is_ok());

        // A tampered body must fail.
        assert!(verify(
            b"signed threat intelligence payloaX",
            &FeedIntegrity::Ed25519 {
                public_key: &public,
                signature: &sig,
            }
        )
        .is_err());

        // A wrong key must fail.
        let other =
            Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
                .unwrap();
        assert!(verify(
            body,
            &FeedIntegrity::Ed25519 {
                public_key: other.public_key().as_ref(),
                signature: &sig,
            }
        )
        .is_err());
    }

    #[test]
    fn tls_only_is_permissive() {
        assert!(verify(b"anything", &FeedIntegrity::TlsOnly).is_ok());
    }
}
