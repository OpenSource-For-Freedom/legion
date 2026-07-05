# Compliance & Control Mapping

This document maps Legion's **technical** controls to the OWASP Top 10 (2021),
the NIST SP 800-53 Rev. 5 control families / NIST CSF functions, and the SOC 2
Trust Services Criteria (TSC).

> **Scope note.** OWASP Top 10 is an application-security checklist and is
> addressed in code. **NIST 800-53/CSF and SOC 2 are organizational frameworks** —
> SOC 2 in particular is an *auditor-issued attestation* about a service
> organization's controls (change management, access reviews, vendor management,
> incident response, personnel security, etc.). Software cannot itself "be" SOC 2
> compliant. The mapping below shows how Legion implements the **technical**
> controls those frameworks expect, making a deployment *audit-ready*. Process and
> governance controls remain the operator's responsibility (see "Operator
> responsibilities").

## OWASP Top 10 (2021)

| # | Category | Status | Implementation |
|---|----------|--------|----------------|
| A01 | Broken Access Control | ✅ Addressed | Loopback-only bind; OS-enforced privilege (UAC/polkit); DNS-rebinding `Host` guard; same-origin (no CORS). For multi-user/remote, an authenticated reverse proxy is the documented pattern. |
| A02 | Cryptographic Failures | ✅ Addressed | Outbound TLS via rustls with cert validation; data at rest restricted to owner (`0600`/`0700`); loopback transport keeps traffic on-host. |
| A03 | Injection | ✅ Addressed | SQL fully parameterized; client renders all server data with HTML-escaping (incl. quotes); external commands use fixed argv with no shell. |
| A04 | Insecure Design | ✅ Addressed | Least-privilege-by-default web surface; request body limits; rate limiting; fail-closed rule parsing (bad rules skipped, not executed). |
| A05 | Security Misconfiguration | ✅ Addressed | Secure defaults (loopback, no permissive CORS); full security-header set; generic error responses; owner-only file permissions. |
| A06 | Vulnerable & Outdated Components | ✅ Addressed | `Cargo.lock` committed; `cargo audit` (RUSTSEC) and `cargo deny` (advisories/bans/sources) in CI; rustls instead of system OpenSSL. |
| A07 | Identification & Auth Failures | ✅ By design | Authentication delegated to the OS login/elevation model rather than an in-app credential store (no password storage to compromise). Reverse-proxy auth documented for shared deployments. |
| A08 | Software & Data Integrity Failures | ✅ Addressed | Dependencies pinned via lockfile; `cargo deny sources` blocks unknown registries/git (anti dependency-confusion); rule feed fetched over HTTPS only and validated before caching. |
| A09 | Security Logging & Monitoring Failures | ✅ Addressed | `audit_log` table + structured `legion.audit` logs for sensitive actions (server start, scans, feed/rule updates, acknowledgements); server-side error logging. |
| A10 | Server-Side Request Forgery (SSRF) | ✅ Addressed | The only server-fetched, config-controlled URL (the rule feed) is scheme-restricted to `https://`; all other endpoints are fixed, hardcoded hosts. |

## NIST SP 800-53 Rev. 5 — selected control families

| Control | Family | How Legion supports it |
|---------|--------|------------------------|
| AC-3 / AC-6 | Access Enforcement / Least Privilege | OS elevation gates privileged telemetry; loopback bind; owner-only data files. |
| AC-4 | Information Flow Enforcement | Same-origin enforcement; DNS-rebinding `Host` guard; CSP `connect-src 'self'`. |
| AU-2 / AU-3 / AU-12 | Audit Events / Content / Generation | `audit_log` with timestamp, actor, action, detail, source; mirrored to structured logs for forwarding. |
| SC-5 | Denial-of-Service Protection | Request body size limit; fixed-window rate limiter. |
| SC-7 | Boundary Protection | Loopback default; explicit boundary warning on non-loopback bind. |
| SC-8 / SC-13 | Transmission Confidentiality / Cryptography | rustls TLS with validation for all outbound feeds; reverse-proxy TLS guidance for remote access. |
| SC-18 | Mobile Code | Hardened CSP, `X-Frame-Options`, `nosniff`; client-side output encoding. |
| SC-28 | Protection of Information at Rest | `0600`/`0700` permissions on DB, config, and cached rules (Unix). |
| SI-10 | Information Input Validation | Parameterized SQL; HTML output encoding; YARA rule parser fails closed. |
| SI-7 | Software/Information Integrity | Lockfile + `cargo deny`/`cargo audit`; HTTPS-only, validated rule feed. |
| RA-5 | Vulnerability Monitoring | Continuous dependency scanning in CI; OSV/KEV/AbuseIPDB enrichment in the product itself. |

### NIST CSF 2.0 functions
- **Identify** — package/asset inventory, baseline fingerprint of the host.
- **Protect** — least privilege, secure defaults, input/output validation.
- **Detect** — YARA scanning, baseline drift, threat-feed correlation, audit log.
- **Respond** — alerting, quarantine guidance, acknowledgement workflow.
- **Recover / Govern** — operator responsibility (see below).

## SOC 2 Trust Services Criteria (technical contribution)

| TSC | Criterion | Legion contribution |
|-----|-----------|---------------------|
| CC6.1 | Logical access controls | OS-delegated authentication/elevation; owner-only data; loopback boundary. |
| CC6.6 | Boundary protection | Loopback bind, Host guard, same-origin, security headers. |
| CC6.7 | Restrict information transmission | rustls TLS; reverse-proxy TLS pattern documented. |
| CC7.1 | Detection of vulnerabilities | `cargo audit`/`cargo deny` in CI; the SIEM's own CVE/KEV/OSV detection. |
| CC7.2 | Security event monitoring | Audit log + structured logs of security-relevant actions. |
| CC7.3 / CC7.4 | Incident evaluation & response | Alerting/acknowledgement workflow feeds the operator's IR process. |
| CC8.1 | Change management | Lockfile, CI gates (fmt/clippy/test/audit/deny), reproducible release builds. |

> **Auth note.** Beyond OS-delegated elevation, every `/api/*` route is gated by a
> per-session bearer token (32-byte OS CSPRNG, constant-time compared; delivered
> to the browser as a `SameSite=Strict; HttpOnly` cookie). This strengthens
> CC6.1 / A07 beyond "OS-delegated only."

## Cryptography & FIPS 140-3 posture

| Crypto use | Implementation | Algorithm | FIPS-approved algorithm? | Validated module? |
|------------|----------------|-----------|--------------------------|-------------------|
| Outbound TLS (all feeds, model download) | rustls → **ring** | TLS 1.2/1.3 AEAD suites | Yes | **No** (ring has no CMVP cert) |
| Feed/KEV body hashing, digest pinning | ring `digest::SHA256` | SHA-256 (FIPS 180-4) | Yes | No |
| Signed-feed verification | ring `signature::ED25519` | Ed25519 (FIPS 186-5) | Yes | No |
| Session-token RNG | `getrandom` → Linux `getrandom(2)` | kernel DRBG | Yes | Follows the kernel (FIPS kernel = SP 800-90A) |

**Assessment.** Every algorithm Legion uses is FIPS-approved and modern — there is
**no weak primitive anywhere** (no MD5/SHA-1/RC4, no in-app password hashing). The
gap is *module provenance*: all crypto is provided by `ring`, which is **not** a
FIPS 140-2/140-3 validated cryptographic module. So Legion **functions** but is
**not FIPS-compliant** as shipped. Note that "rustls instead of system OpenSSL"
(listed as a positive elsewhere for supply-chain/portability) is what removes the
FIPS option — a validated module would come from the OS (Ubuntu Pro FIPS OpenSSL)
or `aws-lc-rs`'s FIPS feature.

**Path to FIPS (deliberately deferred, opt-in).** The validated-module fix —
switching the rustls provider and `legion-core`'s direct `ring` calls to
`aws-lc-rs` with its `fips` feature (or OS OpenSSL) — is a build- and API-level
**breaking change**. It should land behind an opt-in `fips` Cargo feature so the
default build is unchanged. No algorithm migration is required.

## CIS Controls v8 (selected)

| Control | Area | How Legion supports it | Notes / gaps |
|---------|------|------------------------|--------------|
| 1 & 2 | Asset & Software Inventory | Enumerates cargo/npm/pip packages; baseline host fingerprint | **Gap:** no `dpkg`/apt inventory yet (Debian system packages not scanned). |
| 3 | Data Protection | `0600`/`0700` perms on DB, config, cached rules, session token; installer `chmod 700` on the data dir | — |
| 4 | Secure Configuration | Loopback-only bind by default; DNS-rebinding Host guard; LLM host pinned to loopback (`LEGION_ALLOW_REMOTE_LLM` to override); full security-header set/CSP | — |
| 5 & 6 | Account / Access Management | OS-delegated elevation (polkit/pkexec→sudo); never elevates silently; per-session API token | Web binary runs elevated for its lifetime (privsep is a larger future item). |
| 8 | Audit Log Management | `audit_log` table + structured `legion.audit` log mirror (enabled for forwarding) | **Gap:** no retention/rotation or tamper-evidence yet. |
| 10 | Malware Defenses | Pure-Rust YARA engine; bundled + OS-specific rules; HTTPS-only signed rule updates; quarantine workflow | — |
| 16 | Application Software Security | Memory-safe Rust; release `overflow-checks`; C agent built with FORTIFY, stack-protector, stack-clash, CET (x86), RELRO/NOW, noexecstack, PIE; CI fmt/clippy/test/`cargo audit`/`cargo deny` | — |

> Debian/Ubuntu specifics: ship a hardened `systemd` unit (see
> `agents/ares/training/systemd/legion-lora.service`); AppArmor (default on
> Debian/Ubuntu) confinement for the web binary is a recommended future add.

## Accepted exceptions (vulnerability risk acceptance)

Per NIST RA-5 / SOC 2 CC7.1, advisories without an available upstream fix are
documented and accepted rather than silently suppressed. Current exceptions are
recorded in [`deny.toml`](deny.toml) and [`.cargo/audit.toml`](.cargo/audit.toml):

| Advisory | Crate | Class | Rationale | Review trigger |
|----------|-------|-------|-----------|----------------|
| RUSTSEC-2024-0436 | `paste 1.0.15` | Unmaintained (not a vulnerability) | Transitive via `ratatui` (TUI rendering only). No fix exists; resolved only when `ratatui` drops the dependency. | Each `ratatui` release |
| RUSTSEC-2026-0002 | `lru 0.12.5` | Unsound `IterMut` (Stacked Borrows) | Transitive via `ratatui`; fixed in `lru 0.13` but `ratatui 0.29` pins `^0.12`. Not reachable from Legion code paths. | Each `ratatui` release |

`cargo audit` and `cargo deny` both report **clean** with these tracked
exceptions; there are **no** advisories at "vulnerability" severity.

## Operator responsibilities (not solvable in code)

A SOC 2 / NIST program additionally requires controls Legion **cannot** provide
on its own. The deploying organization must own:

- Authentication & SSO for any shared/remote deployment (reverse proxy).
- Centralized log retention, forwarding, and review of the audit trail.
- Access reviews, onboarding/offboarding, and least-privilege administration.
- Vendor/third-party risk management and a documented change-management process.
- Incident response runbooks, business continuity, and personnel security.
- Periodic penetration testing and risk assessments.

## Verifying the controls

```sh
# Dependency / supply-chain checks (same as CI)
cargo audit
cargo deny check advisories bans sources

# Lint & tests
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace

# Spot-check the running web controls
curl -sD - -o /dev/null http://127.0.0.1:3000/            # security headers present
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'Host: evil.example' http://127.0.0.1:3000/api/alerts   # -> 403 (rebinding guard)
curl -s http://127.0.0.1:3000/api/audit                   # audit trail
```
