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
| A01 | Broken Access Control | ✅ Addressed | Loopback-only bind; OS-enforced privilege (UAC/polkit/osascript); DNS-rebinding `Host` guard; same-origin (no CORS). For multi-user/remote, an authenticated reverse proxy is the documented pattern. |
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
| RA-5 | Vulnerability Monitoring | Continuous dependency scanning in CI; OSV/KEV/ThreatFox enrichment in the product itself. |

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
