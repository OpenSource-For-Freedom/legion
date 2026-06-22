# Legion Compliance Comb — SOC 2 / FIPS / CIS (2026-06-13)

Full-codebase compliance review of the Legion SIEM/SOAR workspace, targeting
**Debian-based Linux** deployment. Constraint for remediations: **no breaking
changes**, full test suite must stay green (baseline: **52 passed / 0 failed**).

Scope covered four dimensions in parallel: SOC 2 / OWASP / NIST control
verification, FIPS 140-3 cryptographic readiness, CIS Controls v8 + CIS
Debian/Ubuntu hardening, and model-identity / provenance. Frameworks mapping
lives in [`COMPLIANCE.md`](../COMPLIANCE.md); this file is the point-in-time audit
record and remediation log.

## TL;DR

Legion was already well-hardened (loopback-only bind, DNS-rebind guard,
`0600/0700` data perms, per-session API token with constant-time compare,
parameterized SQL, rustls cert validation, HTTPS-only feeds, OS-delegated auth,
pure-Rust YARA, audit-log table). The comb found **no critical defects** and **no
model misrepresentation**. It produced a set of non-breaking hardening + accuracy
fixes (applied) and a short list of larger items (deferred, opt-in).

## Findings & disposition

### SOC 2 / OWASP / NIST
| Finding | Severity | Disposition |
|---|---|---|
| CSP allowed external `img-src https://cdn.simpleicons.org`; dashboard fetched OS icons from a CDN (leaks host-OS + visit timing); contradicted the "no external origins" claim | Low–Med | **FIXED** — icons vendored and served same-origin from `GET /icons/:slug`; CSP tightened to `img-src 'self' data:`. |
| `legion.audit` structured-log mirror (AU-2/AU-3) suppressed by `EnvFilter::new("warn")` in the web binary | Low | **FIXED** — filter now `warn,legion.audit=info` (honors `RUST_LOG`). |
| A07 understates auth — a real per-session bearer token gates `/api/*` | Info | **DOC** — noted in COMPLIANCE.md. |
| Everything else (parameterized SQL, perms, loopback+Host guard+body limit+rate limit, rustls validation, https-only feeds, audit DB writes, dependency exceptions) | — | **HOLDS** as claimed. |

### FIPS 140-3
| Finding | Severity | Disposition |
|---|---|---|
| All crypto (TLS, SHA-256, Ed25519, RNG seeding) is `ring`-backed; algorithms are FIPS-approved but `ring` is not a CMVP-validated module → not FIPS-compliant as shipped | Med (for FIPS deployments) | **DOC + DEFERRED** — posture documented in COMPLIANCE.md; validated-module swap (`aws-lc-rs` `fips` feature or OS OpenSSL) is breaking → opt-in `fips` feature, not done now. |
| No weak algorithms anywhere (no MD5/SHA-1/RC4; no in-app password hashing) | — | **HOLDS** (good). |

### CIS Controls v8 / Debian hardening
| Finding | Severity | Disposition |
|---|---|---|
| `legion-lora.service` had no sandboxing directives | Med | **FIXED** — added NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, kernel/cgroup/namespace protections, RestrictAddressFamilies, SystemCallFilter, empty CapabilityBoundingSet, etc. |
| C agent missing `-fstack-clash-protection` and CET `-fcf-protection` | Low | **FIXED** — added to the Linux build (`-fcf-protection=full` scoped to x86). |
| No `[profile.release]` hardening | Low | **FIXED** — added `overflow-checks`, `strip`, `lto="thin"`, `codegen-units=1`. `panic="abort"` deliberately **excluded** (would change unwind/test semantics). |
| Installer data dir not `chmod`'d; Ollama installed via `curl|sh` without disclosure | Low | **FIXED** — `chmod 700` on the data dir; supply-chain notice + opt-out hint before the Ollama installer (kept default-on to avoid behavior change). |
| No dpkg/apt software inventory on Debian | Med (functional) | **DEFERRED** — add a `dpkg-query`/`/var/lib/dpkg/status` reader to feed OSV/KEV. |
| Audit log has no retention/rotation or tamper-evidence | Low–Med | **DEFERRED** — add `prune_audit_log` + optional per-row hash chain. |
| Web binary runs elevated for its lifetime | Low (mitigated by loopback+token) | **DEFERRED** — privileged-collector / web-server privsep (architecture change). |
| No AppArmor profile shipped (Debian default LSM) | Low | **DEFERRED** — optional confinement profile for `legion-web`. |

### Model identity / provenance
| Finding | Severity | Disposition |
|---|---|---|
| Ares model misrepresentation risk (the "qwen ares = Claude, smaller" idea) | — | **NONE FOUND** — persona is `qwen3:8b` + a system prompt that *forbids* claiming to be Claude (`Modelfile.ares`, `knowledge.rs`), locked by a unit test. No "is Claude"/Anthropic claim anywhere; Claude/Anthropic strings are only guardrails or malware signatures. |
| Missing Qwen3 base-model attribution/license (redistributed derivative) | Med (licensing) | **FIXED** — added [`NOTICE`](../NOTICE), README "Model attribution", and a ares-doc clarification. |
| "No data leaves your system" onboarding claim overstated (default-on web search + threat feeds egress) | Low–Med | **FIXED** — reworded to scope the claim to local inference and disclose optional outbound enrichment. |
| DeepSeek identity filter consistent but name-based (homoglyph/rename bypass disclosed) | Low | **DEFERRED** — PON-3 (digest/allowlist enforcement + Unicode-NFKC fold). |

## Changes applied in this pass
- `crates/legion-web/src/main.rs` — same-origin `/icons/:slug` handler + embedded SVGs; CSP `img-src 'self' data:`; audit-log `EnvFilter` fix; comment updates.
- `crates/legion-web/src/dashboard.html` — badge icon → `/icons/...` (static + JS); reworded onboarding privacy claim.
- `Cargo.toml` — `[profile.release]` hardening (safe subset).
- `agents/Makefile` — C-agent stack-clash + CET (x86) flags.
- `agents/ares/training/systemd/legion-lora.service` — systemd sandboxing.
- `scripts/install.sh` — data-dir `chmod 700`; Ollama installer disclosure.
- `NOTICE` (new), `README.md`, `docs/ares_mode.md`, `COMPLIANCE.md` — attribution, FIPS & CIS sections, accuracy fixes.

All changes are non-breaking; the full workspace test suite remains green.

## Deferred (recommended next, larger / opt-in)
1. **FIPS:** `fips` Cargo feature switching crypto to `aws-lc-rs` (FIPS) or OS OpenSSL.
2. **CIS 1/2:** dpkg/apt inventory for Debian system-package CVE coverage.
3. **CIS 8:** audit-log retention + tamper-evidence (hash chain / signed checkpoints).
4. **CIS 5/6:** privilege separation between the elevated collector and the web server.
5. **Defense-in-depth:** AppArmor profile for `legion-web`; PON-3 digest/allowlist model-identity enforcement.
