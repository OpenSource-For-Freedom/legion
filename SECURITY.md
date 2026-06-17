# Security Policy

Legion is a local security monitor. This document describes its security model,
how it is hardened, how to deploy it safely, and how to report vulnerabilities.

## Reporting a vulnerability

Please report security issues **privately**:

- Open a [GitHub security advisory](https://github.com/OpenSource-For-Freedom/legion/security/advisories/new), or
- Email the maintainers (see the repository profile).

Do **not** open a public issue for an undisclosed vulnerability. We aim to
acknowledge reports within 5 business days and to ship a fix or mitigation as
quickly as the severity warrants. Coordinated disclosure is appreciated.

Supported version: the latest `main`. Fixes are not back-ported to older tags.

## Security model

Legion is designed to run **on the machine it protects**, for the user who owns
that machine. Access control is delegated to the **operating system** rather than
an in-app login:

- **Loopback by default.** `legion-web` binds `127.0.0.1` and serves plain HTTP.
  Traffic never leaves the host. A DNS-rebinding guard rejects any request whose
  `Host` header is not a loopback name, and no CORS headers are emitted
  (same-origin only).
- **OS elevation, not app auth.** On launch the interactive front-ends request
  administrator rights through the **native OS prompt** — UAC (Windows), and a
  polkit/`pkexec` dialog or `sudo` (Linux). Elevation lets Legion read privileged telemetry (Windows
  Security log, full process table, raw sockets). Pass `--no-elevate` (or set
  `LEGION_NO_ELEVATE=1`) to skip it; elevation is also skipped automatically in
  CI and where no interactive prompt channel exists.
- **Owner-only data at rest.** The SQLite database, configuration, and cached
  rules are created `0600`/`0700` (owner only) on Unix.

## Hardening controls (implemented)

| Area | Control |
|------|---------|
| Network exposure | Loopback bind by default; explicit warning if a non-loopback `--host` is set |
| DNS rebinding | `Host`-header allowlist middleware on loopback binds |
| CORS | No `Access-Control-Allow-*` headers (same-origin only) |
| Response headers | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP, CORP, `Cache-Control: no-store` |
| Injection (XSS) | All server-supplied data is HTML-escaped (incl. quotes) before DOM insertion |
| Injection (SQL) | 100% parameterized queries (`rusqlite` bound params); no string-built SQL |
| Command exec | External tools invoked with fixed argv (no shell, no interpolated input) |
| SSRF | Rule-feed fetches require an `https://` scheme |
| DoS | 64 KiB request body limit; fixed-window rate limiter |
| Error handling | Generic client responses; full errors logged server-side only |
| Secrets at rest | DB/config/rules restricted to owner (Unix `0600`/`0700`) |
| Transport | rustls (no system OpenSSL); outbound clients enforce timeouts and validate certificates |
| Audit | Security-relevant actions recorded to an `audit_log` table and structured logs |
| Supply chain | `Cargo.lock` committed; `cargo audit` and `cargo deny` in CI |

## Deploying beyond localhost

The dashboard has **no built-in authentication** by design. If you must reach it
from another host, do **not** simply bind `0.0.0.0`. Instead:

1. Keep `legion-web` bound to `127.0.0.1`, and
2. Front it with a reverse proxy (nginx/Caddy/Traefik) that terminates TLS and
   enforces authentication (mTLS, OIDC/SSO, or HTTP basic over TLS), or
3. Reach it over an SSH tunnel / WireGuard rather than exposing the port.

Binding a non-loopback `--host` disables the DNS-rebinding guard and logs a
warning; only do so behind an authenticated proxy as above.

## Reproducible / verifiable builds

- `Cargo.lock` is committed; CI builds release binaries on Linux and
  Windows from the locked graph.
- TLS uses `rustls`, removing the system OpenSSL attack surface.
