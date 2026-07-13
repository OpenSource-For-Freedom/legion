# Legion — Full Security & DevSecOps Audit (2026-07)

**Date:** 2026-07-10
**Auditor role:** Senior security engineer + DevSecOps manager
**Scope:** Entire workspace — `legion-web`, `legion-core`, `legion-ares`, the dashboard front-end,
supply chain / dependencies, and CI/CD + release/install tooling.
**Method:** Six parallel domain deep-reviews (web/API, frontend XSS, core injection/integrity,
ARES/LLM, supply-chain, CI/CD), each reading source end-to-end and verifying leads carried over
from the prior (interrupted) 2026-07-11 audit run. Findings below are de-duplicated across domains.

> Prior point-in-time records: `docs/SECURITY-AUDIT.md` (2026-06-11), `docs/COMPLIANCE-AUDIT-2026-06.md`.
> Remediation tie-in: `docs/SPRINT-PLAN-CROSS-PLATFORM.md` (Sprint 0/3 absorb the release-chain items).

---

## 1. Executive summary

Legion remains a **security-conscious codebase** and, notably, a security *product* that mostly
practices what it preaches: SQL is fully parameterized, there are **no `unsafe` blocks**, command
execution never touches a shell with request data, TLS is rustls-only, the model-download path is
SHA-256 fail-closed, output is escaped at every DOM sink, and the privilege-elevation helper is
path-confined and TOCTOU-safe. Dependencies are 100% crates.io with a strict source policy, and CI
runs `cargo-audit` **and** `cargo-deny` on every push.

The audit found **no verified remote-code-execution against a default install** and **no SQLi/XSS/shell-injection**.
The material risk is concentrated in two places:

1. **The local trust boundary is wrong.** The per-session API token — the thing that gates every
   privileged, often root-level action — is handed to *any* local user via the unauthenticated `/`
   route. Loopback reachability is treated as equivalent to same-user; it is not. This is a
   **regression** of the original WEB-1 finding the token was introduced to fix.
2. **The distribution/model supply chain is verifiable in mechanism but not in practice.** Installers
   pull root-run binaries from a *different* GitHub namespace than CI publishes to; releases are
   checksummed but not signed and carry no SBOM/provenance; and the advertised model digest-pinning
   (`verify_pinned`) is **dead code**.

Everything else is Medium/Low hardening and defense-in-depth.

### Toolchain status
| Check | Result |
|-------|--------|
| Dependency sources | ✅ 100% crates.io — 0 git/path/patch deps |
| CI advisory/source gate | ✅ `cargo audit` + `cargo deny check advisories bans sources` on every push |
| `unsafe` blocks in workspace | ✅ none (the 2 grep hits are string literals) |
| SQL | ✅ fully parameterized; the one `format!` uses a hardcoded column array |
| `cargo-audit` / `cargo-deny` installed locally | ⚠️ no (covered by CI) |

### Findings by severity
| Sev | Count | IDs |
|-----|-------|-----|
| High | 2 | H1 (token disclosure), H2 (namespace/provenance split) |
| Medium | 8 | M1 verify_pinned dead · M2 openai_compat unverified · M3 YARA panic · M4 rule-feed TOFU · M5 CSP unsafe-inline · M6 no signing/SBOM · M7 appimagetool unpinned · M8 actions unpinned |
| Low | 10 | L1–L10 (below) |

---

## 2. High

### H1 — Session token disclosed to any local user via the unauthenticated `/` route  — ✅ FIXED (2026-07-10)
> **Remediated.** A same-user guard ([peercred.rs](../crates/legion-web/src/peercred.rs)) now runs
> outermost on loopback binds: it resolves the peer's owning UID from `/proc/net/tcp` and refuses any
> local user other than the launching user (root + `PKEXEC_UID`/`SUDO_UID` authorized, so the elevated
> browser flow is intact). Verified end-to-end against real `/proc` (allow + deny). Follow-up: IPv6 peers
> and non-Linux still fail open unless `LEGION_STRICT_PEERCRED` is set — extend peer-UID lookup to those.
> See CHANGELOG "Security".

**Domain:** Web/API · **File:** [main.rs:436-454](../crates/legion-web/src/main.rs#L436-L454), routing [main.rs:2015-2018](../crates/legion-web/src/main.rs#L2015)
The per-session bearer token that gates every privileged `/api/*` action is returned in a
`Set-Cookie` header from `GET /`, which is served **without authentication**. A socket bound to
`127.0.0.1` accepts connections from **all** local users — loopback is not user-partitioned — so any
local process/account can `curl -s -D - http://127.0.0.1:3000/ | grep set-cookie`, scrape the token,
and drive the full API. Because the web process self-elevates at startup, a token holder can invoke
`POST /api/runner/launch` → `systemctl start legionr@default` **as root** ([runner.rs:75-81](../crates/legion-core/src/runner.rs#L75-L81)),
plus scans, feed pulls, model install, arbitrary-path `open`, and read of all telemetry/alerts/audit/chat.
The owner-only perms on `session.token` are moot because the same secret is vended over unauthenticated HTTP.
**This is a regression of WEB-1** (the finding the token was created to close).
**Fix (best first):** (1) switch the loopback HTTP model to a **Unix-domain socket / Windows named pipe**
with filesystem perms + `SO_PEERCRED` peer-UID check — make "same user" the real boundary; (2) require
possession of the owner-only file token before minting the browser cookie; (3) at minimum, verify peer
UID on `/` and refuse cross-user connects. Stop equating loopback reachability with same-user.

### H2 — Installers fetch and root-execute binaries from a non-authoritative namespace; repo identity is split  — ✅ FIXED (2026-07-10)
> **Remediated.** Verified factually that `tbgor/legion` **returns 404 (does not exist)** while
> `OpenSource-For-Freedom/legion` hosts the real releases — so the installers pointed at an *unclaimed,
> squattable* namespace (also broken installs). Repointed `Cargo.toml` `repository` and both installers'
> `REPO`/usage comments to `OpenSource-For-Freedom/legion`; corrected raw URLs resolve (200), no `tbgor`
> refs remain outside this report. **Residual (functional, not the security fix):** current published
> `latest` (v1.0.34) still has `.zip` assets from the old workflow while `install.sh` fetches `.tar.gz`
> (current workflow's format) — resolves on the next CI release, or teach the installer to accept both.
> The remaining M6 half (sign + SBOM so the checksum proves *authenticity*, not just integrity) is still
> open → Sprint 3.

**Domain:** CI/CD · **Files:** [scripts/install.sh:6](../scripts/install.sh#L6) (`REPO="tbgor/legion"`), [scripts/install.ps1:20](../scripts/install.ps1#L20), [Cargo.toml:16](../Cargo.toml#L16) vs git origin / [README.md:58](../README.md#L58) = `OpenSource-For-Freedom/legion`
The authoritative project — git origin, CI badges, releases page, security-advisory link, and the org
that owns the CI runner action — is **`OpenSource-For-Freedom/legion`**, which is also where the release
workflows publish (they run in origin with the default `GITHUB_TOKEN`). But **both documented install
one-liners download and `sudo`/UAC-execute `legion-web` from `tbgor/legion`** — a *different* account CI
never publishes to. If that namespace is unclaimed, transferred, or attacker-controlled, whoever holds it
gets **RCE as root/admin** on every user who runs the documented install. `Cargo.toml`'s `repository =
tbgor/legion` compounds the ambiguity. Compounding this (M6): the installer's `.sha256` is fetched from
the **same host** as the binary, so a hostile release origin simply serves a matching checksum.
**Fix:** Pick one canonical namespace (`OpenSource-For-Freedom`, per origin + CI) and make git origin,
`Cargo.toml`, README, SECURITY.md, and both installers consistent; ensure the `tbgor` namespace is owned
by the same party or retired so it cannot be squatted.

---

## 3. Medium

### M1 — Model digest pinning is dead code (`verify_pinned` called nowhere)
**ARES** · [model_registry.rs:486](../crates/legion-ares/src/model_registry.rs#L486), whole `pins.rs`, false claim [CHANGELOG.md:141](../CHANGELOG.md#L141)
The TOFU pin store (`model_pins.json`) is write-only: `pin_current()` records the Ollama manifest digest,
but nothing ever calls `verify_pinned()` to compare a live digest against it. A model swapped under an
approved tag after first pin (`ollama cp`, re-pull, direct store edit) is never detected — the exact threat
the module's own doc-comment claims to close. The CHANGELOG asserts pinning is "wired into the web
install/update handlers"; it is wired **nowhere**. **Fix:** call `verify_pinned` before every inference on
the Ollama path and fail closed on mismatch, or delete the module and stop advertising it. Prefer shipping
the pin in the manifest over TOFU.

### M2 — Default `openai_compat` runtime binds no artifact verification to inference
**ARES** · [main.rs:1881-1899](../crates/legion-web/src/main.rs#L1881-L1899), [chat.rs:368-397](../crates/legion-ares/src/chat.rs#L368), default runtime [config.rs:17](../crates/legion-ares/src/config.rs#L17)
The shipped default runtime is `openai_compat` (llama.cpp server), **not** Ollama. On this path a GGUF is
downloaded and SHA-256-verified to `data_dir/models/*.gguf` — but that staged file is **never handed to the
runtime**; the external server loads whatever weights the operator started it with, and Legion sends only the
model *name string*. So the one real enforced integrity control is disconnected from what actually runs, and
digest pinning (Ollama-only) doesn't apply here at all → "poisoned analyst" with no integrity signal, while
the dashboard implies the model was "downloaded and verified." **Blast radius is capped** (see Holds: no
model-output→action channel). **Fix:** point the local server at the pinned staged GGUF, or re-check the
served model identity via `/v1/models`, and surface an explicit "unverified external model" state.

### M3 — YARA lexer panics (DoS) on `\x` escape followed by a multi-byte UTF-8 char
**Core** · [yara.rs:867-868](../crates/legion-core/src/yara.rs#L867-L868)
The `\x` hex-escape slices two raw bytes (`src[i+1..i+3]`) with only a numeric bound (`i+2 < n`), no
char-boundary check. A rule literal like `"\x€"` makes `i+3` land mid-codepoint → `str` range-index panic
("not a char boundary"). Reachable on every rule-compile of attacker-influenced text — `update_rules`
compiles rules fetched from the remote `rules_repo` (which is trust-on-fetch, M4). **Fix:** read the two hex
bytes via `b.get(i+1)/b.get(i+2)` with `is_ascii_hexdigit`, or guard `is_char_boundary(i+3)`; wrap
`lex`/`compile` on fetched rules in `catch_unwind`.

### M4 — YARA rule feed is trust-on-fetch (no publisher signature)
**Core** · [yara.rs:229-311](../crates/legion-core/src/yara.rs#L229-L311)
Downloaded rules are trusted on TLS transport alone — a repo/CDN compromise or cert MITM can serve rules
that trigger M3 or silently redefine detection (rules that compile but never match, blinding the scanner).
The integrity primitives exist and are used elsewhere (`integrity::FeedIntegrity::{Sha256,Ed25519}`,
`read_capped_verified`) but aren't applied here. (HTTPS-enforced, 30s timeout, 32 MiB cap, compile-validated
— so integrity/DoS bounds hold; only publisher *authenticity* is missing.) **Fix:** ship an Ed25519-signed
rules manifest (already verifiable) or per-file SHA-256 and route `update_rules` through `read_capped_verified`.

### M5 — CSP allows `script-src 'unsafe-inline'` — no DOM-XSS backstop
**Frontend/Web** · [main.rs:165-171](../crates/legion-web/src/main.rs#L165-L171)
All 53 `innerHTML` sinks currently escape correctly (verified — including the high-risk LLM-output path), so
**there is no live XSS today**. But `'unsafe-inline'` means the app's entire XSS posture rests on the
`esc()`/`escHtml()` helpers being applied at every sink; one missed escape becomes code execution that, via
the same-origin cookie, drives the full API. Two sinks already skip escaping (benign today — L5). **Fix:**
move inline `<script>` to a same-origin asset (or per-response nonce) and drop `'unsafe-inline'` from
`script-src`, restoring a real second layer.

### M6 — No release signing, SBOM, or provenance; checksum from same host as artifact
**CI/CD + Supply-chain** · [release.yml:106-113](../.github/workflows/release.yml#L106), [release-on-main.yml:173-185](../.github/workflows/release-on-main.yml#L173)
Releases ship `*.tar.gz`/`*.AppImage`/`*.sha256` only — no cosign/minisign/GPG signature, no CycloneDX/SPDX
SBOM, no SLSA `attest-build-provenance`. The installer's checksum is fetched from the same release host as the
binary, so it proves integrity, not authenticity — SECURITY.md/COMPLIANCE.md's "verifiable build" claim is
circular without a signature. Highest-value missing control for an elevated-privilege security product.
**Fix:** add `id-token: write` + `actions/attest-build-provenance`, sign artifacts (cosign keyless/minisign)
with the public key shipped out-of-band, verify signature before checksum in installers, attach a CycloneDX SBOM.

### M7 — AppImage build downloads unpinned, unverified tooling from a mutable tag and bundles it into the shipped artifact
**CI/CD + Supply-chain** · [build-appimage.sh:48-49](../scripts/build-appimage.sh#L48-L49) (via release workflows)
`appimagetool` and the type2 `runtime` are pulled from AppImage's `continuous` (rolling, mutable) releases
over `curl` with **no checksum/signature**, then the runtime is embedded into every published
`Legion-*.AppImage` — inside the `contents: write` release job. Upstream mutation/compromise flows straight
into the signed release. **Fix:** pin to a tagged AppImageKit release and verify a hardcoded SHA-256 before
use (the project already applies this pattern to its own archives and the Ares model).

### M8 — No CI action is SHA-pinned; `dtolnay/rust-toolchain@master` rides a mutable branch
**CI/CD + Supply-chain** · [ci.yml:29,32](../.github/workflows/ci.yml#L29), release workflows
Every `uses:` is a floating ref. Sharpest: `dtolnay/rust-toolchain@master` — any push to that branch runs in
CI. Tag-pinned third-parties (`softprops/action-gh-release@v2`, `EmbarkStudios/cargo-deny-action@v2`,
`OpenSource-For-Freedom/Legion_runner@v1.0.40`) are still mutable; `softprops` runs in the write-token release
job. **Mitigating:** all jobs use GitHub-hosted runners (no self-hosted fork-PR RCE), and `Legion_runner`
runs only in read-only CI. **Fix:** pin all third-party actions to full commit SHAs (with version comments) +
Dependabot; replace `@master`/`@stable`.

---

## 4. Low (defense-in-depth / conditional)

| ID | Domain | Finding | File |
|----|--------|---------|------|
| L1 | Web/ARES | Remote-LLM opt-in has no metadata/link-local/RFC-1918 blocklist once `LEGION_ALLOW_REMOTE_LLM` set; `AresConfig::load` not re-validated at startup (boot-time probe uses host before the execution-path check) | [config.rs:133-163](../crates/legion-ares/src/config.rs#L133), [main.rs:1794-1833](../crates/legion-web/src/main.rs#L1794) |
| L2 | Web/Front | `POST /api/open` reveals arbitrary existing paths (no scan-root/alert confinement); token-gated, no shell, no injection — but an arbitrary-path existence oracle for a token holder | [main.rs:590-599](../crates/legion-web/src/main.rs#L590), [fsroots.rs:108-141](../crates/legion-core/src/fsroots.rs#L108) |
| L3 | Core | YARA `rule_files` entries used in `dir.join`/`fs::write` without bare-filename validation → path traversal writing fetched content, gated by owner-only config perms | [yara.rs:281-282](../crates/legion-core/src/yara.rs#L281) |
| L4 | ARES | "DeepSeek blocked" is shallow substring match, defeated by rename/rehost; non-binding on the operator-named openai_compat path | [model_registry.rs:72-79](../crates/legion-ares/src/model_registry.rs#L72) |
| L5 | Frontend | Docker telemetry (`cpu`,`mem`,`state`) and agent-loop tick scalars rendered to `innerHTML` unescaped — benign source today, but the exact class that becomes XSS under M5 | [dashboard.html:1621](../crates/legion-web/src/dashboard.html#L1621), [dashboard.html:2368](../crates/legion-web/src/dashboard.html#L2368) |
| L6 | CI/CD | `contents: write` granted workspace-wide in `release-on-main.yml` (build job compiles deps with a write-scoped token) | [release-on-main.yml:17-18](../.github/workflows/release-on-main.yml#L17) |
| L7 | CI/CD | Version string `grep|sed`'d from Cargo.toml then inlined into `run:` via `${{ }}` (template-injection pattern; bounded to main-writers) | [release-on-main.yml:41,111,130](../.github/workflows/release-on-main.yml#L41) |
| L8 | CI/CD | Installers pipe third-party remote installer (Ollama) to a root shell, no hash pin (opt-out exists, default on) | [install.sh:54](../scripts/install.sh#L54), [install.ps1:112-113](../scripts/install.ps1#L112) |
| L9 | Supply-chain | `deny.toml` has no `[licenses]` table; CI never checks licenses on the MIT-distributed product | [deny.toml](../deny.toml), [ci.yml:90-93](../.github/workflows/ci.yml#L90) |
| L10 | Supply-chain | Vendored zig dev-build (`.local-tools/`) has no fetch script/checksum/provenance (untracked, not in release path, local-dev only) | [.local-tools/cc](../.local-tools/cc) |

**Non-security robustness note:** `db.rs` uses `conn.lock().unwrap()` in ~30 places; a panic while the DB
mutex is held poisons it and cascades. Consider `lock().unwrap_or_else(|e| e.into_inner())` uniformly.

---

## 5. Holding defenses (verified — credit where due)

- **AuthZ gate**: every privileged `/api/*` route is behind `require_auth`; only `/` + `/icons/:slug` are unauth (the `/` token leak is the exception — H1). Token is 32-byte CSPRNG, **constant-time compared** (`ct_eq`), owner-only file, never logged.
- **SSRF default posture**: `validate_host` requires `http(s)://` + loopback; userinfo trick handled via `rsplit('@')` (rejects `http://127.0.0.1@169.254.169.254/`); re-validated on the execution path, not just at save.
- **Privilege elevation**: per-action UAC/polkit; elevated helper `canonicalize()`s argv and rejects anything outside `data_dir()` / not named `ares.pending.json` (defeats argv injection + symlink TOCTOU); re-runs `validate()` under elevation.
- **Command execution**: ~20 `Command::new` sites use argv arrays, no shell with request data; scanner refuses PATH-based interpreters under elevation and only runs known absolute paths.
- **SQL**: fully parameterized; the one `format!` iterates a hardcoded column array.
- **Model download**: `download_verified_to_file` is SHA-256 fail-closed (bail + remove partial); both callers pass `Sha256`. (Gap is *binding to runtime*, M2 — not the download.)
- **ARES blast radius**: autonomous loop runs a fixed table of **read-only** probes, escalates on a deterministic keyword/score gate; the LLM is used for **text synthesis only** — no model-output→action channel, so prompt injection / poisoned model degrades to misleading text, not RCE. Prompts explicitly mark scan data untrusted.
- **XSS output encoding**: all server/LLM/feed data escaped at sinks; `mdLite` escapes-then-decorates; no `eval`/`Function`/`document.write`/`insertAdjacentHTML`; token is `HttpOnly` + `SameSite=Strict`, not in `localStorage`.
- **Transport/browser**: loopback bind (non-loopback refused without `--allow-insecure-bind`), `host_guard` DNS-rebinding defense, no CORS, `SameSite=Strict` CSRF defense, full security-header set, 64 KB body cap + 4 KB chat cap, 600/10s rate limiter, generic-500 error hygiene, audit logging of privileged actions.
- **Dependencies**: 100% crates.io, 0 git/path/patch, `unknown-registry/unknown-git = deny`, `yanked = deny`; rustls-only TLS (no OpenSSL C surface); two ignored advisories (`paste` RUSTSEC-2024-0436, `lru` RUSTSEC-2026-0002) are justified & in sync; release profile `overflow-checks=true`, strip/lto. CI runs `cargo audit` + `cargo deny`.
- **No `unsafe`** anywhere in the workspace. `build.rs` is benign (Windows-only icon embed of a committed asset, no network/codegen).

---

## 6. Prioritized remediation roadmap

**P0 — trust boundary & provenance (do first; feeds Sprint 0/1/3):**
1. **H1** — replace loopback-HTTP-as-auth with UDS/named-pipe + peer-UID, or require the file token to mint the cookie. *This is the top fix.*
2. **H2 / M6** — unify the repo namespace; add artifact **signing + SBOM + provenance**; verify signature (not just checksum) in installers.

**P1 — supply-chain hardening (Sprint 3):**
3. **M1/M2** — make model integrity real: enforce `verify_pinned` (or remove it + fix the CHANGELOG) and bind the verified GGUF to the runtime.
4. **M7/M8** — pin `appimagetool` + all CI actions to SHAs with checksum verification.
5. **M4/L3** — sign the YARA rule feed; validate `rule_files` as bare filenames.

**P2 — defense-in-depth:**
6. **M3** — fix the YARA lexer panic (+ `catch_unwind` on fetched rules).
7. **M5/L5** — CSP nonce, drop `'unsafe-inline'`; escape the two benign sinks.
8. **L1/L2/L4/L6–L10** — metadata blocklist + startup revalidation, `/api/open` confinement, digest-anchored model policy, least-privilege release token, `env:`-passed version, opt-in Ollama, `[licenses]` policy, zig provenance.

**Net posture:** solid engineering with a small number of high-leverage gaps. Fixing H1 and the
provenance chain (H2/M6) closes the two issues a real attacker would actually use.
