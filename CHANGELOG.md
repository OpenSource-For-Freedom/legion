# Changelog

All notable changes to Legion are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.35] - 2026-07-12

### Security

- **Full 2026-07 audit remediation (M1–M8, L1–L10).** Follow-up to the two Highs:
  - **M1** — the model digest pin (`verify_pinned`, previously dead code) is now
    enforced fail-closed on the Ollama path before inference.
  - **M3/L3/M4** — fixed a YARA lexer panic on `\x`+multibyte input (DoS via a
    hostile rule feed), rejected traversing rule-file names, and added optional
    per-file SHA-256 pinning for the rule feed (`catch_unwind` guards compile).
  - **M5/L5** — non-HTML responses now get a strict, script-free CSP; benign
    docker/agent-loop dashboard sinks are escaped. (Dropping `script-src
    'unsafe-inline'` on the dashboard itself is tracked — it needs the ~54 inline
    handlers refactored to delegated listeners, browser-verified.)
  - **M2** — the dashboard no longer implies external-runtime weights are
    "verified"; it states artifact-SHA vs. runtime-attestation honestly.
  - **L1** — remote-LLM opt-in now blocks cloud-metadata/link-local/private/
    plaintext targets and revalidates the on-disk config at startup.
  - **L2** — `/api/open` is confined to flagged alert paths or the scan root.
  - **M6/M7/M8** — all CI actions SHA-pinned (`@master` replaced); `appimagetool`/
    runtime downloads SHA-256-verified fail-closed; release build-provenance
    attestation + CycloneDX SBOM added. (Detached artifact signing + installer
    signature verification remain — they need a keyless-cosign vs. minisign
    decision.)
  - **L6/L7/L8/L9/L10** — release token scoped to the publish job; tag passed via
    `env:` not `${{ }}` inlining; Ollama install made opt-in; `[licenses]`
    allow-list enforced in CI; verified `scripts/fetch-zig.sh` replaces the
    trust-on-first-placement vendored toolchain.
  - Hardened `db.rs` against mutex-poison cascades (uniform `into_inner` recovery).
  - `clippy -D warnings`, `rustfmt --check`, and the full suite stay green.
- **Fixed installer namespace / provenance split (audit 2026-07 H2).** The
  documented one-liner installers (`scripts/install.sh`, `scripts/install.ps1`)
  and the `Cargo.toml` `repository` field pointed at `tbgor/legion` — a namespace
  that **does not exist** (GitHub 404) and that CI never publishes to. That both
  broke the documented install and left an unclaimed namespace an attacker could
  register to serve root-run binaries. All references now point at the
  authoritative `OpenSource-For-Freedom/legion` (matching `git origin` and the
  release workflows). Note: the current published `latest` release still carries
  `.zip` assets from the pre-`tar.gz` workflow, so `install.sh` (which fetches
  `*.tar.gz`) will succeed against the next CI-cut release; re-cutting a release
  or teaching the installer to accept both archive formats closes that gap.
- **Fixed cross-user session-token disclosure on the loopback dashboard (audit
  2026-07 H1).** A socket bound to `127.0.0.1` is reachable by every local user,
  so the session cookie vended by the unauthenticated `GET /` route could be
  scraped by any local account and used to drive the privileged (often
  root-level) API. A new same-user guard (`crates/legion-web/src/peercred.rs`)
  now runs outermost on loopback binds: it resolves the peer connection's owning
  UID from `/proc/net/tcp` and refuses any local user other than the one who
  launched Legion (root and the elevating human via `PKEXEC_UID`/`SUDO_UID` are
  authorized, so the self-elevated browser flow is unchanged). Escape hatches:
  `LEGION_DISABLE_PEERCRED` disables it; `LEGION_STRICT_PEERCRED` also refuses
  peers whose UID cannot be determined (IPv6 / non-Linux) instead of failing
  open. Verified end-to-end against real `/proc` (allow + deny branches) with new
  unit tests; `clippy -D warnings`, `rustfmt --check`, and the suite stay green.

### Removed

- **macOS support dropped — Legion now targets Linux and Windows only.** Removed
  the macOS YARA rule sets (`crates/legion-core/rules/macos.yar`,
  `rules-feed/macos/`), the macOS unified-log telemetry and `netstat` parsing
  paths, macOS privilege/elevation handling, the C agent's macOS code paths, the
  macOS branch of `scripts/install.sh`, the macOS unified-log test fixture, and
  the `macos-latest` / `*-apple-*` entries from the CI and release matrices. No
  `target_os = "macos"` code paths remain. Build, `clippy -D warnings`,
  `rustfmt --check`, and the test suite are green on Linux and Windows.

### Changed

- **Local model runtime is now an OpenAI-compatible server; Ollama is legacy.**
  Ares defaults to `llm_runtime = "openai_compat"` and talks to a local model
  server (e.g. `llama.cpp`'s `llama-server`) at
  `http://127.0.0.1:8080/v1/chat/completions`, loading the staged Hugging Face
  GGUF directly — no `ollama create` import. Ollama is still supported as an
  opt-in legacy backend (`llm_runtime = "ollama"`, `/api/chat` on `:11434`). The
  SSRF/loopback guard is now the generic `LEGION_ALLOW_REMOTE_LLM` (the legacy
  `LEGION_ALLOW_REMOTE_OLLAMA` is still honored).
- **Agent rebrand: Poncho + Mythos → Ares (the agent of war).** The agent crate
  (`legion-poncho` → `legion-ares`), the local model (`legion-mythos:*` →
  `legion-ares:*`), the agent directory (`agents/poncho` → `agents/ares`), its
  config file (`poncho.json` → `ares.json`), all structs (`PonchoChat`/
  `PonchoConfig` → `AresChat`/`AresConfig`), the dashboard, and the docs are
  unified under the single name **Ares**.
- **Single auto-provisioned model.** Removed the multi-model
  catalog, picker, and the install/update/scan surface
  (`/api/agent/models`, `/api/agent/install`, `/api/agent/update`,
  `/api/agent/scan-model` and the dashboard model-management panel). Ares ships
  exactly one model per hardware tier, provisioned automatically on startup
  (pulled and SHA-256-verified from Hugging Face, or built from the embedded
  Modelfile as a fallback); the tier is still auto-selected and, on the legacy
  Ollama backend, digest pinning is retained.
- **Alerts auto-resolve.** Each scan reconciles findings per detector scope
  (`reconcile_alerts`), so a finding that no longer holds (peer gone, file no
  longer matches, IP off the blacklist) clears itself instead of lingering.
- **Whole-system scanning.** Package and YARA scans now cover every fixed drive /
  mount (`fsroots`), with shared exclusions for OS pseudo-filesystems, recycle
  bins, WinSxS, and build/VCS dirs; removable/network media are skipped.
- **Cut the "new public peer" false positive.** A novel outbound IP is no longer
  an alert on its own — only threat-intel-corroborated peers escalate.

### Added

- **Hugging Face model distribution.** The trained Ares model is published to the
  `tburns-actual/legion-ares` Hugging Face repo as per-tier `Q4_K_M` GGUFs. On
  first launch Legion reads the in-repo `agents/ares/models/manifest.json`,
  downloads the tier's GGUF, streams it through a size cap, and SHA-256-verifies
  it against the manifest before it is served. Added a CI check that verifies the
  model manifest and its endpoint. Design: `docs/MODEL-DISTRIBUTION.md`.
- **`legion-ares:qwen3-1.7b` tier published** in the model manifest — the fast
  default for machines under 6 GB VRAM (including 4 GB laptop GPUs).
- **Open-in-file-manager.** `POST /api/open` reveals a flagged file in Explorer
  (Windows) / the file manager (Linux); the dashboard FILE/PATH cells are now
  clickable, and YARA/heuristic alerts carry the triggering path.
- **Alert hygiene + retention.** Startup prune of legacy pre-refactor alert rows
  plus an age-out retention sweep (30-day hard, 14-day for unacked Low/Info).

### Fixed

- **Windows release build.** The release workflows' `Build release binaries` step
  used a bash line-continuation but no `shell:`, so it ran under PowerShell on
  `windows-latest` and failed parsing `--package`. Pinned the step to
  `shell: bash` in `release.yml` and `release-on-main.yml`.

### Security

- **`anyhow` bumped to 1.0.103 (RUSTSEC-2026-0190).** Clears the `cargo-deny`
  advisory gate — an unsoundness in `anyhow`'s `Error::downcast_mut()`.
- **macOS removal and the rebrand are covered by the same green gates** (build,
  clippy `-D warnings`, fmt, full test suite on Linux + Windows).

### Security (prior audit)

Remediation of findings from the full-scale security audit
(`docs/SECURITY-AUDIT.md`). Build, clippy (`-D warnings`), and the test suite
are green across Linux/Windows in CI.

#### Critical

- **Web control plane now requires authentication (WEB-1).** Every `/api/*`
  route is gated by a per-session bearer token generated from the OS CSPRNG at
  startup. The browser dashboard receives it as a `SameSite=Strict; HttpOnly`
  cookie (so same-origin `fetch()` authenticates automatically and cross-site
  requests cannot carry it), and CLI clients can pass it via `Authorization:
  Bearer` / `X-Legion-Token`. The token is written to an owner-only
  `session.token` file and printed at startup. Token comparison is
  constant-time. Override with `LEGION_API_TOKEN`.
- **ARES Ollama host is validated (PON-2).** `ollama_host` must be `http(s)://`
  and resolve to loopback unless `LEGION_ALLOW_REMOTE_OLLAMA=1` is set,
  closing an SSRF / system-prompt-exfiltration vector. The policy is now
  re-checked on the chat/hunt execution path, not only at config-save time.

#### High

- **Evasion-resistant model blocking (PON-3).** `is_blocked` now normalises the
  tag (lowercase, strip non-alphanumerics) before matching, so separator,
  registry/namespace-prefix and `:tag`-suffix variants of a blocked family
  (`deep-seek`, `hf.co/u/DeepSeek-R1:q4`) no longer slip through. Documented as
  a policy filter, not a cryptographic control.
- **Bounded HTTP response bodies (CORE-1).** All feed / threat-intel / YARA-rule
  fetches now stream through a 32 MiB cap (`legion_core::http`), so a malicious
  or compromised feed can no longer exhaust memory.
- **YARA hex matcher is bounded (CORE-2).** Hex patterns are capped at 4096
  tokens at compile time and the matcher runs under a step budget, preventing
  stack-overflow and exponential blow-up from a hostile fetched rule.

#### Medium

- **Scanner no longer follows symlinks and is depth-bounded (CORE-4).** The
  package walker uses `symlink_metadata`, skips symlinks (no scan-root escape /
  loop), and caps recursion depth.
- **YARA filesize overflow fixed (CORE-7).** `n GB`-style literals use
  `checked_mul`, surfacing a compile warning instead of a panic/wrap.
- **Elevated config helper is path-confined (WEB-2).** `--apply-ares-config`
  now rejects any path outside the protected data directory or with an
  unexpected filename before reading it with elevated rights.
- **C agent build hardening (CAGENT-1).** The Makefile appends
  `_FORTIFY_SOURCE=2`, stack protector, PIE and (Linux) full RELRO / `noexecstack`
  via `override` so the mitigations cannot be stripped by command-line
  `CFLAGS`; Windows adds `/GS /guard:cf /DYNAMICBASE /NXCOMPAT`. The broken
  `make test` target (referenced a non-existent `tests/Makefile`) now compiles
  and runs the test directly.

#### Follow-ups now implemented

- **Cryptographic feed integrity (CORE-3).** New `legion_core::integrity`
  provides SHA-256 hashing and Ed25519 detached-signature verification (via the
  in-tree `ring`), plus a `FeedIntegrity` policy plumbed through
  `http::read_capped_verified` — feeds routed through it (CISA KEV, cyber
  events, abuse IPs) log their body SHA-256 for auditability, and a
  non-`TlsOnly` policy is fail-closed. The CISA KEV feed honours an
  operator-pinned SHA-256 via `LEGION_KEV_SHA256`.
- **Model digest pinning (PON-1).** New `legion_ares::pins` records an
  approved model's Ollama manifest digest trust-on-first-use
  (`model_pins.json`, owner-only); installs pin, updates re-pin, and
  `verify_pinned` flags a digest that changed under a tag without an explicit
  update as a possible swap. Wired into the web install/update handlers.

### Added

- `docs/SECURITY-AUDIT.md` — full-scale audit report (findings + remediation).
- `legion_core::http` — bounded response-body read helpers.
- `legion_core::integrity` — feed SHA-256 / Ed25519 verification (CORE-3).
- `legion_ares::pins` — model digest pinning (PON-1).
- Security regression tests: web token auth, ARES blocking-evasion and host
  validation, YARA overflow/oversized-rule/jump-budget, scanner symlink safety,
  feed integrity (sha256 + Ed25519 round-trip/tamper), digest-pin TOFU.
