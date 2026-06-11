# Legion — Full-Scale Security & Code-Quality Audit

**Date:** 2026-06-11
**Scope:** Entire workspace — `legion-core`, `legion-web`, `legion-poncho`, `legion-tui`,
`legion-cli`, the native C agent (`agents/`), build/CI, and the supply-chain config.
**Method:** Source review of every crate, the C agent, and the dashboard front-end, plus
`cargo build`, `cargo clippy`, and `cargo test` on the full workspace.

> **Remediation status (2026-06-11):** the 3 Critical, 3 of 4 High, and several
> Medium findings have been fixed on `feature/production` with regression tests
> (see `CHANGELOG.md`). Remediated: WEB-1, WEB-2, PON-2, PON-3, CORE-1, CORE-2,
> CORE-4, CORE-7, CAGENT-1. Tracked as follow-ups: CORE-3 (feed integrity) and
> full PON-1 digest pinning. Remaining Mediums/Lows are the documented backlog.

---

## 1. Executive summary

Legion is a **security-conscious codebase**. The build is clean, the test suite is green,
clippy is silent, SQL is fully parameterised, TLS is enforced on every hard-coded feed URL,
the dashboard escapes untrusted data at its render sinks, and the data-at-rest directory is
locked to the owner on Unix. The author has clearly anticipated most of the standard
local-web-server attack surface (DNS-rebinding guard, body-size limits, security headers, a
rate limiter).

The findings below are therefore mostly **architectural** rather than blatant bugs. The two
themes that matter most:

1. **The web control plane has no authentication.** Every privileged action (service launch,
   model install, scans, outbound fetches) is reachable by any local process that can open a
   socket to `127.0.0.1:3000`. Loopback is not a privilege boundary.
2. **The PONCHO model supply chain is unverified.** Models are pulled with no digest/signature
   check from an operator-settable, unvalidated `ollama_host`, and the "DeepSeek is blocked"
   policy is shallow substring matching that a rename or rehost defeats.

### Toolchain status (all green)

| Check | Result |
|-------|--------|
| `cargo build --workspace --all-targets` | ✅ exit 0 |
| `cargo clippy --workspace --all-targets` | ✅ exit 0, no warnings |
| `cargo test --workspace` | ✅ 75 passed, 0 failed |

### Findings by severity

| Sev | Count | IDs |
|-----|-------|-----|
| Critical | 3 | WEB-1, PON-1, PON-2 |
| High | 7 | WEB-2, WEB-3, WEB-4, CORE-1, CORE-2, CORE-3, PON-3 |
| Medium | 12 | WEB-5…8, CORE-4…9, PON-4, CAGENT-1 |
| Low / quality | many | see §7 |

---

## 2. legion-web — the HTTP control plane

`crates/legion-web/src/main.rs` (~1539 lines, single-file Axum server).

### WEB-1 (Critical) — No authentication on any endpoint; privileged ops exposed to any local process
There is no token, password, session, or origin-pairing on **any** route. The design
delegates access control "to the OS per privileged action," but that only covers **one**
action (`api_agent_config_save`, which re-prompts via UAC/polkit). Every other privileged
mutation has no OS gate:

- `POST /api/runner/launch` → starts a systemd service (`main.rs:744`)
- `POST /api/runner/stop` / `POST /api/runner/doctor` (`main.rs:732`, `756`)
- `POST /api/agent/install|update|scan-model` → pulls/installs an LLM model (`main.rs:1008`, `1038`, `1054`)
- `POST /api/scan`, `POST /api/feeds/refresh`, `POST /api/yara/update` (`main.rs:509`, `438`, `632`)

Any local UID (or another container sharing the loopback namespace) can drive these. The
audit log records the actor as `"operator"`, which is misleading — the server cannot
authenticate the caller.

**Fix:** require a per-session bearer token (printed to the controlling terminal at startup)
on all `/api/*` routes, plus a same-origin/CSRF token on mutating routes.

### WEB-2 (High) — Elevated `--apply-poncho-config` trusts an argv path; TOCTOU on the staged file
`elevated_persist_config` stages a file under `data_dir()` then re-invokes the binary
**elevated** with `--apply-poncho-config <path>` (`main.rs:1151–1180`). The elevated helper
reads whatever path it is handed and writes it with hardened perms, but does **not** verify
the path is inside `data_dir()`, that the file is the one this process staged (no nonce), or
that it is owner-owned. A race between the stage-write and the elevated read, or a crafted
invocation, lets an attacker control content written with admin rights. `cfg.validate()` only
checks semantic config fields.

**Fix:** in the helper, canonicalise the argument and reject any path outside `data_dir()`;
embed a one-time nonce; verify owner/permissions before reading.

### WEB-3 (High) — SSRF / unbounded outbound fetch reachable unauthenticated
`POST /api/feeds/refresh` triggers four outbound fetches; `POST /api/agent/install` pulls an
arbitrary model **tag from the request body** (`main.rs:1008`) whose only validation is a
denylist (`is_blocked`), not an allowlist. Combined with WEB-1, any local process can drive
repeated outbound fetches and arbitrary model pulls. See also PON-2 (the registry host itself
is operator-controlled).

### WEB-4 (High) — Mutating no-body endpoints rely solely on `host_guard` for CSRF defense
JSON-body routes are protected from cross-origin abuse by the `application/json`
content-type preflight, and DNS-rebinding is blocked by `host_guard` (`main.rs:171–191`). But
the no-body mutators (`/api/runner/launch`, `/api/scan`, `/api/feeds/refresh`,
`/api/agent/clear|hunt`) have **only** `host_guard` between them and a malicious local web
page. That is a single point of failure.

**Fix:** require a custom header / CSRF token on every mutating route, independent of
`host_guard`.

### WEB-5 (Medium) — `host_guard` is dropped entirely on non-loopback bind
Binding `--host 0.0.0.0` disables `host_guard` and emits only a `tracing::warn!`
(`main.rs:1490–1515`) — turning the unauthenticated control plane into a remote one. Refuse to
start on a non-loopback bind unless an auth token is configured.

### WEB-6 (Medium) — Global (not per-client) rate limiter
`RateLimiter` is a single global counter (`main.rs:196–227`): one noisy client — or the
dashboard's own polling — can exhaust the 600/10s budget and deny the operator. Expensive
endpoints (`/api/scan`, `/api/agent/hunt`) are not separately throttled.

### WEB-7 (Medium) — Per-request work amplification (DoS)
`api_scan` walks the whole scan root, runs AI detection over all packages and processes, and
`tokio::spawn`s an unbounded OSV query — per request, with no concurrency cap or dedup
(`main.rs:509–599`). Many concurrent scans/hunts can exhaust the blocking pool and memory.
The 64 KiB body limit bounds request size but not work. **Fix:** debounce scans (single-flight),
cap concurrent hunts.

### WEB-8 (Medium) — `scan_root` canonicalisation silently falls back to the raw path
`args.scan_root.canonicalize().unwrap_or(args.scan_root)` (`main.rs:1401`). Not a remote
vector (no endpoint takes a file path), but symlink/relative components in the operator-supplied
root go unresolved.

**Note (verified good):** the dashboard escapes untrusted fields via `esc()` (`dashboard.html:1274`)
at every `innerHTML` sink (alerts, connections, events). The CSP `'unsafe-inline'` for scripts
(`main.rs:138–144`) is a defense-in-depth gap, not a live XSS hole.

---

## 3. legion-core — scanner / YARA / feeds / threat-intel

### CORE-1 (High) — Unbounded response bodies on every network fetch
No fetch caps the response body; each reads the whole thing into memory:
`feeds.rs:133,146`, `threat_intel.rs:191,294,387`, `yara.rs:253`. The only bound is the
timeout, which does not bound size. A malicious/compromised feed can exhaust memory.
**Fix:** stream with a max-bytes ceiling or check `Content-Length` and reject oversized bodies.

### CORE-2 (High) — Unbounded recursion in the YARA hex matcher → stack overflow
`hex_match_at` (`yara.rs:617–645`) recurses one frame per token, with the `Jump` arm recursing
inside a loop, and `count_hex` restarts the match at **every** offset. A remotely-fetched rule
with chained open-ended jumps (`{ 90 [0-] 90 [0-] 90 … }`) drives both a stack-overflow abort
and exponential blowup. Rule compilation validates syntax but does not execute the matcher, so
a pathological pattern passes the `update_rules` validation and only explodes at scan time.
**Fix:** make the matcher iterative with a bounded jump budget and a per-file scan deadline.

### CORE-3 (High) — Remote feeds are trusted without integrity verification
No signature/checksum on any feed (CISA KEV, ThreatFox, cyber events, the YARA rules repo).
Free-form strings from the feed (`ThreatFoxIoc.ioc/malware/threat_type`,
`threat_intel.rs:393–401`) are stored and surfaced as alerts; a compromised feed can poison the
baseline, flood alerts (fatigue), or suppress detection. For a tool whose trust anchor *is*
these feeds, this is the structural weak point. **Fix:** pin/verify provenance and validate
field shapes (IP parses, confidence ≤ 100).

### CORE-4 (Medium) — Package scanner follows symlinks and is unbounded
`scanner.rs:218–256` uses `path.is_dir()` (follows symlinks) with no depth/file-count cap — a
symlink loop or out-of-root symlink causes infinite recursion / scanning outside root. The
YARA walker does this correctly (`symlink_metadata` + `max_files`, `yara.rs:468–474`); the two
walkers should be consolidated.

### CORE-5 (Medium) — Lockfiles read fully into memory unbounded
`scan_cargo_lock`/`scan_npm_lock` (`scanner.rs:75,115`) `read_to_string` with no size check; the
npm path additionally parses the whole file as `serde_json::Value`. A hostile repo under the
scan root can plant a multi-GB lockfile.

### CORE-6 (Medium) — `expand_env` can panic on multi-byte UTF-8 scan paths
`yara.rs:314–353` mixes byte indexing with `&str` slicing; a non-ASCII byte near a `%VAR%`/`${VAR}`
delimiter can slice off a char boundary → panic. Input is local config, so lower severity.

### CORE-7 (Medium) — `parse_number_with_unit` integer overflow from a malicious rule
`Ok(n * m)` (`yara.rs:1421–1441`) with attacker-controlled `n` and `m` up to `1024³` panics in
debug / wraps in release. **Fix:** `checked_mul`/`saturating_mul`.

### CORE-8 (Medium) — TOCTOU in `scan_file`
`metadata()` size-check then a separate `fs::read` (`yara.rs:427–439`); the file can be swapped
between the two, bypassing the size guard. **Fix:** open once, `fstat` the handle, bounded read.

### CORE-9 (Medium) — External tools resolved via `PATH`
`pip`/`pip3` (`scanner.rs:159`), `ss`/`netstat`/`journalctl`/`docker`/`powershell` (`telemetry.rs`),
and the elevation/privilege helpers `id`/`net`/`sudo`/`pkexec` (`privilege.rs`) are all invoked by
bare name. In an environment with an attacker-influenced `PATH`, a planted binary runs — and for
the privilege helpers that means the *elevation decision itself* can be subverted. Where feasible
use absolute paths or validate the resolved binary.

**Verified good in core:** SQL is fully parameterised (`db.rs`, rusqlite `params!`) — no injection;
the DB dir/file are hardened to `0700/0600` on Unix (`lib.rs:47–70`); all feed URLs are HTTPS and
no cert validation is ever disabled; regex rule bodies are deliberately compiled to `Matcher::Never`
so attacker regex cannot run; `runner.rs` uses only static command arrays (no interpolation).

---

## 4. legion-poncho — the local-LLM agent

PONCHO is genuinely **read-only** with respect to the host: it does not shell out on untrusted
input, does not eval/exec model output, and does not run downloaded code. The risk is in the
**model supply chain** and **policy enforcement**.

### PON-1 (Critical) — No integrity verification on model downloads
`install_model` (`model_registry.rs:213–233`) POSTs `{"name": tag}` to `{ollama_host}/api/pull`
and treats any 2xx as success — no hash pinning, no signature, no digest allowlist. The
`ModelInfo.digest` field is displayed but never verified. A spoofed/compromised registry can
deliver an arbitrary model (with an arbitrary embedded SYSTEM prompt) that PONCHO then runs as
its "blue-team hunter." **Fix:** verify `digest` from `/api/show` against an allowlist before a
model is usable.

### PON-2 (Critical) — `ollama_host` is operator-controlled, unvalidated; run path never re-checks the block
`ollama_host` (`config.rs:8`) defaults to plaintext `http://localhost:11434` but is freely
settable via `POST /api/agent/config` with no scheme/host validation. Pointing it at
`http(s)://attacker/…` makes every model call hit attacker infrastructure (SSRF) **and exfiltrates
the full knowledge-base system prompt** — alerts, connections, events — on every chat. Compounding
this, the chat/hunt path (`chat.rs:218`) runs `cfg.model` directly and **never calls
`is_blocked`/`validate`** — enforcement exists only at save and install time. **Fix:** allowlist
the host (scheme + host), default-deny non-local, and re-check the policy on the execution path.

### PON-3 (High) — DeepSeek block is shallow substring matching, trivially bypassed
`is_blocked` (`model_registry.rs:138`) does `tag.to_lowercase().contains("deepseek")`. Case is
handled, but it is defeated by a registry/mirror prefix (`hf.co/u/ds-r1:q4`), a local rename
(`ollama cp deepseek-r1:7b ds:7b`), or homoglyphs (`deepseеk` with a Cyrillic е). It is a **label
filter, not a security control**; the README's "blocked by policy" claim overstates the guarantee.
**Fix:** block by model identity (digest deny-list / strict approved-tag allowlist enforced at run
time), and soften the README claim.

### PON-4 (Medium) — Weak `scan_model` heuristic + prompt-injection surface
`scan_model` (`model_registry.rs:277–309`) is literal substring matching on the modelfile,
trivially evaded, and reports `clean:true` when the manifest is empty/unparseable
(false safety). Separately, the system prompt is built from live attacker-influenceable data
(alert details, connection strings, container names, `knowledge.rs:115–308`) with only partial
truncation. Because PONCHO has no tools/write access, the worst case is **poisoned analysis output**
(false negatives in a security tool), not RCE — hence Medium. **Fix:** treat `scan_model` as
advisory; never report clean on an empty manifest; delimit/escape injected context.

**Verified good in poncho:** no command/code execution from model output anywhere; rule
evaluation (`rules.rs`) and `mythos.rs` are pure data classification; rule/config paths join
fixed filenames under a caller-supplied dir (no traversal); config save hardens perms; search is
keyless and hardcoded to one endpoint (no SSRF, no secrets).

---

## 5. Native C agent (`agents/`)

Small codebase (~530 lines across `agent.c`, `agent.h`, `test_agent.c`). One-shot CLI that prints
telemetry JSON; **no network listener, no IPC server, no setuid, no privilege management**. No
`strcpy`/`strcat`/`sprintf`/`gets`; `sscanf` uses width limits; all format strings are literals;
the single malloc is checked. No critical memory-safety or injection bugs found.

### CAGENT-1 (Medium→High) — Build enables almost no exploit mitigations
`agents/Makefile:5` `CFLAGS ?= -O2 -Wall -Wextra -std=gnu11`. Missing: `-D_FORTIFY_SOURCE=2`,
`-fstack-protector-strong`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-Wformat-security`; Windows side
missing `/GS /guard:cf /DYNAMICBASE /NXCOMPAT`. The `?=` also lets the environment strip `-Wall`.
This is the single highest-value fix for the C agent. **Add a non-overridable hardening append.**

Lesser C findings: macOS `popen("netstat … | grep …")` runs `/bin/sh` and resolves tools via
`PATH` (fixed literal, so no injection today, but PATH-sensitive); several macOS syscall return
values are unchecked, feeding stack garbage into telemetry on failure; `legion_collect` always
returns 0 even on failure (contract says `-1`). **Build note:** `make test` references a
non-existent `agents/tests/Makefile` and will fail.

---

## 6. Build, CI & supply chain

- **CI** (`.github/workflows/ci.yml` + `cargo-deny`) and `deny.toml` are well-configured:
  crates.io-only sources, git/unknown-registry denied (anti dependency-confusion), yanked = deny.
  Two tracked, documented advisory exceptions (RUSTSEC-2024-0436 paste, RUSTSEC-2026-0002 lru),
  both transitive via ratatui with no reachable fix — reasonable.
- **Dependencies** are current: axum 0.7.9, rustls 0.23, reqwest 0.12 (rustls-tls, no OpenSSL),
  tokio 1.52, rusqlite 0.31 (bundled). No `danger_accept_invalid_certs` anywhere in the tree.
- `cargo-audit`/`cargo-deny` are not installed in this environment, so the live advisory DB was
  not queried here; CI runs cargo-deny, which covers it.

---

## 7. Low-severity / code-quality backlog

- `lock().unwrap()` throughout `legion-web` — a panic while holding a lock poisons it and turns
  subsequent handlers into panics that bypass `AppError`. Prefer `parking_lot` or
  `unwrap_or_else(|e| e.into_inner())`.
- Several agent handlers return `e.to_string()` directly to the client (`main.rs:1014,1041,1061,…`),
  leaking paths/internals — inconsistent with the otherwise-careful generic error response.
- `quarantine::remediation_cmd` interpolates an attacker-controllable package `name` into shell
  command strings shown to the operator (`quarantine.rs:78`) — copy-pasting a crafted suggestion
  (`name = "foo; rm -rf ~"`) injects into the operator's shell. Escape or display non-executable.
- `harden_file`/`harden_dir` are Unix-only no-ops; on Windows the DB relies on the profile ACL.
  `data_dir()` falls back to CWD if `APPDATA`/`HOME` is unset.
- `.expect()` on HTTP client build (`feeds.rs:154`, `model_registry.rs:130`, `chat.rs:81`) panics
  instead of propagating.
- Detection-fidelity smells: `osv_ecosystem` defaults unknown ecosystems to `"PyPI"`
  (`threat_intel.rs:100`); `severity_from_cvss` infers severity by substring (`threat_intel.rs:110`);
  IPv6 IOCs silently never match (`threat_intel.rs:419`); `search.rs` percent-decode is byte-as-char
  (mojibake). Duplicated walker logic across `scanner.rs`/`yara.rs`.

---

## 8. Prioritised remediation order

1. **WEB-1** — add a session bearer token to `/api/*` (closes the biggest hole and most of WEB-3/4).
2. **PON-1 / PON-2** — verify model digests; allowlist + TLS-gate `ollama_host`; re-check policy on
   the run path.
3. **CORE-1 / CORE-2 / CORE-3** — cap response bodies; make the hex matcher iterative + add a scan
   deadline; verify feed integrity.
4. **CAGENT-1** — add C hardening flags (non-overridable).
5. **WEB-2** — nonce + path-confinement on the elevated config helper.
6. **PON-3** — identity-based DeepSeek blocking; soften the README claim.
7. Medium DoS/robustness (WEB-5…8, CORE-4…8) and the §7 quality backlog.

*No source files were modified by this audit. All findings include file:line anchors for triage.*
