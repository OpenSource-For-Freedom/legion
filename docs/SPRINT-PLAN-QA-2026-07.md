# Legion — Live System / Security / Feature Test + QA Sprint (2026-07)

**Method:** Release build → local install via `legion-web install` → live instance on
`127.0.0.1:3000` → every endpoint and security behavior exercised against the running server.
**Result:** core is solid and the 2026-07 security fixes all hold live. Found **3 functional bugs**,
**1 high-value gap**, and several UX/perf improvements. This doc is the findings catalog + the sprint
that fixes them.

---

## 1. What passed live (verified against the running server)

| Area | Result |
|---|---|
| Deploy: `legion-web install` | ✅ binary placed, data dir `0700`, PATH, `.desktop`, idempotent |
| H1 same-user guard | ✅ `GET /` served to same-user; token cookie vended |
| Auth gate | ✅ `/api/*` 401 without token, 200 with |
| M5 CSP split | ✅ `/` → `script-src 'unsafe-inline'`; `/api/*` → `script-src 'none'` |
| Security headers | ✅ XFO=DENY, nosniff, no-referrer, COOP/CORP present |
| L2 `/api/open` confinement | ✅ `/etc/passwd` refused + audit-logged `alert.open.denied`; scan-root path opened |
| H2 namespace | ✅ `/api/runner/commands` shows `OpenSource-For-Freedom/Legion_runner` |
| Error hygiene | ✅ 500s return generic body, no internal path leak |
| Telemetry / feeds / scan | ✅ real CPU/mem, live connections, KEV pull (1637), 13 440 cargo pkgs, 86 OSV, 40 YARA |
| Drift detection | ✅ produced a real "process-count spike" alert |
| Model-absent handling (chat) | ✅ graceful "could not reach a language model" |

---

## 2. Findings

### P1 — bugs / high-value
- **F1 — `/api/runner/doctor` returns 500 when the runner isn't installed.** `RunnerManager::doctor()`
  execs `legionr` directly ([runner.rs:72](../crates/legion-core/src/runner.rs#L72)); the binary is
  absent → `os error 2` → generic 500. `runner_status()` already gates on `legionr_available` — doctor
  must do the same and return a clean "runner not installed" report.
- **F2 — OSV vulnerabilities and YARA matches never become alerts.** A scan found **86 known-vulnerable
  packages + 40 YARA matches** but `alerts_generated: 0`; OSV is saved via `save_osv_vulns`
  ([main.rs:843](../crates/legion-web/src/main.rs#L843)), not `save_alerts`. The primary Alerts view —
  the whole point of a SIEM — misses the most actionable findings. Surface them as `Package`/`Yara`
  alerts (deduped, severity from CVSS / rule meta).
- **F3 — Scans are synchronous and block the HTTP request.** `POST /api/scan` took ~18 s bounded to one
  tree and **minutes** at the `scan_all_drives:true` default (253 % CPU, whole-disk walk). No progress,
  no cancel; a browser fetch just hangs. Move scans to a background job with a `GET /api/scan/status`
  poll (job id, phase, counts) and return `202 Accepted` immediately.

### P2 — correctness / UX
- **F4 — Fallback model collapses to the primary.** With `model_auto:true`, boot-time hardware
  selection sets `model` and `fallback_model` to the same tier (live log: fallback == primary), so the
  fallback gives no resilience. Select a genuinely distinct fallback (smaller tier), or drop the
  fallback concept when they'd be equal.
- **F5 — `/api/agent/hunt` takes ~20 s+ to fail when the model is unreachable.** Long per-model timeout ×
  primary+fallback. Tighten the connect/read timeout and short-circuit when the runtime probe is already
  known-offline; the chat path already messages this instantly.
- **F6 — Misleading "could not reach a language model" when the server answered.** A server *was* on
  `:8080` and returned `400 Bad Request`; the user-facing message says "could not reach," masking a
  request-format/compat problem. Distinguish "unreachable" from "reached but errored (status N)".

### P1 — self-detection false positives  — ✅ FIXED
- **F9 — Legion flagged its own files (and the vendored toolchain) as rootkits/miners/reverse-shells.**
  A security tool's signature files contain every malware indicator by design, so scanning them
  self-matches; a compiler/libc trips behavioural rules on normal linker symbols. Live scan of the repo
  produced Critical "rootkit" alerts on `ares.rs`/`alerts.rs`, "crypto miner" on the zig/mingw toolchain,
  and every rule matching `rules-feed/linux.yar`. **Fixed:** self-exclude Legion's own binary + data +
  rule dirs; skip `.yar`/`.yara` files and the `rules-feed`/`agents`/`.local-tools` dirs; tightened
  `Linux_Rootkit_Indicators` (needs a rootkit-specific string) and `Linux_Fileless_Exec` (`memfd_create`
  needs corroboration). **Result: YARA false positives 40 → 11 (−72%), all signature-file and toolchain
  self-matches gone.** The residual 11 are Legion's *own source `.rs` files*, matched only because the
  scan target was the Legion source repo (its rootkit-detection code literally contains rootkit
  strings) — not a real-world scan target. Note: `install.sh` "curl|sh" / `.bashrc` hits are arguably
  *true* positives (it does exactly that).

### P3 — polish
- **F7 — `/api/open` denial returns HTTP 500,** not `403`. Confinement works (audit-logged) but the
  status is wrong; return `403 Forbidden` with a clear body.
- **F8 — `scan_all_drives:true` default is very aggressive** (whole disk, 200 k files) on first run.
  Consider defaulting to key paths with an explicit "full-disk scan" opt-in, or lazy/scheduled full scans.

### Carried over from the 2026-07 audit (still open, unchanged)
- CSP: drop dashboard `script-src 'unsafe-inline'` (needs ~54 inline handlers → delegated listeners).
- Release: detached artifact signing + installer signature verification (cosign vs minisign decision).
- Installer: Windows path (`winreg` PATH + `.lnk`) then retire the shell installers.
- H1 follow-up: IPv6 / non-Linux peer-cred (currently fail-open unless `LEGION_STRICT_PEERCRED`).

---

## 3. Sprint

### Sprint A — bugs & alert value (this deployment)
- [ ] **F1** doctor: gate on `legionr_available`, return a structured "not installed" report.
- [ ] **F7** `/api/open`: return `403` on the confinement denial.
- [ ] **F2** surface OSV + YARA findings as deduped alerts (severity from CVSS / rule meta).
- [ ] **F6** distinguish "unreachable" vs "reached-but-errored" in the model failure message.
- **DoD:** each re-tested against the live server; suite + clippy + fmt green.

### Sprint B — scan async + model resilience
- [ ] **F3** background scan job + `202` + `/api/scan/status` polling; dashboard progress.
- [ ] **F5** tighten hunt timeouts + offline short-circuit.
- [ ] **F4** distinct fallback tier (or drop when equal).
- [ ] **F8** reconsider `scan_all_drives` default / add scheduled full scans.

### Sprint C — audit remainders
- [ ] CSP inline-handler refactor (browser-verified) → drop `unsafe-inline`.
- [ ] Artifact signing + installer signature verification.
- [ ] Windows installer path (`winreg` + `.lnk`), retire shell installers.
- [ ] IPv6 / non-Linux peer-cred lookup.
