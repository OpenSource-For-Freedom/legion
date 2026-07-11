# Legion — Cross-Platform App Delivery + HARDN Coexistence Sprint Plan

**Date:** 2026-07-10
**Owner:** Legion maintainers
**Goal:** Ship Legion as a first-class installable **app on Windows and Linux**. On Linux,
Legion runs **alongside HARDN-XDR with zero functional or resource overlap** — HARDN hardens
and collects, Legion is the SIEM/SOAR dashboard + Ares analyst over that data.

> Companion doc: security remediations from the 2026-07 full audit (in progress) feed into
> Sprint 0/3 as marked. See `docs/SECURITY-AUDIT-2026-07.md` when published.

---

## 1. North Star

- **One product, two OSes.** Windows and Linux each get a real, signed, double-click app —
  not a `cargo run`. Same dashboard, same Ares analyst, same local-only guarantee.
- **On Linux, Legion is a good HARDN citizen.** The two are complementary layers of one XDR
  stack from the same org. They must never fight over ports, services, files, or duties.

```
        PREVENT / ENFORCE / COLLECT              DETECT / EXPLAIN / RESPOND
   ┌──────────────────────────────┐        ┌──────────────────────────────┐
   │           HARDN-XDR           │  data  │            LEGION            │
   │  auditd, sysctl, sshd, apt,   │ ─────▶ │  dashboard :31xx, Ares LLM,  │
   │  fail2ban, AppArmor, LEGION   │ (hardn │  SIEM/SOAR alerts, threat    │
   │  monitoring loop (hardn.svc)  │ source)│  intel, package/IP scans     │
   └──────────────────────────────┘        └──────────────────────────────┘
```

---

## 2. The No-Overlap Contract (HARDN ↔ Legion on Linux)

This is the binding spec Sprint 1 implements and Sprint 4 tests.

| Domain | HARDN owns | Legion owns | Rule |
|---|---|---|---|
| **Host hardening** | auditd, AIDE, sysctl, sshd, fail2ban, firejail, modprobe, apt, sudoers, logrotate, rsyslog (all under `/etc/hardn` + `/etc/*/*hardn*`) | nothing here | Legion **never writes** HARDN's hardening config. It observes only. |
| **Collection daemon** | `hardn.service` runs the LEGION monitoring loop; `legion-daemon.service` ships disabled | dashboard + analyst UI | When HARDN present, Legion runs **companion mode**: it does **not** start its own collector. |
| **Config root** | `/etc/hardn` | `/etc/legion` | Never cross-write. |
| **Data dir** | HARDN's stores | `/var/lib/legion`, `~/.cache/legion` | Separate trees; assert in test. |
| **Ports** | API `8000`, **Grafana `3000`**, Prometheus `9090`, syslog | dashboard **`3100`** (auto-negotiated) | Legion **moves off 3000** and auto-picks a free port. |
| **Telemetry** | emits `hardn*`-sourced events | ingests them (seam exists: `telemetry.rs:219`) | Legion consumes; never re-collects the same signal. |
| **SOAR / response** | hardening remediations | alert triage + Ares-suggested actions | Coordinate so a finding isn't double-remediated. |
| **Package mgmt** | apt hardening | Cargo/npm/pip **scanning** only | No overlap by nature. |

### Presence detection → runtime mode
Legion picks its mode at startup:

- **Companion mode** (HARDN detected — `/etc/hardn` exists, `hardn.service` active, or `hardn` on PATH):
  collector **off**, dashboard reads HARDN's telemetry via the `hardn` source seam, dashboard
  shows a "HARDN: enforcing" status tile, port auto-negotiated off 3000.
- **Standalone mode** (no HARDN): full Legion collector + dashboard, current behavior.

---

## 3. Sprints

Cadence: **2-week sprints**, Sprint 0 is a 1-week runway. Sizing is indicative; reorder P0 audit
fixes ahead of features if the audit surfaces Criticals.

### Sprint 0 — Foundations & decisions (1 wk)
- [ ] **Ratify this contract** with HARDN maintainers; lock service names, ports, paths.
- [ ] **Configurable dashboard port** + auto-pick-free-port; change default `3000 → 3100`.
      (`legion-web` bind + `packaging/appimage/AppRun` + `install.sh` + desktop `Comment=`.)
- [ ] **Mode abstraction:** factor collection/enforcement behind a trait so
      `standalone | companion | windows` back-ends plug in without touching the web layer.
- [ ] **CI matrix skeleton:** add Windows and Linux(`.deb`) build jobs (stubbed).
- [ ] **Audit P0 intake:** slot any Critical/High from the running security audit here.
- **DoD:** dashboard starts on a negotiated port; mode trait merged with unit tests; CI matrix green (stubs).

### Sprint 1 — Linux app + HARDN coexistence core (2 wk)
- [ ] **HARDN presence-detection module** (file + systemd + PATH probes; cached, cheap).
- [ ] **Companion mode:** suppress Legion's own collector when HARDN present; ingest HARDN
      telemetry via the existing `hardn`-source seam; add **"HARDN status" dashboard tile**.
- [ ] **Namespace guard test:** prove Legion writes only `/etc/legion`, `/var/lib/legion`,
      `~/.cache/legion` — never any HARDN path. Fail CI if it does.
- [ ] **`.deb` package** (Debian target — matches HARDN's platform): systemd **user** unit
      named `legion-web.service` (distinct from `hardn.service`/`legion-daemon.service`);
      `postinst` refuses to enable a collector if `hardn.service` owns the LEGION loop.
- [ ] Port-negotiation documented in README + install output.
- **DoD:** on a HARDN box, `apt install ./legion.deb` → dashboard on 3100, no second collector,
      no file/port/service collision; on a clean box, standalone mode unchanged.

### Installer language decision (2026-07)
The parallel PowerShell (`install.ps1`, `restart.ps1`) + bash (`install.sh`) installers are being
replaced by **one Rust implementation** shipped inside `legion-web` — no interpreter, no duplicated
logic, code-signable, reusing the crate's `privilege`/`data_dir`/`harden_dir`. A prototype
`legion-web install` + `legion-web restart` (`crates/legion-web/src/install.rs`) is landed and
Linux-verified (binary placement, `0700` data dir, PATH, `.desktop`, idempotent). Remaining: Windows
path (`setx`→`winreg`, Start-menu `.lnk`), then retire the shell installers and update the README.
Native packages (MSI/.deb) below wrap this subcommand.

### Sprint 2 — Windows app (2 wk)
- [ ] **Windows host:** tray app **or** Windows Service wrapping `legion-web` (recommend: tray app
      that supervises the server; auto-opens browser). Per-user data at `%LOCALAPPDATA%\Legion`.
- [ ] **Installer:** MSI via `cargo-wix`/WiX (or NSIS EXE); Start-menu + optional startup entry.
- [ ] **Windows Event Log ingestion** wired end-to-end (README already advertises it) with
      `windows-eventlog` telemetry source tag.
- [ ] **Loopback-only firewall scoping**; confirm no inbound exposure.
- [ ] **Authenticode code-signing** in CI; ship a **signed** installer.
- **DoD:** signed MSI installs on Win10/11, dashboard opens, Event Log alerts appear, uninstall is clean.

### Sprint 3 — Packaging, provenance & release hardening (2 wk)  *(audit-driven)*
- [ ] **SHA-pin all CI actions**; least-privilege `permissions:` per job. *(audit finding)*
- [ ] **Release signing** (cosign/minisign) + published **checksums** + **SBOM**. *(audit finding)*
- [ ] **Fix repo-identity mismatch** — `Cargo.toml repository` vs `OpenSource-For-Freedom/legion`. *(audit finding)*
- [ ] Linux release matrix ships **AppImage + .deb**; evaluate **Flatpak**.
- [ ] Version-check / update-nag (no silent auto-update on a security tool).
- **DoD:** every released artifact is signed, checksummed, SBOM-attached, from a pinned pipeline.

### Sprint 4 — Integration, E2E & docs (2 wk)
- [ ] **E2E matrix:** (a) Legion standalone/Linux, (b) Legion + HARDN companion, (c) Windows.
- [ ] **Coexistence integration test in CI:** stand up a HARDN service stub; assert **no** port,
      daemon, or file collision and that companion mode engages.
- [ ] **Docs:** "Running Legion alongside HARDN" + Windows install guide + updated README matrix.
- [ ] **Audit remediation verification** pass (close out the 2026-07 audit).
- **DoD:** all three E2E lanes green; coexistence test gates merges; docs published.

---

## 4. Cross-cutting Definition of Done
- No breaking changes to the standalone experience; full test suite stays green.
- Legion never touches a HARDN-owned path, port, or service on any code path (asserted by test).
- Every install path (AppImage, .deb, MSI) yields the **same** local-only, loopback-bound dashboard.
- All release artifacts signed + checksummed + SBOM.

## 5. Key risks / decisions to confirm
1. **Companion-mode depth** *(decision):* dashboard-only over HARDN's data (recommended) vs.
   namespaced parallel collector. Recommendation avoids all duplication.
2. **Windows form factor** *(decision):* tray-app supervisor (recommended) vs. true Windows Service.
3. **Port default:** `3100` proposed — confirm it's clear of other local tooling.
4. **HARDN's embedded LEGION daemon vs. standalone Legion versioning** — keep the shared daemon
   code in sync, or formally split. Needs HARDN-maintainer alignment (Sprint 0).
