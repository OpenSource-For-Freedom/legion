# Working on Legion

Read this before changing anything. It is the working guide for the codebase:
what is here, how it is laid out, the rules that are not negotiable, and the
traps that have already cost real time.

Per-feature detail lives in [`docs/specs/`](specs/). Start with
[`specs/README.md`](specs/README.md) for the index.

---

## What Legion is

A local-first SIEM/SOAR console for a developer workstation or a server. It
scans package trees, correlates them against OSV and CISA KEV, runs a YARA
engine, watches for confirmed-malicious dependencies and DPRK workstation
indicators, and carries an on-device AI analyst (ARES).

Everything binds to `127.0.0.1`. The model runs locally. No account, no
telemetry, nothing leaves the host.

## How this project fails

Not crashes. **Confident claims with nothing behind them.** Every serious defect
found in this codebase has been of one shape: a feature that looked finished,
reported success, and did nothing.

Real examples, all fixed, all of which passed review and CI first:

| Looked like | Actually |
|---|---|
| Model staged from Hugging Face, SHA verified | Nothing ever loaded it. Every hunt silently ran `engine-only`. |
| KEV escalation wired and tested | Joined on CVE ids that were always empty, so it could never fire. |
| 153 OSV findings | All `severity: null`, all `cve_ids: []` — the batch API returns IDs only. |
| Posture score 100/A | Medium and Low deducted nothing, so most of the queue was ignored. |
| Package sensor, "zero false positive" | 11 of 34 list entries were opinions; it would page Critical on legitimate software. |
| Windows peer-cred guard | Compared usernames, so `CORP\alice` == `ATTACKER\alice`. Zero tests. |
| AppImage rebuilt | `mksquashfs` failed, appimagetool exited 0, the old file stayed. |

The through-line: **the build succeeded, so the fix was assumed to ship.** It is
not enough to verify the artifact. Verify the running system.

## Non-negotiables

1. **Verify, do not infer.** Read the live resource, count the rows, hit the
   endpoint, check what is actually being served. A green build, a passing test
   and a committed file are all claims.
2. **Say what is not true.** Especially before a demo, especially when it is
   inconvenient. This is a security tool; a false clean bill of health is worse
   than no tool.
3. **No false positives in anything that pages.** A quarantine or a critical
   alert on legitimate software gets the tool uninstalled. When a signal is
   ambiguous, report it as an advisory, not an alarm.
4. **Legion is a background monitor, not the workload.** It must not take the
   machine. See [`specs/resource-budget.md`](specs/resource-budget.md).
5. **Additive changes.** Do not rename fields, change API shapes, or alter
   defaults other code depends on without saying so first.
6. **Commits never mention Claude** and never add `Co-Authored-By`.

## Layout

```
crates/
  legion-core/    detection, storage, feeds, response.  No HTTP, no agent.
  legion-ares/    the AI analyst: model lifecycle, chat, hunt, autonomous loop.
  legion-web/     axum server + the embedded dashboard (single HTML file).
  legion-cli/     headless equivalent of most of the console.
  legion-tui/     terminal alert viewer.
agents/           C agent prototype (not a workspace member) + ARES model manifest.
rules-feed/       YARA rules shipped and updatable.
packaging/        AppImage AppRun/desktop entry, winget manifests.
.legion/          committed CI egress allowlist.
```

`legion-core` must not depend on `legion-web` or `legion-ares`. Detection logic
belongs in core so the CLI, TUI and server all get it.

## The gate

Every one of these before a push. CI runs the same set on ubuntu **and**
windows.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p legion-web
```

**clippy is not installed on the usual dev box.** There is no rustup; Rust is
the distro package. Side-load it without root:

```bash
CL=~/.cache/legion-clippy
mkdir -p $CL && cd $CL
apt-get download rust-1.93-clippy     # NOT rust-clippy, that is a 3.5KB stub
dpkg-deb -x rust-1.93-clippy_*.deb $CL
export PATH="$CL/usr/lib/rust-1.93/bin:$PATH"
```

Skipping clippy locally has cost a red CI run more than once. Windows CI has
also caught two things a Linux-only clippy structurally cannot: dead code behind
a `#[cfg]` that never compiles here, and platform arms that do not exist.

MSRV is **1.87**, enforced by `rust-version` in `Cargo.toml` rather than by
prose. CI runs `stable`, so the MSRV itself is not build-verified.

## Verifying a change actually shipped

This is where this project loses time, so it has its own checklist.

```bash
# 1. Is the binary current?
sha256sum target/release/legion-web

# 2. Is the AppImage payload the same binary?
./dist/Legion-*.AppImage --appimage-extract >/dev/null
sha256sum squashfs-root/usr/bin/legion-web     # must match (1)

# 3. Is the RUNNING app that binary?
sha256sum ~/.cache/legion/legion-web           # AppRun's staged copy

# 4. Is the new code actually being served?
curl -s http://127.0.0.1:3000/ | grep -c 'YOUR_NEW_SYMBOL'
```

Step 4 is the one that matters and the one most often skipped.

Three traps, all of which have bitten:

- **A root-owned `legion-web` survives `pkill`.** Legion self-elevates, so the
  serving process is root's. `sudo pkill -x legion-web` or nothing changes.
- **`AppRun` exits early when a dashboard is already up.** It opens the browser
  and stops — it never refreshes `~/.cache/legion/legion-web`. So relaunching
  over a running instance silently runs the old binary.
- **`pkill -f legion` matches your own shell.** Use `pkill -x`.

## Data locations

| What | Where | Why |
|---|---|---|
| Database, session token, config | `data_dir()` — `~/.local/share/legion` (`%APPDATA%\legion`) | Per-account, follows `HOME`. |
| Model weights, llama-server | `/var/lib/legion` (`%ProgramData%\legion`), falling back to `data_dir()` | Machine-wide: `HOME` becomes `/root` on elevation, and the model is over a gigabyte. |
| AppRun's staged binary | `~/.cache/legion/legion-web` | What actually runs. |

Large artifacts are deliberately **not** passed through `harden_dir` — they are
public, hash-verified downloads, and `0700` would defeat the sharing that is the
point.

## Testing conventions

- Detection logic gets a **negative** test as well as a positive one. "Legit
  package stays silent" is as important as "typosquat fires".
- Platform-specific parsers are written as pure functions over captured output
  so they can be tested on any OS. The Windows peer-cred code shipped broken
  because it was compiled by CI and never executed.
- When a bug is fixed, the test should encode **why it mattered**, not just the
  behaviour. See `osv_findings_without_detail_cannot_drive_kev_or_severity`.
