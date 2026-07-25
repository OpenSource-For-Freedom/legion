# Package scanning

**Status: Real.** `crates/legion-core/src/scanner.rs`

Finds what is actually installed so everything downstream has something concrete
to correlate against.

## What it does

| Ecosystem | Source | Method |
|---|---|---|
| cargo | `Cargo.lock` | Hand-rolled line parser, no `toml` dependency |
| npm | `package-lock.json` | v1, v2 and v3 lockfile formats |
| pip | `pip list --format=json` | Subprocess, system-wide |

Three entry points: `scan(root)`, `scan_roots(&[..])`, and `scan_system()` which
walks every fixed drive. The walk is depth-capped at 64, never follows symlinks,
and skips the deny-lists in `fsroots.rs` (`/proc`, `/sys`, `node_modules`,
`.git`, `target`, Windows system trees, and Legion's own directories).

## Verify

```bash
cargo test -p legion-core --lib scanner
```

Measured on a developer workstation: `scan_system()` takes **~7.5s** and returns
about 9,800 packages. It is not the slow part of a scan — YARA is.

## Limits

- **`node_modules` is excluded from the walk.** A package installed but absent
  from a lockfile is invisible. Detection is lockfile-driven by design.
- **pip is system-wide regardless of scan root.** `scan_roots` always appends
  `pip list`, so pip results are never scoped to a directory.
- **Install scripts are not inspected.** `scan_npm_lock` reads `version` only —
  not `scripts`, `hasInstallScript`, `resolved` or `integrity`. `package.json`
  is never opened.
- **No lockfile diffing.** A version bump or a swapped `resolved` URL (the
  dependency-confusion shape) produces no signal on its own.

## Fixed here, worth knowing

`trim_start_matches("node_modules/")` stripped only the **leading** segment, so
a transitive key `node_modules/foo/node_modules/evil` became the name
`foo/node_modules/evil` and matched nothing. **Every transitive dependency was
invisible to every downstream check** — the most common real supply-chain shape.
The name is what follows the *last* `node_modules/`. v1 lockfiles had the mirror
bug: nested `dependencies` were never walked.
