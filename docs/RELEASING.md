# Releasing Legion

`Cargo.toml` `[workspace.package].version` is the **single source of truth** for
the release version. A release is cut by bumping that version and merging to
`main` — nothing is tagged or published by hand in the normal flow.

## Cut a release (normal flow)

1. **Bump the version.** Edit `[workspace.package].version` in `Cargo.toml` to the
   next version (e.g. `1.1.35` → `1.1.36`), then sync the lockfile:

   ```sh
   cargo check --workspace   # updates Cargo.lock's workspace-crate versions
   ```

2. **Stamp the changelog.** Move the `## [Unreleased]` entries under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md`, leaving a fresh empty
   `## [Unreleased]`.

3. **Open a PR and merge it to `main`.** On merge, the
   [`Release on main`](../.github/workflows/release-on-main.yml) workflow runs and:
   - validates every shipping target (`fmt` / `clippy -D warnings` / `test` /
     release build on Linux **and** Windows),
   - **only if the tag `vX.Y.Z` does not already exist**, creates the tag and
     publishes a GitHub Release with the built assets.

That's it — the tag and Release are created for you.

## The one gotcha: the version must be *new*

The publish step is gated on `needs.version.outputs.exists == 'false'` — i.e. it
publishes **only when the tag derived from `Cargo.toml` does not yet exist**. If
you merge to `main` without bumping the version, the workflow still builds and
tests everything (it's the validation gate on every push), but the publish job is
**skipped** and no Release is cut. This is by design, but it means:

> **Every release needs its own version bump.** After a release, `Cargo.toml`
> already holds the just-published version, so the *next* merge to `main` will
> skip publishing until you bump again.

## Release assets

Each published Release carries (built by CI):

- `legion-<tag>-x86_64-unknown-linux-musl.tar.gz` (+ `.sha256`) — Linux
- `legion-<tag>-x86_64-pc-windows-msvc.tar.gz` (+ `.sha256`) — Windows
- `Legion-<tag>-x86_64.AppImage` (+ `.sha256`) — Linux desktop
- `legion-<tag>-sbom.cdx.json` — CycloneDX SBOM

Build provenance is attested during publish.

## Manual / hotfix path (tags)

The [`Release`](../.github/workflows/release.yml) workflow is the alternative: it
triggers on pushing a `vX.Y.Z` tag and builds + publishes, with a step that
**verifies the pushed tag matches `Cargo.toml`'s version**. Use it only for a
release cut directly from a tag (e.g. a hotfix off a non-`main` ref). It does not
double-fire with `release-on-main`: the tag that `release-on-main` pushes is
created with the Actions bot token, and `GITHUB_TOKEN`-pushed tags do not trigger
other workflows.

## Versioning note

The published line is `v1.x.y`. Keep bumping forward from the latest tag — do not
reuse an existing tag (see the gotcha above). A stray early `v0.1.0` tag exists in
history; ignore it.
