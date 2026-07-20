# Packaging and release

**Status: Real.** `scripts/build-appimage.sh`, `.github/workflows/release*.yml`

| Platform | Deliverable |
|---|---|
| Linux x86_64 | AppImage (static type2 runtime, no `libfuse2` needed) + `.tar.gz` |
| Windows x86_64 | `.zip` + winget manifest set |

The Linux archive **contains the AppImage** alongside the binary, README and
LICENSE — someone who downloads the archive should get the double-clickable app,
not a bare binary they must know how to run.

Winget manifests are generated at release time from the artifact's real SHA-256.
No MSI: unsigned it buys a scarier prompt and no real trust, and `legion-web`
already self-installs (`legion-web install` copies the binary, sets PATH and
writes a Start-Menu shortcut).

## Verify

```bash
bash scripts/build-appimage.sh target/release/legion-web dist/Legion-x86_64.AppImage
./dist/Legion-x86_64.AppImage --appimage-extract >/dev/null
sha256sum squashfs-root/usr/bin/legion-web target/release/legion-web   # must match
```

## Limits

- The winget manifests are **untested until a real tag is cut**. The
  substitution logic is verified; the generated manifest has never been fed to
  winget.
- No macOS build.

## Fixed here, worth knowing

`build-appimage.sh` wrote `$OUT` in place, which fails with "Text file busy"
whenever the previous AppImage is running (a FUSE-mounted AppImage holds its own
file open) — and **appimagetool exits 0 anyway**:

```
Could not open regular file for writing as destination: Text file busy
mksquashfs exited with code 1
sfs_mksquashfs error
exit: 0
```

Every rebuild silently left the **old** AppImage on disk while reporting
success. That is how a fix gets committed, "rebuilt", verified in the binary,
and still never reaches the running app. It now packs to a temp file and
`mv`s it into place (`rename(2)` over a running executable is permitted, so it
is atomic and immune to `ETXTBSY`), then checks the artifact rather than
trusting the exit code.
