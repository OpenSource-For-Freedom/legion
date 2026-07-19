//! Scanner traversal safety (audit CORE-4): the package walker must not follow
//! links (which could escape the scan root or form an unbounded loop).
//!
//! These ran only on Unix, so `cargo test` on windows-latest compiled them to
//! **zero tests** and reported green — a comforting result that asserted nothing.
//! Windows has the same attack surface through directory junctions and other
//! reparse points, which `PackageScanner::scan` walks over just the same, so the
//! cases are exercised on both platforms now.

use legion_core::scanner::PackageScanner;
use std::path::Path;

/// Create a directory link at `link` pointing to `target`.
///
/// Returns false when the platform will not let us make one, in which case the
/// caller skips rather than fails: an environment that cannot build the fixture
/// tells us nothing about the scanner.
#[cfg(unix)]
fn link_dir(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

/// Windows: use a **junction** rather than `symlink_dir`, which requires
/// Developer Mode or `SeCreateSymbolicLinkPrivilege` and so would silently skip
/// on a stock CI runner. A junction needs no privilege and is the reparse point
/// an attacker can actually plant.
#[cfg(windows)]
fn link_dir(target: &Path, link: &Path) -> bool {
    std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.display().to_string(),
            &target.display().to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        && link.exists()
}

#[cfg(not(any(unix, windows)))]
fn link_dir(_target: &Path, _link: &Path) -> bool {
    false
}

#[test]
fn scan_does_not_follow_link_loops() {
    let root = tempfile::tempdir().unwrap();
    let sub = root.path().join("project");
    std::fs::create_dir(&sub).unwrap();

    // A real lockfile so the scan has something legitimate to find.
    std::fs::write(
        sub.join("Cargo.lock"),
        "# This file is automatically @generated\nversion = 3\n",
    )
    .unwrap();

    // A link that points back at the root would loop forever if followed.
    if !link_dir(root.path(), &sub.join("loop")) {
        eprintln!("skipping: this platform/session cannot create a directory link");
        return;
    }

    // Must return (bounded) rather than recurse infinitely / overflow the stack.
    // Reaching the assertion at all proves the walk terminated.
    let result = PackageScanner::scan(root.path());
    assert!(
        result.packages.len() < 1000,
        "link loop produced a traversal explosion ({} packages)",
        result.packages.len()
    );
}

#[test]
fn scan_does_not_escape_root_via_linked_dir() {
    // `outside` holds a lockfile the scan must NOT reach through a link.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("Cargo.lock"),
        "# generated\nversion = 3\n[[package]]\nname = \"escapee\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    if !link_dir(outside.path(), &root.path().join("linked")) {
        eprintln!("skipping: this platform/session cannot create a directory link");
        return;
    }

    let result = PackageScanner::scan(root.path());
    let leaked = result.packages.iter().any(|p| p.name == "escapee");
    assert!(
        !leaked,
        "scan followed a directory link outside the scan root"
    );
}
