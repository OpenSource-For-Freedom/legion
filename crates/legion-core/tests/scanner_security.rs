//! Scanner traversal safety (audit CORE-4): the package walker must not follow
//! symlinks (which could escape the scan root or form an unbounded loop).

use legion_core::scanner::PackageScanner;

#[test]
#[cfg(unix)]
fn scan_does_not_follow_symlink_loops() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let sub = root.path().join("project");
    std::fs::create_dir(&sub).unwrap();

    // A real lockfile so the scan has something legitimate to find.
    std::fs::write(
        sub.join("Cargo.lock"),
        "# This file is automatically @generated\nversion = 3\n",
    )
    .unwrap();

    // A symlink that points back at the root would loop forever if followed.
    symlink(root.path(), sub.join("loop")).unwrap();

    // Must return (bounded) rather than recurse infinitely / overflow the stack.
    // Reaching the assertion at all proves the walk terminated.
    let result = PackageScanner::scan(root.path());
    assert!(
        result.packages.len() < 1000,
        "symlink loop produced a traversal explosion ({} packages)",
        result.packages.len()
    );
}

#[test]
#[cfg(unix)]
fn scan_does_not_escape_root_via_symlinked_dir() {
    use std::os::unix::fs::symlink;

    // `outside` holds a lockfile the scan must NOT reach through a symlink.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("Cargo.lock"),
        "# generated\nversion = 3\n[[package]]\nname = \"escapee\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("linked")).unwrap();

    let result = PackageScanner::scan(root.path());
    let leaked = result.packages.iter().any(|p| p.name == "escapee");
    assert!(!leaked, "scan followed a symlink outside the scan root");
}
