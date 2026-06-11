use legion_core::runner::{command_plan_for_host, status_for_host, RunnerHost, LEGION_RUNNER_REPO};

#[test]
fn runner_linux_status_is_supported_and_linux_only() {
    let status = status_for_host(RunnerHost::Linux);
    assert!(status.supported);
    assert!(status.linux_only);
    assert_eq!(status.host, RunnerHost::Linux);
    assert_eq!(status.repo_url, LEGION_RUNNER_REPO);
}

#[test]
fn runner_windows_wsl_plan_wraps_commands_for_wsl() {
    let plan = command_plan_for_host(&RunnerHost::WindowsWsl);
    assert!(plan
        .install
        .iter()
        .all(|cmd| cmd.starts_with("wsl -e bash -lc")));
    assert!(plan
        .launch
        .iter()
        .any(|cmd| cmd.contains("legionr@default")));
    assert!(plan
        .provision
        .iter()
        .any(|cmd| cmd.contains("LEGIONR_TOKEN")));
}

#[test]
fn runner_plain_windows_reports_wsl_requirement() {
    let status = status_for_host(RunnerHost::WindowsNoWsl);
    assert!(!status.supported);
    assert!(!status.wsl_available);
    assert!(status.message.contains("WSL"));
}
