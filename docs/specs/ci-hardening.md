# CI hardening

**Status: Partial — monitoring, not enforcement.** `.github/workflows/`, `.legion/`

## Legion_runner

Every job in every workflow (9 total) runs Legion_runner as its **first step**,
before `actions/checkout` — the step that pulls code onto the runner is
otherwise the one step nothing watches.

Pinned by commit SHA (`Wraith-security/Legion_runner@29bd7988`, v1.0.42), never
a tag: a tag can be moved by whoever controls the upstream repo.

Configuration: `egress-policy: audit`, `ebpf: auto`, `file-integrity: true`,
`learn: true`, a committed `policy-file`, and per-job `allowed-presets` matched
to what each job actually fetches (cargo+rust for Rust jobs, apt for the C
agent, nothing extra for the GitHub-only release job).

## Dependabot

`cargo` weekly, `github-actions` **daily** — a hijacked action executes inside
the release pipeline with the token that publishes artifacts, so the exposure
window matters more than review churn. Updates are grouped so review is a few
meaningful PRs; security updates stay ungrouped and exempt from the PR limit.
Dependabot preserves SHA pinning. Legion_runner itself is excluded: it is the
control enforcing CI egress policy, so bumping it should be a human decision.

## Why audit and not block

Block mode was tried and **broke `actions/checkout` on 3 of 7 jobs**:

```
fatal: unable to access 'https://github.com/Wraith-security/legion/':
Failed to connect to github.com port 443 after 132445 ms
```

That is not a gap in the allowlist. `allow-github` defaults to true precisely so
a job can reach GitHub, and the failure was a ~132s connect timeout rather than
a clean refusal — traffic dropped, not denied by policy. It was also
non-deterministic: four jobs passed and three failed in the same run with
identical configuration.

Everything needed for enforcement is in place — learned baseline, committed
allowlist, per-job presets — so it is a one-word change per job once that is
resolved upstream.

## Limits

- Monitoring only. Nothing is currently blocked.
- The learned baseline lives in the Actions cache and is subject to eviction.
