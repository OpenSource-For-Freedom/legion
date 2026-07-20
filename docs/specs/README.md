# Legion feature specs

One sheet per capability. Each states what the feature **actually does today**,
where it lives, how to verify it yourself, and — the part that matters most here
— **what it does not do**.

A spec that only describes the happy path is how this project gets into trouble.
Every sheet carries a "Limits" section, and it is not optional.

Read [`../SKILL.md`](../SKILL.md) first.

## Status vocabulary

| Term | Means |
|---|---|
| **Real** | Implemented, tested, and verified running. |
| **Partial** | Works, with a stated gap. The gap is named in Limits. |
| **Advisory** | Reports, never acts. Deliberate. |
| **Not built** | Named here because someone will otherwise assume it exists. |

## Detection

| Spec | Status | One line |
|---|---|---|
| [package-scanning](package-scanning.md) | Real | Finds installed packages across cargo, npm, pip. |
| [osv-correlation](osv-correlation.md) | Real | Vulnerability findings with real severities, CVEs and fix versions. |
| [kev-escalation](kev-escalation.md) | Real | Raises anything CISA lists as actively exploited to Critical. |
| [malicious-packages](malicious-packages.md) | Real | Confirmed-malicious dependencies, split from mere opinion. |
| [package-sensor](package-sensor.md) | Real | Continuous 60s watcher, alert-only by design. |
| [dprk-indicators](dprk-indicators.md) | Real | Contagious Interview / PolinRider workstation indicators. |
| [yara-engine](yara-engine.md) | Partial | Hand-written YARA subset. Throughput is the limit. |
| [baseline-and-drift](baseline-and-drift.md) | Real | First-run host snapshot, diffed thereafter. |
| [threat-feeds](threat-feeds.md) | Real | CISA KEV + Feodo Tracker botnet C2. |

## Analysis

| Spec | Status | One line |
|---|---|---|
| [ares-agent](ares-agent.md) | Real | On-device analyst: chat, hunt, autonomous loop. |
| [model-lifecycle](model-lifecycle.md) | Real | Pulls, verifies and serves the model locally. |
| [gpu-offload](gpu-offload.md) | Real | Hardware-adaptive, measured, and polite about it. |
| [posture-score](posture-score.md) | Real | A single number that shows its own arithmetic. |

## Response

| Spec | Status | One line |
|---|---|---|
| [soar-response](soar-response.md) | Advisory | Quarantine files, generate fix commands. Never auto-executes. |
| [alerts-and-reconcile](alerts-and-reconcile.md) | Real | Findings that disappear when they stop being true. |

## Platform

| Spec | Status | One line |
|---|---|---|
| [security-model](security-model.md) | Partial | Loopback binding, peer credentials, elevation. |
| [resource-budget](resource-budget.md) | Real | What Legion will and will not take from your machine. |
| [packaging](packaging.md) | Real | AppImage, winget, and the release archive. |
| [ci-hardening](ci-hardening.md) | Partial | Legion_runner egress monitoring on every job. |
