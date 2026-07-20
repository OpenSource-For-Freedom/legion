# ARES agent

**Status: Real.** `crates/legion-ares/`

The blue-team analyst built into Legion. Answers from what Legion actually sees:
alerts, packages, scans, drift and events.

## Three surfaces

| Surface | Trigger | Behaviour |
|---|---|---|
| **Chat** | `POST /api/agent/chat` | Grounded Q&A over the current console state. |
| **Hunt** | `POST /api/agent/hunt` | Deterministic rule evaluation, then LLM synthesis. |
| **Autonomous loop** | Always on | 5-minute ticks, escalates to a full hunt past a 0.45 posture threshold with a 10-minute cooldown. |

## Engine-first, by design

A hunt builds its findings **deterministically first** — 60 rules across OWASP,
NIST, CIS, DEV and SYSTEM framework sets, plus OS-lane probes — and the model
only *synthesises* a summary over them. If the model is unavailable the report
still stands and is labelled `model_used: engine-only`. The findings are never
the model's invention.

Lanes are platform-scoped: `WindowsKernel`, `LinuxKernel`, `WslBridge`,
`Container`, `Generic`. Probes are read-only (`tasklist`, `sc query`, `netstat`,
`ss`, `systemctl`, SUID scans).

## Framework findings do not enter the alert queue

Rule hits are posture/configuration findings with no file, package or IP to act
on. They are reported in the Hunt Analysis panel and deliberately excluded from
the queue and the Critical KPI. The UI labels them **CRIT RULES / HIGH RULES**
against **QUEUE ALERTS** so the two counts can be reconciled.

This was a real complaint: six frameworks re-labelling one weak signal produced
six artifact-less Criticals and a manufactured F grade.

## Verify

```bash
cargo test -p legion-ares
curl -s localhost:3000/api/agent/status
```

## Limits

- `AresNeuralHunter` is a keyword and fixed-weight scorer, not a neural network.
  The name is internal and never surfaced in the UI, but it is misleading in the
  code.
- Web search scrapes DuckDuckGo HTML and breaks whenever that markup changes.
- Digest pinning (`pins.rs`) is enforced only on the legacy Ollama path.
- Chat history is session-scoped and in-memory; it is restored to the page on
  reload but does not survive a restart.
