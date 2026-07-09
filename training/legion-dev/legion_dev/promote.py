"""
Promote gate — never regress the live model. Promote only if the candidate
clears every eval gate AND does not score below the current model on pass rate.
Publishing to users (manifest bump / HF upload) is a separate, deliberate step.
"""

from __future__ import annotations

from dataclasses import dataclass

from .evaluate import EvalReport


@dataclass
class PromoteDecision:
    promote: bool
    reason: str
    candidate_pass_rate: float
    baseline_pass_rate: float | None


def decide(candidate: EvalReport, baseline: EvalReport | None) -> PromoteDecision:
    if not candidate.gates_cleared:
        return PromoteDecision(False, "candidate did not clear all eval gates",
                               candidate.pass_rate, baseline.pass_rate if baseline else None)
    if baseline is None:
        return PromoteDecision(True, "candidate clears all gates; no baseline to regress against",
                               candidate.pass_rate, None)
    if candidate.pass_rate < baseline.pass_rate:
        return PromoteDecision(False,
                               f"regression: candidate {candidate.pass_rate:.2f} < baseline {baseline.pass_rate:.2f}",
                               candidate.pass_rate, baseline.pass_rate)
    return PromoteDecision(True,
                           f"candidate clears gates and matches/beats baseline "
                           f"({candidate.pass_rate:.2f} >= {baseline.pass_rate:.2f})",
                           candidate.pass_rate, baseline.pass_rate)
