"""
Critic / grader — the rejection-sampling gate. Thin wrapper over the
deterministic scorer; the SAME code grades training candidates and evaluates the
trained model, so a pair can't be accepted under looser rules than the model is
later judged by.
"""

from __future__ import annotations

from dataclasses import dataclass

from .evidence import EvidenceBundle
from .score import ScoreResult, score_answer


@dataclass
class Verdict:
    accepted: bool
    metrics: dict[str, float]
    reasons: list[str]
    result: ScoreResult


def grade(answer: str, bundle: EvidenceBundle) -> Verdict:
    res = score_answer(answer, bundle)
    return Verdict(accepted=res.passed, metrics=res.as_metrics(),
                   reasons=res.reasons, result=res)


def accept(answer: str, bundle: EvidenceBundle) -> bool:
    return score_answer(answer, bundle).passed
