"""
Critic — thin wrapper over the executing grader. Same code accepts training
candidates and judges the trained model, so nothing is accepted under looser
rules than it is later evaluated by.
"""

from __future__ import annotations

from dataclasses import dataclass

from .score import Verdict, grade


@dataclass
class Critique:
    accepted: bool
    reasons: list[str]
    verdict: Verdict


def critique(answer: str, task, **kw) -> Critique:
    v = grade(answer, task, **kw)
    return Critique(accepted=v.passed, reasons=v.reasons, verdict=v)
