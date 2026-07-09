"""
Teacher / synthesizer with EXECUTION-VERIFIED rejection sampling. For each task
the local coder teacher (Ollama) proposes a full solution; we run the task's
tests against it and keep the answer only if it actually passes. Sampling repeats
with rising temperature until one passes or attempts run out. The reference
solution (hand-verified, passing) is the fallback so every task still yields a
correct gold example — and because the fallback is a *real working solution*, not
a stub, it never poisons the data the way a template stub would.

Backends:
  "model"     — teacher only; reject the task if no sample passes.
  "hybrid"    — teacher, fall back to the verified reference (default).
  "reference" — the verified reference straight away (offline seed / smoke).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import ollama_client as oc
from .contracts import SYNTHESIS_SYSTEM
from .executor import run_task
from .extract import extract_code


@dataclass
class Candidate:
    task: str
    answer: str
    backend: str
    passed: bool
    reasons: list[str]
    attempts: int = 0


def _reference(task) -> Candidate:
    ans = task.reference_answer()
    res = run_task(task, task.reference)
    reasons = [] if res.passed else ["reference failed its own tests"]
    return Candidate(task.name, ans, "reference", res.passed, reasons, attempts=0)


def synthesize(task, *, backend: str = "hybrid", model: str = "qwen2.5-coder:7b",
               host: str = oc.DEFAULT_HOST, attempts: int = 5, timeout: float = 180.0,
               exec_timeout: float = 30.0, num_predict: int = 1536) -> Candidate:
    if backend == "reference":
        return _reference(task)

    user = task.render()
    last: Candidate | None = None
    for n in range(attempts):
        temp = 0.2 + 0.2 * n
        try:
            ans = oc.chat(model, SYNTHESIS_SYSTEM, user, host=host, temperature=temp,
                          num_ctx=8192, timeout=timeout, num_predict=num_predict)
        except Exception as e:
            if backend == "hybrid":
                return _reference(task)
            return Candidate(task.name, "", "model", False, [f"teacher error: {e}"], attempts=n + 1)

        code = extract_code(ans)
        if not code:
            last = Candidate(task.name, ans, "model", False, ["no code block"], attempts=n + 1)
            continue
        leaked = [s for s in task.forbidden if s and s in ans]
        res = run_task(task, code, timeout=exec_timeout)
        reasons = []
        if leaked:
            reasons.append("leaked forbidden literal")
        if not res.passed:
            reasons.append("execution timed out" if res.timed_out else "tests failed")
        ok = res.passed and not leaked
        last = Candidate(task.name, ans, "model", ok, reasons, attempts=n + 1)
        if ok:
            return last

    if backend == "hybrid":
        return _reference(task)
    return last or _reference(task)
