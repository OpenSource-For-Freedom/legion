"""
Dataset assembly: executable tasks -> teacher (execution-verified) -> deduped SFT
set + a frozen, held-out test set of tasks. Only solutions that pass their tests
become training rows; the frozen test tasks are never trained on.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .contracts import SYNTHESIS_SYSTEM
from .synth import synthesize
from .tasks import Task, test_tasks, train_tasks


@dataclass
class SFTExample:
    task: str
    user: str
    answer: str
    backend: str

    def to_messages(self) -> dict:
        return {"messages": [
            {"role": "system", "content": SYNTHESIS_SYSTEM},
            {"role": "user", "content": self.user},
            {"role": "assistant", "content": self.answer},
        ], "meta": {"task": self.task, "backend": self.backend}}


@dataclass
class DatasetStats:
    candidates: int = 0
    accepted: int = 0
    rejected: int = 0
    deduped: int = 0
    train: int = 0
    val: int = 0
    test: int = 0
    by_backend: dict[str, int] = field(default_factory=dict)
    reject_reasons: list[str] = field(default_factory=list)


def task_to_dict(t: Task) -> dict:
    return {"name": t.name, "prompt": t.prompt, "starter": t.starter, "tests": t.tests,
            "reference": t.reference, "solution_file": t.solution_file, "test_file": t.test_file,
            "tags": t.tags, "forbidden": t.forbidden}


def task_from_dict(d: dict) -> Task:
    return Task(name=d["name"], prompt=d["prompt"], starter=d["starter"], tests=d["tests"],
                reference=d["reference"], solution_file=d.get("solution_file", "solution.py"),
                test_file=d.get("test_file", "test_solution.py"),
                tags=d.get("tags", []), forbidden=d.get("forbidden", []))


def frozen_test_tasks() -> list[Task]:
    return test_tasks()


def build_dataset(out_dir, *, instructions_per=3, max_examples=256, val_frac=0.2,
                  teacher_backend="hybrid", model="qwen2.5-coder:7b", host=None,
                  attempts=5, exec_timeout=30.0, deadline=None) -> DatasetStats:
    """Synthesize `instructions_per` verified solutions per training task (more
    passing samples = more diversity). deadline (time.monotonic seconds) optionally
    stops synthesis early for a time-box."""
    import time

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    stats = DatasetStats()
    examples: list[SFTExample] = []
    seen: set[str] = set()

    for task in train_tasks():
        for _ in range(instructions_per):
            if deadline is not None and time.monotonic() >= deadline:
                break
            kw = dict(backend=teacher_backend, model=model, attempts=attempts, exec_timeout=exec_timeout)
            if host:
                kw["host"] = host
            cand = synthesize(task, **kw)
            stats.candidates += 1
            if not cand.passed:
                stats.rejected += 1
                stats.reject_reasons.extend(cand.reasons)
                continue
            stats.accepted += 1
            key = " ".join(cand.answer.split())
            if key in seen:
                stats.deduped += 1
                continue
            seen.add(key)
            examples.append(SFTExample(task=task.name, user=task.render(),
                                       answer=cand.answer, backend=cand.backend))
            stats.by_backend[cand.backend] = stats.by_backend.get(cand.backend, 0) + 1
            if len(examples) >= max_examples:
                break
        if len(examples) >= max_examples:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break

    val_n = max(1, int(len(examples) * val_frac)) if examples else 0
    step = max(1, len(examples) // val_n) if val_n else 1
    val = [e for i, e in enumerate(examples) if val_n and i % step == 0][:val_n]
    val_set = {id(e) for e in val}
    train = [e for e in examples if id(e) not in val_set]

    _write_jsonl(out / "train.jsonl", [e.to_messages() for e in train])
    _write_jsonl(out / "val.jsonl", [e.to_messages() for e in val])

    test_rows = []
    for t in test_tasks():
        test_rows.append({"task": task_to_dict(t), "user_prompt": t.render(),
                          "reference_gold": t.reference_answer()})
    _write_jsonl(out / "test.jsonl", test_rows)

    stats.train, stats.val, stats.test = len(train), len(val), len(test_rows)
    return stats


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def read_jsonl(path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows
