"""
Multimodal dataset assembly: render each task to a SCREENSHOT, pair it with the
execution-verified solution (same gate as the text pipeline — the code must pass
`pytest`), and emit image+text -> code SFT rows for the vision model. The frozen
test tasks are held out.

Rows (train/val):  {"task", "image", "user_text", "answer", "backend"}
Rows (test):       {"task": <dict>, "image", "user_text", "reference_gold"}
The image is a rendered view of text we already have, so the data is grounded and
the code is still execution-verified — no real screenshots required.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .dataset import DatasetStats, task_to_dict
from .render import task_screenshot
from .synth import synthesize
from .tasks import test_tasks, train_tasks


def _user_text(task) -> str:
    # The EYES role in the one-agent profile: observe the screenshot and hand off a
    # precise observation to the coder. Do NOT solve it here.
    return (
        f"This screenshot shows `{task.solution_file}` from the user's project. Read it "
        "carefully and report a precise OBSERVATION for the coding model that will fix "
        "it: transcribe the code you see verbatim, state what it does and what looks "
        "wrong, and restate the task. Do not write the fix yourself, hand off a clear, "
        "accurate observation."
    )


def _observation(task) -> str:
    """Grounded ground-truth observation the eyes hand to the coder: a verbatim
    transcript of what the screenshot shows plus what needs doing. Built from the
    task's known text (the screenshot is a rendering of it), so it is exact."""
    return (
        f"The screenshot shows `{task.solution_file}`:\n\n"
        f"```python\n{task.starter.strip()}\n```\n\n"
        f"What it needs: {task.prompt.strip()}\n"
        f"It currently fails the tests in `{task.test_file}`. "
        f"Handoff to the coder: rewrite `{task.solution_file}` so every test passes, "
        "keeping the public names the tests import."
    )


def frozen_test_pairs_vl(out_dir, *, kind="code") -> list[tuple]:
    """(task, image_path, user_text) for each held-out task, images rendered under out_dir."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pairs = []
    for t in test_tasks():
        img = task_screenshot(t, out, kind=kind)
        pairs.append((t, img, _user_text(t)))
    return pairs


def build_vl_dataset(out_dir, *, kind="code", instructions_per=3, max_examples=256,
                     val_frac=0.2, teacher_backend="hybrid", model="qwen2.5-coder:7b",
                     host=None, attempts=5, exec_timeout=30.0, deadline=None) -> DatasetStats:
    import time

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stats = DatasetStats()
    rows: list[dict] = []
    seen: set[str] = set()

    for task in train_tasks():
        img = task_screenshot(task, out, kind=kind, exec_timeout=exec_timeout)
        rel = str(Path(img).relative_to(out)) if str(img).startswith(str(out)) else img
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
            rows.append({"task": task.name, "image": rel, "user_text": _user_text(task),
                         "answer": cand.answer, "backend": cand.backend})
            stats.by_backend[cand.backend] = stats.by_backend.get(cand.backend, 0) + 1
            if len(rows) >= max_examples:
                break
        if len(rows) >= max_examples:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break

    val_n = max(1, int(len(rows) * val_frac)) if rows else 0
    step = max(1, len(rows) // val_n) if val_n else 1
    val = [r for i, r in enumerate(rows) if val_n and i % step == 0][:val_n]
    val_ids = {id(r) for r in val}
    train = [r for r in rows if id(r) not in val_ids]

    _write(out / "train_vl.jsonl", train)
    _write(out / "val_vl.jsonl", val)

    test_rows = []
    for t in test_tasks():
        img = task_screenshot(t, out, kind=kind, exec_timeout=exec_timeout)
        rel = str(Path(img).relative_to(out)) if str(img).startswith(str(out)) else img
        test_rows.append({"task": task_to_dict(t), "image": rel,
                          "user_text": _user_text(t), "reference_gold": t.reference_answer()})
    _write(out / "test_vl.jsonl", test_rows)

    stats.train, stats.val, stats.test = len(train), len(val), len(test_rows)
    return stats


def _write(path: Path, rows: list[dict]) -> None:
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
