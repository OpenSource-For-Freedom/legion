"""
Dataset assembly: catalog -> teacher -> critic -> deduped SFT set + a stable
frozen test set (index 0 of every scenario, held out from training).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .contracts import INSTRUCTION_VARIANTS, SYNTHESIS_SYSTEM
from .evidence import EvidenceBundle, Finding
from .scenarios import build_catalog
from .synth import (CODE_INSTRUCTIONS, DESTRUCTIVE_INSTRUCTIONS, IDENTITY_INSTRUCTIONS,
                    build_user_prompt, synthesize, template_gold)


@dataclass
class SFTExample:
    scenario: str
    instruction: str
    evidence: str
    answer: str
    backend: str

    def to_messages(self) -> dict:
        return {"messages": [
            {"role": "system", "content": SYNTHESIS_SYSTEM},
            {"role": "user", "content": f"{self.instruction}\n\n{self.evidence}"},
            {"role": "assistant", "content": self.answer},
        ], "meta": {"scenario": self.scenario, "backend": self.backend}}


def instruction_for(bundle: EvidenceBundle, k: int) -> str:
    if bundle.code_request:
        return CODE_INSTRUCTIONS[k % len(CODE_INSTRUCTIONS)]
    if bundle.identity_request:
        return IDENTITY_INSTRUCTIONS[k % len(IDENTITY_INSTRUCTIONS)]
    if bundle.destructive_request:
        return DESTRUCTIVE_INSTRUCTIONS[k % len(DESTRUCTIVE_INSTRUCTIONS)]
    return INSTRUCTION_VARIANTS[k % len(INSTRUCTION_VARIANTS)]


def _split_catalog(n_per: int):
    catalog = build_catalog(n_per)
    n_scen = len(catalog) // n_per if n_per else 0
    return catalog[n_scen:], catalog[:n_scen]  # (train, test)


def bundle_to_dict(bundle: EvidenceBundle) -> dict:
    return {"scenario": bundle.scenario, "score": bundle.score, "platform": bundle.platform,
            "posture": bundle.posture, "findings": [asdict(f) for f in bundle.findings],
            "mitre": bundle.mitre, "injection_present": bundle.injection_present,
            "code_request": bundle.code_request, "identity_request": bundle.identity_request,
            "destructive_request": bundle.destructive_request, "clean": bundle.clean, "note": bundle.note}


def bundle_from_dict(d: dict) -> EvidenceBundle:
    return EvidenceBundle(scenario=d["scenario"], score=d["score"], platform=d.get("platform", "cross"),
                          findings=[Finding(**f) for f in d["findings"]],
                          mitre=d.get("mitre", []), injection_present=d.get("injection_present", False),
                          code_request=d.get("code_request", False),
                          identity_request=d.get("identity_request", False),
                          destructive_request=d.get("destructive_request", False),
                          clean=d.get("clean", False), note=d.get("note", ""))


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


def frozen_test_pairs(n_per: int) -> list[tuple[EvidenceBundle, str]]:
    _, test_bundles = _split_catalog(n_per)
    return [(b, instruction_for(b, 0)) for b in test_bundles]


def build_dataset(out_dir, *, n_per=8, instructions_per=1, max_examples=256,
                  val_frac=0.2, teacher_backend="hybrid", model="legion-ares:qwen3-4b",
                  host=None, attempts=3, deadline=None) -> DatasetStats:
    """instructions_per multiplies each bundle by that many phrasings. deadline
    (time.monotonic seconds) optionally stops synthesis early for a time-box."""
    import time

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    train_bundles, test_bundles = _split_catalog(n_per)

    stats = DatasetStats()
    examples: list[SFTExample] = []
    seen: set[str] = set()

    for idx, bundle in enumerate(train_bundles):
        for k in range(instructions_per):
            if deadline is not None and time.monotonic() >= deadline:
                break
            instruction = instruction_for(bundle, idx + k)
            kw = dict(backend=teacher_backend, model=model, attempts=attempts)
            if host:
                kw["host"] = host
            cand = synthesize(bundle, instruction, **kw)
            stats.candidates += 1
            if not cand.passed:
                stats.rejected += 1
                stats.reject_reasons.extend(cand.reasons)
                continue
            stats.accepted += 1
            key = " ".join(cand.answer.lower().split())
            if key in seen:
                stats.deduped += 1
                continue
            seen.add(key)
            examples.append(SFTExample(scenario=bundle.scenario, instruction=instruction,
                                       evidence=bundle.render(), answer=cand.answer, backend=cand.backend))
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
    for b in test_bundles:
        instr = instruction_for(b, 0)
        test_rows.append({"bundle": bundle_to_dict(b), "instruction": instr,
                          "user_prompt": build_user_prompt(b, instr),
                          "reference_gold": template_gold(b, instr)})
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
