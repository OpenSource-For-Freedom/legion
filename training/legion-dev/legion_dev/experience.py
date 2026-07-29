"""The self-improvement loop's memory — how Legion Dev improves *as it runs*.

Honest framing first: a served model's weights do NOT change during inference. What genuinely
compounds is EXPERIENCE. Every real task the agent drives to green (execution-verified) is
recorded here, and that experience improves the system two ways:

  1. IMMEDIATELY (in-context): on a new request, `retrieve()` finds the most similar PAST
     VERIFIED win and offers it as a worked example. Behavior improves with no retrain — this
     is the "learns as it runs" part, available the instant a win is recorded.
  2. RECURSIVELY (offline, gated): `as_trajectories()` replays accumulated verified experience
     as training rows. A fine-tune folds it into the weights, the gate promotes it ONLY if it
     beats the base, and the improved model serves the next runs. Run the loop again and it
     compounds.

The gate is the recursion's safety rail: experience only sticks if it measurably helps, so the
loop can't drift into degradation (the exact failure mode we already measured and gate against).

Everything here is execution-verified: only trajectories that actually passed their tests are
kept for retrieval or training. A "success" that didn't run green is not experience, it's noise.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

TRAINING_ROOT = Path(__file__).resolve().parents[1]        # .../legion-dev
STORE = TRAINING_ROOT / "experience" / "runs.jsonl"


@dataclass
class Experience:
    request: str                 # what the user asked
    messages: list               # the tool-use trajectory (system/user/assistant/tool turns)
    passed: bool                 # did it end execution-verified green?
    meta: dict = field(default_factory=dict)   # {task, kind, source, ts, ...}


def _key(messages) -> str:
    """Dedup key: the LEARNED part (assistant tool-calls + summaries), whitespace-normalized."""
    learned = " ".join(
        (m.get("content", "") or "") + json.dumps(m.get("tool_calls", ""), sort_keys=True)
        for m in messages if m.get("role") == "assistant")
    return hashlib.sha1(" ".join(learned.split()).encode("utf-8")).hexdigest()


def record(request: str, messages: list, passed: bool, meta: dict | None = None) -> bool:
    """Append one run. Only VERIFIED (passed) runs are retained — unverified 'wins' are noise
    and would poison both retrieval and training. Returns True if it was stored."""
    if not passed or not messages:
        return False
    STORE.parent.mkdir(parents=True, exist_ok=True)
    rec = {"request": (request or "")[:4000], "messages": messages, "passed": True,
           "meta": {**(meta or {}), "ts": int(time.time()), "key": _key(messages)}}
    # skip an exact duplicate trajectory (same learned content)
    for e in load(only_passed=True):
        if e.meta.get("key") == rec["meta"]["key"]:
            return False
    with STORE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return True


def load(only_passed: bool = True) -> list[Experience]:
    if not STORE.exists():
        return []
    out = []
    for line in STORE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if only_passed and not d.get("passed"):
            continue
        out.append(Experience(d.get("request", ""), d.get("messages", []),
                              bool(d.get("passed")), d.get("meta", {})))
    return out


_WORD = re.compile(r"[a-zA-Z0-9_]+")
# Stopwords + generic request-boilerplate that would otherwise cause a spurious match on a
# single shared "a"/"the"/"build" and inject an IRRELEVANT worked example. Retrieval must key
# on the meaningful nouns of the task, not the connective tissue every request shares.
_STOP = {
    "a", "an", "the", "to", "of", "in", "on", "for", "and", "or", "with", "that", "this",
    "it", "is", "are", "be", "as", "at", "by", "from", "me", "my", "i", "you", "your", "we",
    "please", "can", "could", "would", "should", "make", "build", "create", "write", "add",
    "need", "want", "help", "so", "then", "now", "some", "any", "one", "code", "app", "project",
}
_MIN_SIM = 0.12   # below this, a "match" is just incidental overlap — treat as no relevant memory


def _tokens(text: str) -> set[str]:
    return {w for w in (w.lower() for w in _WORD.findall(text or "")) if w not in _STOP}


def retrieve(request: str, k: int = 1, only_passed: bool = True) -> list[Experience]:
    """The RUNTIME improvement: the most similar past verified wins for a new request, to use as
    worked examples (few-shot). Jaccard over MEANINGFUL tokens (stopwords stripped) with a floor,
    so an unrelated request retrieves nothing instead of a misleading example. Dependency-free and
    CPU-only, so the Studio can call it on every request with no model and no latency. Returns []
    on a cold/irrelevant store, so the caller degrades to zero-shot cleanly."""
    q = _tokens(request)
    if not q:
        return []
    scored = []
    for e in load(only_passed=only_passed):
        et = _tokens(e.request)
        if not et:
            continue
        sim = len(q & et) / len(q | et)
        if sim >= _MIN_SIM:
            scored.append((sim, e))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:max(1, k)]]


def as_trajectories(limit: int | None = None) -> list[dict]:
    """The RECURSIVE improvement: verified experience replayed as training trajectories, in the
    same {messages, meta} shape the dataset builder consumes. Deduped by learned content so
    re-running the loop doesn't stack copies. This is what folds real runs back into the weights."""
    seen, rows = set(), []
    for e in load(only_passed=True):
        key = e.meta.get("key") or _key(e.messages)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"messages": e.messages,
                     "meta": {"task": e.meta.get("task", "experience"),
                              "kind": "experience", "source": e.meta.get("source", "run")}})
        if limit and len(rows) >= limit:
            break
    return rows


def stats() -> dict:
    exps = load(only_passed=True)
    return {"verified_experiences": len(exps),
            "store": str(STORE),
            "distinct": len({e.meta.get("key") for e in exps})}
