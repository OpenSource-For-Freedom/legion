"""
Persistent run log — one append-only record of every training run's successes
and failures, so you can glance at one file instead of scraping verbose stdout.

Files under logs/:
  runs.log    human-readable, one line per event
  runs.jsonl  same events as JSON rows

Status tags: INFO, OK (stage ok), WARN, FAIL (stage failed), DONE (whole run
finished — message carries SUCCESS/PARTIAL/SKIPPED/CRASH).

View:  python -m legion_dev.runlog        # last 40 lines
       python -m legion_dev.runlog 100
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
RUNS_LOG = LOG_DIR / "runs.log"
RUNS_JSONL = LOG_DIR / "runs.jsonl"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(stage: str, status: str, message: str = "", run_id: str = "-", **fields) -> str:
    """Append one event. Never raises — logging must not break a run."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        extra = ("  " + " ".join(f"{k}={v}" for k, v in fields.items())) if fields else ""
        line = f"{_ts()} [{status:<4}] run={run_id} stage={stage:<10} {message}{extra}"
        with open(RUNS_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        row = {"ts": _ts(), "status": status, "run_id": run_id,
               "stage": stage, "message": message, **fields}
        with open(RUNS_JSONL, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
        return line
    except Exception:
        return ""


def tail(n: int = 40) -> str:
    try:
        lines = RUNS_LOG.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return f"(no run log yet at {RUNS_LOG})"
    return "\n".join(lines[-n:])


if __name__ == "__main__":
    import sys
    print(tail(int(sys.argv[1]) if len(sys.argv) > 1 else 40))
