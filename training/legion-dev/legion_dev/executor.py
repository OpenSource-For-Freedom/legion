"""
The sandboxed test runner — THE quality signal. A candidate solution is written
into a fresh temp dir alongside the task's *pristine* test file (the model never
gets to edit the tests), then pytest runs in a subprocess with a hard timeout.
Pass = returncode 0. Everything downstream (rejection sampling in synth, the eval
pass@1, the tests) grades against this, so "accepted" means "actually runs and
passes real tests", not "looks plausible".

Safety note: this executes model-written code. It runs in a throwaway temp dir,
in a separate process, with a wall-clock timeout and no bytecode cache. On a
shared/untrusted host you'd want a container or seccomp; for a single local user
running a local model on bounded coding tasks, subprocess + timeout is the
pragmatic boundary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecResult:
    passed: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else ""))[-4000:]


def run_pytest(files: dict[str, str], *, timeout: float = 30.0, python: str | None = None) -> ExecResult:
    """Write {relpath: content} into a temp dir and run pytest there."""
    python = python or sys.executable
    workdir = Path(tempfile.mkdtemp(prefix="legiondev-"))
    try:
        for rel, content in files.items():
            path = workdir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(workdir)
        try:
            proc = subprocess.run(
                [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header", str(workdir)],
                cwd=str(workdir), capture_output=True, encoding="utf-8", errors="replace",
                timeout=timeout, env=env)
        except subprocess.TimeoutExpired as e:
            return ExecResult(False, -1, e.stdout or "", e.stderr or "", timed_out=True,
                              error=f"timed out after {timeout}s")
        except FileNotFoundError as e:
            return ExecResult(False, -1, "", str(e), error="python/pytest not found")
        return ExecResult(proc.returncode == 0, proc.returncode, proc.stdout or "", proc.stderr or "")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_task(task, solution_code: str, *, timeout: float = 30.0, python: str | None = None) -> ExecResult:
    """Run `task`'s tests against a candidate solution. Tests come from the task,
    never from the model, so a candidate can't pass by editing the tests."""
    files = {task.solution_file: solution_code, task.test_file: task.tests}
    return run_pytest(files, timeout=timeout, python=python)


def run_project(task, candidate_files: dict[str, str], *, timeout: float = 60.0,
                python: str | None = None) -> ExecResult:
    """Grade a multi-file PROJECT: run the task's pristine tests against the candidate's
    non-test files. The task's tests are layered LAST so a candidate can never win by
    shipping its own copy of a test file — the spec always wins. Mirrors run_task, but the
    candidate is a whole {relpath: content} tree instead of one solution string."""
    files = {**(candidate_files or {}), **task.tests}
    return run_pytest(files, timeout=timeout, python=python)
