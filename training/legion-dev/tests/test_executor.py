from legion_dev.executor import run_pytest


def test_passing_solution_passes():
    files = {"solution.py": "def add(a, b):\n    return a + b\n",
             "test_solution.py": "from solution import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"}
    res = run_pytest(files)
    assert res.passed and res.returncode == 0


def test_failing_solution_fails():
    files = {"solution.py": "def add(a, b):\n    return a - b\n",
             "test_solution.py": "from solution import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"}
    res = run_pytest(files)
    assert not res.passed


def test_infinite_loop_times_out():
    files = {"solution.py": "def go():\n    while True:\n        pass\n",
             "test_solution.py": "from solution import go\n\ndef test_go():\n    go()\n"}
    res = run_pytest(files, timeout=3.0)
    assert not res.passed and res.timed_out


def test_model_cannot_win_by_editing_tests():
    # run_task always writes the task's pristine tests, so a "solution" that also
    # defines a passing test file can't help — but here we prove a broken solution
    # against real tests fails regardless of what's in the solution file.
    files = {"solution.py": "def add(a, b):\n    return 0\n\ndef test_add():\n    assert True\n",
             "test_solution.py": "from solution import add\n\ndef test_real():\n    assert add(1, 2) == 3\n"}
    assert not run_pytest(files).passed
