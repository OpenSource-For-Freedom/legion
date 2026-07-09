"""
The executable coding curriculum. Each task is a real, self-contained Python
problem: a `starter` file (buggy or stubbed), a `tests` file (the spec, run by
pytest), and a hand-verified `reference` solution that passes those tests. The
model is shown the task + starter + tests and must return the complete corrected
file; the executor decides pass/fail by running the tests.

This replaces the old "grounded synthesis over a signals bundle" framing — the
gate is now `pytest`, not a text heuristic. Families: bug-fix, implement-from-
spec, refactor, edge-case handling, plus two security tasks (SQL injection,
hardcoded secret) that are *also* checked by execution.

Held-out test set (never trained on): TEST_NAMES below.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Task:
    name: str
    prompt: str
    starter: str            # contents of the solution file the model edits
    tests: str              # pytest file (the spec) — pristine, never shown-then-edited
    reference: str          # a verified solution that passes `tests`
    solution_file: str = "solution.py"
    test_file: str = "test_solution.py"
    tags: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)  # literals the answer must not contain

    def render(self) -> str:
        return (
            "Language: Python.\n"
            f"Task: {self.prompt}\n\n"
            f"FILE {self.solution_file}:\n```python\n{self.starter.strip()}\n```\n\n"
            f"TESTS {self.test_file} (do not modify these):\n```python\n{self.tests.strip()}\n```\n\n"
            f"Return the complete corrected {self.solution_file} in a single ```python code block "
            "so that every test passes."
        )

    def reference_answer(self) -> str:
        return (f"Here is the corrected `{self.solution_file}`:\n\n"
                f"```python\n{self.reference.strip()}\n```")


def _t(name, prompt, starter, tests, reference, **kw):
    return Task(name=name, prompt=prompt, starter=starter, tests=tests, reference=reference, **kw)


TASKS: list[Task] = [
    _t("fix_add", "add(a, b) should return the sum of a and b. Fix the bug.",
       "def add(a, b):\n    return a - b\n",
       "from solution import add\n\ndef test_add():\n    assert add(2, 3) == 5\n    assert add(-1, 1) == 0\n",
       "def add(a, b):\n    return a + b\n", tags=["bugfix"]),

    _t("factorial", "Implement factorial(n) returning n! for n >= 0 (0! == 1).",
       "def factorial(n):\n    raise NotImplementedError\n",
       "from solution import factorial\n\ndef test_factorial():\n    assert factorial(0) == 1\n    assert factorial(1) == 1\n    assert factorial(5) == 120\n",
       "def factorial(n):\n    result = 1\n    for i in range(2, n + 1):\n        result *= i\n    return result\n", tags=["implement"]),

    _t("sum_to_n", "sum_to_n(n) should return 1 + 2 + ... + n. Fix the off-by-one bug.",
       "def sum_to_n(n):\n    total = 0\n    for i in range(n):\n        total += i\n    return total\n",
       "from solution import sum_to_n\n\ndef test_sum_to_n():\n    assert sum_to_n(5) == 15\n    assert sum_to_n(1) == 1\n    assert sum_to_n(0) == 0\n",
       "def sum_to_n(n):\n    total = 0\n    for i in range(1, n + 1):\n        total += i\n    return total\n", tags=["bugfix"]),

    _t("fizzbuzz", "Implement fizzbuzz(n): a list for 1..n where multiples of 3 are 'Fizz', of 5 are 'Buzz', of 15 'FizzBuzz', else the number as a string.",
       "def fizzbuzz(n):\n    raise NotImplementedError\n",
       "from solution import fizzbuzz\n\ndef test_fizzbuzz():\n    assert fizzbuzz(5) == ['1', '2', 'Fizz', '4', 'Buzz']\n    assert fizzbuzz(15)[-1] == 'FizzBuzz'\n",
       "def fizzbuzz(n):\n    out = []\n    for i in range(1, n + 1):\n        if i % 15 == 0:\n            out.append('FizzBuzz')\n        elif i % 3 == 0:\n            out.append('Fizz')\n        elif i % 5 == 0:\n            out.append('Buzz')\n        else:\n            out.append(str(i))\n    return out\n", tags=["implement"]),

    _t("mutable_default", "append_item(item, bucket) must not share state across calls. Fix the mutable-default-argument bug.",
       "def append_item(item, bucket=[]):\n    bucket.append(item)\n    return bucket\n",
       "from solution import append_item\n\ndef test_append_item():\n    assert append_item(1) == [1]\n    assert append_item(2) == [2]\n",
       "def append_item(item, bucket=None):\n    if bucket is None:\n        bucket = []\n    bucket.append(item)\n    return bucket\n", tags=["bugfix"]),

    _t("is_palindrome", "Implement is_palindrome(s): True if s reads the same forwards and backwards, ignoring case and non-alphanumeric characters.",
       "def is_palindrome(s):\n    raise NotImplementedError\n",
       "from solution import is_palindrome\n\ndef test_is_palindrome():\n    assert is_palindrome('A man, a plan, a canal: Panama') is True\n    assert is_palindrome('hello') is False\n    assert is_palindrome('') is True\n",
       "def is_palindrome(s):\n    cleaned = [c.lower() for c in s if c.isalnum()]\n    return cleaned == cleaned[::-1]\n", tags=["implement"]),

    _t("safe_div", "safe_div(a, b) should return a / b, or None when b == 0. Fix the crash.",
       "def safe_div(a, b):\n    return a / b\n",
       "from solution import safe_div\n\ndef test_safe_div():\n    assert safe_div(6, 3) == 2\n    assert safe_div(1, 0) is None\n",
       "def safe_div(a, b):\n    if b == 0:\n        return None\n    return a / b\n", tags=["bugfix", "edge-case"]),

    _t("flatten", "Implement flatten(nested): concatenate a list of lists into one flat list (one level).",
       "def flatten(nested):\n    raise NotImplementedError\n",
       "from solution import flatten\n\ndef test_flatten():\n    assert flatten([[1, 2], [3], [4, 5]]) == [1, 2, 3, 4, 5]\n    assert flatten([]) == []\n",
       "def flatten(nested):\n    result = []\n    for sub in nested:\n        result.extend(sub)\n    return result\n", tags=["implement"]),

    _t("get_user_id", "get_user_id(data) should return data['id'] if present, else None. Fix the KeyError.",
       "def get_user_id(data):\n    return data['id']\n",
       "from solution import get_user_id\n\ndef test_get_user_id():\n    assert get_user_id({'id': 7}) == 7\n    assert get_user_id({}) is None\n",
       "def get_user_id(data):\n    return data.get('id')\n", tags=["bugfix", "edge-case"]),

    _t("word_count", "Implement word_count(text): a dict mapping each whitespace-separated word to its count.",
       "def word_count(text):\n    raise NotImplementedError\n",
       "from solution import word_count\n\ndef test_word_count():\n    assert word_count('a b a') == {'a': 2, 'b': 1}\n    assert word_count('') == {}\n",
       "def word_count(text):\n    counts = {}\n    for word in text.split():\n        counts[word] = counts.get(word, 0) + 1\n    return counts\n", tags=["implement"]),

    _t("sum_even", "sum_even(nums) should sum the even numbers. Fix the parity bug.",
       "def sum_even(nums):\n    return sum(n for n in nums if n % 2 == 1)\n",
       "from solution import sum_even\n\ndef test_sum_even():\n    assert sum_even([1, 2, 3, 4]) == 6\n    assert sum_even([]) == 0\n",
       "def sum_even(nums):\n    return sum(n for n in nums if n % 2 == 0)\n", tags=["bugfix"]),

    _t("fibonacci", "Implement fib(n): the n-th Fibonacci number, 0-indexed (fib(0)=0, fib(1)=1).",
       "def fib(n):\n    raise NotImplementedError\n",
       "from solution import fib\n\ndef test_fib():\n    assert fib(0) == 0\n    assert fib(1) == 1\n    assert fib(10) == 55\n",
       "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n", tags=["implement"]),

    _t("reverse_string", "reverse(s) should return s reversed. Fix it.",
       "def reverse(s):\n    return s\n",
       "from solution import reverse\n\ndef test_reverse():\n    assert reverse('abc') == 'cba'\n    assert reverse('') == ''\n",
       "def reverse(s):\n    return s[::-1]\n", tags=["bugfix"]),

    _t("dedupe", "Implement dedupe(items): remove duplicates while preserving first-seen order.",
       "def dedupe(items):\n    raise NotImplementedError\n",
       "from solution import dedupe\n\ndef test_dedupe():\n    assert dedupe([1, 2, 1, 3, 2]) == [1, 2, 3]\n    assert dedupe([]) == []\n",
       "def dedupe(items):\n    seen = set()\n    out = []\n    for x in items:\n        if x not in seen:\n            seen.add(x)\n            out.append(x)\n    return out\n", tags=["implement"]),

    _t("max_of", "max_of(nums) should return the largest number. Fix the bug.",
       "def max_of(nums):\n    return min(nums)\n",
       "from solution import max_of\n\ndef test_max_of():\n    assert max_of([3, 1, 2]) == 3\n    assert max_of([-5, -1]) == -1\n",
       "def max_of(nums):\n    return max(nums)\n", tags=["bugfix"]),

    _t("average", "average(nums) should return the mean, or 0.0 for an empty list. Fix the ZeroDivisionError.",
       "def average(nums):\n    return sum(nums) / len(nums)\n",
       "from solution import average\n\ndef test_average():\n    assert average([2, 4]) == 3\n    assert average([]) == 0.0\n",
       "def average(nums):\n    if not nums:\n        return 0.0\n    return sum(nums) / len(nums)\n", tags=["bugfix", "edge-case"]),

    _t("query_user", "query_user(conn, name) returns rows for the exact name. Rewrite it to be safe against SQL injection (parameterized query).",
       "def query_user(conn, name):\n    cur = conn.cursor()\n    cur.execute(\"SELECT name FROM users WHERE name = '\" + name + \"'\")\n    return cur.fetchall()\n",
       "import sqlite3\nfrom solution import query_user\n\n\ndef _conn():\n    c = sqlite3.connect(':memory:')\n    c.execute('CREATE TABLE users (name TEXT)')\n    c.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])\n    c.commit()\n    return c\n\n\ndef test_exact_match():\n    assert query_user(_conn(), 'alice') == [('alice',)]\n\n\ndef test_injection_blocked():\n    assert query_user(_conn(), \"' OR '1'='1\") == []\n",
       "def query_user(conn, name):\n    cur = conn.cursor()\n    cur.execute('SELECT name FROM users WHERE name = ?', (name,))\n    return cur.fetchall()\n", tags=["security", "bugfix"]),

    _t("get_token", "get_token() must read the token from the API_TOKEN environment variable instead of hardcoding a secret.",
       "def get_token():\n    return 'sk-live-legiondev-DO-NOT-SHIP'\n",
       "import os\nfrom solution import get_token\n\n\ndef test_reads_env():\n    os.environ['API_TOKEN'] = 'env-token-123'\n    assert get_token() == 'env-token-123'\n",
       "import os\n\n\ndef get_token():\n    return os.environ['API_TOKEN']\n",
       tags=["security"], forbidden=["sk-live-legiondev-DO-NOT-SHIP"]),

    _t("merge_dicts", "merge_dicts(a, b) should return a new dict with b's values winning on conflicts, without mutating a. Fix the mutation bug.",
       "def merge_dicts(a, b):\n    a.update(b)\n    return a\n",
       "from solution import merge_dicts\n\ndef test_merge_dicts():\n    a = {'x': 1}\n    b = {'x': 2, 'y': 3}\n    assert merge_dicts(a, b) == {'x': 2, 'y': 3}\n    assert a == {'x': 1}\n",
       "def merge_dicts(a, b):\n    result = dict(a)\n    result.update(b)\n    return result\n", tags=["bugfix"]),

    _t("chunk", "Implement chunk(items, size): split items into consecutive sublists of length size (the last may be shorter).",
       "def chunk(items, size):\n    raise NotImplementedError\n",
       "from solution import chunk\n\ndef test_chunk():\n    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]\n    assert chunk([], 3) == []\n",
       "def chunk(items, size):\n    return [items[i:i + size] for i in range(0, len(items), size)]\n", tags=["implement"]),
]

# Merge the extended task pool (diverse / realistic / security), execution-verified.
from .tasks_extra import EXTRA_TASKS  # noqa: E402
TASKS.extend(EXTRA_TASKS)

# Held-out evaluation tasks (a diverse slice: edge-case, implement, security, structure).
TEST_NAMES = {"safe_div", "is_palindrome", "query_user", "get_token", "chunk",
              "merge_intervals", "valid_parens", "safe_path_join", "binary_search_bug",
              "deep_get"}

_BY_NAME = {t.name: t for t in TASKS}


def all_tasks() -> list[Task]:
    return list(TASKS)


def train_tasks() -> list[Task]:
    return [t for t in TASKS if t.name not in TEST_NAMES]


def test_tasks() -> list[Task]:
    return [t for t in TASKS if t.name in TEST_NAMES]


def get_task(name: str) -> Task:
    return _BY_NAME[name]
