"""Extended task pool: diverse, realistic, execution-verified coding tasks that go
well beyond the toy set. Families: implement-from-spec, real bug-fixes, edge cases,
data structures, and SECURITY (security-first core). Every reference passes its tests.

Merged into TASKS by tasks.py. Keep references correct — the executor gates on pytest.
"""
from __future__ import annotations

from .tasks import _t

EXTRA_TASKS = [
    # --- implement from spec -------------------------------------------------------
    _t("clamp", "Implement clamp(x, lo, hi): return x limited to the range [lo, hi].",
       "def clamp(x, lo, hi):\n    raise NotImplementedError\n",
       "from solution import clamp\n\ndef test_clamp():\n    assert clamp(5, 0, 10) == 5\n    assert clamp(-1, 0, 10) == 0\n    assert clamp(11, 0, 10) == 10\n",
       "def clamp(x, lo, hi):\n    return max(lo, min(x, hi))\n", tags=["implement", "edge-case"]),

    _t("group_by", "Implement group_by(items, key): a dict mapping key(item) to the list of items with that key, preserving order.",
       "def group_by(items, key):\n    raise NotImplementedError\n",
       "from solution import group_by\n\ndef test_group_by():\n    assert group_by([1, 2, 3, 4], lambda n: n % 2) == {1: [1, 3], 0: [2, 4]}\n    assert group_by([], lambda x: x) == {}\n",
       "def group_by(items, key):\n    out = {}\n    for it in items:\n        out.setdefault(key(it), []).append(it)\n    return out\n", tags=["implement"]),

    _t("dedupe", "Implement dedupe(items): remove duplicates while preserving first-seen order.",
       "def dedupe(items):\n    raise NotImplementedError\n",
       "from solution import dedupe\n\ndef test_dedupe():\n    assert dedupe([1, 2, 1, 3, 2]) == [1, 2, 3]\n    assert dedupe([]) == []\n",
       "def dedupe(items):\n    seen = set()\n    out = []\n    for it in items:\n        if it not in seen:\n            seen.add(it)\n            out.append(it)\n    return out\n", tags=["implement"]),

    _t("merge_intervals", "Implement merge_intervals(intervals): merge overlapping [start, end] intervals, sorted by start.",
       "def merge_intervals(intervals):\n    raise NotImplementedError\n",
       "from solution import merge_intervals\n\ndef test_merge_intervals():\n    assert merge_intervals([[1, 3], [2, 6], [8, 10]]) == [[1, 6], [8, 10]]\n    assert merge_intervals([]) == []\n    assert merge_intervals([[1, 4], [4, 5]]) == [[1, 5]]\n",
       "def merge_intervals(intervals):\n    if not intervals:\n        return []\n    ordered = sorted(intervals, key=lambda p: p[0])\n    out = [list(ordered[0])]\n    for start, end in ordered[1:]:\n        if start <= out[-1][1]:\n            out[-1][1] = max(out[-1][1], end)\n        else:\n            out.append([start, end])\n    return out\n", tags=["implement"]),

    _t("moving_average", "Implement moving_average(nums, k): the list of averages of each length-k window (empty if k > len).",
       "def moving_average(nums, k):\n    raise NotImplementedError\n",
       "from solution import moving_average\n\ndef test_moving_average():\n    assert moving_average([1, 2, 3, 4], 2) == [1.5, 2.5, 3.5]\n    assert moving_average([1, 2], 3) == []\n",
       "def moving_average(nums, k):\n    if k > len(nums):\n        return []\n    return [sum(nums[i:i + k]) / k for i in range(len(nums) - k + 1)]\n", tags=["implement"]),

    _t("rle_encode", "Implement rle_encode(s): run-length encode as a list of (char, count) tuples.",
       "def rle_encode(s):\n    raise NotImplementedError\n",
       "from solution import rle_encode\n\ndef test_rle_encode():\n    assert rle_encode('aaabb') == [('a', 3), ('b', 2)]\n    assert rle_encode('') == []\n    assert rle_encode('x') == [('x', 1)]\n",
       "def rle_encode(s):\n    out = []\n    for ch in s:\n        if out and out[-1][0] == ch:\n            out[-1] = (ch, out[-1][1] + 1)\n        else:\n            out.append((ch, 1))\n    return out\n", tags=["implement"]),

    _t("parse_kv", "Implement parse_kv(text): parse 'key=value' lines into a dict; ignore blank lines and '#' comments; strip whitespace.",
       "def parse_kv(text):\n    raise NotImplementedError\n",
       "from solution import parse_kv\n\ndef test_parse_kv():\n    assert parse_kv('a=1\\n b = 2 \\n# c=3\\n\\n') == {'a': '1', 'b': '2'}\n    assert parse_kv('') == {}\n",
       "def parse_kv(text):\n    out = {}\n    for line in text.splitlines():\n        line = line.strip()\n        if not line or line.startswith('#') or '=' not in line:\n            continue\n        k, v = line.split('=', 1)\n        out[k.strip()] = v.strip()\n    return out\n", tags=["implement"]),

    _t("deep_get", "Implement deep_get(data, path, default=None): follow a dotted path into nested dicts, returning default if any key is missing.",
       "def deep_get(data, path, default=None):\n    raise NotImplementedError\n",
       "from solution import deep_get\n\ndef test_deep_get():\n    d = {'a': {'b': {'c': 1}}}\n    assert deep_get(d, 'a.b.c') == 1\n    assert deep_get(d, 'a.x.c', 0) == 0\n    assert deep_get({}, 'a') is None\n",
       "def deep_get(data, path, default=None):\n    cur = data\n    for key in path.split('.'):\n        if not isinstance(cur, dict) or key not in cur:\n            return default\n        cur = cur[key]\n    return cur\n", tags=["implement", "edge-case"]),

    _t("valid_parens", "Implement valid_parens(s): True if brackets ()[]{} are balanced and correctly nested.",
       "def valid_parens(s):\n    raise NotImplementedError\n",
       "from solution import valid_parens\n\ndef test_valid_parens():\n    assert valid_parens('([]{})') is True\n    assert valid_parens('([)]') is False\n    assert valid_parens('(') is False\n    assert valid_parens('') is True\n",
       "def valid_parens(s):\n    pairs = {')': '(', ']': '[', '}': '{'}\n    stack = []\n    for ch in s:\n        if ch in '([{':\n            stack.append(ch)\n        elif ch in pairs:\n            if not stack or stack.pop() != pairs[ch]:\n                return False\n    return not stack\n", tags=["implement"]),

    _t("two_sum", "Implement two_sum(nums, target): return the indices [i, j] (i < j) of two numbers that add to target, or None.",
       "def two_sum(nums, target):\n    raise NotImplementedError\n",
       "from solution import two_sum\n\ndef test_two_sum():\n    assert two_sum([2, 7, 11, 15], 9) == [0, 1]\n    assert two_sum([3, 2, 4], 6) == [1, 2]\n    assert two_sum([1, 2], 10) is None\n",
       "def two_sum(nums, target):\n    seen = {}\n    for i, n in enumerate(nums):\n        if target - n in seen:\n            return [seen[target - n], i]\n        seen[n] = i\n    return None\n", tags=["implement"]),

    _t("roman_to_int", "Implement roman_to_int(s): convert a Roman numeral string to an integer.",
       "def roman_to_int(s):\n    raise NotImplementedError\n",
       "from solution import roman_to_int\n\ndef test_roman_to_int():\n    assert roman_to_int('III') == 3\n    assert roman_to_int('IV') == 4\n    assert roman_to_int('MCMXCIV') == 1994\n",
       "def roman_to_int(s):\n    vals = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}\n    total = 0\n    prev = 0\n    for ch in reversed(s):\n        v = vals[ch]\n        total += -v if v < prev else v\n        prev = v\n    return total\n", tags=["implement"]),

    # --- real bug fixes ------------------------------------------------------------
    _t("binary_search_bug", "binary_search(arr, target) should return the index of target in a sorted arr or -1. Fix the off-by-one that misses the last element.",
       "def binary_search(arr, target):\n    lo, hi = 0, len(arr) - 1\n    while lo < hi:\n        mid = (lo + hi) // 2\n        if arr[mid] == target:\n            return mid\n        elif arr[mid] < target:\n            lo = mid + 1\n        else:\n            hi = mid - 1\n    return -1\n",
       "from solution import binary_search\n\ndef test_binary_search():\n    assert binary_search([1, 3, 5, 7], 7) == 3\n    assert binary_search([1, 3, 5, 7], 1) == 0\n    assert binary_search([1, 3, 5, 7], 4) == -1\n",
       "def binary_search(arr, target):\n    lo, hi = 0, len(arr) - 1\n    while lo <= hi:\n        mid = (lo + hi) // 2\n        if arr[mid] == target:\n            return mid\n        elif arr[mid] < target:\n            lo = mid + 1\n        else:\n            hi = mid - 1\n    return -1\n", tags=["bugfix"]),

    _t("avg_empty", "average(nums) should return the mean, or 0.0 for an empty list. Fix the ZeroDivisionError.",
       "def average(nums):\n    return sum(nums) / len(nums)\n",
       "from solution import average\n\ndef test_average():\n    assert average([2, 4]) == 3.0\n    assert average([]) == 0.0\n",
       "def average(nums):\n    if not nums:\n        return 0.0\n    return sum(nums) / len(nums)\n", tags=["bugfix", "edge-case"]),

    _t("dict_iter_mutate", "drop_negatives(d) should return a dict without negative values. Fix the 'changed size during iteration' bug.",
       "def drop_negatives(d):\n    for k in d:\n        if d[k] < 0:\n            del d[k]\n    return d\n",
       "from solution import drop_negatives\n\ndef test_drop_negatives():\n    assert drop_negatives({'a': 1, 'b': -2, 'c': 3}) == {'a': 1, 'c': 3}\n    assert drop_negatives({}) == {}\n",
       "def drop_negatives(d):\n    return {k: v for k, v in d.items() if v >= 0}\n", tags=["bugfix"]),

    _t("rotate_list", "rotate(items, k) should rotate the list right by k (k may exceed len). Fix the crash/incorrect result on k >= len.",
       "def rotate(items, k):\n    return items[-k:] + items[:-k]\n",
       "from solution import rotate\n\ndef test_rotate():\n    assert rotate([1, 2, 3, 4, 5], 2) == [4, 5, 1, 2, 3]\n    assert rotate([1, 2, 3], 3) == [1, 2, 3]\n    assert rotate([1, 2, 3], 0) == [1, 2, 3]\n",
       "def rotate(items, k):\n    if not items:\n        return items\n    k %= len(items)\n    if k == 0:\n        return list(items)\n    return items[-k:] + items[:-k]\n", tags=["bugfix", "edge-case"]),

    _t("title_case", "title_case(s) should upper-case the first letter of each word and lower-case the rest. Fix the bug that upper-cases everything.",
       "def title_case(s):\n    return ' '.join(w.upper() for w in s.split())\n",
       "from solution import title_case\n\ndef test_title_case():\n    assert title_case('hELLO wORLD') == 'Hello World'\n    assert title_case('') == ''\n",
       "def title_case(s):\n    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())\n", tags=["bugfix"]),

    # --- security (security-first core) --------------------------------------------
    _t("safe_path_join", "safe_path_join(base, name) should join name under base, but REJECT path traversal (raise ValueError if the result escapes base).",
       "import os\n\ndef safe_path_join(base, name):\n    return os.path.join(base, name)\n",
       "import pytest\nfrom solution import safe_path_join\n\ndef test_safe_path_join():\n    # separator-agnostic: os.path.join is correct code but yields '\\\\' on Windows.\n    # What matters is the SECURITY property (traversal is rejected), not the OS separator.\n    assert safe_path_join('/data', 'a.txt').replace('\\\\', '/') == '/data/a.txt'\n    with pytest.raises(ValueError):\n        safe_path_join('/data', '../etc/passwd')\n    with pytest.raises(ValueError):\n        safe_path_join('/data', '/etc/passwd')\n",
       "import posixpath\n\ndef safe_path_join(base, name):\n    base_norm = posixpath.normpath(base)\n    full = posixpath.normpath(posixpath.join(base_norm, name))\n    if full != base_norm and not full.startswith(base_norm + '/'):\n        raise ValueError('path escapes base directory')\n    return posixpath.join(base, name)\n", tags=["security", "edge-case"]),

    _t("param_query", "build_user_query(username) must build a PARAMETERIZED query, not string concatenation. Return (sql, params) with a placeholder. Fix the SQL-injection bug.",
       "def build_user_query(username):\n    sql = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n    return sql, ()\n",
       "from solution import build_user_query\n\ndef test_param_query():\n    sql, params = build_user_query(\"bob\")\n    assert '?' in sql or '%s' in sql\n    assert params == ('bob',)\n    # an injection payload must NOT end up inside the SQL text\n    sql2, params2 = build_user_query(\"x'; DROP TABLE users; --\")\n    assert 'DROP TABLE' not in sql2\n    assert params2 == (\"x'; DROP TABLE users; --\",)\n",
       "def build_user_query(username):\n    sql = 'SELECT * FROM users WHERE name = ?'\n    return sql, (username,)\n", tags=["security", "bugfix"]),

    _t("token_from_env", "get_api_token() must read the token from the API_TOKEN environment variable, never a hardcoded secret. Remove the hardcoded key.",
       "import os\n\ndef get_api_token():\n    return 'sk-live-abc123hardcodedsecret'\n",
       "import os\nfrom solution import get_api_token\n\ndef test_token_from_env(monkeypatch):\n    monkeypatch.setenv('API_TOKEN', 'from-env-xyz')\n    assert get_api_token() == 'from-env-xyz'\n    monkeypatch.delenv('API_TOKEN', raising=False)\n    assert get_api_token() in (None, '')\n",
       "import os\n\ndef get_api_token():\n    return os.environ.get('API_TOKEN')\n", tags=["security", "bugfix"], forbidden=["sk-live-abc123hardcodedsecret"]),

    _t("sanitize_filename", "sanitize_filename(name) should return a safe base filename: strip any directory components and path separators.",
       "def sanitize_filename(name):\n    raise NotImplementedError\n",
       "from solution import sanitize_filename\n\ndef test_sanitize_filename():\n    assert sanitize_filename('report.txt') == 'report.txt'\n    assert sanitize_filename('../../etc/passwd') == 'passwd'\n    assert sanitize_filename('a/b/c.log') == 'c.log'\n    assert sanitize_filename('') == ''\n",
       "import os\n\ndef sanitize_filename(name):\n    return os.path.basename(name.replace('\\\\', '/').rstrip('/'))\n", tags=["security"]),

    _t("safe_int", "safe_int(s, default=0) should parse s as an int, returning default on any bad input (never raise).",
       "def safe_int(s, default=0):\n    return int(s)\n",
       "from solution import safe_int\n\ndef test_safe_int():\n    assert safe_int('42') == 42\n    assert safe_int('nope') == 0\n    assert safe_int(None, -1) == -1\n    assert safe_int('3.5', 7) == 7\n",
       "def safe_int(s, default=0):\n    try:\n        return int(s)\n    except (TypeError, ValueError):\n        return default\n", tags=["edge-case", "bugfix"]),

    # --- SECURITY: extra signal for the gap the base model actually fails ---------
    # The held-out test set exposes two security failures (get_token, safe_path_join).
    # These TRAIN tasks teach the same skills on DIFFERENT functions (no test leakage):
    # path-traversal containment, command injection, secret hygiene, unsafe eval.
    _t("resolve_in_root", "resolve_in_root(root, rel) must return the normalized path of rel under root, and raise ValueError if rel escapes root (path traversal). Fix the vulnerability.",
       "import posixpath\n\ndef resolve_in_root(root, rel):\n    return posixpath.join(root, rel)\n",
       "import pytest\nfrom solution import resolve_in_root\n\ndef test_resolve_in_root():\n    assert resolve_in_root('/srv/data', 'a/b.txt') == '/srv/data/a/b.txt'\n    with pytest.raises(ValueError):\n        resolve_in_root('/srv/data', '../../etc/passwd')\n    with pytest.raises(ValueError):\n        resolve_in_root('/srv/data', '/etc/passwd')\n",
       "import posixpath\n\ndef resolve_in_root(root, rel):\n    root_norm = posixpath.normpath(root)\n    full = posixpath.normpath(posixpath.join(root_norm, rel))\n    if full != root_norm and not full.startswith(root_norm + '/'):\n        raise ValueError('path escapes root')\n    return full\n", tags=["security", "edge-case"]),

    _t("build_command", "build_command(filename) must return an argv LIST for subprocess (never a shell string), so a filename cannot inject shell commands. Fix the command-injection bug.",
       "def build_command(filename):\n    return 'cat ' + filename\n",
       "from solution import build_command\n\ndef test_build_command():\n    cmd = build_command('notes.txt')\n    assert isinstance(cmd, list)\n    assert cmd == ['cat', 'notes.txt']\n    evil = build_command('a.txt; rm -rf /')\n    assert isinstance(evil, list)\n    assert evil == ['cat', 'a.txt; rm -rf /']\n",
       "def build_command(filename):\n    return ['cat', filename]\n", tags=["security", "bugfix"]),

    _t("redact_secrets", "redact_secrets(line) must replace the VALUE of any API_TOKEN=... or PASSWORD=... in a log line with *** so secrets are never logged. Leave the rest of the line unchanged.",
       "def redact_secrets(line):\n    return line\n",
       "from solution import redact_secrets\n\ndef test_redact_secrets():\n    assert redact_secrets('API_TOKEN=sk-live-abc123') == 'API_TOKEN=***'\n    assert redact_secrets('user=bob PASSWORD=hunter2') == 'user=bob PASSWORD=***'\n    assert redact_secrets('nothing to hide') == 'nothing to hide'\n",
       "import re\n\ndef redact_secrets(line):\n    return re.sub(r'(API_TOKEN|PASSWORD)=\\S+', r'\\1=***', line)\n", tags=["security"]),

    _t("safe_load_config", "safe_load_config(text) must parse the config as JSON. NEVER eval/exec untrusted input. Return the parsed dict, or {} if the text is not a valid JSON object.",
       "def safe_load_config(text):\n    return eval(text)\n",
       "from solution import safe_load_config\n\ndef test_safe_load_config():\n    assert safe_load_config('{\"a\": 1}') == {'a': 1}\n    assert safe_load_config('not json') == {}\n    assert safe_load_config('__import__(\"os\").system(\"echo pwned\")') == {}\n",
       "import json\n\ndef safe_load_config(text):\n    try:\n        data = json.loads(text)\n    except Exception:\n        return {}\n    return data if isinstance(data, dict) else {}\n", tags=["security", "bugfix"], forbidden=["eval(", "exec("]),
]
