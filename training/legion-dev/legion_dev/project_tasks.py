"""Multi-file PROJECT tasks — the end-to-end tier of the training platform.

Single-file tasks (tasks.py) train "fix this function". They cannot train "build this
project", because they contain no projects: one solution file, one test file. This module
adds the missing tier: each task is a small, real, MULTI-FILE package where the tests import
ACROSS modules, so the agent must scaffold several files, wire a package together, run the
suite, read the failure, and iterate — the actual loop that breaks on app requests today.

Contract (mirrors Task, but every field is a {relpath: content} map, not one string):
  - starter   : files present when the agent starts (stubs / partial scaffold / empty pkg)
  - tests      : pristine pytest files (the SPEC). Never shown-then-edited, never graded-on-self.
  - reference  : a verified COMPLETE solution (all non-test files) that passes `tests`.
Grading is by EXECUTION over the final workspace (executor.run_project), never by string match.
Every reference here is checked by verify_project_references() — a task whose reference does
not pass its own tests is a poisoned label and must not train.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProjectTask:
    name: str
    prompt: str
    starter: dict[str, str]     # {relpath: content} present at start
    tests: dict[str, str]       # {relpath: content} pristine pytest spec
    reference: dict[str, str]   # {relpath: content} verified complete solution (non-test files)
    tags: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)

    # --- convenience for the eval/executor (mirror Task's single-file surface) ---
    @property
    def test_files(self) -> set[str]:
        return set(self.tests)

    def seed(self) -> dict[str, str]:
        """The full workspace the agent starts from: starter files + the pristine tests."""
        return {**self.starter, **self.tests}


def _pt(name, prompt, starter, tests, reference, **kw):
    return ProjectTask(name=name, prompt=prompt, starter=starter, tests=tests,
                       reference=reference, **kw)


# ---------------------------------------------------------------------------------------------
# The pool. Kept small per task (2-4 files) but genuinely cross-module. Prompts describe the
# WHOLE deliverable; starters give a package skeleton with NotImplementedError stubs so the
# agent must implement + wire, not just paste one function.
# ---------------------------------------------------------------------------------------------

PROJECT_TASKS: list[ProjectTask] = [

    _pt("calc_package",
        "Build a `calc` Python package. `calc/operations.py` must define add, sub, mul, and "
        "div(a, b) where div raises ValueError on divide-by-zero. `calc/__init__.py` must "
        "re-export all four so `from calc import add, sub, mul, div` works. Make the tests pass.",
        starter={
            "calc/__init__.py": "",
            "calc/operations.py": "def add(a, b):\n    raise NotImplementedError\n",
        },
        tests={
            "test_calc.py": (
                "import pytest\n"
                "from calc import add, sub, mul, div\n\n"
                "def test_ops():\n"
                "    assert add(2, 3) == 5\n"
                "    assert sub(5, 2) == 3\n"
                "    assert mul(3, 4) == 12\n"
                "    assert div(10, 2) == 5\n\n"
                "def test_div_zero():\n"
                "    with pytest.raises(ValueError):\n"
                "        div(1, 0)\n"
            ),
        },
        reference={
            "calc/__init__.py": "from .operations import add, sub, mul, div\n",
            "calc/operations.py": (
                "def add(a, b):\n    return a + b\n\n"
                "def sub(a, b):\n    return a - b\n\n"
                "def mul(a, b):\n    return a * b\n\n"
                "def div(a, b):\n    if b == 0:\n        raise ValueError('divide by zero')\n    return a / b\n"
            ),
        },
        tags=["project", "package"]),

    _pt("todo_store",
        "Build a `todo` package with an in-memory task store. `todo/store.py` defines a "
        "`TodoStore` class: add(text) returns a new integer id (starting at 1); list() returns "
        "the items as dicts {id, text, done} in insertion order; complete(id) marks one done "
        "(raise KeyError for an unknown id); remaining() returns the count of not-done items. "
        "`todo/__init__.py` re-exports TodoStore.",
        starter={
            "todo/__init__.py": "",
            "todo/store.py": "class TodoStore:\n    def __init__(self):\n        raise NotImplementedError\n",
        },
        tests={
            "test_todo.py": (
                "import pytest\n"
                "from todo import TodoStore\n\n"
                "def test_add_and_list():\n"
                "    s = TodoStore()\n"
                "    a = s.add('write tests')\n"
                "    b = s.add('ship it')\n"
                "    assert a == 1 and b == 2\n"
                "    items = s.list()\n"
                "    assert [i['text'] for i in items] == ['write tests', 'ship it']\n"
                "    assert all(i['done'] is False for i in items)\n\n"
                "def test_complete_and_remaining():\n"
                "    s = TodoStore()\n"
                "    s.add('a'); s.add('b')\n"
                "    assert s.remaining() == 2\n"
                "    s.complete(1)\n"
                "    assert s.remaining() == 1\n"
                "    assert s.list()[0]['done'] is True\n"
                "    with pytest.raises(KeyError):\n"
                "        s.complete(99)\n"
            ),
        },
        reference={
            "todo/__init__.py": "from .store import TodoStore\n",
            "todo/store.py": (
                "class TodoStore:\n"
                "    def __init__(self):\n"
                "        self._items = []\n"
                "        self._next = 1\n\n"
                "    def add(self, text):\n"
                "        tid = self._next\n"
                "        self._next += 1\n"
                "        self._items.append({'id': tid, 'text': text, 'done': False})\n"
                "        return tid\n\n"
                "    def list(self):\n"
                "        return [dict(i) for i in self._items]\n\n"
                "    def _find(self, tid):\n"
                "        for i in self._items:\n"
                "            if i['id'] == tid:\n"
                "                return i\n"
                "        raise KeyError(tid)\n\n"
                "    def complete(self, tid):\n"
                "        self._find(tid)['done'] = True\n\n"
                "    def remaining(self):\n"
                "        return sum(1 for i in self._items if not i['done'])\n"
            ),
        },
        tags=["project", "package", "state"]),

    _pt("ds_package",
        "Build a `ds` data-structures package with two modules. `ds/stack.py` defines Stack "
        "(push, pop -> raises IndexError when empty, peek, is_empty, __len__). `ds/queue.py` "
        "defines Queue (enqueue, dequeue -> raises IndexError when empty, is_empty, __len__, "
        "FIFO order). `ds/__init__.py` re-exports both.",
        starter={
            "ds/__init__.py": "",
            "ds/stack.py": "class Stack:\n    pass\n",
            "ds/queue.py": "class Queue:\n    pass\n",
        },
        tests={
            "test_ds.py": (
                "import pytest\n"
                "from ds import Stack, Queue\n\n"
                "def test_stack():\n"
                "    s = Stack()\n"
                "    assert s.is_empty()\n"
                "    s.push(1); s.push(2)\n"
                "    assert len(s) == 2 and s.peek() == 2\n"
                "    assert s.pop() == 2 and s.pop() == 1\n"
                "    with pytest.raises(IndexError):\n"
                "        s.pop()\n\n"
                "def test_queue():\n"
                "    q = Queue()\n"
                "    assert q.is_empty()\n"
                "    q.enqueue('a'); q.enqueue('b')\n"
                "    assert len(q) == 2\n"
                "    assert q.dequeue() == 'a' and q.dequeue() == 'b'\n"
                "    with pytest.raises(IndexError):\n"
                "        q.dequeue()\n"
            ),
        },
        reference={
            "ds/__init__.py": "from .stack import Stack\nfrom .queue import Queue\n",
            "ds/stack.py": (
                "class Stack:\n"
                "    def __init__(self):\n        self._data = []\n\n"
                "    def push(self, x):\n        self._data.append(x)\n\n"
                "    def pop(self):\n"
                "        if not self._data:\n            raise IndexError('pop from empty stack')\n"
                "        return self._data.pop()\n\n"
                "    def peek(self):\n        return self._data[-1]\n\n"
                "    def is_empty(self):\n        return not self._data\n\n"
                "    def __len__(self):\n        return len(self._data)\n"
            ),
            "ds/queue.py": (
                "from collections import deque\n\n"
                "class Queue:\n"
                "    def __init__(self):\n        self._data = deque()\n\n"
                "    def enqueue(self, x):\n        self._data.append(x)\n\n"
                "    def dequeue(self):\n"
                "        if not self._data:\n            raise IndexError('dequeue from empty queue')\n"
                "        return self._data.popleft()\n\n"
                "    def is_empty(self):\n        return not self._data\n\n"
                "    def __len__(self):\n        return len(self._data)\n"
            ),
        },
        tags=["project", "package", "data-structures"]),

    _pt("pubsub",
        "Build an `events` package with a synchronous pub/sub event emitter. `events/emitter.py` "
        "defines EventEmitter: on(name, handler) subscribes; emit(name, *args) calls every "
        "handler for that event in subscription order; off(name, handler) unsubscribes; "
        "emit on an unknown event is a no-op. `events/__init__.py` re-exports EventEmitter.",
        starter={
            "events/__init__.py": "",
            "events/emitter.py": "class EventEmitter:\n    def on(self, name, handler):\n        raise NotImplementedError\n",
        },
        tests={
            "test_events.py": (
                "from events import EventEmitter\n\n"
                "def test_emit_order_and_off():\n"
                "    e = EventEmitter()\n"
                "    seen = []\n"
                "    def h1(x): seen.append(('h1', x))\n"
                "    def h2(x): seen.append(('h2', x))\n"
                "    e.on('tick', h1); e.on('tick', h2)\n"
                "    e.emit('tick', 1)\n"
                "    assert seen == [('h1', 1), ('h2', 1)]\n"
                "    e.off('tick', h1)\n"
                "    e.emit('tick', 2)\n"
                "    assert seen[-1] == ('h2', 2)\n\n"
                "def test_unknown_event_noop():\n"
                "    e = EventEmitter()\n"
                "    e.emit('nope', 1, 2, 3)\n"
            ),
        },
        reference={
            "events/__init__.py": "from .emitter import EventEmitter\n",
            "events/emitter.py": (
                "class EventEmitter:\n"
                "    def __init__(self):\n        self._handlers = {}\n\n"
                "    def on(self, name, handler):\n"
                "        self._handlers.setdefault(name, []).append(handler)\n\n"
                "    def off(self, name, handler):\n"
                "        if name in self._handlers and handler in self._handlers[name]:\n"
                "            self._handlers[name].remove(handler)\n\n"
                "    def emit(self, name, *args):\n"
                "        for h in list(self._handlers.get(name, [])):\n"
                "            h(*args)\n"
            ),
        },
        tags=["project", "package", "events"]),

    _pt("state_machine",
        "Build an `sm` package with a finite state machine. `sm/machine.py` defines "
        "StateMachine(initial, transitions) where transitions is {(state, event): next_state}. "
        "Methods: state (property, current state); fire(event) moves to the next state and "
        "returns it, or raises ValueError if (current_state, event) has no transition; "
        "can(event) returns bool. `sm/__init__.py` re-exports StateMachine.",
        starter={
            "sm/__init__.py": "",
            "sm/machine.py": "class StateMachine:\n    def __init__(self, initial, transitions):\n        raise NotImplementedError\n",
        },
        tests={
            "test_sm.py": (
                "import pytest\n"
                "from sm import StateMachine\n\n"
                "TRANS = {('idle', 'start'): 'running', ('running', 'stop'): 'idle', ('running', 'pause'): 'paused', ('paused', 'start'): 'running'}\n\n"
                "def test_transitions():\n"
                "    m = StateMachine('idle', TRANS)\n"
                "    assert m.state == 'idle'\n"
                "    assert m.fire('start') == 'running'\n"
                "    assert m.can('pause') is True\n"
                "    assert m.fire('pause') == 'paused'\n"
                "    assert m.fire('start') == 'running'\n\n"
                "def test_invalid_transition():\n"
                "    m = StateMachine('idle', TRANS)\n"
                "    assert m.can('stop') is False\n"
                "    with pytest.raises(ValueError):\n"
                "        m.fire('stop')\n"
                "    assert m.state == 'idle'\n"
            ),
        },
        reference={
            "sm/__init__.py": "from .machine import StateMachine\n",
            "sm/machine.py": (
                "class StateMachine:\n"
                "    def __init__(self, initial, transitions):\n"
                "        self._state = initial\n"
                "        self._t = dict(transitions)\n\n"
                "    @property\n"
                "    def state(self):\n        return self._state\n\n"
                "    def can(self, event):\n        return (self._state, event) in self._t\n\n"
                "    def fire(self, event):\n"
                "        key = (self._state, event)\n"
                "        if key not in self._t:\n"
                "            raise ValueError(f'no transition for {event!r} from {self._state!r}')\n"
                "        self._state = self._t[key]\n"
                "        return self._state\n"
            ),
        },
        tags=["project", "package", "state"]),

    _pt("inventory_service",
        "Build an `inventory` package split into a model and a service. `inventory/model.py` "
        "defines an Item dataclass (name: str, price: float, qty: int). `inventory/service.py` "
        "defines Inventory: add(item), remove(name) (raise KeyError if missing), total_value() "
        "(sum of price*qty), low_stock(threshold) (names with qty < threshold, in insertion "
        "order). `inventory/__init__.py` re-exports Item and Inventory.",
        starter={
            "inventory/__init__.py": "",
            "inventory/model.py": "# define the Item dataclass here\n",
            "inventory/service.py": "# define the Inventory service here\n",
        },
        tests={
            "test_inventory.py": (
                "import pytest\n"
                "from inventory import Item, Inventory\n\n"
                "def test_service():\n"
                "    inv = Inventory()\n"
                "    inv.add(Item('nails', 0.10, 100))\n"
                "    inv.add(Item('hammer', 12.0, 3))\n"
                "    assert inv.total_value() == pytest.approx(0.10 * 100 + 12.0 * 3)\n"
                "    assert inv.low_stock(10) == ['hammer']\n"
                "    inv.remove('nails')\n"
                "    assert inv.total_value() == pytest.approx(36.0)\n"
                "    with pytest.raises(KeyError):\n"
                "        inv.remove('nope')\n"
            ),
        },
        reference={
            "inventory/__init__.py": "from .model import Item\nfrom .service import Inventory\n",
            "inventory/model.py": (
                "from dataclasses import dataclass\n\n"
                "@dataclass\n"
                "class Item:\n    name: str\n    price: float\n    qty: int\n"
            ),
            "inventory/service.py": (
                "class Inventory:\n"
                "    def __init__(self):\n        self._items = []\n\n"
                "    def add(self, item):\n        self._items.append(item)\n\n"
                "    def remove(self, name):\n"
                "        for i, it in enumerate(self._items):\n"
                "            if it.name == name:\n                del self._items[i]\n                return\n"
                "        raise KeyError(name)\n\n"
                "    def total_value(self):\n        return sum(it.price * it.qty for it in self._items)\n\n"
                "    def low_stock(self, threshold):\n        return [it.name for it in self._items if it.qty < threshold]\n"
            ),
        },
        tags=["project", "package", "dataclass"]),

    # --------- held-out PROJECT test set (never trained on) -----------------------------------

    _pt("router_dispatch",
        "Build a `web` package with a tiny HTTP-style router (no server). `web/router.py` "
        "defines Router: route(path, method='GET') is a DECORATOR registering a handler; "
        "dispatch(path, method='GET') calls the matching handler and returns its value, or "
        "raises LookupError (404) when nothing matches. `web/__init__.py` re-exports Router.",
        starter={
            "web/__init__.py": "",
            "web/router.py": "class Router:\n    def route(self, path, method='GET'):\n        raise NotImplementedError\n",
        },
        tests={
            "test_web.py": (
                "import pytest\n"
                "from web import Router\n\n"
                "def test_routing():\n"
                "    app = Router()\n\n"
                "    @app.route('/ping')\n"
                "    def ping():\n        return 'pong'\n\n"
                "    @app.route('/users', method='POST')\n"
                "    def create():\n        return 'created'\n\n"
                "    assert app.dispatch('/ping') == 'pong'\n"
                "    assert app.dispatch('/users', 'POST') == 'created'\n"
                "    with pytest.raises(LookupError):\n"
                "        app.dispatch('/ping', 'POST')\n"
                "    with pytest.raises(LookupError):\n"
                "        app.dispatch('/missing')\n"
            ),
        },
        reference={
            "web/__init__.py": "from .router import Router\n",
            "web/router.py": (
                "class Router:\n"
                "    def __init__(self):\n        self._routes = {}\n\n"
                "    def route(self, path, method='GET'):\n"
                "        def deco(fn):\n"
                "            self._routes[(method, path)] = fn\n"
                "            return fn\n"
                "        return deco\n\n"
                "    def dispatch(self, path, method='GET'):\n"
                "        fn = self._routes.get((method, path))\n"
                "        if fn is None:\n            raise LookupError(f'404 {method} {path}')\n"
                "        return fn()\n"
            ),
        },
        tags=["project", "package", "web", "held-out"]),

    _pt("config_merge",
        "Build a `conf` package that layers configuration. `conf/loader.py` defines "
        "load(*layers) where each layer is a dict; later layers override earlier ones, "
        "MERGING nested dicts recursively (not replacing them). `conf/__init__.py` re-exports "
        "load. Return a new dict; never mutate the inputs.",
        starter={
            "conf/__init__.py": "",
            "conf/loader.py": "def load(*layers):\n    raise NotImplementedError\n",
        },
        tests={
            "test_conf.py": (
                "from conf import load\n\n"
                "def test_deep_merge():\n"
                "    base = {'db': {'host': 'localhost', 'port': 5432}, 'debug': False}\n"
                "    override = {'db': {'port': 6543}, 'debug': True}\n"
                "    merged = load(base, override)\n"
                "    assert merged == {'db': {'host': 'localhost', 'port': 6543}, 'debug': True}\n"
                "    # inputs untouched\n"
                "    assert base['db']['port'] == 5432\n"
                "    assert load() == {}\n"
            ),
        },
        reference={
            "conf/__init__.py": "from .loader import load\n",
            "conf/loader.py": (
                "import copy\n\n"
                "def _merge(a, b):\n"
                "    out = copy.deepcopy(a)\n"
                "    for k, v in b.items():\n"
                "        if k in out and isinstance(out[k], dict) and isinstance(v, dict):\n"
                "            out[k] = _merge(out[k], v)\n"
                "        else:\n            out[k] = copy.deepcopy(v)\n"
                "    return out\n\n"
                "def load(*layers):\n"
                "    result = {}\n"
                "    for layer in layers:\n        result = _merge(result, layer)\n"
                "    return result\n"
            ),
        },
        tags=["project", "package", "held-out"]),

    _pt("csv_report",
        "Build a `report` package that summarizes CSV rows. `report/parse.py` defines "
        "parse_rows(text) -> list of dicts (first line is the header, comma-separated). "
        "`report/summary.py` defines total_by(rows, key_col, value_col) -> dict mapping each "
        "distinct key to the SUM of the numeric value column. `report/__init__.py` re-exports "
        "both. Handle a trailing newline and empty input (empty text -> []).",
        starter={
            "report/__init__.py": "",
            "report/parse.py": "def parse_rows(text):\n    raise NotImplementedError\n",
            "report/summary.py": "def total_by(rows, key_col, value_col):\n    raise NotImplementedError\n",
        },
        tests={
            "test_report.py": (
                "from report import parse_rows, total_by\n\n"
                "CSV = 'region,amount\\nwest,10\\neast,5\\nwest,7\\n'\n\n"
                "def test_parse_and_summary():\n"
                "    rows = parse_rows(CSV)\n"
                "    assert rows == [\n"
                "        {'region': 'west', 'amount': '10'},\n"
                "        {'region': 'east', 'amount': '5'},\n"
                "        {'region': 'west', 'amount': '7'},\n"
                "    ]\n"
                "    assert total_by(rows, 'region', 'amount') == {'west': 17, 'east': 5}\n"
                "    assert parse_rows('') == []\n"
            ),
        },
        reference={
            "report/__init__.py": "from .parse import parse_rows\nfrom .summary import total_by\n",
            "report/parse.py": (
                "def parse_rows(text):\n"
                "    lines = [ln for ln in text.splitlines() if ln.strip()]\n"
                "    if not lines:\n        return []\n"
                "    header = lines[0].split(',')\n"
                "    return [dict(zip(header, ln.split(','))) for ln in lines[1:]]\n"
            ),
            "report/summary.py": (
                "def total_by(rows, key_col, value_col):\n"
                "    out = {}\n"
                "    for r in rows:\n"
                "        out[r[key_col]] = out.get(r[key_col], 0) + int(r[value_col])\n"
                "    return out\n"
            ),
        },
        tags=["project", "package", "held-out"]),
]


# Train / held-out split. The held-out set is what the agent eval scores on; the train set is
# what trajectories are synthesized from. No project appears in both (no leakage).
_HELD_OUT = {"router_dispatch", "config_merge", "csv_report"}


def project_train_tasks() -> list[ProjectTask]:
    return [t for t in PROJECT_TASKS if t.name not in _HELD_OUT]


def project_test_tasks() -> list[ProjectTask]:
    return [t for t in PROJECT_TASKS if t.name in _HELD_OUT]
