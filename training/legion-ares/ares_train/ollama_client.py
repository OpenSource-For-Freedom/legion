"""
Minimal Ollama client (stdlib only) — loopback chat for the teacher and the
Ollama-based evaluator. think=False disables Qwen3's chain-of-thought (otherwise
a 4B emits a long <think> block and takes minutes); num_predict bounds length.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")


def _check_loopback(host: str) -> None:
    if os.environ.get("LEGION_ALLOW_REMOTE_OLLAMA") == "1":
        return
    h = host.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    if h not in {"localhost", "127.0.0.1", "::1"} and not h.startswith("127."):
        raise ValueError(f"refusing non-loopback Ollama host {host!r} "
                         "(set LEGION_ALLOW_REMOTE_OLLAMA=1 to override)")


def _post(host: str, path: str, payload: dict, timeout: float) -> dict:
    _check_loopback(host)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(host.rstrip("/") + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def is_up(host: str = DEFAULT_HOST, timeout: float = 5.0) -> bool:
    try:
        _check_loopback(host)
        req = urllib.request.Request(host.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def list_models(host: str = DEFAULT_HOST, timeout: float = 5.0) -> list[str]:
    req = urllib.request.Request(host.rstrip("/") + "/api/tags")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    return [m["name"] for m in body.get("models", [])]


def chat(model: str, system: str, user: str, *, host: str = DEFAULT_HOST,
         temperature: float = 0.3, num_ctx: int = 4096, timeout: float = 120.0,
         think: bool | None = False, num_predict: int = 512) -> str:
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": num_ctx, "num_predict": num_predict},
    }
    if think is not None:
        payload["think"] = think
    try:
        body = _post(host, "/api/chat", payload, timeout)
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace") if hasattr(e, "read") else ""
        if e.code == 400 and "think" in msg.lower():
            payload.pop("think", None)
            body = _post(host, "/api/chat", payload, timeout)
        else:
            raise
    content = body.get("message", {}).get("content", "")
    if "</think>" in content:
        content = content.rsplit("</think>", 1)[-1]
    return content.strip()
