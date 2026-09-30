"""The wire record: what the agent actually asked the model, kept outside the agent.

Idea credit: NVIDIA's Open Agent Safety Platform — monitoring "on the node's
only path to the model", out of the agent's reach — and its premise that "an
agent … cannot be expected to fully govern its own behavior".

An agent's own audit log and traces live in the process they audit, so a
compromised agent can drop entries. This proxy sits on the model path and
outside that process, so with ``PROXY_WIRE_RECORD`` set it appends one line
per model response:

    {"ts", "host", "path", "status", "model", "request_sha256", "response_bytes",
     "tool_calls": [{"name", "args_sha256"}], "prev", "hash"}

- **Never text.** Tool names, argument *hashes* and sizes only — no prompt, no
  response, no argument values.
- **Hash-chained.** Each line's ``hash`` covers its content and the previous
  line's hash, so editing, deleting or reordering a line breaks the chain from
  there on (``python -m secrets_proxy.wire_record verify FILE``). That is
  tamper-*evident*, not tamper-proof: anyone who can rewrite the whole file can
  rebuild the chain, so keep the file where the agent can't write and copy the
  latest hash off the box (backups) to anchor it.

The agent-side check (prax ``scripts/check_wire_record.py``) compares these
tool calls with the agent's own trace; a tool call on the wire the trace
doesn't show is the signal.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from typing import Any

logger = logging.getLogger("secrets_proxy.wire_record")

GENESIS = "0" * 64
# Hosts whose responses are model calls. Extend with PROXY_WIRE_RECORD_HOSTS.
DEFAULT_HOSTS = ("api.openai.com", "openrouter.ai", "api.anthropic.com")


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _args_hash(args: Any) -> str:
    """Hash of a tool call's arguments, canonical whether they came as a JSON
    string (OpenAI) or an object (Anthropic)."""
    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except ValueError:
            return _sha(args)
    return _sha(json.dumps(args, sort_keys=True, separators=(",", ":"), default=str))


# --- extracting tool calls ------------------------------------------------------

def _from_json(doc: dict) -> tuple[list[dict], str]:
    calls: list[dict] = []
    for choice in doc.get("choices") or []:                      # OpenAI chat
        for tc in ((choice or {}).get("message") or {}).get("tool_calls") or []:
            fn = tc.get("function") or {}
            calls.append({"name": fn.get("name", "?"), "args_sha256": _args_hash(fn.get("arguments", ""))})
    for item in doc.get("output") or []:                         # OpenAI Responses
        if (item or {}).get("type") == "function_call":
            calls.append({"name": item.get("name", "?"), "args_sha256": _args_hash(item.get("arguments", ""))})
    for block in doc.get("content") or []:                       # Anthropic messages
        if isinstance(block, dict) and block.get("type") == "tool_use":
            calls.append({"name": block.get("name", "?"), "args_sha256": _args_hash(block.get("input") or {})})
    return calls, str(doc.get("model") or "")


def _from_sse(text: str) -> tuple[list[dict], str]:
    """Reassemble streamed tool calls (OpenAI deltas, Anthropic blocks)."""
    oa: dict[int, dict] = {}          # OpenAI: index -> {name, args}
    an: dict[int, dict] = {}          # Anthropic: block index -> {name, args}
    done: list[dict] = []             # OpenAI Responses: completed function calls
    model = ""
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            ev = json.loads(payload)
        except ValueError:
            continue
        model = model or str(ev.get("model") or (ev.get("message") or {}).get("model") or "")
        for choice in ev.get("choices") or []:
            for tc in ((choice or {}).get("delta") or {}).get("tool_calls") or []:
                slot = oa.setdefault(int(tc.get("index", 0)), {"name": "", "args": ""})
                fn = tc.get("function") or {}
                slot["name"] = slot["name"] or fn.get("name") or ""
                slot["args"] += fn.get("arguments") or ""
        kind = ev.get("type")
        if kind == "content_block_start" and (ev.get("content_block") or {}).get("type") == "tool_use":
            an[int(ev.get("index", 0))] = {"name": ev["content_block"].get("name", "?"), "args": ""}
        elif kind == "content_block_delta" and (ev.get("delta") or {}).get("type") == "input_json_delta":
            slot = an.get(int(ev.get("index", 0)))
            if slot is not None:
                slot["args"] += ev["delta"].get("partial_json") or ""
        elif kind == "response.output_item.done" and (ev.get("item") or {}).get("type") == "function_call":
            item = ev["item"]
            done.append({"name": item.get("name", "?"), "args": item.get("arguments", "")})
    calls = [{"name": s["name"] or "?", "args_sha256": _args_hash(s["args"])}
             for _, s in sorted(oa.items())]
    calls += [{"name": s["name"], "args_sha256": _args_hash(s["args"])} for _, s in sorted(an.items())]
    calls += [{"name": s["name"], "args_sha256": _args_hash(s["args"])} for s in done]
    return calls, model


def extract(content_type: str, body: bytes) -> tuple[list[dict], str]:
    """(tool calls, model) from a model response body; ([], "") if unrecognised."""
    text = (body or b"").decode("utf-8", errors="replace")
    if "text/event-stream" in (content_type or "") or text.lstrip().startswith(("data:", "event:")):
        return _from_sse(text)
    try:
        doc = json.loads(text)
    except ValueError:
        return [], ""
    return _from_json(doc) if isinstance(doc, dict) else ([], "")


# --- the record --------------------------------------------------------------------

class WireRecord:
    def __init__(self, path: str, hosts: tuple[str, ...] = DEFAULT_HOSTS):
        self.path = path
        self.hosts = tuple(h.lower() for h in hosts)
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as fh:
                last = b""
                for line in fh:
                    if line.strip():
                        last = line
            return json.loads(last)["hash"] if last else GENESIS
        except FileNotFoundError:
            return GENESIS
        except (OSError, ValueError, KeyError):
            logger.warning("wire record %s unreadable; continuing the chain from genesis", self.path)
            return GENESIS

    def wants(self, host: str) -> bool:
        host = (host or "").lower()
        return any(host == h or host.endswith("." + h) for h in self.hosts)

    def append(self, *, host: str, path: str, status: int, request_body: bytes,
               response_type: str, response_body: bytes) -> dict:
        calls, model = extract(response_type, response_body)
        entry = {
            "ts": round(time.time(), 3), "host": host, "path": path.split("?", 1)[0],
            "status": status, "model": model, "request_sha256": _sha(request_body or b""),
            "response_bytes": len(response_body or b""), "tool_calls": calls,
        }
        with self._lock:
            entry["prev"] = self._prev
            entry["hash"] = _sha(self._prev + json.dumps(
                {k: v for k, v in entry.items() if k not in ("prev", "hash")},
                sort_keys=True, separators=(",", ":")))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            self._prev = entry["hash"]
        return entry


def from_env() -> WireRecord | None:
    path = os.environ.get("PROXY_WIRE_RECORD") or ""
    if not path:
        return None
    extra = tuple(h.strip() for h in (os.environ.get("PROXY_WIRE_RECORD_HOSTS") or "").split(",") if h.strip())
    return WireRecord(path, DEFAULT_HOSTS + extra)


def verify(path: str) -> tuple[bool, str]:
    """Check the chain. (ok, message) — the message names the first bad line."""
    prev, n = GENESIS, 0
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, f"line {n}: not JSON"
            if entry.get("prev") != prev:
                return False, f"line {n}: chain broken (a line before it was removed, edited or reordered)"
            body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
            if _sha(prev + json.dumps(body, sort_keys=True, separators=(",", ":"))) != entry.get("hash"):
                return False, f"line {n}: content does not match its hash (edited)"
            prev = entry["hash"]
    return True, f"{n} lines, chain intact, head {prev[:16]}"


if __name__ == "__main__":  # python -m secrets_proxy.wire_record verify FILE
    if len(sys.argv) != 3 or sys.argv[1] != "verify":
        print("usage: python -m secrets_proxy.wire_record verify FILE", file=sys.stderr)
        sys.exit(2)
    ok, msg = verify(sys.argv[2])
    print(("OK: " if ok else "BROKEN: ") + msg)
    sys.exit(0 if ok else 1)
