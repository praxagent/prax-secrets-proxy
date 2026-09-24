"""Egress policy for the forward proxy — what Prax itself may reach, request by request.

Off unless ``PROXY_EGRESS_POLICY`` names a policy file: then the forward proxy
stops passing unknown destinations through and decides every request first.
Because this proxy terminates TLS for all of Prax's traffic (it has to, to
inject keys), the decision sees the whole request — host, port, method AND
path — for HTTPS too.

Policy JSON (same shape as prax-sandbox's egress gate, plus ``paths``)::

    {"default": "ask",
     "rules": [
       {"host": "api.openai.com", "action": "allow"},
       {"host": "discord.com", "action": "allow"},
       {"host": "*.example.com", "methods": ["GET"], "paths": ["/public/"], "action": "allow"},
       {"host": "news.example", "action": "allow", "clean_only": true},
       {"host": "evil.example", "action": "deny"}],
     "allow_private_addresses": []}

``ask`` holds the request while the harness asks a person (admin API, same
contract as the sandbox gate: ``GET /pending``, ``POST /pending/{id}``,
``POST /taint``, ``GET /status``). Answers are remembered per host + method +
path for ``PROXY_EGRESS_ALLOW_TTL`` seconds; an allow given while clean is not
reused once tainted; no answer is a deny. Names are checked against private,
loopback and link-local addresses only after something allowed them — a
denied or merely-asked-about name is never resolved here (run mitmproxy with
``connection_strategy=lazy`` so it does not resolve them either).
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import itertools
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field

logger = logging.getLogger("secrets_proxy.egress")

ALLOW, DENY, ASK = "allow", "deny", "ask"
_ACTIONS = {ALLOW, DENY, ASK}


@dataclass(frozen=True)
class Rule:
    host: str
    action: str
    ports: frozenset[int] = frozenset()
    methods: frozenset[str] = frozenset()
    paths: tuple[str, ...] = ()
    clean_only: bool = False

    def matches(self, host: str, port: int, method: str, path: str, tainted: bool) -> bool:
        h, pat = host.lower().rstrip("."), self.host.lower().rstrip(".")
        if pat == "*":
            pass  # any host; narrow it with methods / paths / clean_only
        elif pat.startswith("*."):
            if not (h.endswith(pat[1:]) and len(h) > len(pat) - 1):
                return False
        elif h != pat:
            return False
        if self.ports and port not in self.ports:
            return False
        if self.methods and method.upper() not in self.methods:
            return False
        if self.paths and not any(path.startswith(p) for p in self.paths):
            return False
        return not (self.clean_only and tainted)


@dataclass
class Policy:
    default: str = ASK
    rules: list[Rule] = field(default_factory=list)
    allow_private_addresses: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        default = str(data.get("default", ASK)).lower()
        if default not in _ACTIONS:
            raise ValueError(f"default must be one of {sorted(_ACTIONS)}")
        rules = []
        for i, raw in enumerate(data.get("rules", [])):
            action = str(raw.get("action", "")).lower()
            if action not in _ACTIONS or not raw.get("host"):
                raise ValueError(f"rule {i}: needs a host and an action in {sorted(_ACTIONS)}")
            rules.append(Rule(
                host=str(raw["host"]), action=action,
                ports=frozenset(int(p) for p in raw.get("ports", [])),
                methods=frozenset(str(m).upper() for m in raw.get("methods", [])),
                paths=tuple(str(p) for p in raw.get("paths", [])),
                clean_only=bool(raw.get("clean_only", False)),
            ))
        return cls(default, rules, frozenset(data.get("allow_private_addresses", [])))

    def decide(self, host: str, port: int, method: str, path: str, tainted: bool) -> tuple[str, str]:
        for i, rule in enumerate(self.rules):
            if rule.matches(host, port, method, path, tainted):
                return rule.action, f"rule {i} ({rule.host})"
        return self.default, "default"


def is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


@dataclass
class _Pending:
    id: str
    key: str
    host: str
    port: int
    method: str
    path: str
    tainted: bool
    future: asyncio.Future
    created: float = field(default_factory=time.monotonic)


class EgressPolicy:
    """Decisions, pending questions, remembered answers and taint."""

    def __init__(self, policy: Policy, admin_token: str, *, ask_timeout: float = 120.0,
                 allow_ttl: float = 600.0, deny_ttl: float = 60.0, taint_ttl: float = 300.0,
                 resolver=None):
        self.policy = policy
        self.admin_token = admin_token
        self.ask_timeout, self.allow_ttl, self.deny_ttl, self.taint_ttl = ask_timeout, allow_ttl, deny_ttl, taint_ttl
        self._resolver = resolver or self._resolve
        self._decisions: dict[str, tuple[str, float, str, bool]] = {}
        self._pending: dict[str, _Pending] = {}
        self._by_key: dict[str, str] = {}
        self._ids = itertools.count(1)
        self._tainted_until = 0.0
        self.taint_reason = ""

    @property
    def tainted(self) -> bool:
        return time.monotonic() < self._tainted_until

    def set_taint(self, tainted: bool, reason: str = "", ttl: float | None = None) -> None:
        if tainted:
            self._tainted_until = time.monotonic() + (ttl or self.taint_ttl)
            self.taint_reason = reason
        else:
            self._tainted_until, self.taint_reason = 0.0, ""

    @staticmethod
    def key(host: str, port: int, method: str, path: str) -> str:
        return f"{host.lower()}:{port} {method.upper()} {path.split('?', 1)[0]}"

    async def check(self, host: str, port: int, method: str, path: str) -> tuple[str, str]:
        """``(allow|deny, reason)`` for one request. May wait for a person."""
        tainted = self.tainted
        action, why = self.policy.decide(host, port, method, path, tainted)
        if action == DENY:
            return DENY, why
        literal = self._literal_refusal(host)
        if literal:
            return DENY, literal
        if action == ASK:
            action, why = await self._asked(host, port, method, path, tainted)
            if action != ALLOW:
                return DENY, why
        refusal = await self._resolved_refusal(host, port)
        return (DENY, refusal) if refusal else (ALLOW, why)

    async def _asked(self, host, port, method, path, tainted) -> tuple[str, str]:
        key = self.key(host, port, method, path)
        cached = self._decisions.get(key)
        if cached and time.monotonic() < cached[1]:
            action, _, why, granted_tainted = cached
            if not (action == ALLOW and tainted and not granted_tainted):
                return action, f"remembered: {why}"
        pid = self._by_key.get(key)
        pending = self._pending.get(pid) if pid else None
        if pending is None:
            pending = _Pending(str(next(self._ids)), key, host, port, method,
                               path.split("?", 1)[0], tainted,
                               asyncio.get_running_loop().create_future())
            self._pending[pending.id], self._by_key[key] = pending, pending.id
        try:
            return await asyncio.wait_for(asyncio.shield(pending.future), self.ask_timeout)
        except TimeoutError:
            self._forget(pending)
            self._decisions[key] = (DENY, time.monotonic() + self.deny_ttl, "no answer", tainted)
            return DENY, "asked; no answer in time"

    def _forget(self, p: _Pending) -> None:
        self._pending.pop(p.id, None)
        if self._by_key.get(p.key) == p.id:
            self._by_key.pop(p.key, None)

    def answer(self, pending_id: str, allow: bool, ttl: float | None = None, by: str = "") -> bool:
        p = self._pending.get(pending_id)
        if p is None:
            return False
        action = ALLOW if allow else DENY
        why = f"{'allowed' if allow else 'denied'} by {by or 'the harness'}"
        if allow and self.tainted and not p.tainted:
            action, why = DENY, "tainted since this was asked; ask again"
        hold = ttl if ttl is not None else (self.allow_ttl if action == ALLOW else self.deny_ttl)
        self._decisions[p.key] = (action, time.monotonic() + hold, why, p.tainted)
        self._forget(p)
        if not p.future.done():
            p.future.set_result((action, why))
        return True

    def pending(self) -> list[dict]:
        now = time.monotonic()
        return [{"id": p.id, "host": p.host, "port": p.port, "method": p.method, "path": p.path,
                 "tainted": p.tainted, "age_seconds": round(now - p.created, 1),
                 "expires_in_seconds": max(0.0, round(self.ask_timeout - (now - p.created), 1))}
                for p in self._pending.values()]

    def _literal_refusal(self, host: str) -> str:
        try:
            ip = str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            return ""
        if not is_public(ip) and ip not in self.policy.allow_private_addresses:
            return f"{host} is a non-public address"
        return ""

    async def _resolve(self, host: str, port: int) -> list[str]:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return list(dict.fromkeys(i[4][0] for i in infos))

    async def _resolved_refusal(self, host: str, port: int) -> str:
        """After an allow: a name that resolves inside is still refused (SSRF)."""
        if self._literal_refusal(host) or _is_ip(host):
            return self._literal_refusal(host)
        try:
            addrs = await self._resolver(host, port)
        except OSError as exc:
            return f"{host} did not resolve ({exc})"
        bad = [a for a in addrs if not is_public(a) and a not in self.policy.allow_private_addresses]
        return f"{host} resolves to a non-public address ({bad[0]})" if bad else ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def from_env() -> EgressPolicy | None:
    path = os.environ.get("PROXY_EGRESS_POLICY", "")
    if not path:
        return None
    token = os.environ.get("PROXY_EGRESS_ADMIN_TOKEN", "")
    if not token:
        raise SystemExit("egress policy: refusing to start without PROXY_EGRESS_ADMIN_TOKEN")
    with open(path) as f:
        policy = Policy.from_dict(json.load(f))
    return EgressPolicy(policy, token,
                        ask_timeout=float(os.environ.get("PROXY_EGRESS_ASK_TIMEOUT", "120")),
                        allow_ttl=float(os.environ.get("PROXY_EGRESS_ALLOW_TTL", "600")))


# --- admin API (same contract as prax-sandbox's egress gate) ---------------------

async def handle_admin(egress: EgressPolicy, reader, writer) -> None:
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(4096)
            if not chunk or len(data) > 65536:
                return
            data += chunk
        head, _, leftover = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
        token = headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not egress.admin_token or not hmac.compare_digest(token, egress.admin_token):
            await _json(writer, 401, {"error": "unauthorized"})
            return
        length = int(headers.get("content-length") or 0)
        raw = leftover + (await reader.readexactly(length - len(leftover)) if length > len(leftover) else b"")
        body = json.loads(raw[:length]) if length else {}
        if method == "GET" and path == "/status":
            await _json(writer, 200, {"tainted": egress.tainted, "taint_reason": egress.taint_reason,
                                      "pending": len(egress._pending)})
        elif method == "GET" and path == "/pending":
            await _json(writer, 200, {"pending": egress.pending()})
        elif method == "POST" and path.startswith("/pending/"):
            ok = egress.answer(path.rsplit("/", 1)[-1], bool(body.get("allow")),
                               ttl=body.get("ttl"), by=str(body.get("by", "")))
            await _json(writer, 200 if ok else 404, {"answered": ok})
        elif method == "POST" and path == "/taint":
            egress.set_taint(bool(body.get("tainted")), str(body.get("reason", "")), body.get("ttl"))
            await _json(writer, 200, {"tainted": egress.tainted})
        else:
            await _json(writer, 404, {"error": "not found"})
    except Exception as exc:  # noqa: BLE001 — one bad admin call must not stop the proxy
        await _json(writer, 400, {"error": str(exc)[:200]})
    finally:
        writer.close()


async def _json(writer, status: int, obj) -> None:
    body = json.dumps(obj).encode()
    writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
                 f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    await writer.drain()
