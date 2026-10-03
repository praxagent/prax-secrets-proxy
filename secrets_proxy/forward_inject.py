"""Generic, config-driven credential injection for the FORWARD (MITM) proxy.

The reverse-proxy (``app.py``) handles the model APIs, which expose a base-URL
knob. Everything else — Twilio, ElevenLabs, search APIs, … — sends its request
*directly and encrypted* to the real host, so the only way to inject a credential
is a transparent forward proxy that terminates TLS and rewrites the request by
destination host. This module is the injection brain for that proxy; the thin
mitmproxy glue lives in ``mitm_addon.py``.

Design note — this is CONFIG, not per-API code
-----------------------------------------------
Injection is a small finite set of *schemes*, keyed by destination host:
``bearer`` · ``header:<Name>`` · ``basic`` (two envs) · ``query:<param>``. Adding a
service is one rule in the forward-map, never new code. The map is generated from
Prax's canonical credential registry (``credential_registry.py``) so the proxy and
Prax can't drift — see ``docs/security/credentials.md`` in the prax repo.

The real keys are read from THIS process's env at request time; they are never
logged and never returned to the client.
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode

# A dotted JSON path for ws-json:<path>, e.g. d.token.
_WS_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


@dataclass(frozen=True)
class ForwardRule:
    """How to authenticate one destination host.

    ``host`` matches the request host exactly or as a dot-suffix (so ``tavily.com``
    also covers ``api.tavily.com``).
    """
    host: str
    scheme: str                 # bearer | header:<Name> | basic | query:<param> | ws-json:<path>
    key_env: str | None = None  # env var holding the secret (bearer/header/query/ws-json)
    user_env: str | None = None  # basic auth: username env
    pass_env: str | None = None  # basic auth: password env
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Prepended to a header:<Name> value, e.g. "Bot " for Discord's REST API.
    prefix: str = ""
    # Program identities (secrets_proxy/callers.py) this rule injects for; empty =
    # every caller. A rule marked ``exclusive`` MUST name callers: it is for a
    # credential exactly one instance may use (a Discord bot token — two
    # instances holding it both answer every message).
    callers: frozenset[str] = frozenset()
    exclusive: bool = False

    def matches(self, host: str) -> bool:
        h = (host or "").lower()
        return h == self.host or h.endswith("." + self.host)

    def serves(self, caller: str) -> bool:
        return not self.callers or caller in self.callers

    @property
    def websocket(self) -> bool:
        """Injected into WebSocket messages, not HTTP requests."""
        return self.scheme.startswith("ws-json:")


class ForwardInjector:
    """Applies the first matching :class:`ForwardRule` to an outgoing request."""

    def __init__(self, rules: list[ForwardRule]):
        for r in rules:
            if r.exclusive and not r.callers:
                raise ValueError(
                    f"forward map: the rule for {r.host} is exclusive (one instance only) "
                    "and must name its callers — refusing to start rather than hand the "
                    "credential to every caller")
            if r.websocket and not _WS_PATH.fullmatch(r.scheme.split(":", 1)[1]):
                raise ValueError(f"forward map: bad websocket path in {r.scheme!r}")
        # Longest host first so a specific rule wins over a broad suffix.
        self._rules = sorted(rules, key=lambda r: len(r.host), reverse=True)

    # -- construction ------------------------------------------------------
    @classmethod
    def from_map(cls, data: list[dict]) -> ForwardInjector:
        rules = [
            ForwardRule(
                host=d["host"].lower(),
                scheme=d["scheme"],
                key_env=d.get("key_env"),
                user_env=d.get("user_env"),
                pass_env=d.get("pass_env"),
                extra_headers=d.get("extra_headers") or {},
                prefix=str(d.get("prefix") or ""),
                callers=frozenset(str(c) for c in d.get("callers") or ()),
                exclusive=bool(d.get("exclusive", False)),
            )
            for d in data
        ]
        return cls(rules)

    @classmethod
    def from_env(cls) -> ForwardInjector:
        """Load the forward-map from ``PROXY_FORWARD_MAP`` (a JSON file path).

        Empty/unset → an injector with no rules (a pass-through proxy that adds no
        credentials — safe default).
        """
        path = os.environ.get("PROXY_FORWARD_MAP")
        if not path or not os.path.exists(path):
            return cls([])
        with open(path, encoding="utf-8") as fh:
            return cls.from_map(json.load(fh))

    # -- injection ---------------------------------------------------------
    def rule_for(self, host: str) -> ForwardRule | None:
        return next((r for r in self._rules if r.matches(host)), None)

    def secret_available(self, rule: ForwardRule) -> bool:
        if rule.scheme == "basic":
            return bool(os.environ.get(rule.user_env or "") or os.environ.get(rule.pass_env or ""))
        return bool(os.environ.get(rule.key_env or ""))

    def rules_for(self, host: str, caller: str = "") -> list[ForwardRule]:
        """ALL HTTP rules matching *host* that serve *caller*, longest-host first
        (a host may need several injections — e.g. Google CSE needs ?key= and ?cx=)."""
        return [r for r in self._rules if r.matches(host) and not r.websocket and r.serves(caller)]

    def http_rule_for(self, host: str, caller: str = "") -> ForwardRule | None:
        return next(iter(self.rules_for(host, caller)), None)

    def ws_rules_for(self, host: str, caller: str = "") -> list[ForwardRule]:
        return [r for r in self._rules if r.matches(host) and r.websocket and r.serves(caller)]

    def inject_ws_text(self, host: str, text: str, caller: str = "") -> str | None:
        """The client->server WebSocket message with the credential set at each
        matching rule's JSON path, or None if nothing applied (left untouched).

        For protocols that carry the credential in a message rather than a header
        — Discord's gateway sends the bot token in IDENTIFY and RESUME as
        ``d.token``. Only a JSON object that already has the field is changed.
        """
        rules = self.ws_rules_for(host, caller)
        if not rules:
            return None
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        changed = False
        for rule in rules:
            key = os.environ.get(rule.key_env or "")
            *parents, leaf = rule.scheme.split(":", 1)[1].split(".")
            node = doc
            for part in parents:
                node = node.get(part) if isinstance(node, dict) else None
            if key and isinstance(node, dict) and leaf in node:
                node[leaf] = rule.prefix + key
                changed = True
        return json.dumps(doc, separators=(",", ":")) if changed else None

    def inject(self, host: str, headers: dict[str, str], query: str = "",
               caller: str = "") -> tuple[dict[str, str], str]:
        """Return (headers, query_string) with the real credential(s) injected.

        Applies EVERY matching rule for the host. Any client-supplied value in the
        same slot is stripped first — the proxy owns auth, never the (keyless)
        client. If no rule matches or a secret is absent, the request passes
        through unchanged.
        """
        out = dict(headers)
        for rule in self.rules_for(host, caller):
            query = self._apply(rule, out, query)
        return out, query

    def _apply(self, rule: ForwardRule, out: dict[str, str], query: str) -> str:
        scheme = rule.scheme

        if scheme == "bearer":
            key = os.environ.get(rule.key_env or "")
            _strip(out, "authorization")
            if key:
                out["Authorization"] = f"Bearer {key}"

        elif scheme.startswith("header:"):
            name = scheme.split(":", 1)[1]
            key = os.environ.get(rule.key_env or "")
            _strip(out, name.lower())
            if key:
                out[name] = rule.prefix + key

        elif scheme == "basic":
            user = os.environ.get(rule.user_env or "") or ""
            pw = os.environ.get(rule.pass_env or "") or ""
            _strip(out, "authorization")
            if user or pw:
                token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                out["Authorization"] = f"Basic {token}"

        elif scheme.startswith("query:"):
            param = scheme.split(":", 1)[1]
            key = os.environ.get(rule.key_env or "")
            if key:
                pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k != param]
                pairs.append((param, key))
                query = urlencode(pairs)

        for k, v in rule.extra_headers.items():
            out[k] = v
        return query


def _strip(headers: dict[str, str], lower_name: str) -> None:
    """Remove any header whose name matches (case-insensitively)."""
    for k in [k for k in headers if k.lower() == lower_name]:
        del headers[k]
