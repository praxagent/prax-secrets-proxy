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
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode


@dataclass(frozen=True)
class ForwardRule:
    """How to authenticate one destination host.

    ``host`` matches the request host exactly or as a dot-suffix (so ``tavily.com``
    also covers ``api.tavily.com``).
    """
    host: str
    scheme: str                 # bearer | header:<Name> | basic | query:<param>
    key_env: str | None = None  # env var holding the secret (bearer/header/query)
    user_env: str | None = None  # basic auth: username env
    pass_env: str | None = None  # basic auth: password env
    extra_headers: dict[str, str] = field(default_factory=dict)

    def matches(self, host: str) -> bool:
        h = (host or "").lower()
        return h == self.host or h.endswith("." + self.host)


class ForwardInjector:
    """Applies the first matching :class:`ForwardRule` to an outgoing request."""

    def __init__(self, rules: list[ForwardRule]):
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

    def rules_for(self, host: str) -> list[ForwardRule]:
        """ALL rules matching *host*, longest-host first (a host may need several
        injections — e.g. Google CSE needs both ?key= and ?cx=)."""
        return [r for r in self._rules if r.matches(host)]

    def inject(self, host: str, headers: dict[str, str], query: str = "") -> tuple[dict[str, str], str]:
        """Return (headers, query_string) with the real credential(s) injected.

        Applies EVERY matching rule for the host. Any client-supplied value in the
        same slot is stripped first — the proxy owns auth, never the (keyless)
        client. If no rule matches or a secret is absent, the request passes
        through unchanged.
        """
        out = dict(headers)
        for rule in self.rules_for(host):
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
                out[name] = key

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
