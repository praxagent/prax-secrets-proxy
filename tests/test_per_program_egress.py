"""Per-program egress: identities come from WHICH token was presented, and
rules with ``callers`` apply only to those programs. Idea credit: NVIDIA OpenShell."""
from __future__ import annotations

import asyncio
import base64
import importlib
import json
import time

import pytest

from secrets_proxy import callers as cl
from secrets_proxy import egress_policy as ep

SANDBOX_TOKEN, BROWSER_TOKEN = "sandbox-tok", "browser-tok"


def _callers():
    return cl.Callers("main-tok", "prax", {"sandbox": cl.digest(SANDBOX_TOKEN),
                                           "browser": cl.digest(BROWSER_TOKEN)})


def test_identity_is_whose_token_matched():
    c = _callers()
    assert c.identify("main-tok") == "prax"
    assert c.identify(SANDBOX_TOKEN) == "sandbox"
    assert c.identify(BROWSER_TOKEN) == "browser"
    assert c.identify("wrong") is None and c.identify("") is None
    assert c.required and not cl.Callers().required


@pytest.mark.parametrize("bad", [
    lambda: cl.Callers("", "prax", {"Bad Name": "0" * 64}),
    lambda: cl.Callers("t", "prax", {"prax": "0" * 64}),   # main name reused
])
def test_bad_configuration_is_refused(bad):
    with pytest.raises(ValueError):
        bad()


def test_from_env_reads_hashes_only(tmp_path, monkeypatch):
    f = tmp_path / "callers.json"
    f.write_text(json.dumps({"callers": {"sandbox": {"token_sha256": cl.digest(SANDBOX_TOKEN)}}}))
    monkeypatch.setenv("PROXY_FORWARD_CALLERS", str(f))
    monkeypatch.setenv("PROXY_FORWARD_AUTH_TOKEN", "main-tok")
    monkeypatch.delenv("PROXY_FORWARD_AUTH_NAME", raising=False)
    c = cl.Callers.from_env()
    assert c.identify(SANDBOX_TOKEN) == "sandbox" and c.identify("main-tok") == "prax"
    f.write_text(json.dumps({"callers": {"sandbox": {"token_sha256": "not-a-hash"}}}))
    with pytest.raises(ValueError):
        cl.Callers.from_env()


def test_cli_prints_a_token_matching_its_hash(capsys):
    assert cl._cli(["new", "sandbox"]) == 0
    out = capsys.readouterr().out
    token = out.split("): ", 1)[1].split("\n", 1)[0].strip()
    assert cl.digest(token) in out
    assert cl._cli(["new", "Bad Name"]) == 2


POLICY = {"default": "deny", "rules": [
    {"host": "api.openai.com", "callers": ["prax"], "action": "allow"},
    {"host": "pypi.org", "callers": ["sandbox"], "methods": ["GET"], "action": "allow"},
    {"host": "*", "methods": ["GET"], "callers": ["browser", "prax"], "action": "allow"},
    {"host": "example.org", "action": "ask"},
]}


def _gate(policy=POLICY, ceiling=None):
    return ep.EgressPolicy(ep.Policy.from_dict(policy), "admin",
                           ceiling=ep.Policy.from_dict(ceiling) if ceiling else None,
                           resolver=lambda h, p: asyncio.sleep(0, result=["93.184.216.34"]),
                           ask_timeout=0.05)


def _check(gate, host, caller, method="GET"):
    return asyncio.run(gate.check(host, 443, method, "/", caller=caller))[0]


def test_only_the_named_program_may_reach_the_credential_host():
    gate = _gate()
    assert _check(gate, "api.openai.com", "prax", "POST") == "allow"
    assert _check(gate, "api.openai.com", "sandbox", "POST") == "deny"
    assert _check(gate, "api.openai.com", "", "POST") == "deny"


def test_rules_differ_by_program():
    gate = _gate()
    assert _check(gate, "pypi.org", "sandbox") == "allow"
    assert _check(gate, "news.example", "sandbox") == "deny"   # the web is not the sandbox's
    assert _check(gate, "news.example", "browser") == "allow"


def test_an_answer_for_one_program_is_not_an_answer_for_another():
    gate = _gate()
    for who in ("sandbox", "browser"):
        gate._decisions[gate.key("example.org", 443, "POST", "/", who)] = (
            "allow" if who == "sandbox" else "deny", time.monotonic() + 600, "a person", False)
    assert _check(gate, "example.org", "sandbox", "POST") == "allow"
    assert _check(gate, "example.org", "browser", "POST") == "deny"
    assert _check(gate, "example.org", "prax", "POST") == "deny"   # asked; nobody answered


def test_pending_questions_name_the_program():
    gate = _gate()

    async def ask_and_look():
        task = asyncio.create_task(gate.check("example.org", 443, "POST", "/", caller="sandbox"))
        await asyncio.sleep(0.01)
        seen = gate.pending()
        await task
        return seen

    seen = asyncio.run(ask_and_look())
    assert seen and seen[0]["caller"] == "sandbox"


def test_a_ceiling_can_be_per_program():
    ceiling = {"default": "deny", "rules": [
        {"host": "api.openai.com", "callers": ["prax"], "action": "allow"},
        {"host": "*", "methods": ["GET"], "action": "allow"}]}
    wide = {"default": "allow", "rules": []}
    gate = _gate(wide, ceiling)
    assert _check(gate, "api.openai.com", "prax", "POST") == "allow"
    assert _check(gate, "api.openai.com", "sandbox", "POST") == "deny"


def test_diff_names_the_program_a_change_opens_for():
    old = ep.Policy.from_dict(POLICY)
    new = ep.Policy.from_dict({**POLICY, "rules": [
        {"host": "api.openai.com", "callers": ["prax", "sandbox"], "action": "allow"},
        *POLICY["rules"][1:]]})
    opened = {c["request"] for c in ep.diff(old, new, credential_hosts=frozenset({"api.openai.com"}))}
    assert "POST api.openai.com/ by sandbox" in opened
    assert not any("by prax" in r or "by browser" in r for r in opened)


# --- through the addon: the identity comes from the token, not the username ----

def _fake_mitmproxy():
    """The addon builds its 407 with mitmproxy, a container-only dependency."""
    import sys
    import types
    if "mitmproxy.http" in sys.modules:
        return

    class _Response:
        def __init__(self, status_code, content=b"", headers=None):
            self.status_code, self.content, self.headers = status_code, content, headers or {}

        @classmethod
        def make(cls, status_code=200, content=b"", headers=None):
            return cls(status_code, content, headers)

    http_mod = types.ModuleType("mitmproxy.http")
    http_mod.Response = _Response
    pkg = types.ModuleType("mitmproxy")
    pkg.http = http_mod
    sys.modules["mitmproxy"], sys.modules["mitmproxy.http"] = pkg, http_mod


@pytest.fixture()
def addon(monkeypatch, tmp_path):
    _fake_mitmproxy()
    f = tmp_path / "callers.json"
    f.write_text(json.dumps({"callers": {"sandbox": {"token_sha256": cl.digest(SANDBOX_TOKEN)}}}))
    monkeypatch.setenv("PROXY_FORWARD_CALLERS", str(f))
    monkeypatch.setenv("PROXY_FORWARD_AUTH_TOKEN", "main-tok")
    monkeypatch.setenv("PROXY_FORWARD_MAP", "")
    monkeypatch.delenv("PROXY_EGRESS_POLICY", raising=False)
    import secrets_proxy.mitm_addon as m
    m = importlib.reload(m)
    seen = []

    class _Gate:
        async def check(self, host, port, method, path, caller=""):
            seen.append(caller)
            return "allow", "test"

    m._egress = _Gate()
    return m, seen


class _Req:
    def __init__(self, token, user="prax"):
        raw = base64.b64encode(f"{user}:{token}".encode()).decode()
        self.headers = {"Proxy-Authorization": f"Basic {raw}"}
        self.pretty_host = self.host = "api.openai.com"
        self.port, self.method, self.path = 443, "POST", "/v1/chat"


class _Flow:
    def __init__(self, token, user="prax"):
        self.request, self.response = _Req(token, user), None


def test_the_addon_passes_the_authenticated_identity(addon):
    m, seen = addon
    asyncio.run(m.request(_Flow("main-tok")))
    asyncio.run(m.request(_Flow(SANDBOX_TOKEN, user="sandbox")))
    assert seen == ["prax", "sandbox"]


def test_claiming_another_programs_name_changes_nothing(addon):
    m, seen = addon
    asyncio.run(m.request(_Flow(SANDBOX_TOKEN, user="prax")))   # username says prax
    assert seen == ["sandbox"]


def test_an_unknown_token_is_refused_before_any_decision(addon):
    m, seen = addon
    f = _Flow("nope")
    asyncio.run(m.request(f))
    assert f.response.status_code == 407 and seen == []


class _Conn:
    pass


def test_a_tunnels_identity_reaches_its_requests(addon):
    m, seen = addon
    conn = _Conn()
    connect = _Flow(SANDBOX_TOKEN, user="prax")
    connect.client_conn = conn
    m.http_connect(connect)
    inner = _Flow("")
    inner.request.headers = {}          # HTTPS: nothing inside the tunnel
    inner.client_conn = conn
    asyncio.run(m.request(inner))
    assert inner.response is None and seen == ["sandbox"]
