"""The forward proxy decides every request Prax makes (egress policy on).

Because this proxy terminates TLS for all of Prax's traffic, the decision sees
method and path for HTTPS too. These tests drive the policy engine directly
and the addon hook with stand-in flows.
"""
import asyncio
import importlib
import json

import pytest

from secrets_proxy.egress_policy import EgressPolicy, Policy, handle_admin

TOKEN = "adm"


def _egress(policy: dict, **kw):
    async def resolver(host, port):
        return {"inside.example": ["10.0.0.5"]}.get(host, ["93.184.216.34"])
    return EgressPolicy(Policy.from_dict(policy), TOKEN, resolver=resolver, **kw)


def test_rules_see_method_and_path():
    p = Policy.from_dict({"default": "deny", "rules": [
        {"host": "api.example", "methods": ["GET"], "paths": ["/public/"], "action": "allow"}]})
    assert p.decide("api.example", 443, "GET", "/public/x", False)[0] == "allow"
    assert p.decide("api.example", 443, "POST", "/public/x", False)[0] == "deny"
    assert p.decide("api.example", 443, "GET", "/private", False)[0] == "deny"


def test_deny_and_ssrf():
    async def run():
        e = _egress({"default": "allow", "rules": [{"host": "evil.example", "action": "deny"}]})
        assert (await e.check("evil.example", 443, "GET", "/"))[0] == "deny"
        assert (await e.check("inside.example", 443, "GET", "/"))[0] == "deny"   # resolves private
        assert (await e.check("169.254.169.254", 80, "GET", "/"))[0] == "deny"
        assert (await e.check("ok.example", 443, "GET", "/"))[0] == "allow"
    asyncio.run(run())


def test_a_denied_name_is_never_resolved():
    looked = []

    async def run():
        async def spy(host, port):
            looked.append(host)
            return ["93.184.216.34"]
        e = EgressPolicy(Policy.from_dict({"default": "deny"}), TOKEN, resolver=spy)
        assert (await e.check("s3cret.attacker.example", 443, "GET", "/"))[0] == "deny"
    asyncio.run(run())
    assert looked == []


def test_ask_waits_for_an_answer_keyed_by_method_and_path():
    async def run():
        e = _egress({"default": "ask"}, ask_timeout=5)
        t = asyncio.create_task(e.check("api.example", 443, "GET", "/status?x=1"))
        await asyncio.sleep(0.05)
        [p] = e.pending()
        assert (p["method"], p["path"]) == ("GET", "/status")
        e.answer(p["id"], True, by="tj")
        assert (await t)[0] == "allow"
        # Remembered for the same request shape...
        assert (await e.check("api.example", 443, "GET", "/status?x=2"))[0] == "allow"
        # ...but not for a different method.
        e.ask_timeout = 0.1
        assert (await e.check("api.example", 443, "POST", "/status"))[0] == "deny"
    asyncio.run(run())


def test_clean_allow_not_reused_when_tainted_and_late_answers_void():
    async def run():
        e = _egress({"default": "ask"}, ask_timeout=5)
        t = asyncio.create_task(e.check("news.example", 443, "GET", "/"))
        await asyncio.sleep(0.05)
        e.set_taint(True, "read private data")
        e.answer(e.pending()[0]["id"], True)
        assert (await t)[0] == "deny"  # answered a clean question, but taint arrived
    asyncio.run(run())


def test_admin_api_contract_matches_the_sandbox_gate():
    async def run():
        e = _egress({"default": "ask"}, ask_timeout=5)
        srv = await asyncio.start_server(lambda r, w: handle_admin(e, r, w), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        async def call(method, path, body=None, token=TOKEN):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            raw = json.dumps(body).encode() if body is not None else b""
            head = (f"{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n"
                    f"Content-Length: {len(raw)}\r\n\r\n")
            w.write(head.encode() + raw)
            await w.drain()
            data = await r.read()
            return int(data.split(b" ", 2)[1]), json.loads(data.split(b"\r\n\r\n", 1)[1] or b"{}")

        assert (await call("GET", "/pending", token="x"))[0] == 401
        t = asyncio.create_task(e.check("q.example", 443, "GET", "/"))
        await asyncio.sleep(0.05)
        status, body = await call("GET", "/pending")
        assert status == 200 and body["pending"][0]["expires_in_seconds"] > 0
        await call("POST", f"/pending/{body['pending'][0]['id']}", {"allow": False})
        assert (await t)[0] == "deny"
        assert (await call("POST", "/taint", {"tainted": True}))[1] == {"tainted": True}
        srv.close()
    asyncio.run(run())


# --- the addon hook ----------------------------------------------------------------

@pytest.fixture()
def addon_with_policy(monkeypatch, tmp_path):
    import tests.test_forward_auth  # noqa: F401 — installs the mitmproxy stub
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"default": "deny", "rules": [{"host": "api.openai.com", "action": "allow"}]}))
    monkeypatch.setenv("PROXY_EGRESS_POLICY", str(policy))
    monkeypatch.setenv("PROXY_EGRESS_ADMIN_TOKEN", TOKEN)
    monkeypatch.delenv("PROXY_FORWARD_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("PROXY_FORWARD_MAP", "")
    import secrets_proxy.mitm_addon as m
    m = importlib.reload(m)

    async def public(host, port):
        return ["93.184.216.34"]
    m._egress._resolver = public
    yield m
    monkeypatch.delenv("PROXY_EGRESS_POLICY")
    importlib.reload(m)


class _Req:
    def __init__(self, host, method="GET", path="/", port=443, dialled=None):
        # pretty_host comes from the client's Host header; host is what mitmproxy dials.
        self.pretty_host, self.method, self.path, self.port = host, method, path, port
        self.host = dialled or host
        self.headers = {}

        class Q:
            def items(self, multi=False):
                return []
        self.query = Q()


class _Flow:
    def __init__(self, host, **kw):
        self.request, self.response = _Req(host, **kw), None


def test_addon_blocks_what_the_policy_denies(addon_with_policy):
    blocked, allowed = _Flow("evil.example"), _Flow("api.openai.com")
    asyncio.run(addon_with_policy.request(blocked))
    asyncio.run(addon_with_policy.request(allowed))
    assert blocked.response is not None and blocked.response.status_code == 403
    assert allowed.response is None


def test_policy_off_by_default_passes_everything(monkeypatch):
    import tests.test_forward_auth  # noqa: F401
    monkeypatch.delenv("PROXY_EGRESS_POLICY", raising=False)
    monkeypatch.delenv("PROXY_FORWARD_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("PROXY_FORWARD_MAP", "")
    import secrets_proxy.mitm_addon as m
    m = importlib.reload(m)
    f = _Flow("anything.example")
    asyncio.run(m.request(f))
    assert m._egress is None and f.response is None


def test_the_example_policy_parses_and_reads_the_web_only_while_clean():
    import pathlib
    p = Policy.from_dict(json.loads((pathlib.Path(__file__).parent.parent / "egress-policy.example.json").read_text()))
    assert p.decide("api.openai.com", 443, "POST", "/v1/chat/completions", True)[0] == "allow"
    assert p.decide("blog.example", 443, "GET", "/post", False)[0] == "allow"
    assert p.decide("blog.example", 443, "GET", "/post?q=secret", True)[0] == "ask"
    assert p.decide("paste.example", 443, "POST", "/new", False)[0] == "ask"



# --- review follow-ups -------------------------------------------------------------

def test_a_spoofed_host_header_does_not_choose_the_decision(addon_with_policy):
    # Host says the allowed api.openai.com; the tunnel actually goes elsewhere.
    f = _Flow("api.openai.com", dialled="evil.example")
    asyncio.run(addon_with_policy.request(f))
    assert f.response is not None and f.response.status_code == 403


def test_paths_are_normalised_before_matching():
    p = Policy.from_dict({"default": "deny", "rules": [
        {"host": "a.example", "paths": ["/public"], "action": "allow"}]})
    assert p.decide("a.example", 443, "GET", "/public/x", False)[0] == "allow"
    for sneaky in ("/public/../admin", "/public/%2e%2e/private", "/public/%252e%252e/x", "/publicity"):
        assert p.decide("a.example", 443, "GET", sneaky, False)[0] == "deny", sneaky


def test_private_allowlist_accepts_cidrs():
    async def run():
        e = EgressPolicy(Policy.from_dict({"default": "allow", "allow_private_addresses": ["10.0.0.0/8"]}), TOKEN)
        assert await e.pinned_address("10.1.2.3", 443) == "10.1.2.3"
        with pytest.raises(PermissionError):
            await e.pinned_address("192.168.1.1", 443)
    asyncio.run(run())


def test_a_late_joiner_is_not_left_waiting_on_a_vanished_question():
    async def run():
        e = _egress({"default": "ask"}, ask_timeout=0.3)
        first = asyncio.create_task(e.check("q.example", 443, "GET", "/"))
        await asyncio.sleep(0.2)
        second = asyncio.create_task(e.check("q.example", 443, "GET", "/"))
        t0 = asyncio.get_running_loop().time()
        assert (await first)[0] == "deny" and (await second)[0] == "deny"
        assert asyncio.get_running_loop().time() - t0 < 0.3  # not a second full timeout
    asyncio.run(run())


def test_a_voided_answer_is_not_cached_so_the_retry_asks_again():
    async def run():
        e = _egress({"default": "ask"}, ask_timeout=5)
        t = asyncio.create_task(e.check("n.example", 443, "GET", "/"))
        await asyncio.sleep(0.05)
        e.set_taint(True, "private")
        e.answer(e.pending()[0]["id"], True)
        assert (await t)[0] == "deny"
        retry = asyncio.create_task(e.check("n.example", 443, "GET", "/"))
        await asyncio.sleep(0.05)
        assert e.pending(), "the retry should be a fresh question"
        e.answer(e.pending()[0]["id"], False)
        await retry
    asyncio.run(run())


def test_the_taint_token_only_raises():
    async def run():
        e = EgressPolicy(Policy.from_dict({"default": "ask"}), TOKEN, taint_token="t")
        srv = await asyncio.start_server(lambda r, w: handle_admin(e, r, w), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        async def call(method, path, body, token):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            raw = json.dumps(body).encode()
            w.write(f"{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n"
                    f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
            await w.drain()
            return int((await r.read()).split(b" ", 2)[1])
        assert await call("POST", "/taint", {"tainted": True}, "t") == 200 and e.tainted
        assert await call("POST", "/taint", {"tainted": False}, "t") == 403 and e.tainted
        assert await call("POST", "/pending/1", {"allow": True}, "t") == 403
        srv.close()
    asyncio.run(run())


def test_server_connect_pins_the_checked_address(addon_with_policy):
    class Server:
        address, sni, error = ("api.openai.com", 443), None, None
    class Data:
        server = Server()
    asyncio.run(addon_with_policy.server_connect(Data))
    assert Data.server.address == ("93.184.216.34", 443) and Data.server.sni == "api.openai.com"

    async def rebinding(host, port):
        return ["10.0.0.9"]
    addon_with_policy._egress._resolver = rebinding
    class Server2:
        address, sni, error = ("api.openai.com", 443), None, None
    class Data2:
        server = Server2()
    asyncio.run(addon_with_policy.server_connect(Data2))
    assert Data2.server.error and "non-public" in Data2.server.error


def test_raw_tcp_is_refused_when_the_policy_is_on(addon_with_policy):
    killed = []
    class F:
        server_conn = type("S", (), {"address": ("x", 22)})()
        def kill(self):
            killed.append(1)
    addon_with_policy.tcp_start(F())
    assert killed == [1]
