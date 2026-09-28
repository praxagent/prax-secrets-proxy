"""The forward proxy must authenticate its callers.

The Tier-1 reverse proxy has always required a token. This one did not: any
process able to reach the listener could spend the real credentials
anonymously. It cannot STEAL them — that is what keyless buys — but it could
use them freely, and nothing in the audit log said who.

Measured exposure on the dev box before this landed (2026-08-08): published to
127.0.0.1 only, and NOT reachable from the sandbox container (127.0.0.1, the
docker bridge and host.docker.internal all refused). So the real gap was
host-local callers plus the absence of attribution, not a remote hole. Fixed
anyway — a proxy that is safe only because of how someone happened to publish
its port is not safe, and the topology is a deployment choice.
"""

import asyncio
import base64
import importlib
import sys
import types

import pytest


def _install_fake_mitmproxy():
    """Stub `mitmproxy.http` so the addon's 407 path is testable.

    mitmproxy is a container-runtime dependency, not a test one — the addon
    imports it lazily inside `_unauthorized()` precisely so the rest of the
    module stays importable without it. Stubbing here keeps that property
    rather than making production code degrade for the test's convenience.
    """
    if "mitmproxy.http" in sys.modules:
        return

    class _Response:
        def __init__(self, status_code, content, headers):
            self.status_code = status_code
            self.content = content
            self.headers = headers

        @classmethod
        def make(cls, status_code=200, content=b"", headers=None):
            return cls(status_code, content, headers or {})

    http_mod = types.ModuleType("mitmproxy.http")
    http_mod.Response = _Response
    pkg = types.ModuleType("mitmproxy")
    pkg.http = http_mod
    sys.modules["mitmproxy"] = pkg
    sys.modules["mitmproxy.http"] = http_mod


_install_fake_mitmproxy()


@pytest.fixture()
def addon(monkeypatch):
    """Reload the addon with a token configured (it reads env at import)."""
    def _load(token: str | None):
        if token is None:
            monkeypatch.delenv("PROXY_FORWARD_AUTH_TOKEN", raising=False)
        else:
            monkeypatch.setenv("PROXY_FORWARD_AUTH_TOKEN", token)
        monkeypatch.setenv("PROXY_FORWARD_MAP", "")
        import secrets_proxy.mitm_addon as m
        return importlib.reload(m)
    return _load


class _Headers(dict):
    """Minimal stand-in for mitmproxy's Headers (case-sensitive get + del)."""


class _Req:
    def __init__(self, host, headers=None):
        self.pretty_host = host
        self.headers = _Headers(headers or {})
        self.query = _Q()


class _Q:
    def items(self, multi=False):  # noqa: ARG002
        return []


class _Flow:
    def __init__(self, host, headers=None):
        self.request = _Req(host, headers)
        self.response = None


def basic(user, token):
    raw = base64.b64encode(f"{user}:{token}".encode()).decode()
    return {"Proxy-Authorization": f"Basic {raw}"}


class TestTokenExtraction:
    def test_basic_uses_the_password_half(self, addon):
        m = addon("secret")
        assert m._presented_token(_Headers(basic("prax", "secret"))) == "secret"

    def test_bearer_is_accepted(self, addon):
        m = addon("secret")
        assert m._presented_token(
            _Headers({"Proxy-Authorization": "Bearer secret"})) == "secret"

    def test_missing_or_malformed_is_empty(self, addon):
        m = addon("secret")
        assert m._presented_token(_Headers({})) == ""
        assert m._presented_token(
            _Headers({"Proxy-Authorization": "Basic !!!not-base64"})) == ""
        assert m._presented_token(
            _Headers({"Proxy-Authorization": "Digest whatever"})) == ""


class TestEnforcement:
    def test_missing_credentials_are_refused(self, addon):
        m = addon("secret")
        f = _Flow("api.openai.com")
        asyncio.run(m.request(f))
        assert f.response is not None
        assert f.response.status_code == 407

    def test_wrong_token_is_refused(self, addon):
        m = addon("secret")
        f = _Flow("api.openai.com", basic("prax", "wrong"))
        asyncio.run(m.request(f))
        assert f.response is not None and f.response.status_code == 407

    def test_correct_token_is_allowed_through(self, addon):
        m = addon("secret")
        f = _Flow("api.openai.com", basic("prax", "secret"))
        asyncio.run(m.request(f))
        assert f.response is None, "an authenticated caller must not be blocked"

    def test_refusal_does_not_reveal_whether_the_host_is_a_target(self, addon):
        """Auth is checked BEFORE the injection rule is looked up, so an
        unauthenticated caller cannot probe which hosts get credentials."""
        m = addon("secret")
        known, unknown = _Flow("api.openai.com"), _Flow("example.invalid")
        asyncio.run(m.request(known))
        asyncio.run(m.request(unknown))
        assert known.response.status_code == unknown.response.status_code == 407

    def test_407_advertises_the_scheme(self, addon):
        m = addon("secret")
        f = _Flow("api.openai.com")
        asyncio.run(m.request(f))
        assert "Proxy-Authenticate" in f.response.headers


class TestCredentialHygiene:
    def test_proxy_credential_never_travels_upstream(self, addon):
        """It authenticates the caller to US. Forwarding it to the provider
        would leak our own shared secret to every destination."""
        m = addon("secret")
        f = _Flow("api.openai.com", basic("prax", "secret"))
        asyncio.run(m.request(f))
        assert "Proxy-Authorization" not in f.request.headers

    def test_stripped_even_when_auth_is_disabled(self, addon):
        m = addon(None)
        f = _Flow("api.openai.com", basic("prax", "anything"))
        asyncio.run(m.request(f))
        assert "Proxy-Authorization" not in f.request.headers

    def test_caller_label_is_the_username_never_the_token(self, addon):
        m = addon("secret")
        label = m._caller_label(_Headers(basic("eval-runner", "secret")))
        assert label == "eval-runner"
        assert "secret" not in label


class TestUnconfiguredStaysOpenButLoud:
    def test_no_token_means_no_enforcement(self, addon):
        """Back-compat: an existing deployment must not break on upgrade."""
        m = addon(None)
        f = _Flow("api.openai.com")
        asyncio.run(m.request(f))
        assert f.response is None

    def test_running_hook_warns_when_open(self, addon, caplog):
        m = addon(None)
        with caplog.at_level("WARNING"):
            asyncio.run(m.running())
        assert "PROXY_FORWARD_AUTH_TOKEN is not set" in caplog.text

    def test_running_hook_silent_when_configured(self, addon, caplog):
        m = addon("secret")
        with caplog.at_level("WARNING"):
            asyncio.run(m.running())
        assert "not set" not in caplog.text
