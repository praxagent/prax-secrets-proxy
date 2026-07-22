"""Keyless tests for the forward-proxy credential injector.

Pin the generic, config-driven injection: right key by host, right scheme, client
auth stripped, and no-rule / no-secret requests pass through untouched.
"""
from __future__ import annotations

import base64

import pytest

from secrets_proxy.forward_inject import ForwardInjector, ForwardRule

MAP = [
    {"host": "api.tavily.com", "scheme": "bearer", "key_env": "TAVILY_API_KEY"},
    {"host": "api.elevenlabs.io", "scheme": "header:xi-api-key", "key_env": "ELEVENLABS_API_KEY"},
    {"host": "api.twilio.com", "scheme": "basic",
     "user_env": "TWILIO_ACCOUNT_SID", "pass_env": "TWILIO_AUTH_TOKEN"},
    {"host": "googleapis.com", "scheme": "query:key", "key_env": "GOOGLE_API_KEY"},
]


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tav-REAL")
    monkeypatch.setenv("ELEVENLABS_API_KEY", "el-REAL")
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACreal")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok-REAL")
    monkeypatch.setenv("GOOGLE_API_KEY", "goog-REAL")
    return ForwardInjector.from_map(MAP)


def test_bearer_injected(env):
    h, _ = env.inject("api.tavily.com", {"Content-Type": "application/json"})
    assert h["Authorization"] == "Bearer tav-REAL"


def test_bearer_strips_client_auth(env):
    h, _ = env.inject("api.tavily.com", {"Authorization": "Bearer placeholder"})
    assert h["Authorization"] == "Bearer tav-REAL"
    assert "placeholder" not in h["Authorization"]


def test_custom_header_scheme(env):
    h, _ = env.inject("api.elevenlabs.io", {"x-api-key": "nope"})
    assert h["xi-api-key"] == "el-REAL"


def test_basic_auth_pairs_two_envs(env):
    h, _ = env.inject("api.twilio.com", {})
    scheme, token = h["Authorization"].split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(token).decode() == "ACreal:tok-REAL"


def test_query_param_injected_and_dedup(env):
    _, q = env.inject("www.googleapis.com", {}, query="q=hello&key=CLIENTFAKE")
    from urllib.parse import parse_qs
    parsed = parse_qs(q)
    assert parsed["key"] == ["goog-REAL"]        # client's fake key replaced
    assert parsed["q"] == ["hello"]              # other params preserved


def test_host_suffix_match(env):
    # rule host "googleapis.com" must also cover the api subdomain
    _, q = env.inject("sheets.googleapis.com", {}, query="")
    assert "goog-REAL" in q


def test_unknown_host_passes_through(env):
    orig = {"Authorization": "Bearer client-owned"}
    h, q = env.inject("example.com", dict(orig), query="a=1")
    assert h == orig and q == "a=1"              # untouched — not an injection target


def test_missing_secret_leaves_request_unchanged(monkeypatch):
    inj = ForwardInjector.from_map([{"host": "api.tavily.com", "scheme": "bearer", "key_env": "TAVILY_API_KEY"}])
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    h, _ = inj.inject("api.tavily.com", {"Content-Type": "application/json"})
    assert "Authorization" not in h              # no key → nothing injected


def test_longest_host_rule_wins():
    inj = ForwardInjector.from_map([
        {"host": "example.com", "scheme": "header:X-Broad", "key_env": "K"},
        {"host": "api.example.com", "scheme": "header:X-Specific", "key_env": "K"},
    ])
    import os
    os.environ["K"] = "v"
    try:
        h, _ = inj.inject("api.example.com", {})
        assert "X-Specific" in h and "X-Broad" not in h
    finally:
        del os.environ["K"]


def test_secret_available_reports_correctly(env):
    assert env.secret_available(env.rule_for("api.tavily.com")) is True
    assert env.secret_available(ForwardRule("x.com", "bearer", key_env="NOPE_ENV")) is False
