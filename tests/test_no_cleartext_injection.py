"""A real credential never goes onto a cleartext wire.

Before: plain http:// to an injection host got the key injected and sent
unencrypted (reproduced live 2026-09-30 with a fake key). Idea credit: Agent
Substrate's egress credential injection, which skips cleartext likewise.
"""
from __future__ import annotations

import asyncio
import importlib
import json

import pytest


@pytest.fixture()
def addon(monkeypatch, tmp_path):
    fmap = tmp_path / "map.json"
    fmap.write_text(json.dumps([{"host": "api.example.com", "scheme": "bearer",
                                 "key_env": "FAKE_TEST_KEY"}]))
    monkeypatch.setenv("PROXY_FORWARD_MAP", str(fmap))
    monkeypatch.setenv("FAKE_TEST_KEY", "sk-fake-for-test")
    monkeypatch.delenv("PROXY_FORWARD_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("PROXY_EGRESS_POLICY", raising=False)
    import secrets_proxy.mitm_addon as m
    return importlib.reload(m)


class _Q:
    def items(self, multi=False):  # noqa: ARG002
        return []


class _Req:
    def __init__(self, scheme):
        self.scheme = scheme
        self.pretty_host = self.host = "api.example.com"
        self.headers = {"Authorization": "Bearer placeholder"}
        self.query = _Q()


class _Flow:
    def __init__(self, scheme):
        self.request, self.response = _Req(scheme), None


def test_https_gets_the_credential(addon):
    f = _Flow("https")
    asyncio.run(addon.request(f))
    assert f.request.headers["Authorization"] == "Bearer sk-fake-for-test"


def test_cleartext_http_never_does(addon, caplog):
    f = _Flow("http")
    with caplog.at_level("WARNING"):
        asyncio.run(addon.request(f))
    assert "sk-fake-for-test" not in json.dumps(f.request.headers)
    assert "NOT injecting" in caplog.text and "sk-fake-for-test" not in caplog.text
