"""Keyless tests for the secrets proxy.

The upstream is mocked, so no network and no real keys. These pin the security
properties: the real key is injected + never leaked, client auth is stripped,
only allow-listed providers are reachable, and responses stream.
"""
from __future__ import annotations

import pytest

from secrets_proxy.app import build_proxy_app
from secrets_proxy.config import ProxyConfig

REAL_OPENAI = "sk-REAL-openai-KEY"
REAL_ANTHROPIC = "sk-ant-REAL-KEY"


class _FakeUpstream:
    def __init__(self, status=200, headers=None, chunks=(b'data: {"x":1}\n\n', b"data: [DONE]\n\n")):
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/event-stream", "Transfer-Encoding": "chunked"}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=8192):
        yield from self._chunks

    def close(self):
        self.closed = True


@pytest.fixture()
def proxy(monkeypatch):
    monkeypatch.setenv("OPENAI_KEY", REAL_OPENAI)
    monkeypatch.setenv("ANTHROPIC_KEY", REAL_ANTHROPIC)
    captured = {}

    def fake_request(method, url, headers=None, data=None, **kw):
        captured.update(method=method, url=url, headers=headers or {}, data=data, kw=kw)
        return _FakeUpstream()

    monkeypatch.setattr("secrets_proxy.app.requests.request", fake_request)
    app = build_proxy_app(ProxyConfig())
    return app.test_client(), captured


def test_injects_real_openai_key_when_client_sent_none(proxy):
    client, captured = proxy
    r = client.post("/openai/v1/chat/completions", json={"model": "gpt-x"})
    assert r.status_code == 200
    assert captured["headers"]["Authorization"] == f"Bearer {REAL_OPENAI}"
    assert captured["url"].endswith("/v1/chat/completions")
    assert captured["method"] == "POST"


def test_strips_and_replaces_client_supplied_auth(proxy):
    client, captured = proxy
    client.post("/openai/v1/chat/completions",
                headers={"Authorization": "Bearer proxy-placeholder"}, json={})
    assert captured["headers"]["Authorization"] == f"Bearer {REAL_OPENAI}"
    assert "proxy-placeholder" not in captured["headers"]["Authorization"]


def test_anthropic_injects_x_api_key_and_version(proxy):
    client, captured = proxy
    client.post("/anthropic/v1/messages",
                headers={"x-api-key": "placeholder"}, json={"model": "claude-x"})
    assert captured["headers"]["x-api-key"] == REAL_ANTHROPIC
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in captured["headers"]


def test_unknown_provider_is_404_never_forwarded(proxy):
    client, captured = proxy
    r = client.post("/evil/v1/exfil", json={})
    assert r.status_code == 404
    assert captured == {}  # allowlist: nothing was forwarded


def test_missing_key_is_502(monkeypatch):
    monkeypatch.delenv("OPENAI_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_KEY", raising=False)
    monkeypatch.setattr("secrets_proxy.app.requests.request",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not forward")))
    client = build_proxy_app(ProxyConfig()).test_client()
    r = client.post("/openai/v1/chat/completions", json={})
    assert r.status_code == 502 and "no key" in r.get_json()["error"]


def test_response_streams_through(proxy):
    client, _ = proxy
    r = client.post("/openai/v1/chat/completions", json={})
    body = r.get_data(as_text=True)
    assert 'data: {"x":1}' in body and "[DONE]" in body


def test_hop_by_hop_headers_not_forwarded(proxy):
    client, captured = proxy
    client.post("/openai/v1/chat/completions",
                headers={"Host": "evil.com", "Connection": "keep-alive",
                         "Content-Type": "application/json"}, json={})
    fwd = {k.lower() for k in captured["headers"]}
    assert "host" not in fwd and "connection" not in fwd
    assert "content-type" in fwd


def test_query_string_is_preserved(proxy):
    client, captured = proxy
    client.get("/openai/v1/models?limit=5")
    assert captured["url"].endswith("/v1/models?limit=5")


def test_healthz_reports_readiness_without_values(proxy):
    client, _ = proxy
    j = client.get("/healthz").get_json()
    assert j["ok"] is True
    assert j["providers"] == {"openai": True, "anthropic": True}
    assert REAL_OPENAI not in str(j)


@pytest.fixture()
def authed_proxy(monkeypatch):
    """A proxy that REQUIRES the shared token PROXY_AUTH_TOKEN."""
    monkeypatch.setenv("OPENAI_KEY", REAL_OPENAI)
    monkeypatch.setenv("ANTHROPIC_KEY", REAL_ANTHROPIC)
    monkeypatch.setenv("PROXY_AUTH_TOKEN", "PROXY-SHARED-TOKEN")
    captured = {}

    def fake_request(method, url, headers=None, data=None, **kw):
        captured.update(method=method, url=url, headers=headers or {}, data=data)
        return _FakeUpstream()

    monkeypatch.setattr("secrets_proxy.app.requests.request", fake_request)
    from secrets_proxy.config import ProxyConfig as _Cfg
    app = build_proxy_app(_Cfg.from_env())
    return app.test_client(), captured


def test_auth_missing_token_is_401_never_forwarded(authed_proxy):
    client, captured = authed_proxy
    r = client.post("/openai/v1/chat/completions", json={})
    assert r.status_code == 401
    assert captured == {}  # nothing spent


def test_auth_wrong_token_is_401(authed_proxy):
    client, captured = authed_proxy
    r = client.post("/openai/v1/chat/completions",
                    headers={"Authorization": "Bearer WRONG"}, json={})
    assert r.status_code == 401
    assert captured == {}


def test_auth_correct_bearer_token_passes_and_is_swapped_for_real_key(authed_proxy):
    client, captured = authed_proxy
    r = client.post("/openai/v1/chat/completions",
                    headers={"Authorization": "Bearer PROXY-SHARED-TOKEN"}, json={})
    assert r.status_code == 200
    # The token authenticated the client, then was replaced by the REAL key.
    assert captured["headers"]["Authorization"] == f"Bearer {REAL_OPENAI}"
    assert "PROXY-SHARED-TOKEN" not in captured["headers"]["Authorization"]


def test_auth_correct_anthropic_token_via_x_api_key(authed_proxy):
    client, captured = authed_proxy
    r = client.post("/anthropic/v1/messages",
                    headers={"x-api-key": "PROXY-SHARED-TOKEN"}, json={})
    assert r.status_code == 200
    assert captured["headers"]["x-api-key"] == REAL_ANTHROPIC


def test_auth_401_before_provider_check(authed_proxy):
    # An unauthenticated caller learns nothing — not even whether a provider exists.
    client, captured = authed_proxy
    r = client.post("/evil/v1/exfil", json={})
    assert r.status_code == 401  # not 404 — auth is checked first
    assert captured == {}


def test_audit_log_never_contains_the_key_or_body(proxy, caplog):
    import logging
    client, _ = proxy
    with caplog.at_level(logging.INFO, logger="secrets_proxy"):
        client.post("/openai/v1/chat/completions", json={"secret_in_body": "hunter2"})
    logged = "\n".join(r.message for r in caplog.records)
    assert "/v1/chat/completions" in logged
    assert REAL_OPENAI not in logged
    assert "hunter2" not in logged


# ---------------------------------------------------------------------------
# Silent-failure invariants (docs/research/failure-atlas-llm-gateways.md).
#
# A proxy's most dangerous failures are SILENT — HTTP 200 with a corrupted
# payload. The proxy's defense against the worst class (State/Session: context
# bleeding, cross-request credential leakage, races) is that it holds NO
# per-request mutable state — it's stateless pass-through. These tests pin that
# invariant so a future change can't quietly reintroduce shared state, and pin
# that a truncated upstream is surfaced, never silently completed.
# ---------------------------------------------------------------------------

class _RecordingUpstream:
    """Fake upstream that records the exact headers/body it was called with."""

    def __init__(self, sink, status=200, chunks=(b"ok",)):
        self._sink = sink
        self.status_code = status
        self.headers = {"Content-Type": "text/event-stream"}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=8192):
        yield from self._chunks

    def close(self):
        self.closed = True


@pytest.fixture()
def recording_proxy(monkeypatch):
    """Proxy whose upstream records EVERY call (thread-safe), not just the last."""
    import threading
    monkeypatch.setenv("OPENAI_KEY", REAL_OPENAI)
    monkeypatch.setenv("ANTHROPIC_KEY", REAL_ANTHROPIC)
    calls = []
    lock = threading.Lock()

    def fake_request(method, url, headers=None, data=None, **kw):
        rec = {"url": url, "headers": dict(headers or {}), "data": data}
        with lock:
            calls.append(rec)
        return _RecordingUpstream(rec)

    monkeypatch.setattr("secrets_proxy.app.requests.request", fake_request)
    app = build_proxy_app(ProxyConfig())
    return app, calls


def test_interleaved_requests_never_bleed_credentials(recording_proxy):
    """openai and anthropic requests interleaved must each inject only their OWN
    key — no request ever sees the other provider's credential (context bleeding)."""
    app, calls = recording_proxy
    client = app.test_client()
    for _ in range(5):
        client.post("/openai/v1/chat/completions", json={})
        client.post("/anthropic/v1/messages", json={})

    openai_calls = [c for c in calls if "openai.com" in c["url"]]
    anthropic_calls = [c for c in calls if "anthropic.com" in c["url"]]
    assert len(openai_calls) == 5 and len(anthropic_calls) == 5
    for c in openai_calls:
        assert c["headers"].get("Authorization") == f"Bearer {REAL_OPENAI}"
        assert REAL_ANTHROPIC not in str(c["headers"])          # no cross-bleed
        assert "x-api-key" not in c["headers"]
    for c in anthropic_calls:
        assert c["headers"].get("x-api-key") == REAL_ANTHROPIC
        assert REAL_OPENAI not in str(c["headers"])              # no cross-bleed


def test_concurrent_requests_stay_isolated(recording_proxy):
    """Under real concurrency, each request's injected key matches its provider —
    proving the proxy holds no shared per-request state (race-condition immunity)."""
    import threading
    app, calls = recording_proxy

    def hit(provider):
        # Fresh test_client per thread; the app itself must carry no request state.
        c = app.test_client()
        if provider == "openai":
            c.post("/openai/v1/chat/completions", json={})
        else:
            c.post("/anthropic/v1/messages", json={})

    threads = [threading.Thread(target=hit, args=("openai" if i % 2 == 0 else "anthropic",))
               for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 20
    # Every recorded call is internally consistent: the injected credential
    # matches the provider in its URL. A shared-state race would mismatch these.
    for c in calls:
        if "openai.com" in c["url"]:
            assert c["headers"].get("Authorization") == f"Bearer {REAL_OPENAI}"
            assert "x-api-key" not in c["headers"]
        else:
            assert c["headers"].get("x-api-key") == REAL_ANTHROPIC
            assert "Authorization" not in c["headers"]


def test_request_body_is_not_shared_between_calls(recording_proxy):
    """Each proxied call forwards its OWN body — no leftover state from a prior one."""
    app, calls = recording_proxy
    client = app.test_client()
    client.post("/openai/v1/chat/completions", data=b"FIRST-BODY")
    client.post("/openai/v1/chat/completions", data=b"SECOND-BODY")
    assert calls[0]["data"] == b"FIRST-BODY"
    assert calls[1]["data"] == b"SECOND-BODY"


def test_truncated_upstream_stream_is_surfaced_not_silently_completed(monkeypatch):
    """A mid-stream upstream failure must NOT be swallowed into a clean 200 body.

    The proxy streams pass-through, so a dropped upstream surfaces as a truncated
    client stream (the transport error propagates) — it never fabricates a
    complete-looking response, which would be the classic silent-200 corruption.
    """
    import requests

    monkeypatch.setenv("OPENAI_KEY", REAL_OPENAI)

    class _TruncatingUpstream:
        status_code = 200
        headers = {"Content-Type": "text/event-stream"}

        def iter_content(self, chunk_size=8192):
            yield b'data: {"partial":1}\n\n'
            raise requests.exceptions.ChunkedEncodingError("upstream dropped mid-stream")

        def close(self):
            pass

    monkeypatch.setattr("secrets_proxy.app.requests.request",
                        lambda *a, **k: _TruncatingUpstream())
    client = build_proxy_app(ProxyConfig()).test_client()

    raised = False
    body = b""
    try:
        resp = client.post("/openai/v1/chat/completions", json={})
        body = resp.get_data()
    except requests.exceptions.ChunkedEncodingError:
        raised = True
    # Either the error propagated, or only the partial chunk was delivered — but
    # NEVER a clean body with a fabricated completion the upstream never sent.
    assert raised or (b"partial" in body and b"[DONE]" not in body)
