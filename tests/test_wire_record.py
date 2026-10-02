"""The wire record: tool calls the model returned, hashed and chained, never text."""
from __future__ import annotations

import json

import pytest

from secrets_proxy import wire_record as wr


def _openai(calls):
    return json.dumps({"model": "gpt-x", "choices": [{"message": {"tool_calls": [
        {"function": {"name": n, "arguments": json.dumps(a)}} for n, a in calls]}}]}).encode()


def test_openai_chat_json():
    calls, model = wr.extract("application/json", _openai([("browser_click", {"s": "#go"})]))
    assert model == "gpt-x" and [c["name"] for c in calls] == ["browser_click"]
    assert calls[0]["args_sha256"] == wr._args_hash({"s": "#go"})


def test_anthropic_json():
    body = json.dumps({"model": "claude", "content": [
        {"type": "text", "text": "secret words"},
        {"type": "tool_use", "name": "plugin_import", "input": {"name": "weather"}}]}).encode()
    calls, _ = wr.extract("application/json", body)
    assert calls == [{"name": "plugin_import", "args_sha256": wr._args_hash({"name": "weather"})}]


def test_openai_stream_reassembles_split_arguments():
    events = [
        {"model": "gpt-x", "choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"name": "sandbox_shell", "arguments": "{\"cmd\":"}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": " \"ls\"}"}}]}}]},
    ]
    body = ("".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n").encode()
    calls, model = wr.extract("text/event-stream", body)
    assert model == "gpt-x"
    assert calls == [{"name": "sandbox_shell", "args_sha256": wr._args_hash({"cmd": "ls"})}]


def test_anthropic_stream():
    events = [
        {"type": "message_start", "message": {"model": "claude"}},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "name": "browser_fill"}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"v\":"}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "1}"}},
    ]
    body = "".join(f"event: x\ndata: {json.dumps(e)}\n\n" for e in events).encode()
    calls, model = wr.extract("text/event-stream", body)
    assert model == "claude" and calls == [{"name": "browser_fill", "args_sha256": wr._args_hash({"v": 1})}]


def test_the_record_holds_no_text_and_chains(tmp_path):
    rec = wr.WireRecord(str(tmp_path / "wire.jsonl"))
    secret = "my password is hunter2"
    rec.append(host="openrouter.ai", path="/api/v1/chat/completions?x=1", status=200,
               request_body=secret.encode(), response_type="application/json",
               response_body=_openai([("browser_fill", {"value": secret})]))
    rec.append(host="openrouter.ai", path="/api/v1/chat/completions", status=200,
               request_body=b"{}", response_type="application/json", response_body=b"{}")
    text = (tmp_path / "wire.jsonl").read_text()
    assert "hunter2" not in text and "password" not in text
    first, second = [json.loads(line) for line in text.splitlines()]
    assert first["prev"] == wr.GENESIS and second["prev"] == first["hash"]
    assert first["path"] == "/api/v1/chat/completions"
    assert wr.verify(str(tmp_path / "wire.jsonl"))[0]


def test_a_restarted_proxy_continues_the_chain(tmp_path):
    p = str(tmp_path / "wire.jsonl")
    wr.WireRecord(p).append(host="api.openai.com", path="/v1", status=200, request_body=b"a",
                            response_type="", response_body=b"")
    wr.WireRecord(p).append(host="api.openai.com", path="/v1", status=200, request_body=b"b",
                            response_type="", response_body=b"")
    assert wr.verify(p) == (True, wr.verify(p)[1]) and "2 lines" in wr.verify(p)[1]


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_tampering_breaks_the_chain(tmp_path, tamper):
    p = tmp_path / "wire.jsonl"
    rec = wr.WireRecord(str(p))
    for i in range(3):
        rec.append(host="api.openai.com", path="/v1", status=200, request_body=str(i).encode(),
                   response_type="application/json", response_body=_openai([("t", {"i": i})]))
    lines = p.read_text().splitlines()
    if tamper == "edit":
        entry = json.loads(lines[1])
        entry["tool_calls"] = []
        lines[1] = json.dumps(entry)
    elif tamper == "delete":
        del lines[1]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    ok, msg = wr.verify(str(p))
    assert not ok and "line 2" in msg


def test_hosts(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXY_WIRE_RECORD", str(tmp_path / "w.jsonl"))
    monkeypatch.setenv("PROXY_WIRE_RECORD_HOSTS", "llm.internal")
    rec = wr.from_env()
    assert rec.wants("openrouter.ai") and rec.wants("llm.internal") and not rec.wants("example.com")
    monkeypatch.delenv("PROXY_WIRE_RECORD")
    assert wr.from_env() is None


def test_the_addon_records_model_responses_and_never_breaks_them(tmp_path, monkeypatch):
    import importlib
    from types import SimpleNamespace

    monkeypatch.setenv("PROXY_WIRE_RECORD", str(tmp_path / "wire.jsonl"))
    monkeypatch.setenv("PROXY_FORWARD_MAP", "")
    import secrets_proxy.mitm_addon as m
    m = importlib.reload(m)

    def flow(host, body, ctype="application/json"):
        return SimpleNamespace(
            metadata={"caller": "prax-prod"},
            request=SimpleNamespace(host=host, path="/v1/chat/completions", raw_content=b"{}"),
            response=SimpleNamespace(status_code=200, headers={"content-type": ctype}, content=body))

    m.response(flow("openrouter.ai", _openai([("browser_click", {"s": "a"})])))
    m.response(flow("example.com", b"not a model"))           # not a model host: ignored
    m.response(SimpleNamespace(request=SimpleNamespace(host="api.openai.com"), response=None))
    bad = flow("api.openai.com", b"x")
    bad.response.content = None                                  # odd body: recorded, not raised
    m.response(bad)
    lines = (tmp_path / "wire.jsonl").read_text().splitlines()
    assert [json.loads(line)["host"] for line in lines] == ["openrouter.ai", "api.openai.com"]
    assert json.loads(lines[0])["tool_calls"][0]["name"] == "browser_click"
    assert json.loads(lines[0])["caller"] == "prax-prod"
    monkeypatch.delenv("PROXY_WIRE_RECORD")
    importlib.reload(m)
