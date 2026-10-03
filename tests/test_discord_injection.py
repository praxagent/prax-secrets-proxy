"""Discord through the forward proxy: 'Bot ' on REST, the token in the gateway's
IDENTIFY/RESUME messages, and only for the callers that may run the bot."""
from __future__ import annotations

import json

import pytest

from secrets_proxy.forward_inject import ForwardInjector

DISCORD = [
    {"host": "discord.com", "scheme": "header:Authorization", "prefix": "Bot ",
     "key_env": "DISCORD_BOT_TOKEN", "callers": ["prax-prod"], "exclusive": True},
    {"host": "discord.gg", "scheme": "ws-json:d.token",
     "key_env": "DISCORD_BOT_TOKEN", "callers": ["prax-prod"], "exclusive": True},
]
IDENTIFY = json.dumps({"op": 2, "d": {"token": "placeholder", "intents": 513}})


@pytest.fixture()
def inj(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "fake.bot.token")
    return ForwardInjector.from_map(DISCORD)


def test_rest_gets_the_bot_prefix(inj):
    out, _ = inj.inject("discord.com", {"Authorization": "Bot placeholder"}, caller="prax-prod")
    assert out["Authorization"] == "Bot fake.bot.token"


def test_gateway_identify_and_resume_get_the_token(inj):
    for op in (2, 6):
        msg = json.dumps({"op": op, "d": {"token": "placeholder", "session_id": "s"}})
        out = inj.inject_ws_text("gateway-us-east1-b.discord.gg", msg, "prax-prod")
        assert json.loads(out)["d"]["token"] == "fake.bot.token"


def test_other_messages_are_left_alone(inj):
    for msg in (json.dumps({"op": 1, "d": 42}), json.dumps({"op": 3, "d": {"status": "online"}}),
                "not json"):
        assert inj.inject_ws_text("gateway.discord.gg", msg, "prax-prod") is None


def test_another_caller_gets_nothing(inj):
    """Rule 0: a dev instance holding the placeholder must not become the bot."""
    assert inj.inject_ws_text("gateway.discord.gg", IDENTIFY, "prax-dev") is None
    assert inj.inject_ws_text("gateway.discord.gg", IDENTIFY, "") is None
    out, _ = inj.inject("discord.com", {"Authorization": "Bot placeholder"}, caller="prax-dev")
    assert "fake.bot.token" not in json.dumps(out)


def test_websocket_rules_never_touch_http(inj):
    assert inj.http_rule_for("gateway.discord.gg", "prax-prod") is None
    assert inj.http_rule_for("discord.com", "prax-prod").scheme == "header:Authorization"


def test_an_exclusive_rule_without_callers_refuses_to_load():
    with pytest.raises(ValueError, match="exclusive"):
        ForwardInjector.from_map([{**DISCORD[1], "callers": []}])


def test_a_bad_websocket_path_refuses_to_load():
    with pytest.raises(ValueError, match="websocket path"):
        ForwardInjector.from_map([{"host": "x.example", "scheme": "ws-json:d..token", "key_env": "K"}])
