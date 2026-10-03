"""A ceiling no policy edit or person's answer can exceed, and a diff of what a
policy change newly allows. Idea credit: NVIDIA OpenShell's policy prover."""
from __future__ import annotations

import asyncio
import json

from secrets_proxy import egress_policy as ep

OLD = {"default": "ask", "rules": [
    {"host": "openrouter.ai", "action": "allow"},
    {"host": "*", "methods": ["GET", "HEAD"], "action": "allow", "clean_only": True},
]}
NEW = {"default": "ask", "rules": [
    {"host": "openrouter.ai", "action": "allow"},
    {"host": "pastebin.com", "action": "allow"},
    {"host": "*", "methods": ["GET", "HEAD"], "action": "allow"},
]}
CEILING = {"default": "deny", "rules": [
    {"host": "openrouter.ai", "action": "allow"},
    {"host": "*", "methods": ["GET", "HEAD"], "action": "allow"},
]}


def _policy(d):
    return ep.Policy.from_dict(d)


def _gate(policy, ceiling=None):
    return ep.EgressPolicy(_policy(policy), "admin", ceiling=_policy(ceiling) if ceiling else None,
                           resolver=lambda h, p: asyncio.sleep(0, result=["93.184.216.34"]),
                           ask_timeout=0.05)


def _check(gate, host, method="POST", path="/"):
    return asyncio.run(gate.check(host, 443, method, path))


def test_outside_the_ceiling_is_denied_without_asking():
    gate = _gate(NEW, CEILING)
    verdict, why = _check(gate, "pastebin.com")      # the policy ALLOWS it
    assert verdict == "deny" and "outside the ceiling" in why
    verdict, _ = _check(gate, "example.org")         # the policy would ASK
    assert verdict == "deny" and gate.pending() == []  # nobody is asked
    assert _check(gate, "openrouter.ai")[0] == "allow"
    assert _check(gate, "example.org", "GET")[0] == "allow"


def test_a_remembered_allow_cannot_exceed_the_ceiling():
    import time
    gate = _gate(NEW, CEILING)
    key = gate.key("example.org", 443, "POST", "/")
    gate._decisions[key] = ("allow", time.monotonic() + 600, "a person said yes", False)
    assert _check(gate, "example.org")[0] == "deny"
    assert _check(_gate(NEW), "example.org")[0] == "deny"  # sanity: no answer = deny
    ungated = _gate(NEW)
    ungated._decisions[key] = ("allow", time.monotonic() + 600, "a person said yes", False)
    assert _check(ungated, "example.org")[0] == "allow"   # the same answer works without it


def test_no_ceiling_keeps_the_prior_behaviour():
    assert _check(_gate(NEW), "pastebin.com")[0] == "allow"


def test_diff_names_what_the_new_policy_opens():
    changes = ep.diff(_policy(OLD), _policy(NEW), ceiling=_policy(CEILING),
                      credential_hosts=frozenset({"openrouter.ai"}))
    got = {c["request"]: c for c in changes}
    assert got["POST pastebin.com/"]["was"] == "ask" and got["POST pastebin.com/"]["now"] == "allow"
    assert got["POST pastebin.com/"]["beyond_ceiling"] is True
    # dropping clean_only: reading the web after touching private data
    assert got["GET any other host/ after reading private data"]["now"] == "allow"
    assert "beyond_ceiling" not in got["GET any other host/ after reading private data"]
    assert not any(c["credential"] for c in changes)  # openrouter unchanged


def test_diff_of_identical_policies_is_empty():
    assert ep.diff(_policy(OLD), _policy(OLD)) == []


def test_tightening_is_not_reported():
    assert ep.diff(_policy(NEW), _policy(OLD)) == []


def test_exceeding_lists_policy_rules_past_the_ceiling():
    beyond = ep.exceeding(_policy(NEW), _policy(CEILING))
    assert "POST pastebin.com/" in beyond
    assert not any(b.startswith("POST openrouter.ai") for b in beyond)


def test_cli(tmp_path, capsys):
    for name, doc in (("old", OLD), ("new", NEW), ("ceiling", CEILING)):
        (tmp_path / f"{name}.json").write_text(json.dumps(doc))
    (tmp_path / "map.json").write_text(json.dumps([{"host": "pastebin.com", "scheme": "bearer"}]))
    code = ep._cli(["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"),
                    "--ceiling", str(tmp_path / "ceiling.json"),
                    "--forward-map", str(tmp_path / "map.json")])
    out = capsys.readouterr().out
    assert code == 1
    assert "POST pastebin.com/: ask -> allow" in out
    assert "[carries a credential]" in out and "[beyond the ceiling: will be refused]" in out
    assert ep._cli(["diff", str(tmp_path / "old.json"), str(tmp_path / "old.json")]) == 0
