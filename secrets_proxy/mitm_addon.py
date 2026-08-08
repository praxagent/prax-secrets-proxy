"""mitmproxy addon — the FORWARD (transparent egress) proxy for keyless Prax.

This is the thin glue; all logic is in ``forward_inject.py``. mitmproxy handles
the hard parts (CONNECT, on-the-fly per-host certificate generation, TLS
termination on both legs); this hook just injects the right credential by
destination host, from the registry-generated forward-map.

Run it (in the proxy's own container/host — see docs):

    PROXY_FORWARD_MAP=/config/forward-map.json \\
    mitmdump --mode regular --listen-host 0.0.0.0 --listen-port 8786 \\
             -s secrets_proxy/mitm_addon.py

The client (Prax) then sets ``HTTPS_PROXY=http://<proxy-host>:8786`` and trusts
the mitmproxy CA (``~/.mitmproxy/mitmproxy-ca-cert.pem``, merged into Prax's CA
bundle). See ``docs/security/deployment-topology.md`` in the prax repo.

SECURITY: this process terminates TLS for ALL of Prax's egress, so it sees every
request body and holds every key. It MUST run locked-down and isolated from Prax
(its own container/user). Never logs a key or a body — only ``scheme@host``.
"""
from __future__ import annotations

import base64
import hmac
import logging
import os
from urllib.parse import parse_qsl, urlencode

from secrets_proxy.forward_inject import ForwardInjector

logger = logging.getLogger("secrets_proxy.forward")
_injector = ForwardInjector.from_env()

# Caller authentication. The Tier-1 reverse proxy has always required a token;
# this one did not, so ANY process able to reach the listener could spend the
# real keys — it cannot steal them (that is the point of keyless), but it can
# use them freely and anonymously.
#
# Measured exposure on the dev box 2026-08-08 before this landed: published to
# 127.0.0.1 only (not the network), and NOT reachable from the sandbox
# container (verified over 127.0.0.1, the docker bridge, and
# host.docker.internal — all refused). So the real gap was host-local callers
# and the absence of any per-caller attribution, not a remote hole. Fixed
# anyway: the topology is a deployment choice, and a proxy that is safe only
# because of how someone happened to publish its port is not safe.
_AUTH_TOKEN = os.environ.get("PROXY_FORWARD_AUTH_TOKEN") or ""
_AUTH_REALM = "prax-forward-proxy"


def _presented_token(headers) -> str:  # noqa: ANN001 - mitmproxy Headers
    """Token from Proxy-Authorization, accepting Basic or Bearer.

    Basic is what every HTTP client library sends for a proxy given credentials
    in the URL (``http://user:token@host:port``), which is how Prax's
    ``HTTPS_PROXY`` will carry it; Bearer is accepted so a hand-rolled caller
    has an obvious option. Only the password half of Basic is used — the
    username is free-form and carried into the audit line for attribution.
    """
    raw = headers.get("Proxy-Authorization", "") or ""
    scheme, _, value = raw.partition(" ")
    scheme = scheme.lower()
    if scheme == "bearer":
        return value.strip()
    if scheme == "basic":
        try:
            decoded = base64.b64decode(value.strip()).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - malformed credentials are simply wrong
            return ""
        _user, _, password = decoded.partition(":")
        return password
    return ""


def _caller_label(headers) -> str:  # noqa: ANN001
    """Username half of Basic auth, for the audit line. Never the token."""
    raw = headers.get("Proxy-Authorization", "") or ""
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "basic":
        return "-"
    try:
        decoded = base64.b64decode(value.strip()).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return "-"
    user, _, _pw = decoded.partition(":")
    return user[:40] or "-"


def request(flow) -> None:  # noqa: ANN001 - mitmproxy passes an http.HTTPFlow
    """mitmproxy hook: authenticate the caller, then inject by destination host."""
    req = flow.request
    host = req.pretty_host

    # Authenticate BEFORE looking at the rule, so an unauthenticated caller
    # cannot use response timing to learn which hosts are injection targets.
    if _AUTH_TOKEN:
        presented = _presented_token(req.headers)
        if not hmac.compare_digest(presented, _AUTH_TOKEN):
            logger.warning("[forward] 407 %s (bad or missing proxy credentials)", host)
            flow.response = _unauthorized()
            return
    # Strip the proxy credential regardless: it authenticates the caller to US
    # and must never travel on to the provider.
    if "Proxy-Authorization" in req.headers:
        del req.headers["Proxy-Authorization"]

    rule = _injector.rule_for(host)
    if rule is None:
        return  # not an allow-listed injection target — pass through untouched

    headers = {k: v for k, v in req.headers.items()}
    query = urlencode(list(req.query.items(multi=True)))
    new_headers, new_query = _injector.inject(host, headers, query)

    removed = {k.lower() for k in headers} - {k.lower() for k in new_headers}
    for k in list(req.headers.keys()):
        if k.lower() in removed:
            del req.headers[k]
    for k, v in new_headers.items():
        req.headers[k] = v
    if new_query != query:
        req.query = list(parse_qsl(new_query, keep_blank_values=True))

    # Audit carries WHO, so injections are attributable to a caller rather than
    # anonymous. Never the key, never the body.
    logger.info("[forward] injected %s @ %s (caller=%s)",
                rule.scheme, host, _caller_label(req.headers))


def _unauthorized():  # noqa: ANN202 - mitmproxy Response
    """407, the correct status for proxy auth — and it tells the caller nothing
    about whether the destination host is an injection target."""
    from mitmproxy import http

    return http.Response.make(
        407,
        b"proxy authentication required\n",
        {"Proxy-Authenticate": f'Basic realm="{_AUTH_REALM}"',
         "Content-Type": "text/plain"},
    )


def running() -> None:
    """mitmproxy lifecycle hook — warn loudly if this is running open."""
    if not _AUTH_TOKEN:
        logger.warning(
            "[forward] PROXY_FORWARD_AUTH_TOKEN is not set — ANY caller that can "
            "reach this listener can spend the real credentials anonymously. "
            "Set it, and publish the port to loopback or a private interface only.")
