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

# Egress policy — off unless PROXY_EGRESS_POLICY is set (secrets_proxy/egress_policy.py).
from secrets_proxy import egress_policy as _egress_mod  # noqa: E402

_egress = _egress_mod.from_env()
_ADMIN_PORT = int(os.environ.get("PROXY_EGRESS_ADMIN_PORT", "8791"))


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


async def request(flow) -> None:  # noqa: ANN001 - mitmproxy passes an http.HTTPFlow
    """mitmproxy hook: authenticate the caller, decide the request (policy on),
    then inject by destination host.

    Async so a request held for a person's answer does not stall the others.
    """
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

    # Decide BEFORE anything is injected or sent. The whole request is visible
    # here — TLS is already terminated — so HTTPS is judged on method and path.
    if _egress is not None:
        # Judge the address that will actually be DIALLED (req.host: the CONNECT
        # target or absolute-form URL), not the client-chosen Host header — and
        # refuse a request whose Host header disagrees with it.
        target = (req.host or "").lower().rstrip(".")
        claimed = (host or "").lower().rstrip(".")
        if claimed and claimed != target:
            logger.info("[egress] deny: Host %r does not match the dialled %r", claimed, target)
            flow.response = _forbidden(f"Host header {claimed} does not match the destination {target}")
            return
        host = target
        verdict, why = await _egress.check(host, req.port, req.method, req.path)
        logger.info("[egress] %s %s %s:%s%s — %s", verdict, req.method, host, req.port,
                    req.path.split("?", 1)[0][:80], why)
        if verdict != "allow":
            flow.response = _forbidden(why)
            return

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


async def running() -> None:
    """mitmproxy lifecycle hook: warn if running open; start the egress policy."""
    if not _AUTH_TOKEN:
        logger.warning(
            "[forward] PROXY_FORWARD_AUTH_TOKEN is not set — ANY caller that can "
            "reach this listener can spend the real credentials anonymously. "
            "Set it, and publish the port to loopback or a private interface only.")
    if _egress is None:
        return
    import asyncio

    from mitmproxy import ctx

    # Connect upstream only once a request is allowed. mitmproxy's default
    # ("eager") dials — and so resolves — the destination as soon as a CONNECT
    # arrives, i.e. before the policy has decided: a denied name would still
    # leave as a DNS query.
    ctx.options.update(connection_strategy="lazy")
    # A CONNECT tunnel carrying neither TLS nor HTTP would otherwise become a
    # raw TCP relay that never reaches the request hook — i.e. never decided.
    ctx.options.update(rawtcp=False)
    await asyncio.start_server(
        lambda r, w: _egress_mod.handle_admin(_egress, r, w), "0.0.0.0", _ADMIN_PORT)
    logger.info("[forward] egress policy on: default=%s, %d rules, admin :%d",
                _egress.policy.default, len(_egress.policy.rules), _ADMIN_PORT)


async def server_connect(data) -> None:  # noqa: ANN001 - mitmproxy ServerConnectionHookData
    """Connect to the address that was checked, never a second resolution.

    Every upstream connection passes here (after the request was allowed, with
    connection_strategy=lazy). The name is resolved once, checked against
    private / loopback / link-local ranges, and the connection is pinned to
    that address — a DNS answer that changes between check and connect
    (rebinding) cannot redirect it inside. SNI keeps the original name.
    """
    if _egress is None:
        return
    server = data.server
    host, port = server.address
    try:
        ip = await _egress.pinned_address(str(host), int(port))
    except (PermissionError, OSError) as exc:
        logger.info("[egress] deny connect %s:%s — %s", host, port, exc)
        server.error = f"egress policy: {exc}"
        return
    if server.sni is None and not _is_ip_literal(str(host)):
        server.sni = str(host)
    server.address = (ip, port)


def tcp_start(flow) -> None:  # noqa: ANN001 - mitmproxy TCPFlow
    """Raw TCP is never decided by the request hook: refuse it outright."""
    if _egress is not None:
        logger.info("[egress] deny raw TCP to %s", getattr(flow.server_conn, "address", "?"))
        flow.kill()


def _is_ip_literal(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _forbidden(why: str):  # noqa: ANN202 - mitmproxy Response
    from mitmproxy import http

    return http.Response.make(
        403, f"Blocked by the egress policy: {why}\n".encode(), {"Content-Type": "text/plain"})
