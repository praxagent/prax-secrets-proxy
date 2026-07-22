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

import logging
from urllib.parse import parse_qsl, urlencode

from secrets_proxy.forward_inject import ForwardInjector

logger = logging.getLogger("secrets_proxy.forward")
_injector = ForwardInjector.from_env()


def request(flow) -> None:  # noqa: ANN001 - mitmproxy passes an http.HTTPFlow
    """mitmproxy hook: inject the destination host's credential, if we have a rule."""
    req = flow.request
    host = req.pretty_host
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

    logger.info("[forward] injected %s @ %s", rule.scheme, host)  # never the key/body
