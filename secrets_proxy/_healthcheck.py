"""Container healthcheck — succeed if /healthz returns 200 over HTTPS or HTTP.

Scheme-agnostic so the same check works whether or not TLS is configured. The
self-signed cert is accepted (this runs inside the container against localhost).
"""
import os
import ssl
import sys
import urllib.request

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_port = os.environ.get("PROXY_PORT", "8785")

for _url in (f"https://localhost:{_port}/healthz", f"http://localhost:{_port}/healthz"):
    try:
        if urllib.request.urlopen(_url, context=_ctx, timeout=3).status == 200:  # noqa: S310
            sys.exit(0)
    except Exception:  # noqa: BLE001 - any failure just means "not this scheme / not ready"
        continue
sys.exit(1)
