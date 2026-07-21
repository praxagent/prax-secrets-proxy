"""Run the secrets proxy as a standalone, isolated process.

    # In the PROXY's OWN environment (a separate container/user/host — the ONLY
    # place the real keys live; the agent's process must NOT be able to read them):
    cp .env-example .env      # then put the REAL keys in .env
    python -m secrets_proxy   # loads .env; listens on 127.0.0.1:8785

Then point a KEYLESS agent at it (its env has only placeholders):
    OPENAI_BASE_URL=http://<proxy-host>:8785/openai
    ANTHROPIC_BASE_URL=http://<proxy-host>:8785/anthropic
    OPENAI_KEY=proxy-placeholder      # any non-empty string; the proxy overwrites it
    ANTHROPIC_KEY=proxy-placeholder

For production use a WSGI server (gunicorn/waitress) instead of the dev server;
see the README.
"""
from __future__ import annotations

import logging
import os

from secrets_proxy.app import build_proxy_app
from secrets_proxy.config import ProxyConfig


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [secrets-proxy] %(message)s")
    # Load the proxy's own env file (default .env) — the ONE place the real keys
    # live. Existing os.environ wins (override=False) so `OPENAI_KEY=… python -m
    # secrets_proxy` still works.
    env_file = os.environ.get("PROXY_ENV_FILE", ".env")
    try:
        from dotenv import load_dotenv
        if load_dotenv(env_file, override=False):
            logging.getLogger("secrets_proxy").info("loaded env from %s", env_file)
    except Exception:  # noqa: BLE001 — dotenv is best-effort; env vars still work
        logging.getLogger("secrets_proxy").debug("no %s loaded", env_file)
    cfg = ProxyConfig.from_env()
    app = build_proxy_app(cfg)
    log = logging.getLogger("secrets_proxy")
    have = [n for n, up in cfg.upstreams.items() if up.real_key()]
    scheme = "https" if cfg.tls_context else "http"
    log.info("listening on %s://%s:%d — keys present for: %s",
             scheme, cfg.host, cfg.port,
             ", ".join(have) or "(none — set OPENAI_KEY/ANTHROPIC_KEY)")
    if not cfg.auth_token:
        log.warning("PROXY_AUTH_TOKEN is not set — the proxy is OPEN to anyone who "
                    "can reach the port. Set it (and require it from the agent) "
                    "unless you fully trust reachability (e.g. loopback only).")
    if not cfg.tls_context and cfg.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Serving plain HTTP on a non-loopback address — the token and "
                    "traffic cross the wire in plaintext. Set PROXY_TLS_CERT/"
                    "PROXY_TLS_KEY (see scripts/gen-cert.sh) or use a tunnel.")
    # threaded=True so streaming responses don't block other requests. For prod,
    # front with gunicorn: `gunicorn -k gthread 'secrets_proxy.app:build_proxy_app()'`.
    app.run(host=cfg.host, port=cfg.port, threaded=True, ssl_context=cfg.tls_context)


if __name__ == "__main__":
    main()
