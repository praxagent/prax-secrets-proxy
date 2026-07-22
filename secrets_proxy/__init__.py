"""prax-secrets-proxy — a credential-injecting egress proxy so an agent runs KEYLESS.

The agent (Prax, or any client) runs with NO real API keys. It points its client's
base URL at this proxy — a SEPARATE, isolated service whose env holds the real
keys. The proxy strips whatever placeholder auth the client sent, injects the real
key, forwards to the provider, and streams the response back. The agent can never
read or exfiltrate a key it never holds — the infra-level "make the secret
unreachable" boundary.

Run it isolated (its own container/user/host); the file split alone is not a
boundary — the real wall is that the agent's *process* cannot read the proxy's env.
"""
__all__ = ["ProxyConfig", "Upstream", "build_proxy_app"]


def __getattr__(name):
    """Lazy re-exports so importing this package does NOT pull in Flask/requests.

    The FORWARD-proxy mitmproxy addon imports only ``forward_inject`` (pure
    stdlib) and runs in the mitmproxy image, which has no Flask/requests. Eagerly
    importing ``app`` here crashed the addon on load — so resolve app/config only
    when actually accessed.
    """
    if name == "build_proxy_app":
        from secrets_proxy.app import build_proxy_app
        return build_proxy_app
    if name in ("ProxyConfig", "Upstream"):
        from secrets_proxy import config
        return getattr(config, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
