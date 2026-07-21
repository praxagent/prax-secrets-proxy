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
from secrets_proxy.app import build_proxy_app
from secrets_proxy.config import ProxyConfig, Upstream

__all__ = ["ProxyConfig", "Upstream", "build_proxy_app"]
