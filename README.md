# prax-secrets-proxy

A tiny **credential-injecting egress proxy** so an agent (Prax, or any client) runs
with **no real API keys in its process**. The proxy — a *separate, isolated
service* — holds the keys; the agent points its model client's base URL at the
proxy, which strips the placeholder auth, **injects the real key**, forwards to the
provider, and **streams** the response back.

**The guarantee:** a compromised or prompt-injected agent has **nothing to steal** —
it can't read or exfiltrate a key it never holds. This is the infra-level *"make the
secret unreachable"* boundary: the real wall, versus an in-code guard the agent can
edit (or a second `.env` in the same repo, which the agent's process can just
`open()`).

Part of the [Prax](https://github.com/praxagent/prax) suite. Apache-2.0.

## Why a separate service (and repo)

Two `.env` files in one directory is **not** a boundary — the agent's process can
read any file it has filesystem access to. Real isolation requires the keys to live
where the **agent's process can't reach them**: a separate OS user, container, or
host. This proxy is that separate trust domain. Deploy it isolated; that isolation
— not the file naming — is the security.

**It's opt-in and adds no default friction.** An agent that doesn't want it just
keeps its keys in its own env and never points a base URL here. Nothing to run,
nothing to learn. The proxy is for deployments that want the hardened, keyless mode.

## Run it

**Docker (recommended — a separate container *is* the isolation):**

```bash
cp .env-example .env          # put the REAL keys in .env  (.env is gitignored)
docker compose up --build     # gunicorn on :8785, in its own container
```

**Or natively, in the proxy's own shell:**

```bash
cp .env-example .env          # put the REAL keys in .env  (.env is gitignored)
pip install -e .              # or: uv sync
python -m secrets_proxy       # loads .env; listens on 127.0.0.1:8785
```

Then point a **keyless** agent at it. The agent's "key" is the **proxy access
token** (see below) — not a real provider key:

```bash
OPENAI_BASE_URL=http://<proxy-host>:8785/openai
ANTHROPIC_BASE_URL=http://<proxy-host>:8785/anthropic
OPENAI_KEY=<the PROXY_AUTH_TOKEN>      # the proxy swaps this for the real key
ANTHROPIC_KEY=<the PROXY_AUTH_TOKEN>
```

`GET /healthz` reports which providers have a key (booleans only, never values).

## Access token (the proxy owns it) + TLS

**The proxy owns the token.** So that only the *authorised* agent — not any other
process or person who can reach the port — can spend the keys, the proxy requires a
shared token. Generate it **on the proxy side** and set `PROXY_AUTH_TOKEN` in the
proxy's `.env`; hand the agent a copy as its `OPENAI_KEY`/`ANTHROPIC_KEY`. The agent
presents it in the normal auth slot (`Authorization: Bearer …` / `x-api-key`); the
proxy validates it constant-time, then **strips it and injects the real provider
key**. No token → `401`, before it even reveals whether a provider exists.

```bash
./scripts/gen-token.sh          # prints prx_… → put in PROXY_AUTH_TOKEN + agent's keys
```

**TLS** (so the token + traffic aren't sent in plaintext). On loopback nothing
crosses a wire, so it's optional there; for anything cross-host, turn it on:

```bash
./scripts/gen-cert.sh <proxy-host>          # writes certs/proxy.crt + .key (self-signed)
# proxy .env:   PROXY_TLS_CERT=certs/proxy.crt   PROXY_TLS_KEY=certs/proxy.key
# agent env:    SSL_CERT_FILE=/abs/path/certs/proxy.crt   + https:// base URLs
```

`SSL_CERT_FILE` is honored by the httpx-based OpenAI/Anthropic SDKs, so the agent
trusts the self-signed cert with **no code change**. (mTLS is a natural next step if
you want the proxy to authenticate the agent by client cert instead of a token.)

## What it does — and its honest limits

**Guarantees**
- The agent never holds a real key → it can't be *exfiltrated* from the agent by any
  path (env read, `.env` read, a poisoned tool call, an injection).
- Client-supplied auth is **stripped** and the real key **injected server-side**, so
  a leaked placeholder is worthless.
- **Allowlist by construction** — only the configured providers (`/openai/…`,
  `/anthropic/…`) are reachable; an unknown prefix is a `404`, so it can't be turned
  into an open relay.
- **Audit log** — one line per call (method / provider / path / status / request
  size), **never** the key or body.

- **Token-gated** — with `PROXY_AUTH_TOKEN` set, only a caller presenting the shared
  token can reach any provider; everyone else gets `401`.

**Limits (go in clear-eyed)**
- It stops key **theft**, not key **abuse** — a compromised agent that still holds
  the *token* can make legitimate-looking calls it shouldn't (spam the model; smuggle
  data inside a request to an allowed provider). That's a strong *containment* of the
  key material, not total security — "hardened," not "airtight." Mitigate further
  with rate limits, payload caps, the audit log, and (optionally) a policy inspector
  on flagged requests.
- **The proxy is the trusted component** — it holds the keys, so isolate it (its own
  user/container) and don't let the agent reach *its* config.

## Production

- Front it with a real WSGI server, not the Flask dev server (the Docker image does
  this): `gunicorn -k gthread -w 4 'secrets_proxy.app:build_proxy_app()'`.
- **Set `PROXY_AUTH_TOKEN`** and require it from the agent; **enable TLS** for any
  non-loopback link (or run over a tunnel — WireGuard/Tailscale). Loopback on a
  trusted host can skip both (nothing crosses a wire).
- Run it as its own container/user with the keys in *its* secret store only.

## Test

```bash
pip install -e '.[dev]'
pytest -q          # keyless: mocks the upstream, pins the security properties
```
