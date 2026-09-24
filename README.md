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

This section is the **reverse proxy on `:8785`**. The opt-in forward proxy on `:8786`
has its own, separate token (`PROXY_FORWARD_AUTH_TOKEN`) — see
[Forward (MITM) proxy](#forward-mitm-proxy--opt-in-covers-all-egress).

**The proxy owns the token.** So that only the *authorised* agent — not any other
process or person who can reach the port — can spend the keys, the proxy requires a
shared token. Generate it **on the proxy side** and set `PROXY_AUTH_TOKEN` in the
proxy's `.env`; hand the agent a copy as its `OPENAI_KEY`/`ANTHROPIC_KEY`. The agent
presents it in the normal auth slot (`Authorization: Bearer …` / `x-api-key`); the
proxy validates it constant-time, then **strips it and injects the real provider
key**. With `PROXY_AUTH_TOKEN` set, a missing or wrong token → `401`, before it even
reveals whether a provider exists. Leaving `PROXY_AUTH_TOKEN` **empty runs the reverse
proxy open** to any caller that can reach the port (`docker-compose.yml` publishes it
to `127.0.0.1` only by default, and that reachability is then the only control).

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

(This section describes the reverse proxy on `:8785`. The forward proxy's properties
and verification status are in its own section below.)

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

## Forward (MITM) proxy — opt-in, covers all egress

The reverse proxy above only covers providers that expose a base-URL knob (`/openai`,
`/anthropic`). Everything else an agent calls (search APIs, TTS, telephony, …) goes
straight to the real host over TLS, so the only way to keep *those* keys out of the
agent is a **forward proxy that terminates TLS and injects the credential by
destination host**. That is the `forward` compose profile: mitmproxy running this
repo's addon (`secrets_proxy/mitm_addon.py`; the injection logic is
`secrets_proxy/forward_inject.py`).

```bash
# 1. Generate the host→credential map from Prax's credential registry (run in the prax repo):
python -m prax.services.credential_registry --export-forward-map ../prax-secrets-proxy/forward-map.json
# 2. Set PROXY_FORWARD_AUTH_TOKEN in the proxy's .env (see below), then:
docker compose --profile forward up      # mitmdump on :8786, published to 127.0.0.1 only
```

Natively, the addon needs the `forward` extra (`pip install -e '.[forward]'`, which
pulls in mitmproxy) and runs as
`mitmdump --mode regular --listen-host 127.0.0.1 --listen-port 8786 -s secrets_proxy/mitm_addon.py`
with `PROXY_FORWARD_MAP` pointing at the map file. Pass `--listen-host` explicitly:
mitmdump's `listen_host` default is empty, which binds every interface, so without it
the native listener is not loopback-only the way the compose port mapping is.

**The forward-map.** `forward-map.json` is generated, gitignored, and mounted
read-only into the container. Each rule is a destination host plus one of four
injection schemes (`bearer`, `header:<Name>`, `basic`, `query:<param>`) and the env
var(s) holding the real value; a rule matches its host exactly or as a dot-suffix
(`tavily.com` also covers `api.tavily.com`), longest host first. A host with no rule
passes through untouched, and with no map at all the proxy injects nothing. The map
includes the model providers, so in forward mode you do **not** also set
`OPENAI_BASE_URL`/`ANTHROPIC_BASE_URL`.

**Client wiring.** The client sets `HTTPS_PROXY` (and `HTTP_PROXY`) at the proxy with
the token in the URL's credential slot, and trusts the mitmproxy CA:

```bash
HTTPS_PROXY=http://prax:<PROXY_FORWARD_AUTH_TOKEN>@<proxy-host>:8786
# CA: mitmproxy generates one on first start; the compose file persists it in the
# `mitm-ca` volume at /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem. Copy it out
# and add it to the bundle the client trusts (SSL_CERT_FILE / REQUESTS_CA_BUNDLE).
```

The Prax-side procedure (CA bundle, `NO_PROXY`, non-empty placeholder keys) is in the
prax repo:
[`docs/security/deployment-topology.md`](https://github.com/praxagent/prax/blob/main/docs/security/deployment-topology.md).

**Caller authentication — `PROXY_FORWARD_AUTH_TOKEN`.** This listener has its own
token, separate from the reverse proxy's `PROXY_AUTH_TOKEN`:

- With the token set, the addon reads `Proxy-Authorization` — `Basic user:token`
  (what HTTP clients send for credentials in a proxy URL) or `Bearer token` —
  compares the token constant-time, and answers `407` with
  `Proxy-Authenticate: Basic realm="prax-forward-proxy"` on a missing or wrong token.
  The check runs **before** the injection rule is looked up, so a refused caller
  cannot probe which hosts get credentials.
- The credential is stripped before the request goes upstream, token or no token — it
  authenticates the caller to this proxy and must never reach a provider.
- With the token **empty** the forward proxy is **open**: anyone who can reach
  `:8786` spends the real keys anonymously. The addon logs a warning at startup;
  loopback publishing is then the only control.
- The `Basic` username is free-form and is meant to identify the caller in the
  audit line (see the known gap below).

**Audit.** The addon logs one line per injected request —
`[forward] injected <scheme> @ <host> (caller=<label>)` — and never a key or a body.
(mitmdump's own console output is separate from this line.)

**Known gap (2026-09):** the `caller=` label is always `-`. `request()` in
`secrets_proxy/mitm_addon.py` deletes `Proxy-Authorization` (to keep it off the wire
upstream) before it calls `_caller_label()` on the same headers, so the username is
gone by the time the audit line is built. Reproduced with a valid `Basic` credential.
The unit test for the label (`tests/test_forward_auth.py`,
`test_caller_label_is_the_username_never_the_token`) calls `_caller_label()` on a
hand-built header dict rather than through `request()`, so it does not catch this.

**Verification status.** The 407/allow/strip behaviour above is **unit-tested only**,
against a hand-built request object (`tests/test_forward_auth.py`), not through
mitmproxy. One open question matters for real clients: the check runs in mitmproxy's
`request` hook, and HTTP clients send `Proxy-Authorization` on the `CONNECT` request
when the destination is `https://`, not on the tunnelled requests inside it. Whether
the hook sees that credential for HTTPS destinations has **not been verified live**
with the token set; if it does not, HTTPS callers get `407` on every request once
`PROXY_FORWARD_AUTH_TOKEN` is set. Until that is verified, treat the forward proxy's
token gate as unproven and keep `:8786` on loopback or a private interface.

**What this process can see.** It terminates TLS for **all** proxied egress: every
destination, every request and response body, and it holds every key in the map. It
is strictly more trusted than the reverse proxy. Run it locked down and isolated from
the agent (its own container/user), exactly like the reverse proxy. The "stops theft,
not abuse" limit above applies unchanged.

## Egress policy — opt-in: decide every request Prax makes

By default the forward proxy injects keys for known hosts and **passes
everything else through untouched**. Set `PROXY_EGRESS_POLICY` (and
`PROXY_EGRESS_ADMIN_TOKEN`) and it decides every request instead: `allow`,
`deny`, or `ask`. An `ask` holds the request while a person is asked through
the admin API (`127.0.0.1:${PROXY_EGRESS_ADMIN_PORT:-8791}`).

**Tokens:**
- `PROXY_EGRESS_ADMIN_TOKEN` answers questions and belongs to the relay that
  carries a person's answers (TeamWork `EGRESS_GATES`), **never the agent**.
- `PROXY_EGRESS_TAINT_TOKEN` is the agent's, and can only raise taint. The
policy lives in `secrets_proxy/egress_policy.py`, with an example in
`egress-policy.example.json`.

**Why here.** This proxy already terminates TLS for all of Prax's traffic, so
rules see the **method and path of HTTPS requests**, not only the host. You
can allow `GET` but ask about `POST` to the same site.

**Judged on what is dialled.** A request is judged on the address the proxy
will actually connect to (the CONNECT target or absolute URL), and refused if
its `Host` header disagrees. The connection is **pinned** to the address that
was checked, so DNS rebinding cannot redirect it inside. Paths are decoded
and normalised before matching (`/public/../admin` is not under `/public`).
Raw TCP tunnels, which never reach the request hook, are refused.

**No DNS before a decision.** With the policy on, the add-on switches mitmproxy
to `connection_strategy=lazy`. A denied or merely-asked-about name is never
resolved, so it cannot leave as a DNS query. After an allow, a name that
resolves to a private, loopback or link-local address is still refused
(SSRF).

**Answers are scoped.** They are remembered per host + method + path for
`PROXY_EGRESS_ALLOW_TTL`. An allow given while clean is not reused once the
harness marks the work tainted. No answer means deny.

**Enforcement is the other half.** A policy only binds traffic that goes
through the proxy. Prax's `deploy/systemd/prax.service.d/40-egress-only-through-the-proxy.conf`
restricts the Prax process to loopback, with the kernel enforcing it, so the
proxy is its only way out.

Verified live (2026-09-24), with the real mitmproxy and Prax's approval
poller:
- `GET https://example.net` was allowed by rule;
- `POST https://example.net/upload` was held, then denied by a person (403);
- an unknown host was held, then allowed (200);
- a process under the loopback-only restriction could not connect directly,
  but could through the proxy.

## Production

- Front it with a real WSGI server, not the Flask dev server (the Docker image does
  this): `gunicorn -k gthread -w 4 'secrets_proxy.app:build_proxy_app()'`.
- **Set `PROXY_AUTH_TOKEN`** and require it from the agent; **enable TLS** for any
  non-loopback link (or run over a tunnel — WireGuard/Tailscale). Loopback on a
  trusted host can skip both (nothing crosses a wire).
- Forward mode: set **`PROXY_FORWARD_AUTH_TOKEN`** as well, and read the verification
  status above before relying on it as the control.
- Run it as its own container/user with the keys in *its* secret store only.

## Test

```bash
pip install -e '.[dev]'
pytest -q          # keyless: mocks the upstream, pins the security properties
```
