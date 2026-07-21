#!/usr/bin/env bash
# Generate a self-signed TLS cert+key for the secrets proxy so the token and
# traffic aren't exchanged in plaintext. The client (agent) trusts it by pointing
# SSL_CERT_FILE at the cert — the httpx-based OpenAI/Anthropic SDKs honor it, so
# no client code change. Not a CA-signed cert; fine for a private agent<->proxy link.
#
#   ./scripts/gen-cert.sh [HOST]      # HOST defaults to the proxy's hostname/IP
#
# Then in the proxy's .env:   PROXY_TLS_CERT=certs/proxy.crt
#                             PROXY_TLS_KEY=certs/proxy.key
# And in the agent's env:     SSL_CERT_FILE=/abs/path/to/certs/proxy.crt
#                             OPENAI_BASE_URL=https://<host>:8785/openai   (note https)
set -euo pipefail

HOST="${1:-secrets-proxy}"
OUT_DIR="${CERT_DIR:-certs}"
mkdir -p "$OUT_DIR"

# SAN covers the DNS name and loopback so it validates whether reached by name
# (docker network: secrets-proxy) or 127.0.0.1.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/proxy.key" -out "$OUT_DIR/proxy.crt" \
  -days 825 -subj "/CN=${HOST}" \
  -addext "subjectAltName=DNS:${HOST},DNS:localhost,IP:127.0.0.1"

chmod 600 "$OUT_DIR/proxy.key"
echo "Wrote $OUT_DIR/proxy.crt and $OUT_DIR/proxy.key (CN=${HOST})."
echo "Proxy .env:  PROXY_TLS_CERT=$OUT_DIR/proxy.crt   PROXY_TLS_KEY=$OUT_DIR/proxy.key"
echo "Agent  env:  SSL_CERT_FILE=$(cd "$OUT_DIR" && pwd)/proxy.crt   (and use https:// base URLs)"
