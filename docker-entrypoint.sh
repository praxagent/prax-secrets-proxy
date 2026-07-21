#!/usr/bin/env sh
# Start gunicorn, adding TLS if PROXY_TLS_CERT/PROXY_TLS_KEY are set. The auth
# token (PROXY_AUTH_TOKEN) is read inside the app from the env, so nothing to do
# for it here. Threaded workers so streaming responses don't block.
set -eu

ARGS="-k gthread -w ${PROXY_WORKERS:-4} --threads ${PROXY_THREADS:-8} -b 0.0.0.0:${PROXY_PORT:-8785}"

if [ -n "${PROXY_TLS_CERT:-}" ] && [ -n "${PROXY_TLS_KEY:-}" ]; then
  echo "[secrets-proxy] TLS on: ${PROXY_TLS_CERT}"
  ARGS="$ARGS --certfile ${PROXY_TLS_CERT} --keyfile ${PROXY_TLS_KEY}"
else
  echo "[secrets-proxy] TLS off (plain HTTP) — fine on loopback/tunnel; else set PROXY_TLS_CERT/KEY."
fi

if [ -z "${PROXY_AUTH_TOKEN:-}" ]; then
  echo "[secrets-proxy] WARNING: PROXY_AUTH_TOKEN unset — proxy is OPEN to anyone who can reach it."
fi

# shellcheck disable=SC2086
exec gunicorn $ARGS 'secrets_proxy.app:build_proxy_app()'
