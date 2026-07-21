#!/usr/bin/env bash
# Generate the shared proxy auth token. The PROXY owns this token — it lives in
# the proxy's .env (PROXY_AUTH_TOKEN); the agent is merely handed a copy to
# present (as its OPENAI_KEY/ANTHROPIC_KEY). Run this on the proxy side, then copy
# the printed value into BOTH the proxy's .env and the agent's env.
#
#   ./scripts/gen-token.sh
set -euo pipefail

TOKEN="prx_$(openssl rand -hex 32)"
echo "$TOKEN"
echo >&2 "Proxy .env:  PROXY_AUTH_TOKEN=$TOKEN"
echo >&2 "Agent  env:  OPENAI_KEY=$TOKEN  and  ANTHROPIC_KEY=$TOKEN"
