# The secrets proxy — a tiny, isolated service that holds the real API keys so the
# agent can run KEYLESS. Deploy it in its OWN container/user/host: that isolation
# (the agent's process cannot reach this container's env/filesystem) is the wall.
FROM python:3.13-slim

# Non-root: the keys live in this process's env; don't also hand it root.
RUN useradd --create-home --uid 10001 proxy
WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml README.md ./
COPY secrets_proxy ./secrets_proxy
RUN pip install --no-cache-dir '.[prod]'

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER proxy

ENV PROXY_HOST=0.0.0.0 PROXY_PORT=8785
EXPOSE 8785

# Entrypoint runs gunicorn, adding TLS when PROXY_TLS_CERT/KEY are set and the
# token (PROXY_AUTH_TOKEN) is enforced in-app. Real WSGI server, threaded so
# streaming responses don't block a worker.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
