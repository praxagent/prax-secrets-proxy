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

USER proxy

# Loopback INSIDE the container; publish/attach to a network deliberately. The
# proxy is unauthenticated by design — reachability is the control.
ENV PROXY_HOST=0.0.0.0 PROXY_PORT=8785
EXPOSE 8785

# Real WSGI server, threaded so streaming responses don't block a worker.
CMD ["gunicorn", "-k", "gthread", "-w", "4", "--threads", "8", \
     "-b", "0.0.0.0:8785", "secrets_proxy.app:build_proxy_app()"]
