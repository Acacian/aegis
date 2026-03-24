# Aegis REST API Server — Minimal Docker image
#
# Build:  docker build -t aegis-server examples/docker/
# Run:    docker run -p 8000:8000 -v ./policy.yaml:/app/policy.yaml aegis-server
#
# Mount your policy.yaml into /app/ to use your own rules.

FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4 # python:3.12-slim

WORKDIR /app

# Install Aegis with server extras
RUN pip install --no-cache-dir 'agent-aegis[server]'

# Default policy (can be overridden with volume mount)
COPY policy.yaml /app/policy.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["aegis", "serve", "/app/policy.yaml", "--host", "0.0.0.0", "--port", "8000"]
