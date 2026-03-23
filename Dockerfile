# Aegis MCP Server — Minimal Docker image for Glama
#
# Build:  docker build -t aegis-mcp .
# Run:    docker run -i aegis-mcp
#         docker run -i -v ./policy.yaml:/app/policy.yaml -e AEGIS_POLICY_PATH=/app/policy.yaml aegis-mcp
#
# The MCP server uses stdio transport — run with -i (interactive) for stdin.

FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir 'agent-aegis[mcp]'

COPY policy.example.yaml /app/policy.yaml

ENV AEGIS_POLICY_PATH=/app/policy.yaml

ENTRYPOINT ["aegis-mcp-server"]
