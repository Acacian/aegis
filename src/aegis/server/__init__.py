"""Aegis Governance Framework Server.

Exposes the governance pipeline over HTTP so any language or tool
can benefit from policy checks, approval gates, audit logging,
and multi-agent management.

Quick start (standalone)::

    aegis-server                          # uses ./aegis-server.yaml
    aegis-server --config /etc/aegis.yaml

Quick start (subcommand)::

    aegis serve policy.yaml --port 8000

Programmatically::

    from aegis.server.config import ServerConfig
    from aegis.server.app import create_app_from_config

    config = ServerConfig.from_yaml("aegis-server.yaml")
    app = create_app_from_config(config)
    # Use with any ASGI server: uvicorn, hypercorn, daphne
"""
