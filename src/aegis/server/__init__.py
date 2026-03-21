"""Aegis REST API server.

Exposes the governance pipeline over HTTP so any language or tool
can benefit from policy checks, approval gates, and audit logging.

Quick start::

    aegis serve policy.yaml --port 8000

Or programmatically::

    from aegis.server.app import create_app
    app = create_app(policy_path="policy.yaml")
    # Use with any ASGI server: uvicorn, hypercorn, daphne
"""
