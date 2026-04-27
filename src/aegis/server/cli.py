"""CLI entry point for ``aegis-server``.

Starts the Aegis governance framework server from a configuration file::

    aegis-server                          # uses ./aegis-server.yaml
    aegis-server --config /etc/aegis.yaml # explicit path
    aegis-server --host 0.0.0.0 --port 9000  # override host/port
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    """Entry point for the ``aegis-server`` command."""
    parser = argparse.ArgumentParser(
        prog="aegis-server",
        description="Aegis Governance Framework Server",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to aegis-server.yaml (default: ./aegis-server.yaml)",
    )
    parser.add_argument("--host", default=None, help="Override bind host")
    parser.add_argument("--port", type=int, default=None, help="Override bind port")
    parser.add_argument("--policy", default=None, help="Override policy file path")
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the web dashboard",
    )
    parser.add_argument(
        "--seed-demo",
        type=int,
        metavar="N",
        help="Seed N demo audit entries before starting",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Generate a starter aegis-server.yaml and exit",
    )

    args = parser.parse_args(argv)

    if args.version:
        from aegis import __version__

        print(f"aegis-server {__version__}")
        return

    if args.init:
        _generate_starter_config()
        return

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is required: pip install 'agent-aegis[server]'",
            file=sys.stderr,
        )
        sys.exit(1)

    from aegis.server.config import ServerConfig

    config_path = args.config or _find_config()
    if config_path and Path(config_path).exists():
        config = ServerConfig.from_yaml(config_path)
        print(f"Loaded config: {config_path}")
    else:
        config = ServerConfig()
        if args.config:
            print(f"Config not found: {args.config}, using defaults", file=sys.stderr)

    # CLI overrides
    if args.host:
        config.server.host = args.host
    if args.port:
        config.server.port = args.port
    if args.policy:
        config.policy.path = args.policy
    if args.no_dashboard:
        config.dashboard.enabled = False

    # Seed demo data
    if args.seed_demo and args.seed_demo > 0:
        from aegis.cli.main import _seed_demo_data

        _seed_demo_data(args.seed_demo, config.audit.sqlite.path)

    from aegis.server.app import create_app_from_config

    app = create_app_from_config(config)

    base_url = f"http://{config.server.host}:{config.server.port}"
    print("\n  Aegis Governance Framework Server")
    print(f"  {'=' * 38}")
    print(f"  Server:    {base_url}")
    print(f"  Policy:    {config.policy.path}")
    print(f"  Audit:     {config.audit.backend}")
    if config.dashboard.enabled:
        print(f"  Dashboard: {base_url}/dashboard")
    print(f"  API:       {base_url}/api/v1/")
    print(f"  Agents:    {base_url}/api/v1/agents")
    print()

    uvicorn.run(app, host=config.server.host, port=config.server.port)


def _find_config() -> str | None:
    """Search for config file in common locations."""
    candidates = [
        "aegis-server.yaml",
        "aegis-server.yml",
        "config/aegis-server.yaml",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


_STARTER_CONFIG = """\
# Aegis Governance Framework Server Configuration
# Docs: https://acacian.github.io/aegis/guides/framework/

server:
  host: 127.0.0.1
  port: 8000

policy:
  path: policy.yaml

audit:
  backend: sqlite            # sqlite | redis | postgres
  sqlite:
    path: aegis_audit.db
  # redis:
  #   url: redis://localhost:6379/0
  # postgres:
  #   dsn: postgresql://user:pass@localhost/aegis

auth:
  api_key: ${AEGIS_API_KEY}
  admin_key: ${AEGIS_ADMIN_KEY}

guardrails:
  injection: true
  pii: true
  toxicity: false
  prompt_leak: false

dashboard:
  enabled: true

agents:
  heartbeat_timeout: 60      # seconds before agent is considered stale
"""


def _generate_starter_config() -> None:
    """Write a starter aegis-server.yaml."""
    output = Path("aegis-server.yaml")
    if output.exists():
        print(f"File already exists: {output}", file=sys.stderr)
        sys.exit(1)
    output.write_text(_STARTER_CONFIG, encoding="utf-8")
    print(f"Created {output}")
    print()
    print("Next steps:")
    print("  1. Edit aegis-server.yaml to match your setup")
    print("  2. Run: aegis-server")


if __name__ == "__main__":
    main()
