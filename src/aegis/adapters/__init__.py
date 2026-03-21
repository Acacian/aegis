"""Adapters for external systems.

Each adapter has optional dependencies — install only what you need::

    pip install 'agent-aegis[langchain]'
    pip install 'agent-aegis[httpx]'
    pip install 'agent-aegis[all]'
"""

from aegis.adapters.base import BaseExecutor

__all__ = ["BaseExecutor"]
