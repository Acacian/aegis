"""Rule packs for Aegis guardrails.

Packs are YAML files that declare guardrail rules.  They can be loaded
by name (for built-in packs) or by filesystem path.

Example::

    from aegis.packs import load_pack, list_builtin_packs

    pack = load_pack("pii")
    guardrails = pack.to_guardrails()
"""

from aegis.packs.loader import list_builtin_packs, load_pack
from aegis.packs.schema import Pack, PackRule

__all__ = [
    "Pack",
    "PackRule",
    "list_builtin_packs",
    "load_pack",
]
