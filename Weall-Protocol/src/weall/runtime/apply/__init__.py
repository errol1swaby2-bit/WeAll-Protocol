# src/weall/runtime/apply/__init__.py
"""Domain-specific apply modules.

These modules implement deterministic ledger state transitions for subsets
of tx types. The monolithic legacy router (domain_apply_all.py) will delegate
to these modules once all apply/* modules are staged.

NOTE: Keep this package import-safe (no imports that require domain_apply_all).
"""

from __future__ import annotations

__all__ = [
    "storage",
    "poh",
    "dispute",
    "content",
    "governance",
    "treasury",
    "groups",
    "identity",
    "social",
    "economics",
    "notifications",
]
