# src/weall/runtime/apply/__init__.py
"""Domain-specific apply modules.

These modules implement deterministic ledger state transitions for subsets
of tx types. The canonical dispatcher delegates to these modules once each
apply/* module is staged.

NOTE: Keep this package import-safe and avoid importing the dispatcher here.
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
