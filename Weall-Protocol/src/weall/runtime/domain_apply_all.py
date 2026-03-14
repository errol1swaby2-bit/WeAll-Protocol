# src/weall/runtime/domain_apply_all.py
# ---------------------------------------------------------------------------
# Thin compatibility wrapper.
#
# Public API:
#   ApplyError
#   apply_tx
#   Json
# ---------------------------------------------------------------------------

from __future__ import annotations

from typing import Any, Dict

from weall.runtime.errors import ApplyError
from weall.runtime.domain_dispatch import apply_tx

Json = Dict[str, Any]

__all__ = ["ApplyError", "apply_tx", "Json"]
