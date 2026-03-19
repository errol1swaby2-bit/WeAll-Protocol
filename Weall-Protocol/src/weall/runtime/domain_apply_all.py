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

from typing import Any

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError

Json = dict[str, Any]

__all__ = ["ApplyError", "apply_tx", "Json"]
