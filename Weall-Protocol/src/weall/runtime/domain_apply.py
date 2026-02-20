# src/weall/runtime/domain_apply.py
# ---------------------------------------------------------------------------
# Public, stable import path for applying tx envelopes.
# ---------------------------------------------------------------------------

from __future__ import annotations

from weall.runtime.domain_apply_all import ApplyError, apply_tx

__all__ = ["ApplyError", "apply_tx"]
