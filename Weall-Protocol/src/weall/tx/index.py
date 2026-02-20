"""
Compatibility module.

Some older code/tests import TxIndex from `weall.tx.index`, but the current source of truth
lives in `weall.tx.canon`. This module re-exports the public surface for backwards compatibility.
"""

from __future__ import annotations

from weall.tx.canon import (  # noqa: F401
    CanonError,
    TxIndex,
    load_tx_index_auto,
    load_tx_index_json,
)
