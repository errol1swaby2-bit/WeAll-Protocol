"""Runtime TxIndex shim.

The canonical TxIndex implementation lives in `weall.tx.canon`.
Historically some runtime modules imported it from `weall.runtime.tx_index`.

Keep this module as a stable import path.
"""

from __future__ import annotations

from pathlib import Path

from weall.tx.canon import TxIndex as _TxIndex

TxIndex = _TxIndex


def load_tx_index(path: str | Path) -> TxIndex:
    """Convenience wrapper for loading the generated tx index."""
    return TxIndex.load_from_file(str(path))


__all__ = ["TxIndex", "load_tx_index"]
