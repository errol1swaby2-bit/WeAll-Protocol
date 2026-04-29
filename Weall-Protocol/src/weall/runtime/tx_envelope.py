"""Backward-compatibility shim.

Some older modules/tests import TxEnvelope from `weall.runtime.tx_envelope`.
The canonical implementation now lives in `weall.runtime.tx_admission_types`.

Keep this thin re-export so imports remain stable.
"""

from __future__ import annotations

from .tx_admission_types import TxEnvelope

__all__ = ["TxEnvelope"]
