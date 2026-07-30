"""WeAll M3 closure tooling v2.

This package is intentionally separate from protocol runtime code.  It provides
typed evidence parsing, rate-limit-safe HTTP verification, deterministic process
ownership, and resumable stage receipts.
"""

from .models import EvidenceKind, Transcript, parse_transcript
from .receipts import ReceiptStore, StageReceipt

__all__ = [
    "EvidenceKind",
    "Transcript",
    "parse_transcript",
    "ReceiptStore",
    "StageReceipt",
]

__version__ = "0.1.0"
