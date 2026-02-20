from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ApplyError(Exception):
    """Canonical error type for domain apply and dispatch failures."""

    code: str
    reason: str
    details: Any | None = None

    def __str__(self) -> str:  # pragma: no cover
        if self.details is None:
            return f"{self.code}:{self.reason}"
        return f"{self.code}:{self.reason}:{self.details}"
