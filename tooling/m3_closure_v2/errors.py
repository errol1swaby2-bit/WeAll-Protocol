from __future__ import annotations


class ClosureToolingError(RuntimeError):
    """Base class for deterministic closure-tooling failures."""


class ContractError(ClosureToolingError):
    """An input failed an explicit evidence or configuration contract."""


class HttpVerificationError(ClosureToolingError):
    """An HTTP verification request exhausted its bounded retry policy."""


class ReceiptError(ClosureToolingError):
    """A stage receipt is missing, corrupt, or no longer bound to its outputs."""


class ProcessOwnershipError(ClosureToolingError):
    """A process record does not identify the process currently using its PID."""
