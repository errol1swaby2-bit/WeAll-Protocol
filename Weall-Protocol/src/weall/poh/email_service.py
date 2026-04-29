from __future__ import annotations

"""Compatibility import for the WeAll-owned PoH email verification service."""

from weall.poh.email_verification import EmailVerificationService, OracleRequestError

__all__ = ["EmailVerificationService", "OracleRequestError"]
