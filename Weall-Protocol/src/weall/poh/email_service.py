# src/weall/poh/email_service.py
"""
DEPRECATED: legacy / experimental Cloudflare Turnstile verification module.

The live PoH email flow is implemented in:
  src/weall/poh/email_verification.py

This module remains only to avoid import confusion if old references exist.
Do not use it for new code.
"""

from __future__ import annotations

from weall.poh.email_verification import EmailVerificationService  # re-export
