from __future__ import annotations

"""Pydantic request/response schemas for the public API.

Keep this module intentionally small and stable.

Note:
  The protocol's canonical tx payload schemas live elsewhere (tx_schema/tx_canon).
  These API schemas exist only for HTTP input validation and UX stability.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class PohEmailStartRequest(BaseModel):
    account: str = Field(..., description="Account id, e.g. @alice")
    email: str = Field(..., description="Email address")

    # Optional client signing (used when the client has a local keypair)
    pubkey: Optional[str] = Field(default=None, description="Base64 pubkey")
    sig: Optional[str] = Field(default=None, description="Base64 signature")
    nonce: int = Field(default=0, description="Account nonce used for signing")

    # Anti-bot token (optional depending on deployment)
    turnstile_token: Optional[str] = Field(default=None, description="Cloudflare Turnstile token")

    # Any extra fields are ignored (forward compatible)
    model_config = {"extra": "allow"}


class PohEmailConfirmRequest(BaseModel):
    account: str = Field(..., description="Account id, e.g. @alice")
    email: str = Field(..., description="Email address")
    code: str = Field(..., description="Verification code")

    pubkey: Optional[str] = Field(default=None, description="Base64 pubkey")
    sig: Optional[str] = Field(default=None, description="Base64 signature")
    nonce: int = Field(default=0, description="Account nonce used for signing")

    turnstile_token: Optional[str] = Field(default=None, description="Cloudflare Turnstile token")

    model_config = {"extra": "allow"}
