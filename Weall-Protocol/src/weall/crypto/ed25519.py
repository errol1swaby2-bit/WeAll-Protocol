from __future__ import annotations

"""Compatibility wrapper for Ed25519 signing/verification.

Some network modules expect:
  verify_ed25519_sig(pubkey_str, message_bytes, sig_str) -> bool

The canonical implementation in this codebase lives in weall.crypto.sig
as verify_ed25519_signature(message=..., sig=..., pubkey=...).

This module keeps imports stable and avoids duplicating crypto logic.
"""

from typing import Final

from weall.crypto.sig import sign_ed25519 as _sign_ed25519
from weall.crypto.sig import verify_ed25519_signature as _verify_ed25519_signature

_SCHEME: Final[str] = "ed25519"


def verify_ed25519_sig(pubkey_str: str, message_bytes: bytes, sig_str: str) -> bool:
    """Verify an Ed25519 signature.

    Args:
      pubkey_str: encoded public key (32 bytes) as hex or base64/base64url
      message_bytes: the signed message bytes
      sig_str: encoded signature (64 bytes) as hex or base64/base64url

    Returns:
      True if valid, else False.
    """

    return bool(_verify_ed25519_signature(message=message_bytes, sig=sig_str, pubkey=pubkey_str))


def sign_ed25519(message_bytes: bytes, privkey_str: str, *, encoding: str = "hex") -> str:
    """Sign a message using an Ed25519 private key.

    Args:
      message_bytes: message to sign
      privkey_str: encoded private key seed (32 bytes) as hex or base64/base64url
      encoding: output encoding: "hex" (default) or "b64"

    Returns:
      Signature string.
    """

    return _sign_ed25519(message=message_bytes, privkey=privkey_str, encoding=encoding)


def scheme() -> str:
    """Return the scheme name."""

    return _SCHEME
