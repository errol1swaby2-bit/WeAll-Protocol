from __future__ import annotations

"""Optional ML-DSA adapter.

This adapter uses pyca/cryptography's ML-DSA hazmat API when it is installed
and backed by a provider that supports ML-DSA.  It deliberately does not provide
a toy fallback.  If the backend is unavailable, callers must fail closed.
"""

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm


def _decode_bytes(s: str) -> bytes:
    value = str(s or "").strip()
    if not value:
        raise ValueError("empty string")
    try:
        return bytes.fromhex(value)
    except Exception:
        pass
    padding = "=" * (-len(value) % 4)
    return base64.b64decode((value + padding).replace("-", "+").replace("_", "/"))


def _encode_bytes(data: bytes, *, encoding: str = "hex") -> str:
    if encoding == "hex":
        return data.hex()
    if encoding in {"b64", "base64"}:
        return base64.b64encode(data).decode("ascii")
    raise ValueError("unsupported encoding")


def _mldsa_classes() -> tuple[Any, Any]:
    from cryptography.hazmat.primitives.asymmetric import mldsa

    return mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey


def mldsa_backend_status() -> dict[str, Any]:
    try:
        private_cls, _public_cls = _mldsa_classes()
        # generate() is the reliable availability probe because pyca exposes the
        # classes even when the linked backend lacks ML-DSA support.
        try:
            private_cls.generate()
        except UnsupportedAlgorithm as exc:
            return {
                "available": False,
                "backend": "pyca-cryptography",
                "algorithm": "ML-DSA-65",
                "reason": "unsupported_backend",
                "detail": str(exc),
            }
        return {
            "available": True,
            "backend": "pyca-cryptography",
            "algorithm": "ML-DSA-65",
            "reason": "ok",
        }
    except Exception as exc:
        return {
            "available": False,
            "backend": "pyca-cryptography",
            "algorithm": "ML-DSA-65",
            "reason": "module_unavailable",
            "detail": str(exc),
        }


def generate_mldsa65_keypair(*, encoding: str = "hex") -> dict[str, str]:
    private_cls, _public_cls = _mldsa_classes()
    private_key = private_cls.generate()
    public_key = private_key.public_key()
    return {
        "privkey": _encode_bytes(private_key.private_bytes_raw(), encoding=encoding),
        "pubkey": _encode_bytes(public_key.public_bytes_raw(), encoding=encoding),
    }


def sign_mldsa65(*, message: bytes, privkey: str, encoding: str = "hex", context: bytes | None = None) -> str:
    private_cls, _public_cls = _mldsa_classes()
    key = private_cls.from_seed_bytes(_decode_bytes(privkey))
    sig = key.sign(message, context) if context is not None else key.sign(message)
    return _encode_bytes(sig, encoding=encoding)


def verify_mldsa65_signature(*, message: bytes, sig: str, pubkey: str, context: bytes | None = None) -> bool:
    try:
        _private_cls, public_cls = _mldsa_classes()
        key = public_cls.from_public_bytes(_decode_bytes(pubkey))
        if context is not None:
            key.verify(_decode_bytes(sig), message, context)
        else:
            key.verify(_decode_bytes(sig), message)
        return True
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False
    except Exception:
        return False
