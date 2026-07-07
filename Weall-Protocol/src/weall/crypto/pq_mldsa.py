from __future__ import annotations

"""ML-DSA adapter backed by pyca/cryptography.

WeAll intentionally depends on a standards-aligned implementation instead of a
local educational/toy Dilithium copy.  ``pq-mldsa-v1`` maps to ML-DSA-65 from
FIPS 204 through pyca/cryptography's hazmat API.  If the installed dependency or
linked backend does not expose ML-DSA, public/closed testnet cryptographic gates
must fail closed.
"""

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

MLDSA_PARAMETER_SET = "ML-DSA-65"
MLDSA_SEED_BYTES = 32
MLDSA65_PUBLIC_KEY_BYTES = 1952
MLDSA65_SIGNATURE_BYTES = 3309
MLDSA_CONTEXT = b"weall:pq-mldsa-v1:protocol-signature"


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
        try:
            private_cls.generate()
        except UnsupportedAlgorithm as exc:
            return {
                "available": False,
                "backend": "pyca-cryptography",
                "minimum_cryptography_version": "47.0.0",
                "repo_locked_cryptography_version": "48.0.0",
                "algorithm": MLDSA_PARAMETER_SET,
                "reason": "unsupported_backend",
                "detail": str(exc),
            }
        return {
            "available": True,
            "backend": "pyca-cryptography",
            "minimum_cryptography_version": "47.0.0",
            "repo_locked_cryptography_version": "48.0.0",
            "algorithm": MLDSA_PARAMETER_SET,
            "reason": "ok",
            "public_key_bytes": MLDSA65_PUBLIC_KEY_BYTES,
            "signature_bytes": MLDSA65_SIGNATURE_BYTES,
            "context": MLDSA_CONTEXT.decode("ascii"),
        }
    except Exception as exc:
        return {
            "available": False,
            "backend": "pyca-cryptography",
            "minimum_cryptography_version": "47.0.0",
            "repo_locked_cryptography_version": "48.0.0",
            "algorithm": MLDSA_PARAMETER_SET,
            "reason": "module_unavailable",
            "detail": str(exc),
        }


def require_mldsa_backend() -> None:
    status = mldsa_backend_status()
    if status.get("available") is not True:
        raise RuntimeError(f"mldsa_backend_unavailable:{status.get('reason')}")


def mldsa65_public_key_from_seed(*, privkey: str, encoding: str = "hex") -> str:
    private_cls, _public_cls = _mldsa_classes()
    seed = _decode_bytes(privkey)
    if len(seed) != MLDSA_SEED_BYTES:
        raise ValueError("mldsa privkey must be 32-byte seed")
    key = private_cls.from_seed_bytes(seed)
    return _encode_bytes(key.public_key().public_bytes_raw(), encoding=encoding)


def generate_mldsa65_keypair(*, encoding: str = "hex") -> dict[str, str]:
    private_cls, _public_cls = _mldsa_classes()
    private_key = private_cls.generate()
    public_key = private_key.public_key()
    return {
        "sig_profile": "pq-mldsa-v1",
        "alg": "ML-DSA",
        "parameter_set": MLDSA_PARAMETER_SET,
        "privkey": _encode_bytes(private_key.private_bytes_raw(), encoding=encoding),
        "pubkey": _encode_bytes(public_key.public_bytes_raw(), encoding=encoding),
    }


def sign_mldsa65(
    *,
    message: bytes,
    privkey: str,
    encoding: str = "hex",
    context: bytes | None = MLDSA_CONTEXT,
) -> str:
    private_cls, _public_cls = _mldsa_classes()
    seed = _decode_bytes(privkey)
    if len(seed) != MLDSA_SEED_BYTES:
        raise ValueError("mldsa privkey must be 32-byte seed")
    key = private_cls.from_seed_bytes(seed)
    sig = key.sign(message, context) if context is not None else key.sign(message)
    return _encode_bytes(sig, encoding=encoding)


def verify_mldsa65_signature(
    *,
    message: bytes,
    sig: str,
    pubkey: str,
    context: bytes | None = MLDSA_CONTEXT,
) -> bool:
    try:
        _private_cls, public_cls = _mldsa_classes()
        sig_bytes = _decode_bytes(sig)
        pub_bytes = _decode_bytes(pubkey)
        if len(pub_bytes) != MLDSA65_PUBLIC_KEY_BYTES:
            return False
        if len(sig_bytes) != MLDSA65_SIGNATURE_BYTES:
            return False
        key = public_cls.from_public_bytes(pub_bytes)
        if context is not None:
            key.verify(sig_bytes, message, context)
        else:
            key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False
    except Exception:
        return False
