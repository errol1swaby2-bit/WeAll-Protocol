# projects/Weall-Protocol/src/weall/util/ipfs_cid.py
from __future__ import annotations

"""IPFS CID validation and lightweight multihash verification helpers.

CID validation remains dependency-free.  Byte verification is intentionally
limited to formats the node can verify without a full IPLD/UnixFS stack:

* CIDv1/base32 with raw codec (0x55) and sha2-256 multihash.
* CIDv0/base58btc sha2-256 multihash when the provider returns the raw block
  bytes rather than a UnixFS file view.

For DAG-PB/UnixFS CIDs served through normal gateways, the gateway usually
returns file bytes, while the CID multihash commits to the DAG block.  Those
are reported as unsupported unless the raw bytes happen to match the multihash.
Callers that need gateway-file verification should commit a file-byte sha256 in
the media record; the media proxy verifies that hash before caching.
"""

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

_CIDV0_RE = re.compile(r"^Qm[1-9A-HJ-NP-Za-km-z]{44}$")  # base58btc (no 0,O,I,l)
_CIDV1_BASE32_RE = re.compile(r"^b[a-z2-7]{10,}$")  # base32 lowercase (bafy..., bagy...)

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {ch: idx for idx, ch in enumerate(_BASE58_ALPHABET)}
_SHA2_256 = 0x12
_RAW_CODEC = 0x55
_DAG_PB_CODEC = 0x70


@dataclass(frozen=True)
class CidValidation:
    ok: bool
    reason: str
    cid: str


@dataclass(frozen=True)
class CidMultihashInfo:
    ok: bool
    reason: str
    cid: str
    version: int
    codec: int
    multihash_code: int
    digest: bytes


@dataclass(frozen=True)
class CidByteVerification:
    ok: bool
    supported: bool
    reason: str
    cid: str
    version: int
    codec: int
    multihash_code: int
    expected_digest_hex: str
    actual_digest_hex: str


def normalize_cid(cid: str) -> str:
    return (cid or "").strip()


def validate_ipfs_cid(cid: str, *, max_len: int = 128) -> CidValidation:
    c = normalize_cid(cid)
    if not c:
        return CidValidation(False, "missing_cid", "")
    if len(c) > int(max_len):
        return CidValidation(False, "cid_too_long", c)

    if _CIDV0_RE.match(c):
        return CidValidation(True, "ok", c)
    if _CIDV1_BASE32_RE.match(c):
        return CidValidation(True, "ok", c)
    return CidValidation(False, "invalid_cid_format", c)


def _decode_base58btc(text: str) -> bytes:
    value = 0
    for ch in text:
        if ch not in _BASE58_INDEX:
            raise ValueError("invalid_base58btc")
        value = value * 58 + _BASE58_INDEX[ch]
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    return (b"\x00" * pad) + raw


def _decode_unsigned_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    pos = int(offset)
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint_too_large")
    raise ValueError("truncated_varint")


def _decode_cidv1_base32_payload(cid: str) -> bytes:
    payload = cid[1:].upper()
    padding = "=" * ((8 - (len(payload) % 8)) % 8)
    try:
        return base64.b32decode(payload + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - normalized for callers
        raise ValueError("invalid_base32_payload") from exc


def parse_cid_multihash(cid: str) -> CidMultihashInfo:
    c = normalize_cid(cid)
    valid = validate_ipfs_cid(c)
    if not valid.ok:
        return CidMultihashInfo(False, valid.reason, valid.cid, -1, -1, -1, b"")

    try:
        if _CIDV0_RE.match(c):
            raw = _decode_base58btc(c)
            mh_code, pos = _decode_unsigned_varint(raw, 0)
            mh_len, pos = _decode_unsigned_varint(raw, pos)
            digest = raw[pos : pos + mh_len]
            if len(digest) != mh_len or pos + mh_len != len(raw):
                return CidMultihashInfo(False, "bad_cidv0_multihash_length", c, 0, _DAG_PB_CODEC, mh_code, digest)
            return CidMultihashInfo(True, "ok", c, 0, _DAG_PB_CODEC, mh_code, digest)

        raw = _decode_cidv1_base32_payload(c)
        version, pos = _decode_unsigned_varint(raw, 0)
        codec, pos = _decode_unsigned_varint(raw, pos)
        mh_code, pos = _decode_unsigned_varint(raw, pos)
        mh_len, pos = _decode_unsigned_varint(raw, pos)
        digest = raw[pos : pos + mh_len]
        if version != 1:
            return CidMultihashInfo(False, "unsupported_cid_version", c, version, codec, mh_code, digest)
        if len(digest) != mh_len or pos + mh_len != len(raw):
            return CidMultihashInfo(False, "bad_cidv1_multihash_length", c, version, codec, mh_code, digest)
        return CidMultihashInfo(True, "ok", c, version, codec, mh_code, digest)
    except Exception as exc:  # noqa: BLE001 - dependency-free parser normalizes failures
        return CidMultihashInfo(False, str(exc) or "cid_parse_failed", c, -1, -1, -1, b"")


def verify_cid_multihash_bytes(cid: str, data: bytes | bytearray | memoryview) -> CidByteVerification:
    """Verify byte content against supported CID multihashes.

    ``supported`` means the CID/multihash pair is one this lightweight verifier
    can evaluate directly.  Unsupported is not the same as a mismatch; callers
    may require a committed file-byte sha256 for those formats.
    """

    info = parse_cid_multihash(cid)
    if not info.ok:
        return CidByteVerification(False, False, info.reason, info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), "")

    if info.multihash_code != _SHA2_256 or len(info.digest) != 32:
        return CidByteVerification(False, False, "unsupported_multihash", info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), "")

    raw = bytes(data)
    actual = hashlib.sha256(raw).digest()

    # CIDv1 raw explicitly commits to the exact bytes. CIDv0/DAG-PB commits to
    # the raw block bytes; this can be verified only when the provider returns
    # the block itself, not a UnixFS-decoded file view.  Treat both as supported
    # direct-byte verification, but callers may prefer committed sha256 for
    # gateway file bytes.
    if info.codec not in {_RAW_CODEC, _DAG_PB_CODEC}:
        return CidByteVerification(False, False, "unsupported_codec", info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), actual.hex())

    if hmac_compare_digest(actual, info.digest):
        reason = "cidv1_raw_sha2_256" if info.codec == _RAW_CODEC else "cidv0_dag_pb_sha2_256_direct"
        return CidByteVerification(True, True, reason, info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), actual.hex())
    if info.codec == _DAG_PB_CODEC:
        return CidByteVerification(False, False, "cidv0_dag_pb_direct_verification_unavailable", info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), actual.hex())
    return CidByteVerification(False, True, "cid_multihash_mismatch", info.cid, info.version, info.codec, info.multihash_code, info.digest.hex(), actual.hex())


def hmac_compare_digest(a: bytes, b: bytes) -> bool:
    # Avoid importing hmac for older lightweight uses of this module while still
    # keeping a constant-time comparison for same-length digests.
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
