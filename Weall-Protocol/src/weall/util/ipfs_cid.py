# projects/Weall-Protocol/src/weall/util/ipfs_cid.py
from __future__ import annotations

"""IPFS CID validation helpers.

We keep validation lightweight and dependency-free:
  - CIDv0 (base58btc) commonly starts with "Qm" and is length 46.
  - CIDv1 (base32 lowercase) commonly starts with "b" and uses the RFC4648
    base32 alphabet in lowercase: a-z2-7.

This is NOT a full multiformats parser. The goal is to fail-closed on obviously
bad / dangerous inputs, while accepting the vast majority of real-world CIDs.
"""

import re
from dataclasses import dataclass


_CIDV0_RE = re.compile(r"^Qm[1-9A-HJ-NP-Za-km-z]{44}$")  # base58btc (no 0,O,I,l)
_CIDV1_BASE32_RE = re.compile(r"^b[a-z2-7]{10,}$")  # base32 lowercase (bafy..., bagy...)


@dataclass(frozen=True)
class CidValidation:
    ok: bool
    reason: str
    cid: str


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
