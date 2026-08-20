from __future__ import annotations

"""Signed deterministic consensus beacon using ML-DSA.

This module intentionally does *not* treat randomized ML-DSA signature bytes as
randomness.  ML-DSA proofs authenticate a fixed canonical beacon context, while
the beacon output is derived only from that context:

  context = domain || chain_id || height || parent_block_hash || proposer_pubkey
  proof   = ML-DSA-Sign(proposer_key, context)
  output  = sha256(context)

This construction is not a standards-track secret-key VRF and does not promise
unpredictability.  Its safety purpose is narrower: for a fixed parent, height,
and canonical proposer key there is exactly one consensus beacon output, so a
proposer cannot grind randomized ML-DSA signatures to choose among outputs.
The proof demonstrates authorization by the bound proposer key.
"""

import hashlib
from typing import Any

from weall.crypto.sig import sign_mldsa, verify_mldsa_signature

Json = dict[str, Any]

SCHEME = "mldsa_beacon_v2"
DOMAIN = "weall-vrf-beacon-v2"


def vrf_message(*, chain_id: str, height: int, prev_block_hash: str, pubkey: str) -> bytes:
    """Return the canonical signed beacon context."""

    s = f"{DOMAIN}|{str(chain_id)}|{int(height)}|{str(prev_block_hash)}|{str(pubkey).strip()}"
    return s.encode("utf-8")


def vrf_output_from_message(message: bytes) -> str:
    """Return the deterministic beacon output for canonical context bytes."""

    return hashlib.sha256(bytes(message)).hexdigest()


def make_vrf_record(
    *,
    chain_id: str,
    height: int,
    prev_block_hash: str,
    pubkey: str,
    privkey: str,
) -> Json:
    """Create a signed deterministic beacon record for a block header."""

    pubkey_s = str(pubkey or "").strip()
    if not pubkey_s:
        raise ValueError("vrf_missing_pubkey")
    msg = vrf_message(
        chain_id=chain_id,
        height=height,
        prev_block_hash=prev_block_hash,
        pubkey=pubkey_s,
    )
    proof = sign_mldsa(message=msg, privkey=privkey, encoding="hex")
    out = vrf_output_from_message(msg)
    return {
        "scheme": SCHEME,
        "pubkey": pubkey_s,
        "proof": str(proof),
        "output": str(out),
    }


def verify_vrf_record(
    *,
    vrf: Json,
    chain_id: str,
    height: int,
    prev_block_hash: str,
) -> tuple[bool, str]:
    """Verify a signed deterministic beacon record and return ``(ok, reason)``."""

    if not isinstance(vrf, dict):
        return False, "vrf_not_object"
    if str(vrf.get("scheme") or "") != SCHEME:
        return False, "vrf_scheme"

    pubkey = str(vrf.get("pubkey") or "").strip()
    proof = str(vrf.get("proof") or "").strip()
    output = str(vrf.get("output") or "").strip()

    if not pubkey or not proof or not output:
        return False, "vrf_missing_fields"

    msg = vrf_message(
        chain_id=chain_id,
        height=height,
        prev_block_hash=prev_block_hash,
        pubkey=pubkey,
    )

    if not verify_mldsa_signature(message=msg, sig=proof, pubkey=pubkey):
        return False, "vrf_bad_signature"

    want_out = vrf_output_from_message(msg)
    if want_out != output:
        return False, "vrf_output_mismatch"

    return True, ""


def state_vrf_output(state: Json) -> str | None:
    """Best-effort helper to fetch the latest deterministic beacon output."""

    r = state.get("rand")
    if not isinstance(r, dict):
        return None
    v = r.get("vrf")
    if not isinstance(v, dict):
        return None
    out = v.get("output")
    return str(out).strip() if isinstance(out, str) and out.strip() else None
