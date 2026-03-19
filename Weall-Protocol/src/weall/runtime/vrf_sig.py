from __future__ import annotations

"""Verifiable randomness based on Ed25519 signatures ("sig-VRF").

We implement a VRF-like primitive using deterministic Ed25519 signatures:

  proof = Ed25519Sign(privkey, message)
  output = sha256(proof_bytes)

Anyone can verify the proof with the public key and reproduce `output`.

Security notes:
- This is not a standards-track VRF (e.g., IETF ECVRF). It is a pragmatic,
  dependency-light construction that is *verifiable* and *deterministic*.
- Bias resistance requires the message to be fixed and non-malleable.
  We bind the proof to the canonical block header fields.
- Withholding is still possible (a proposer can refuse to produce a block).
  Mitigations include multi-validator aggregation after quorum (future).
"""

import hashlib
from typing import Any

from weall.crypto.sig import sign_ed25519, verify_ed25519_signature

Json = dict[str, Any]

SCHEME = "ed25519_sig_v1"
DOMAIN = "weall-vrf"


def vrf_message(*, chain_id: str, height: int, prev_block_hash: str, block_ts_ms: int) -> bytes:
    """Return the canonical message bytes for VRF signing."""

    s = f"{DOMAIN}|{str(chain_id)}|{int(height)}|{str(prev_block_hash)}|{int(block_ts_ms)}"
    return s.encode("utf-8")


def vrf_output_from_proof(proof_hex: str) -> str:
    """Compute output hex from a proof (signature) hex string."""
    try:
        pb = bytes.fromhex(str(proof_hex))
    except Exception:
        pb = b""
    return hashlib.sha256(pb).hexdigest()


def make_vrf_record(
    *,
    chain_id: str,
    height: int,
    prev_block_hash: str,
    block_ts_ms: int,
    pubkey: str,
    privkey: str,
) -> Json:
    """Create a VRF record suitable for inclusion in block headers and state."""

    msg = vrf_message(
        chain_id=chain_id,
        height=height,
        prev_block_hash=prev_block_hash,
        block_ts_ms=block_ts_ms,
    )
    proof = sign_ed25519(message=msg, privkey=privkey, encoding="hex")
    out = vrf_output_from_proof(proof)
    return {
        "scheme": SCHEME,
        "pubkey": str(pubkey),
        "proof": str(proof),
        "output": str(out),
    }


def verify_vrf_record(
    *,
    vrf: Json,
    chain_id: str,
    height: int,
    prev_block_hash: str,
    block_ts_ms: int,
) -> tuple[bool, str]:
    """Verify VRF record and return (ok, reason)."""

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
        block_ts_ms=block_ts_ms,
    )

    if not verify_ed25519_signature(message=msg, sig=proof, pubkey=pubkey):
        return False, "vrf_bad_signature"

    want_out = vrf_output_from_proof(proof)
    if want_out != output:
        return False, "vrf_output_mismatch"

    return True, ""


def state_vrf_output(state: Json) -> str | None:
    """Best-effort helper to fetch the latest VRF output stored in state."""
    r = state.get("rand")
    if not isinstance(r, dict):
        return None
    v = r.get("vrf")
    if not isinstance(v, dict):
        return None
    out = v.get("output")
    return str(out).strip() if isinstance(out, str) and out.strip() else None
