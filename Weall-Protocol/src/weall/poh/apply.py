# src/weall/pof_nft/apply.py
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from weall.ledger.state import LedgerView


class PoFNftError(Exception):
    pass


def _sha256_hex(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def deterministic_token_id(*, chain_id: str, owner: str, tier: int, source_id: str) -> str:
    """
    Deterministic token id. No randomness. Replay-safe and idempotent.
    """
    payload = f"{chain_id}|POF_GATE|{owner}|{int(tier)}|{source_id}".encode("utf-8")
    return _sha256_hex(payload)


def canonical_metadata_cid_placeholder(*, tier: int) -> str:
    """
    Placeholder hook: you can later swap to real IPFS CID generation.
    For now we store a deterministic metadata "fingerprint" to keep state stable.
    """
    obj = {"kind": "pof_gate_nft", "tier": int(tier)}
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "meta:" + _sha256_hex(b)[:32]


def apply_pof_nft_mint(
    ledger: LedgerView,
    *,
    chain_id: str,
    owner: str,
    tier: int,
    source_id: str,
    height: int,
    ts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    SYSTEM / block-only: mint the PoF gate NFT for a tier and attribute to owner.

    Idempotent:
      - if token already exists -> no-op (returns existing)
    """
    if not owner:
        raise PoFNftError("owner is required")
    if int(tier) not in (1, 2, 3):
        raise PoFNftError("tier must be 1, 2, or 3")
    if not chain_id:
        raise PoFNftError("chain_id is required")
    if not source_id:
        raise PoFNftError("source_id is required")

    ledger.ensure_account(owner)

    token_id = deterministic_token_id(chain_id=chain_id, owner=owner, tier=int(tier), source_id=source_id)
    tokens = ledger.pof_tokens()
    by_owner = ledger.pof_by_owner()

    existing = tokens.get(token_id)
    if isinstance(existing, dict):
        # Ensure ownership index exists
        bucket = by_owner.get(owner)
        if bucket is None:
            bucket = {}
            by_owner[owner] = bucket
        if isinstance(bucket, dict):
            bucket[token_id] = True
        return {"ok": True, "token_id": token_id, "status": "exists", "tier": int(existing.get("tier", tier))}

    # Create token record
    meta_cid = canonical_metadata_cid_placeholder(tier=int(tier))
    tokens[token_id] = {
        "token_id": token_id,
        "owner": owner,
        "tier": int(tier),
        "minted_height": int(height),
        "minted_ts": ts,
        "source_id": source_id,
        "metadata": {"cid": meta_cid},
        "banned": False,
        "banned_height": None,
        "banned_ts": None,
        "ban_reason": None,
    }

    bucket = by_owner.get(owner)
    if bucket is None:
        bucket = {}
        by_owner[owner] = bucket
    if not isinstance(bucket, dict):
        raise PoFNftError("pof_nfts.by_owner[owner] must be dict")
    bucket[token_id] = True

    return {"ok": True, "token_id": token_id, "status": "minted", "tier": int(tier)}


def apply_pof_nft_ban(
    ledger: LedgerView,
    *,
    token_id: str,
    height: int,
    ts: Optional[int] = None,
    reason: str = "revoked",
) -> Dict[str, Any]:
    """
    SYSTEM / block-only: mark an existing PoF gate NFT as banned (revoked).
    """
    if not token_id:
        raise PoFNftError("token_id required")
    tokens = ledger.pof_tokens()
    tok = tokens.get(token_id)
    if not isinstance(tok, dict):
        raise PoFNftError("unknown token_id")

    tok["banned"] = True
    tok["banned_height"] = int(height)
    tok["banned_ts"] = ts
    tok["ban_reason"] = str(reason or "revoked")

    return {"ok": True, "token_id": token_id, "status": "banned"}
