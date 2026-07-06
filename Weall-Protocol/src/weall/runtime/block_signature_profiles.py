from __future__ import annotations

"""Fail-closed block/validator signature profile helpers."""

import json
from typing import Any

from weall.crypto.signature_profiles import (
    PQ_MLDSA_V1,
    normalize_signature_profile_id,
    profile_allowed_for_context,
)

Json = dict[str, Any]


def canonical_block_signature_payload(block: Json) -> bytes:
    header = block.get("header") if isinstance(block.get("header"), dict) else {}
    profile = normalize_signature_profile_id(
        block.get("sig_profile") or header.get("sig_profile") or block.get("signature_profile")
    )
    payload: Json = {
        "domain_separator": "weall.block.v1",
        "object_kind": "block",
        "chain_id": str(block.get("chain_id") or header.get("chain_id") or ""),
        "network_id": str(block.get("network_id") or header.get("network_id") or ""),
        "height": int(block.get("height") or header.get("height") or 0),
        "block_id": str(block.get("block_id") or header.get("block_id") or ""),
        "prev_block_id": str(block.get("prev_block_id") or header.get("prev_block_id") or block.get("prev") or ""),
        "proposer": str(block.get("proposer") or block.get("node_id") or header.get("proposer") or header.get("node_id") or ""),
        "sig_profile": profile,
        "activation_height": int(block.get("activation_height") or header.get("activation_height") or 0),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def block_signature_profile(block: Json) -> str:
    header = block.get("header") if isinstance(block.get("header"), dict) else {}
    sig = block.get("signature") if isinstance(block.get("signature"), dict) else {}
    return normalize_signature_profile_id(
        block.get("sig_profile")
        or header.get("sig_profile")
        or sig.get("sig_profile")
        or block.get("signature_profile")
    )


def validate_block_signature_profile(
    block: Json,
    *,
    chain_config: Json | None = None,
    require_verifier: bool = False,
) -> tuple[bool, str]:
    profile = block_signature_profile(block)
    if not profile:
        return False, "block_signature_profile_missing"
    ok_profile, reason = profile_allowed_for_context(profile, chain_config=chain_config, require_verifier=require_verifier)
    if not ok_profile:
        return False, reason
    if profile == PQ_MLDSA_V1:
        signature = block.get("signature") if isinstance(block.get("signature"), dict) else {}
        if str(signature.get("alg") or "").strip() not in {"ML-DSA", "ML-DSA-65"}:
            return False, "block_signature_alg_mismatch"
    return True, "ok"


def validate_validator_operator_record(
    record: Any,
    *,
    chain_config: Json | None = None,
    require_verifier: bool = False,
) -> tuple[bool, str]:
    if not isinstance(record, dict):
        return False, "validator_record_not_object"
    profile = normalize_signature_profile_id(record.get("sig_profile") or record.get("signature_profile"))
    if not profile:
        return False, "validator_signature_profile_missing"
    ok_profile, reason = profile_allowed_for_context(profile, chain_config=chain_config, require_verifier=require_verifier)
    if not ok_profile:
        return False, reason
    if profile == PQ_MLDSA_V1 and not str(record.get("pubkey") or record.get("node_pubkey") or "").strip():
        return False, "validator_mldsa_pubkey_missing"
    return True, "ok"
