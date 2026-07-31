from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from weall.runtime.protocol_profile import (
    PRODUCTION_CONSENSUS_PROFILE,
    block_tx_signature_policy,
)

Json = dict[str, Any]
DEFAULT_CONSENSUS_PROFILE_MANIFEST = "configs/consensus_profiles/weall-m1-m3-production-v1.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_payload(value: Mapping[str, Any]) -> Json:
    return {str(k): v for k, v in dict(value).items() if str(k) != "manifest_hash"}


def compute_manifest_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest_payload(value)).encode("utf-8")).hexdigest()


def load_consensus_profile_manifest(path: str | Path | None = None) -> Json:
    raw = Path(path or DEFAULT_CONSENSUS_PROFILE_MANIFEST)
    resolved = raw if raw.is_absolute() else (_repo_root() / raw)
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("consensus_profile_manifest_must_be_object")
    expected = str(value.get("manifest_hash") or "").strip().lower()
    actual = compute_manifest_hash(value)
    if not expected:
        raise ValueError("consensus_profile_manifest_hash_missing")
    if expected != actual:
        raise ValueError("consensus_profile_manifest_hash_mismatch")
    return dict(value)


def consensus_activation_projection(
    state: Mapping[str, Any] | None,
    *,
    chain_id: str = "",
    helper_execution_profile: Mapping[str, Any] | None = None,
) -> Json:
    st = state if isinstance(state, Mapping) else {}
    params = st.get("params") if isinstance(st.get("params"), Mapping) else {}
    meta = st.get("meta") if isinstance(st.get("meta"), Mapping) else {}
    helper = (
        dict(helper_execution_profile)
        if isinstance(helper_execution_profile, Mapping)
        else dict(meta.get("helper_execution_profile") or {})
        if isinstance(meta.get("helper_execution_profile"), Mapping)
        else {}
    )
    return {
        "chain_id": str(chain_id or st.get("chain_id") or ""),
        "protocol_profile_hash": PRODUCTION_CONSENSUS_PROFILE.profile_hash(),
        "block_tx_signature_policy": block_tx_signature_policy(st, chain_id=chain_id),
        "ballot_profile_id": str(params.get("ballot_profile_id") or ""),
        "ballot_profile_active": bool(params.get("ballot_profile_active", False)),
        "m3_civic_governance_strict": bool(params.get("m3_civic_governance_strict", False)),
        "helper_execution_profile": helper,
        "helper_reputation_transition_policy": "diagnostic_only_v1",
        "scheduler_error_policy": "fail_closed",
        "consensus_error_policy": "fail_closed",
        "runtime_mode_consensus_authority": False,
    }


def consensus_activation_hash(
    state: Mapping[str, Any] | None,
    *,
    chain_id: str = "",
    helper_execution_profile: Mapping[str, Any] | None = None,
) -> str:
    projection = consensus_activation_projection(
        state,
        chain_id=chain_id,
        helper_execution_profile=helper_execution_profile,
    )
    return hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()


def consensus_profile_mismatch_reasons(local: Mapping[str, Any], remote: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    keys = (
        "chain_id",
        "protocol_profile_hash",
        "block_tx_signature_policy",
        "ballot_profile_id",
        "ballot_profile_active",
        "m3_civic_governance_strict",
        "helper_execution_profile",
        "helper_reputation_transition_policy",
        "scheduler_error_policy",
        "consensus_error_policy",
        "runtime_mode_consensus_authority",
    )
    for key in keys:
        if local.get(key) != remote.get(key):
            reasons.append(f"consensus_profile_{key}_mismatch")
    return reasons
