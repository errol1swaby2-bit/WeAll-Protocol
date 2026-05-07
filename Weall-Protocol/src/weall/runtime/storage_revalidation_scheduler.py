from __future__ import annotations

"""Deterministic storage proof revalidation planning.

This module does not perform disk or network IO. It evaluates chain state and
materializes the next storage-capacity revalidation work that should be issued
as system transactions. The actual probe material is handled by
``storage_probe_runner`` and the state transition is handled by the storage
apply domain.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class StorageRevalidationAction:
    account_id: str
    node_pubkey: str
    status: str
    reason: str
    challenge_id: str
    payload: Json

    def as_dict(self) -> Json:
        return {
            "account_id": self.account_id,
            "node_pubkey": self.node_pubkey,
            "status": self.status,
            "reason": self.reason,
            "challenge_id": self.challenge_id,
            "payload": dict(self.payload),
        }


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _height(state: Mapping[str, Any]) -> int:
    return _as_int(state.get("height"), 0)


def _params(state: Mapping[str, Any]) -> Mapping[str, Any]:
    params = state.get("params")
    return params if isinstance(params, dict) else {}


def storage_revalidation_window_blocks(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_revalidation_window_blocks"), 0)
    return value if value > 0 else 100


def storage_revalidation_challenge_ttl_blocks(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_revalidation_challenge_ttl_blocks"), 0)
    return value if value > 0 else 100


def storage_revalidation_sample_count(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_revalidation_sample_count"), 0)
    return value if value > 0 else 4


def storage_revalidation_sample_size_bytes(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_revalidation_sample_size_bytes"), 0)
    return value if value > 0 else 4096


def storage_max_failed_challenges(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_max_failed_challenges"), 0)
    return value if value > 0 else 3


def storage_max_missed_challenges(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_max_missed_challenges"), 0)
    return value if value > 0 else 3


def storage_min_availability_score_milli(state: Mapping[str, Any]) -> int:
    value = _as_int(_params(state).get("storage_min_availability_score_milli"), -1)
    return value if value >= 0 else 500


def storage_revalidation_reason(state: Mapping[str, Any], storage: Mapping[str, Any]) -> str:
    current = _height(state)
    proof_status = _as_str(storage.get("proof_status")) or "not_requested"
    proof_expires = _as_int(storage.get("proof_expires_height"), 0)
    failed = _as_int(storage.get("failed_challenge_count"), 0)
    missed = _as_int(storage.get("missed_challenge_count"), 0)
    score = _as_int(storage.get("availability_score_milli"), 1000)

    if failed >= storage_max_failed_challenges(state):
        return "failed_challenge_limit_reached"
    if missed >= storage_max_missed_challenges(state):
        return "missed_challenge_limit_reached"
    if score < storage_min_availability_score_milli(state):
        return "availability_score_below_minimum"
    if proof_status not in ("verified", "active", "revalidation_due"):
        return "proof_not_verified"
    if proof_expires <= 0:
        return "proof_expiry_missing"
    if current > proof_expires:
        return "proof_expired"
    if proof_expires - current <= storage_revalidation_window_blocks(state):
        return "proof_near_expiry"
    return ""


def storage_revalidation_status_for_reason(reason: str) -> str:
    if reason in ("proof_near_expiry",):
        return "revalidation_due"
    if reason in ("proof_expired", "proof_expiry_missing"):
        return "expired"
    if reason in (
        "failed_challenge_limit_reached",
        "missed_challenge_limit_reached",
        "availability_score_below_minimum",
    ):
        return "paused"
    if reason == "proof_not_verified":
        return "not_ready"
    return "current"


def _node_operator_records(state: Mapping[str, Any]) -> Mapping[str, Any]:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return {}
    node_ops = roles.get("node_operators")
    if not isinstance(node_ops, dict):
        return {}
    by_id = node_ops.get("by_id")
    return by_id if isinstance(by_id, dict) else {}


def _challenge_id(state: Mapping[str, Any], account_id: str, node_pubkey: str, proof_expires: int) -> str:
    current = _height(state)
    seed = f"storage-revalidate:{account_id}:{node_pubkey}:{current}:{proof_expires}"
    return "storage-revalidation:" + sha256(seed.encode("utf-8")).hexdigest()[:32]


def build_storage_revalidation_plan(state: Mapping[str, Any]) -> list[StorageRevalidationAction]:
    current = _height(state)
    ttl = storage_revalidation_challenge_ttl_blocks(state)
    sample_count = storage_revalidation_sample_count(state)
    sample_size = storage_revalidation_sample_size_bytes(state)
    actions: list[StorageRevalidationAction] = []

    for account_id_raw, rec_any in _node_operator_records(state).items():
        account_id = _as_str(account_id_raw)
        rec = _as_dict(rec_any)
        responsibilities = _as_dict(rec.get("responsibilities"))
        storage = _as_dict(responsibilities.get("storage"))
        if not account_id or not bool(storage.get("opted_in", False)):
            continue
        reason = storage_revalidation_reason(state, storage)
        if not reason or reason == "proof_not_verified":
            continue
        status = storage_revalidation_status_for_reason(reason)
        node_pubkey = _as_str(storage.get("node_pubkey") or rec.get("node_pubkey"))
        declared = _as_int(storage.get("declared_capacity_bytes"), 0)
        proven = _as_int(storage.get("proven_capacity_bytes"), 0)
        reserved = max(0, min(declared if declared > 0 else proven, proven if proven > 0 else declared))
        if reserved <= 0:
            continue
        proof_expires = _as_int(storage.get("proof_expires_height"), 0)
        cid = _challenge_id(state, account_id, node_pubkey, proof_expires)
        payload = {
            "proof_scope": "capacity_probe",
            "challenge_id": cid,
            "account_id": account_id,
            "node_pubkey": node_pubkey,
            "reserved_capacity_bytes": int(reserved),
            "sample_count": int(sample_count),
            "sample_size_bytes": int(min(sample_size, reserved)),
            "expires_height": int(current + ttl),
            "revalidation": True,
            "revalidation_reason": reason,
            "previous_proof_expires_height": int(proof_expires),
        }
        actions.append(
            StorageRevalidationAction(
                account_id=account_id,
                node_pubkey=node_pubkey,
                status=status,
                reason=reason,
                challenge_id=cid,
                payload=payload,
            )
        )
    actions.sort(key=lambda a: (a.status, a.account_id, a.challenge_id))
    return actions


def apply_storage_revalidation_status(state: Json) -> Json:
    """Materialize passive expiry/paused status without issuing challenges.

    This helper is intended for deterministic maintenance/status surfaces. It
    does not allocate capacity and does not create challenge records.
    """
    updated: list[Json] = []
    by_id = _node_operator_records(state)
    for account_id_raw, rec_any in by_id.items():
        account_id = _as_str(account_id_raw)
        rec = _as_dict(rec_any)
        responsibilities = _as_dict(rec.get("responsibilities"))
        storage = _as_dict(responsibilities.get("storage"))
        if not account_id or not storage:
            continue
        reason = storage_revalidation_reason(state, storage)
        if not reason:
            continue
        status = storage_revalidation_status_for_reason(reason)
        if status in ("expired", "paused"):
            storage["active"] = False
            storage["proof_status"] = "expired" if status == "expired" else "paused"
        responsibilities["storage"] = storage
        rec["responsibilities"] = responsibilities
        updated.append({"account_id": account_id, "status": status, "reason": reason})
    return {"updated": updated}
