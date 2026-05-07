# projects/Weall-Protocol/src/weall/runtime/apply/storage.py
from __future__ import annotations

"""weall.runtime.apply.storage

Storage domain apply semantics.

Key invariants:
  - operator_id == account_id (operators are just accounts)
  - operator "toggle" is user-controlled via offer create/withdraw
  - IPFS replication is deterministic:
      IPFS_PIN_REQUEST assigns N target operators (replication_factor)
      per CID, using a stable ring selection over enabled operators.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.node_operator_responsibilities import evaluate_storage_responsibility
from weall.util.ipfs_cid import validate_ipfs_cid

Json = dict[str, Any]


@dataclass
class StorageApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise StorageApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _height(state: Json) -> int:
    return _as_int(state.get("height"), 0)


def _pick(d: Json, *keys: str) -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return None


def _mk_id(prefix: str, env: TxEnvelope, raw: Any) -> str:
    s = _as_str(raw).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{int(env.nonce)}"


def _ensure_storage(state: Json) -> Json:
    st = _ensure_root_dict(state, "storage")

    if not isinstance(st.get("offers"), dict):
        st["offers"] = {}
    if not isinstance(st.get("leases"), dict):
        st["leases"] = {}
    if not isinstance(st.get("proofs"), dict):
        st["proofs"] = {}
    if not isinstance(st.get("challenges"), dict):
        st["challenges"] = {}
    if not isinstance(st.get("reports"), dict):
        st["reports"] = {}
    if not isinstance(st.get("payouts"), list):
        st["payouts"] = []

    # Operator toggles
    if not isinstance(st.get("operators"), dict):
        st["operators"] = {}

    # IPFS pinning
    if not isinstance(st.get("pins"), dict):
        st["pins"] = {}
    if not isinstance(st.get("pin_confirms"), list):
        st["pin_confirms"] = []

    return st


def _set_operator_enabled(state: Json, account_id: str, enabled: bool, nonce: int) -> None:
    s = _ensure_storage(state)
    ops = s["operators"]
    if not isinstance(ops, dict):
        ops = {}
        s["operators"] = ops

    rec_any = ops.get(account_id)
    rec = rec_any if isinstance(rec_any, dict) else {"account_id": account_id}
    rec["enabled"] = bool(enabled)
    rec["last_change_nonce"] = int(nonce)
    ops[account_id] = rec


def _set_operator_capacity(state: Json, account_id: str, capacity_bytes: int) -> None:
    """Persist capacity and initialize used_bytes if absent."""
    s = _ensure_storage(state)
    ops = s["operators"]
    if not isinstance(ops, dict):
        ops = {}
        s["operators"] = ops

    rec_any = ops.get(account_id)
    rec = rec_any if isinstance(rec_any, dict) else {"account_id": account_id}
    rec["capacity_bytes"] = int(max(0, capacity_bytes))
    if "used_bytes" not in rec:
        rec["used_bytes"] = 0
    ops[account_id] = rec


def _ensure_capacity_challenges(state: Json) -> Json:
    s = _ensure_storage(state)
    if not isinstance(s.get("capacity_challenges"), dict):
        s["capacity_challenges"] = {}
    return s["capacity_challenges"]


def _node_operator_storage_record(state: Json, account_id: str) -> Json:
    roles = _as_dict(state.get("roles"))
    node_ops = _as_dict(roles.get("node_operators"))
    by_id = _as_dict(node_ops.get("by_id"))
    rec = _as_dict(by_id.get(account_id))
    responsibilities = _as_dict(rec.get("responsibilities"))
    storage = _as_dict(responsibilities.get("storage"))
    return storage


def _mut_node_operator_storage_record(state: Json, account_id: str) -> Json:
    roles = state.setdefault("roles", {}) if isinstance(state.get("roles"), dict) else {}
    if state.get("roles") is not roles:
        state["roles"] = roles
    node_ops = roles.setdefault("node_operators", {}) if isinstance(roles.get("node_operators"), dict) else {}
    roles["node_operators"] = node_ops
    by_id = node_ops.setdefault("by_id", {}) if isinstance(node_ops.get("by_id"), dict) else {}
    node_ops["by_id"] = by_id
    rec = by_id.setdefault(account_id, {"account_id": account_id}) if isinstance(by_id.get(account_id), dict) else {"account_id": account_id}
    by_id[account_id] = rec
    responsibilities = rec.setdefault("responsibilities", {}) if isinstance(rec.get("responsibilities"), dict) else {}
    rec["responsibilities"] = responsibilities
    storage = responsibilities.setdefault("storage", {}) if isinstance(responsibilities.get("storage"), dict) else {}
    responsibilities["storage"] = storage
    return storage


def _storage_responsibility_enforced(state: Json, account_id: str) -> bool:
    # Production posture: no legacy storage bypass. The account must have
    # explicit Node Operator responsibility state before it can offer, receive
    # allocation, or prove storage capacity.
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return False
    node_ops = roles.get("node_operators")
    if not isinstance(node_ops, dict):
        return False
    by_id = node_ops.get("by_id")
    return isinstance(by_id, dict) and account_id in by_id


def _require_active_storage_responsibility(state: Json, account_id: str, *, node_pubkey: str = "") -> Json:
    if not _storage_responsibility_enforced(state, account_id):
        raise StorageApplyError("forbidden", "storage_responsibility_not_found", {"account_id": account_id})
    evaluation = evaluate_storage_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict()
    if not bool(evaluation.get("active")):
        raise StorageApplyError(
            "forbidden",
            "storage_responsibility_not_active",
            {"account_id": account_id, "reasons": evaluation.get("reasons") or []},
        )
    return evaluation



def _storage_proof_ttl_blocks(state: Json) -> int:
    params = state.get("params")
    if isinstance(params, dict):
        ttl = _as_int(params.get("storage_proof_ttl_blocks"), 0)
        if ttl > 0:
            return ttl
    return 1000


def _derive_probe_offsets(seed: str, *, capacity_bytes: int, sample_size_bytes: int, sample_count: int) -> list[int]:
    if capacity_bytes <= 0 or sample_size_bytes <= 0 or sample_count <= 0:
        return []
    max_offset = max(0, int(capacity_bytes) - int(sample_size_bytes))
    if max_offset <= 0:
        return [0]
    out: set[int] = {0, max_offset}
    i = 0
    base = seed or "capacity-probe"
    while len(out) < int(sample_count) and i < int(sample_count) * 16:
        h = sha256(f"{base}:{i}".encode("utf-8")).digest()
        raw = int.from_bytes(h[:8], "big", signed=False) % (max_offset + 1)
        offset = (raw // int(sample_size_bytes)) * int(sample_size_bytes)
        if offset > max_offset:
            offset = max_offset
        out.add(int(offset))
        i += 1
    return sorted(out)[: int(sample_count)]


def _clean_probe_offsets(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    seen: set[int] = set()
    for item in value:
        offset = _as_int(item, -1)
        if offset < 0 or offset in seen:
            continue
        out.append(int(offset))
        seen.add(int(offset))
    return sorted(out)


def _clean_probe_responses(value: Any) -> list[Json]:
    if not isinstance(value, list):
        return []
    out: list[Json] = []
    seen: set[int] = set()
    for item_any in value:
        item = item_any if isinstance(item_any, dict) else {}
        offset = _as_int(item.get("offset"), -1)
        size = _as_int(item.get("size"), _as_int(item.get("size_bytes"), 0))
        response_hash = _as_str(item.get("response_hash") or item.get("hash") or item.get("commitment")).strip()
        if offset < 0 or size <= 0 or not response_hash or offset in seen:
            continue
        seen.add(int(offset))
        out.append({"offset": int(offset), "size": int(size), "response_hash": response_hash})
    return sorted(out, key=lambda x: int(x.get("offset", 0)))


def _authorized_storage_verifier(state: Json, verifier_id: str) -> bool:
    verifier = _as_str(verifier_id).strip() or "SYSTEM"
    if verifier == "SYSTEM":
        return True
    s = _ensure_storage(state)
    verifiers = s.get("authorized_verifiers")
    if isinstance(verifiers, list):
        return verifier in {str(v).strip() for v in verifiers if str(v).strip()}
    if isinstance(verifiers, dict):
        rec = verifiers.get(verifier)
        return bool(rec) if not isinstance(rec, dict) else bool(rec.get("active", True))
    return False


def _adjust_storage_accounting(state: Json, account_id: str, *, allocated_delta: int = 0, used_delta: int = 0) -> None:
    storage = _mut_node_operator_storage_record(state, account_id)
    if allocated_delta:
        cur = _as_int(storage.get("allocated_capacity_bytes"), 0)
        storage["allocated_capacity_bytes"] = int(max(0, cur + int(allocated_delta)))
    if used_delta:
        cur = _as_int(storage.get("used_capacity_bytes"), 0)
        storage["used_capacity_bytes"] = int(max(0, cur + int(used_delta)))
    s = _ensure_storage(state)
    ops = s.get("operators")
    if isinstance(ops, dict) and account_id in ops and isinstance(ops.get(account_id), dict):
        op = ops[account_id]
        if allocated_delta:
            cur = _as_int(op.get("allocated_bytes"), _as_int(op.get("allocated_capacity_bytes"), 0))
            op["allocated_bytes"] = int(max(0, cur + int(allocated_delta)))
            op["allocated_capacity_bytes"] = op["allocated_bytes"]
        if used_delta:
            cur = _as_int(op.get("used_bytes"), 0)
            op["used_bytes"] = int(max(0, cur + int(used_delta)))
        ops[account_id] = op


def _capacity_available_for_allocation(state: Json, account_id: str) -> int:
    evaluation = evaluate_storage_responsibility(state, account_id).as_dict()
    if not bool(evaluation.get("active")):
        return 0
    details = _as_dict(evaluation.get("details"))
    proven = _as_int(details.get("proven_capacity_bytes"), 0)
    allocated = _as_int(details.get("allocated_capacity_bytes"), 0)
    return max(0, int(proven) - int(allocated))





def _pin_operator_key(pin_id: str, operator_id: str, suffix: str) -> str:
    return f"{pin_id}:{operator_id}:{suffix}"

def _pin_accounting_marker_set(state: Json, marker: str) -> bool:
    s = _ensure_storage(state)
    markers = s.get("pin_accounting_markers")
    if not isinstance(markers, dict):
        markers = {}
        s["pin_accounting_markers"] = markers
    if marker in markers:
        return False
    markers[marker] = True
    return True

def _release_pin_accounting(state: Json, pin_id: str, operator_id: str, size_bytes: int) -> bool:
    if not pin_id or not operator_id or size_bytes <= 0:
        return False
    marker = _pin_operator_key(pin_id, operator_id, "released")
    if not _pin_accounting_marker_set(state, marker):
        return False
    used_marker = _pin_operator_key(pin_id, operator_id, "used")
    s = _ensure_storage(state)
    used_was_counted = bool(_as_dict(s.get("pin_accounting_markers")).get(used_marker))
    _adjust_storage_accounting(
        state,
        operator_id,
        allocated_delta=-int(size_bytes),
        used_delta=-int(size_bytes) if used_was_counted else 0,
    )
    return True

def _operator_id_from_env(env: TxEnvelope, payload: Json) -> str:
    return _as_str(_pick(payload, "operator_id", "operator", "account_id") or env.signer).strip()


def _operator_has_capacity(state: Json, operator_id: str, size_bytes: int) -> bool:
    if not operator_id:
        return False
    if size_bytes <= 0:
        return evaluate_storage_responsibility(state, operator_id).active
    return _capacity_available_for_allocation(state, operator_id) >= int(size_bytes)


def _replication_factor(state: Json) -> int:
    """
    Replication factor source-of-truth:
      - state["params"]["ipfs_replication_factor"] if present
      - default 1
    """
    params = state.get("params")
    if isinstance(params, dict):
        v = _as_int(params.get("ipfs_replication_factor"), 0)
        if v > 0:
            return v
    return 1


def _enabled_operator_ids(state: Json) -> list[str]:
    """
    Deterministic list of enabled operator account IDs.

    Source:
      - state["storage"]["operators"][account_id]["enabled"] == True
    """
    s = _ensure_storage(state)
    ops_any = s.get("operators")
    if not isinstance(ops_any, dict):
        return []

    out: list[str] = []
    for k, rec_any in ops_any.items():
        acc = _as_str(k).strip()
        if not acc:
            continue
        rec = rec_any if isinstance(rec_any, dict) else {}
        if not bool(rec.get("enabled", True)):
            continue
        if _storage_responsibility_enforced(state, acc):
            evaluation = evaluate_storage_responsibility(state, acc).as_dict()
            if not bool(evaluation.get("active")):
                continue
        out.append(acc)

    out.sort()
    return out


def _eligible_operator_ids_for_size(state: Json, size_bytes: int) -> list[str]:
    """Enabled operators that also pass capacity gating."""
    base = _enabled_operator_ids(state)
    if size_bytes <= 0:
        return base
    return [op for op in base if _operator_has_capacity(state, op, int(size_bytes))]


def _select_targets_for_cid(cid: str, operator_ids: list[str], n: int) -> list[str]:
    """
    Deterministic ring selection:
      start = sha256(cid) % len(ops)
      pick n consecutive entries wrapping around.
    """
    if not operator_ids:
        return []
    if n <= 0:
        return []
    n = min(n, len(operator_ids))

    h = sha256(cid.encode("utf-8")).digest()
    seed = int.from_bytes(h[:8], "big", signed=False)
    start = seed % len(operator_ids)

    targets: list[str] = []
    for i in range(n):
        targets.append(operator_ids[(start + i) % len(operator_ids)])
    return targets


# ---------------------------------------------------------------------------
# Offers / Leases / Proofs / Challenges
# ---------------------------------------------------------------------------


def _apply_storage_offer_create(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    operator_id = _operator_id_from_env(env, payload)
    offer_id = _mk_id("offer", env, _pick(payload, "offer_id", "id"))

    capacity_bytes = _as_int(_pick(payload, "capacity_bytes", "capacity"), 0)
    price = _pick(payload, "price")

    storage_eval = _require_active_storage_responsibility(state, operator_id)
    details = _as_dict(storage_eval.get("details"))
    proven_capacity = _as_int(details.get("proven_capacity_bytes"), 0)
    available_capacity = _capacity_available_for_allocation(state, operator_id)
    if capacity_bytes <= 0:
        capacity_bytes = available_capacity
    elif capacity_bytes > available_capacity:
        raise StorageApplyError(
            "forbidden",
            "offer_capacity_exceeds_available_proven_capacity",
            {"capacity_bytes": int(capacity_bytes), "available_capacity_bytes": int(available_capacity), "proven_capacity_bytes": int(proven_capacity)},
        )

    offers = s["offers"]
    if offer_id in offers:
        _set_operator_enabled(state, operator_id, True, int(env.nonce))
        if capacity_bytes > 0:
            _set_operator_capacity(state, operator_id, int(capacity_bytes))
        return {"applied": "STORAGE_OFFER_CREATE", "offer_id": offer_id, "deduped": True}

    offers[offer_id] = {
        "offer_id": offer_id,
        "operator_id": operator_id,
        "operator": operator_id,  # compat alias
        "cid": _pick(payload, "cid", "content_cid", "ipfs_cid") or None,
        "capacity_bytes": int(capacity_bytes),
        "price": price,
        "status": "active",
        "created_at_nonce": int(env.nonce),
        "created_at_height": int(_height(state)),
        "payload": payload,
    }

    _set_operator_enabled(state, operator_id, True, int(env.nonce))
    if capacity_bytes > 0:
        _set_operator_capacity(state, operator_id, int(capacity_bytes))
    return {"applied": "STORAGE_OFFER_CREATE", "offer_id": offer_id, "deduped": False}


def _apply_storage_offer_withdraw(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    offer_id = _pick(payload, "offer_id", "id")
    if not offer_id:
        raise StorageApplyError("invalid_payload", "missing_offer_id", {"tx_type": env.tx_type})

    offers = s["offers"]
    rec = offers.get(offer_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "offer_not_found", {"offer_id": offer_id})

    operator_id = _as_str(rec.get("operator_id") or rec.get("operator") or "").strip()
    if operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_withdraw", {"offer_id": offer_id}
        )

    already = rec.get("status") == "withdrawn"
    rec["status"] = "withdrawn"
    rec["withdrawn_at_nonce"] = int(env.nonce)
    rec["withdraw_payload"] = payload
    offers[offer_id] = rec

    _set_operator_enabled(state, env.signer, False, int(env.nonce))
    return {"applied": "STORAGE_OFFER_WITHDRAW", "offer_id": offer_id, "deduped": already}


def _apply_storage_lease_create(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _mk_id("lease", env, _pick(payload, "lease_id", "id"))
    offer_id = _pick(payload, "offer_id")
    if not offer_id:
        raise StorageApplyError("invalid_payload", "missing_offer_id", {"lease_id": lease_id})

    offers = s["offers"]
    offer = offers.get(offer_id)
    if not isinstance(offer, dict) or offer.get("status") != "active":
        raise StorageApplyError("not_found", "offer_not_active", {"offer_id": offer_id})

    operator_id = _as_str(offer.get("operator_id") or offer.get("operator") or "").strip()
    if not operator_id:
        raise StorageApplyError(
            "invalid_state", "offer_missing_operator_id", {"offer_id": offer_id}
        )

    leases = s["leases"]
    if lease_id in leases:
        return {"applied": "STORAGE_LEASE_CREATE", "lease_id": lease_id, "deduped": True}

    dur = _as_int(payload.get("duration_blocks"), _as_int(payload.get("blocks"), 0))
    if dur <= 0:
        dur = 1

    start_h = _height(state)
    end_h = start_h + dur

    leases[lease_id] = {
        "lease_id": lease_id,
        "offer_id": offer_id,
        "operator_id": operator_id,
        "operator": operator_id,  # compat alias
        "lessee": env.signer,
        "account_id": env.signer,
        "status": "active",
        "start_height": int(start_h),
        "end_height": int(end_h),
        "created_at_nonce": int(env.nonce),
        "payload": payload,
    }

    size_bytes = _as_int(_pick(payload, "size_bytes", "bytes", "capacity_bytes") or offer.get("capacity_bytes"), 0)
    if size_bytes > 0:
        if _capacity_available_for_allocation(state, operator_id) < int(size_bytes):
            raise StorageApplyError("forbidden", "lease_size_exceeds_available_proven_capacity", {"operator_id": operator_id, "size_bytes": int(size_bytes)})
        leases[lease_id]["size_bytes"] = int(size_bytes)
        _adjust_storage_accounting(state, operator_id, allocated_delta=int(size_bytes))

    proofs = s["proofs"]
    if lease_id not in proofs:
        proofs[lease_id] = []

    return {"applied": "STORAGE_LEASE_CREATE", "lease_id": lease_id, "deduped": False}


def _apply_storage_lease_renew(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id", "id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    if rec.get("lessee") != env.signer:
        raise StorageApplyError("forbidden", "only_lessee_can_renew", {"lease_id": lease_id})

    add_blocks = _as_int(payload.get("add_blocks"), _as_int(payload.get("duration_blocks"), 0))
    if add_blocks <= 0:
        add_blocks = 1

    old_end = _as_int(rec.get("end_height"), 0)
    rec["end_height"] = int(old_end + add_blocks)
    rec["renewed_at_nonce"] = int(env.nonce)
    rec["renew_payload"] = payload
    leases[lease_id] = rec
    return {"applied": "STORAGE_LEASE_RENEW", "lease_id": lease_id, "deduped": False}


def _apply_storage_lease_revoke(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id", "id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(rec.get("operator_id") or rec.get("operator") or "").strip()
    if not bool(getattr(env, "system", False)) and operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_revoke", {"lease_id": lease_id}
        )

    already = rec.get("status") == "revoked"
    if not already:
        size_bytes = _as_int(rec.get("size_bytes"), 0)
        if size_bytes > 0:
            _adjust_storage_accounting(state, operator_id, allocated_delta=-int(size_bytes), used_delta=-int(size_bytes))
    rec["status"] = "revoked"
    rec["revoked_at_height"] = int(_height(state))
    rec["revoked_at_nonce"] = int(env.nonce)
    rec["revoke_payload"] = payload
    leases[lease_id] = rec
    return {"applied": "STORAGE_LEASE_REVOKE", "lease_id": lease_id, "deduped": already}


def _apply_storage_proof_submit(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    lease_id = _pick(payload, "lease_id")
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    leases = s["leases"]
    rec = leases.get(lease_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(rec.get("operator_id") or rec.get("operator") or "").strip()
    if operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_submit_proof", {"lease_id": lease_id}
        )

    proofs = s["proofs"]
    if lease_id not in proofs:
        proofs[lease_id] = []

    proofs[lease_id].append(
        {
            "lease_id": lease_id,
            "at_nonce": int(env.nonce),
            "at_height": int(_height(state)),
            "proof_cid": _pick(payload, "proof_cid", "cid") or None,
            "payload": payload,
        }
    )
    return {"applied": "STORAGE_PROOF_SUBMIT", "lease_id": lease_id, "deduped": False}


def _apply_storage_challenge_issue(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    proof_scope = _as_str(_pick(payload, "proof_scope", "scope") or "lease").strip().lower() or "lease"
    challenge_id = _mk_id("challenge", env, _pick(payload, "challenge_id", "id"))

    if proof_scope in ("capacity", "storage_capacity", "capacity_probe", "storage_capacity_probe"):
        account_id = _as_str(_pick(payload, "account_id", "operator_id", "operator") or "").strip()
        if not account_id:
            raise StorageApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
        if not _storage_responsibility_enforced(state, account_id):
            raise StorageApplyError("forbidden", "storage_responsibility_not_found", {"account_id": account_id})
        storage_rec = _node_operator_storage_record(state, account_id)
        declared = _as_int(storage_rec.get("declared_capacity_bytes"), 0)
        if not bool(storage_rec.get("opted_in", False)) or declared <= 0:
            raise StorageApplyError("forbidden", "storage_responsibility_not_opted_in", {"account_id": account_id})
        node_pubkey = _as_str(_pick(payload, "node_pubkey", "node_public_key") or storage_rec.get("node_pubkey") or "").strip()
        evaluation = evaluate_storage_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict()
        reasons = list(evaluation.get("reasons") or [])
        allowed = {"capacity_proof_pending", "capacity_probe_open", "capacity_verification_pending", "capacity_proof_expired", "capacity_proof_failed", "capacity_revalidation_due"}
        blocking = [r for r in reasons if r not in allowed]
        if blocking:
            raise StorageApplyError("forbidden", "storage_capacity_probe_not_allowed", {"account_id": account_id, "reasons": blocking})
        sample_count = _as_int(_pick(payload, "sample_count", "challenge_count", "samples"), 0)
        sample_size = _as_int(_pick(payload, "sample_size_bytes", "sample_bytes"), 0)
        reserved_capacity = _as_int(_pick(payload, "reserved_capacity_bytes", "challenged_capacity_bytes", "capacity_bytes"), declared)
        expires_height = _as_int(_pick(payload, "expires_height", "expiry_height"), 0)
        current_height = _height(state)
        if sample_count <= 0:
            raise StorageApplyError("invalid_payload", "sample_count_required", {"account_id": account_id})
        if sample_size <= 0:
            raise StorageApplyError("invalid_payload", "sample_size_required", {"account_id": account_id})
        if reserved_capacity <= 0 or reserved_capacity > declared:
            raise StorageApplyError("invalid_payload", "reserved_capacity_must_not_exceed_declared_capacity", {"reserved_capacity_bytes": int(reserved_capacity), "declared_capacity_bytes": int(declared)})
        if sample_size > reserved_capacity:
            raise StorageApplyError("invalid_payload", "sample_size_exceeds_reserved_capacity", {"sample_size_bytes": int(sample_size), "reserved_capacity_bytes": int(reserved_capacity)})
        if expires_height <= current_height:
            raise StorageApplyError("invalid_payload", "expires_height_must_be_future", {"expires_height": int(expires_height), "height": int(current_height)})
        challenges = s["challenges"]
        capacity_challenges = _ensure_capacity_challenges(state)
        if challenge_id in challenges or challenge_id in capacity_challenges:
            return {"applied": "STORAGE_CHALLENGE_ISSUE", "challenge_id": challenge_id, "deduped": True, "proof_scope": "capacity_probe"}
        seed = _as_str(_pick(payload, "challenge_seed", "seed", "challenge_seed_commitment", "seed_commitment") or challenge_id).strip()
        probe_offsets = _clean_probe_offsets(payload.get("probe_offsets")) or _derive_probe_offsets(seed, capacity_bytes=int(reserved_capacity), sample_size_bytes=int(sample_size), sample_count=int(sample_count))
        if len(probe_offsets) < sample_count:
            raise StorageApplyError("invalid_payload", "insufficient_probe_offsets", {"required": int(sample_count), "actual": int(len(probe_offsets))})
        max_offset = max(0, int(reserved_capacity) - int(sample_size))
        for offset in probe_offsets:
            if offset < 0 or offset > max_offset:
                raise StorageApplyError("invalid_payload", "probe_offset_out_of_reserved_range", {"offset": int(offset), "max_offset": int(max_offset)})
        rec = {
            "challenge_id": challenge_id, "proof_scope": "capacity_probe", "lease_id": None,
            "operator_id": account_id, "account_id": account_id, "node_pubkey": node_pubkey or None,
            "declared_capacity_bytes": int(declared), "reserved_capacity_bytes": int(reserved_capacity),
            "probed_capacity_bytes": 0, "sample_count": int(sample_count), "challenge_count": int(sample_count),
            "sample_size_bytes": int(sample_size), "probe_offsets": [int(v) for v in probe_offsets],
            "challenge_seed_commitment": _as_str(_pick(payload, "challenge_seed_commitment", "seed_commitment") or "") or None,
            "issued_at_nonce": int(env.nonce), "issued_at_height": int(current_height),
            "expires_height": int(expires_height), "payload": payload, "status": "open",
        }
        challenges[challenge_id] = rec
        capacity_challenges[challenge_id] = rec
        storage = _mut_node_operator_storage_record(state, account_id)
        storage.update({"proof_status": "probe_open", "latest_challenge_id": challenge_id, "challenge_expires_height": int(expires_height), "sample_count": int(sample_count), "sample_size_bytes": int(sample_size), "reserved_capacity_bytes": int(reserved_capacity), "probe_offsets": [int(v) for v in probe_offsets]})
        if node_pubkey:
            storage["node_pubkey"] = node_pubkey
        return {"applied": "STORAGE_CHALLENGE_ISSUE", "challenge_id": challenge_id, "deduped": False, "proof_scope": "capacity_probe", "probe_offsets": [int(v) for v in probe_offsets]}

    lease_id = _as_str(_pick(payload, "lease_id") or "").strip()
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    lease = s["leases"].get(lease_id)
    if not isinstance(lease, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(lease.get("operator_id") or lease.get("operator") or "").strip()
    if not operator_id:
        raise StorageApplyError(
            "invalid_state", "lease_missing_operator_id", {"lease_id": lease_id}
        )

    hinted_op = _as_str(_pick(payload, "operator_id", "operator") or "").strip()
    if hinted_op and hinted_op != operator_id:
        raise StorageApplyError(
            "invalid_payload",
            "operator_id_must_equal_lease_operator_account_id",
            {"operator_id": hinted_op, "lease_operator_id": operator_id, "lease_id": lease_id},
        )

    account_id = (
        _as_str(_pick(payload, "account_id", "lessee") or "").strip()
        or _as_str(lease.get("lessee")).strip()
    )

    challenges = s["challenges"]
    if challenge_id in challenges:
        return {"applied": "STORAGE_CHALLENGE_ISSUE", "challenge_id": challenge_id, "deduped": True}

    challenges[challenge_id] = {
        "challenge_id": challenge_id,
        "proof_scope": "lease",
        "lease_id": lease_id,
        "operator_id": operator_id,
        "account_id": account_id or None,
        "issued_at_nonce": int(env.nonce),
        "issued_at_height": int(_height(state)),
        "payload": payload,
        "status": "open",
    }
    return {"applied": "STORAGE_CHALLENGE_ISSUE", "challenge_id": challenge_id, "deduped": False}


def _apply_storage_challenge_respond(state: Json, env: TxEnvelope) -> Json:
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    challenge_id = _pick(payload, "challenge_id", "id")
    if not challenge_id:
        raise StorageApplyError("invalid_payload", "missing_challenge_id", {"tx_type": env.tx_type})

    challenges = s["challenges"]
    rec = challenges.get(challenge_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "challenge_not_found", {"challenge_id": challenge_id})

    proof_scope = _as_str(rec.get("proof_scope") or payload.get("proof_scope") or "lease").strip().lower() or "lease"
    if proof_scope in ("capacity", "storage_capacity", "capacity_probe", "storage_capacity_probe"):
        account_id = _as_str(rec.get("account_id") or rec.get("operator_id") or "").strip()
        if not account_id:
            raise StorageApplyError("invalid_state", "capacity_challenge_missing_account_id", {"challenge_id": challenge_id})
        current_height = _height(state)
        expires_height = _as_int(rec.get("expires_height"), 0)
        is_system = bool(getattr(env, "system", False))
        if not is_system:
            if account_id != env.signer:
                raise StorageApplyError("forbidden", "only_operator_account_can_respond", {"challenge_id": challenge_id})
            if expires_height and current_height > expires_height:
                rec["status"] = "expired"
                challenges[challenge_id] = rec
                _ensure_capacity_challenges(state)[challenge_id] = rec
                storage = _mut_node_operator_storage_record(state, account_id)
                storage["proof_status"] = "expired"
                storage["active"] = False
                storage["missed_challenge_count"] = _as_int(storage.get("missed_challenge_count"), 0) + 1
                raise StorageApplyError("forbidden", "storage_capacity_probe_expired", {"challenge_id": challenge_id, "height": int(current_height), "expires_height": int(expires_height)})
            if rec.get("status") not in ("open", "responded"):
                raise StorageApplyError("forbidden", "storage_capacity_probe_not_open", {"challenge_id": challenge_id, "status": rec.get("status")})
            if payload.get("verification_status") is not None or payload.get("verified_capacity_bytes") is not None:
                raise StorageApplyError("forbidden", "system_verification_required", {"challenge_id": challenge_id})
            response_commitment = _as_str(_pick(payload, "response_commitment", "proof_commitment", "probe_commitment_root") or "").strip()
            if not response_commitment:
                raise StorageApplyError("invalid_payload", "response_commitment_required", {"challenge_id": challenge_id})
            probe_responses = _clean_probe_responses(payload.get("probe_responses"))
            required_offsets = [int(v) for v in rec.get("probe_offsets", []) if isinstance(v, int) or str(v).strip().isdigit()]
            sample_size = _as_int(rec.get("sample_size_bytes"), 0)
            if not probe_responses:
                commitments = payload.get("sample_response_commitments") or payload.get("sample_commitments") or []
                if isinstance(commitments, list):
                    probe_responses = [{"offset": int(offset), "size": int(sample_size), "response_hash": str(commitments[i]).strip()} for i, offset in enumerate(required_offsets) if i < len(commitments) and str(commitments[i]).strip()]
            response_offsets = {int(item["offset"]) for item in probe_responses}
            missing_offsets = [int(v) for v in required_offsets if int(v) not in response_offsets]
            if missing_offsets:
                raise StorageApplyError("invalid_payload", "probe_response_offsets_missing", {"challenge_id": challenge_id, "missing_offsets": missing_offsets[:10]})
            for item in probe_responses:
                if _as_int(item.get("size"), 0) != sample_size:
                    raise StorageApplyError("invalid_payload", "probe_response_size_mismatch", {"challenge_id": challenge_id, "offset": int(item.get("offset", 0))})
            measured_capacity = _as_int(_pick(payload, "measured_capacity_bytes", "capacity_bytes"), 0)
            rec.update({"status": "responded", "responded_at_nonce": int(env.nonce), "responded_at_height": int(current_height), "response_payload": payload, "response_commitment": response_commitment, "probe_responses": probe_responses})
            if measured_capacity > 0:
                rec["measured_capacity_bytes"] = int(measured_capacity)
            challenges[challenge_id] = rec
            _ensure_capacity_challenges(state)[challenge_id] = rec
            storage = _mut_node_operator_storage_record(state, account_id)
            storage["proof_status"] = "verification_pending"
            storage["latest_challenge_id"] = challenge_id
            storage["probed_capacity_bytes"] = int(rec.get("reserved_capacity_bytes") or rec.get("challenged_capacity_bytes") or 0)
            return {"applied": "STORAGE_CHALLENGE_RESPOND", "challenge_id": challenge_id, "deduped": False, "proof_scope": "capacity_probe", "verification_pending": True}
        return _apply_storage_capacity_proof_verify(state, env)

    operator_id = _as_str(rec.get("operator_id") or "").strip()
    if not bool(getattr(env, "system", False)) and operator_id and operator_id != env.signer:
        raise StorageApplyError(
            "forbidden", "only_operator_account_can_respond", {"challenge_id": challenge_id}
        )

    already = rec.get("status") == "responded"
    rec["status"] = "responded"
    rec["responded_at_nonce"] = int(env.nonce)
    rec["responded_at_height"] = int(_height(state))
    rec["response_payload"] = payload
    challenges[challenge_id] = rec
    return {
        "applied": "STORAGE_CHALLENGE_RESPOND",
        "challenge_id": challenge_id,
        "deduped": already,
    }


def _apply_storage_capacity_proof_verify(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)
    challenge_id = _as_str(_pick(payload, "challenge_id", "id") or "").strip()
    if not challenge_id:
        raise StorageApplyError("invalid_payload", "missing_challenge_id", {"tx_type": env.tx_type})
    challenges = s["challenges"]
    rec = challenges.get(challenge_id)
    if not isinstance(rec, dict):
        rec = _ensure_capacity_challenges(state).get(challenge_id)
    if not isinstance(rec, dict):
        raise StorageApplyError("not_found", "challenge_not_found", {"challenge_id": challenge_id})
    proof_scope = _as_str(rec.get("proof_scope") or payload.get("proof_scope") or "").strip().lower()
    if proof_scope not in ("capacity", "storage_capacity", "capacity_probe", "storage_capacity_probe"):
        raise StorageApplyError("invalid_payload", "capacity_probe_challenge_required", {"challenge_id": challenge_id, "proof_scope": proof_scope})
    account_id = _as_str(rec.get("account_id") or rec.get("operator_id") or "").strip()
    if not account_id:
        raise StorageApplyError("invalid_state", "capacity_challenge_missing_account_id", {"challenge_id": challenge_id})
    current_height = _height(state)
    expires_height = _as_int(rec.get("expires_height"), 0)
    if expires_height and current_height > expires_height:
        rec["status"] = "expired"
        challenges[challenge_id] = rec
        _ensure_capacity_challenges(state)[challenge_id] = rec
        storage = _mut_node_operator_storage_record(state, account_id)
        storage["proof_status"] = "expired"
        storage["active"] = False
        storage["missed_challenge_count"] = _as_int(storage.get("missed_challenge_count"), 0) + 1
        raise StorageApplyError("forbidden", "storage_capacity_probe_expired", {"challenge_id": challenge_id})
    verifier_id = _as_str(_pick(payload, "verifier_id", "verifier") or "SYSTEM").strip() or "SYSTEM"
    if not _authorized_storage_verifier(state, verifier_id):
        raise StorageApplyError("forbidden", "storage_verifier_not_authorized", {"verifier_id": verifier_id})
    status = _as_str(_pick(payload, "verification_status", "verdict", "status") or "").strip().lower()
    if status not in ("verified", "failed", "rejected"):
        raise StorageApplyError("invalid_payload", "verification_status_required", {"challenge_id": challenge_id})
    storage = _mut_node_operator_storage_record(state, account_id)
    if status == "verified":
        if rec.get("status") != "responded":
            raise StorageApplyError("forbidden", "capacity_probe_response_required", {"challenge_id": challenge_id, "status": rec.get("status")})
        declared = _as_int(storage.get("declared_capacity_bytes"), _as_int(rec.get("declared_capacity_bytes"), 0))
        reserved = _as_int(rec.get("reserved_capacity_bytes"), _as_int(rec.get("challenged_capacity_bytes"), declared))
        verified = _as_int(_pick(payload, "verified_capacity_bytes", "proven_capacity_bytes"), 0)
        if verified <= 0:
            raise StorageApplyError("invalid_payload", "verified_capacity_required", {"challenge_id": challenge_id})
        if declared > 0 and verified > declared:
            raise StorageApplyError("invalid_payload", "verified_capacity_exceeds_declared_capacity", {"verified_capacity_bytes": int(verified), "declared_capacity_bytes": int(declared)})
        if reserved > 0 and verified > reserved:
            raise StorageApplyError("invalid_payload", "verified_capacity_exceeds_reserved_capacity", {"verified_capacity_bytes": int(verified), "reserved_capacity_bytes": int(reserved)})
        receipt_hash = _as_str(_pick(payload, "verification_receipt_hash", "receipt_hash") or "").strip()
        if not receipt_hash:
            raise StorageApplyError("invalid_payload", "verification_receipt_hash_required", {"challenge_id": challenge_id})
        ttl = _as_int(_pick(payload, "proof_ttl_blocks", "ttl_blocks"), _storage_proof_ttl_blocks(state))
        if ttl <= 0:
            ttl = _storage_proof_ttl_blocks(state)
        proven = min(int(verified), int(declared) if declared > 0 else int(verified), int(reserved) if reserved > 0 else int(verified))
        rec.update({"status": "verified", "verified_at_nonce": int(env.nonce), "verified_at_height": int(current_height), "verified_capacity_bytes": int(proven), "verifier_id": verifier_id, "verification_payload": payload})
        storage.update({"proven_capacity_bytes": int(proven), "probed_capacity_bytes": int(reserved), "active": True, "proof_status": "verified", "verified_at_height": int(current_height), "verified_at_nonce": int(env.nonce), "proof_expires_height": int(current_height + ttl), "last_successful_challenge_height": int(current_height), "latest_challenge_id": challenge_id, "failed_challenge_count": 0, "missed_challenge_count": 0, "availability_score_milli": 1000, "capacity_proof": {"challenge_id": challenge_id, "verified_capacity_bytes": int(proven), "verified_at_height": int(current_height), "proof_expires_height": int(current_height + ttl), "verifier_id": verifier_id, "verification_receipt_hash": receipt_hash, "sample_count": _as_int(rec.get("sample_count"), _as_int(rec.get("challenge_count"), 0)), "sample_size_bytes": _as_int(rec.get("sample_size_bytes"), 0)}})
        _set_operator_enabled(state, account_id, True, int(env.nonce))
        _set_operator_capacity(state, account_id, int(proven))
    else:
        rec.update({"status": "failed", "failed_at_nonce": int(env.nonce), "failed_at_height": int(current_height), "verifier_id": verifier_id, "verification_payload": payload})
        storage["active"] = False
        storage["proof_status"] = "failed"
        storage["latest_challenge_id"] = challenge_id
        storage["last_failed_challenge_height"] = int(current_height)
        storage["failed_challenge_count"] = _as_int(storage.get("failed_challenge_count"), 0) + 1
        storage["availability_score_milli"] = max(0, _as_int(storage.get("availability_score_milli"), 1000) - 250)
    challenges[challenge_id] = rec
    _ensure_capacity_challenges(state)[challenge_id] = rec
    return {"applied": "STORAGE_CAPACITY_PROOF_VERIFY", "challenge_id": challenge_id, "proof_scope": "capacity_probe", "verified": status == "verified"}


# ---------------------------------------------------------------------------
# System-only receipts
# ---------------------------------------------------------------------------


def _apply_storage_payout_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    payout_id = _mk_id("payout", env, _pick(payload, "payout_id", "id"))

    rec = {
        "payout_id": payout_id,
        "operator_id": _pick(payload, "operator_id", "operator") or None,
        "amount": _pick(payload, "amount") or 0,
        "at_nonce": int(env.nonce),
        "at_height": int(_height(state)),
        "payload": payload,
    }
    s["payouts"].append(rec)

    return {"applied": "STORAGE_PAYOUT_EXECUTE", "payout_id": payout_id, "deduped": False}


def _apply_storage_report_anchor(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    report_id = _mk_id("report", env, _pick(payload, "key", "report_id", "id"))
    reports = s["reports"]

    if report_id in reports:
        return {"applied": "STORAGE_REPORT_ANCHOR", "report_id": report_id, "deduped": True}

    reports[report_id] = {
        "report_id": report_id,
        "report_cid": _pick(payload, "report_cid", "cid") or None,
        "anchored_at_nonce": int(env.nonce),
        "anchored_at_height": int(_height(state)),
        "payload": payload,
    }
    return {"applied": "STORAGE_REPORT_ANCHOR", "report_id": report_id, "deduped": False}


# ---------------------------------------------------------------------------
# IPFS pinning (canon Storage)
# ---------------------------------------------------------------------------


def _apply_ipfs_pin_request(state: Json, env: TxEnvelope) -> Json:
    """
    User requests pinning for CID.

    Production semantics:
      - We deterministically assign target operators based on enabled operators list
        and replication factor.
      - The pin worker for a given operator only processes pins where it is in targets[].
    """
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    cid = _as_str(_pick(payload, "cid", "ipfs_cid", "content_cid") or "").strip()
    if not cid:
        raise StorageApplyError("invalid_payload", "missing_cid", {"tx_type": env.tx_type})

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise StorageApplyError("invalid_payload", v.reason, {"cid": v.cid})

    size_bytes = _as_int(_pick(payload, "size_bytes", "bytes", "size") or 0, 0)

    pin_id = _mk_id("pin", env, _pick(payload, "pin_id", "id"))

    pins = s["pins"]
    if pin_id in pins:
        return {"applied": "IPFS_PIN_REQUEST", "pin_id": pin_id, "deduped": True}

    rf = _replication_factor(state)
    eligible_ops = _eligible_operator_ids_for_size(state, int(size_bytes))
    targets = _select_targets_for_cid(cid, eligible_ops, rf)
    if size_bytes > 0:
        for target in targets:
            if _pin_accounting_marker_set(state, _pin_operator_key(pin_id, target, "allocated")):
                _adjust_storage_accounting(state, target, allocated_delta=int(size_bytes))

    pins[pin_id] = {
        "pin_id": pin_id,
        "cid": cid,
        "size_bytes": int(size_bytes) if int(size_bytes) > 0 else 0,
        "requested_by": env.signer,
        "requested_at_nonce": int(env.nonce),
        "requested_at_height": int(_height(state)),
        "status": "requested",
        "targets": targets,
        "replication_factor": int(rf),
        "payload": payload,
    }

    return {
        "applied": "IPFS_PIN_REQUEST",
        "pin_id": pin_id,
        "cid": cid,
        "size_bytes": int(size_bytes) if int(size_bytes) > 0 else 0,
        "targets": targets,
        "replication_factor": int(rf),
        "deduped": False,
    }


def _apply_ipfs_pin_confirm(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    s = _ensure_storage(state)
    payload = _as_dict(env.payload)

    pin_id = _as_str(_pick(payload, "pin_id", "id") or "").strip()
    if not pin_id:
        raise StorageApplyError("invalid_payload", "missing_pin_id", {"tx_type": env.tx_type})

    ok = payload.get("ok")
    ok_bool = bool(ok) if isinstance(ok, (bool, int)) else False
    if "ok" not in payload:
        ok_bool = True

    cid = _as_str(_pick(payload, "cid", "ipfs_cid", "content_cid") or "").strip()
    operator_id = _as_str(_pick(payload, "operator_id", "operator") or "").strip()

    pins = s["pins"]
    rec_any = pins.get(pin_id)
    rec = rec_any if isinstance(rec_any, dict) else {"pin_id": pin_id}

    if cid and not _as_str(rec.get("cid")).strip():
        rec["cid"] = cid
    if not cid:
        cid = _as_str(rec.get("cid")).strip()

    if cid:
        v = validate_ipfs_cid(cid)
        if not v.ok:
            raise StorageApplyError("invalid_payload", v.reason, {"cid": v.cid})

    release_requested = bool(payload.get("release")) or _as_str(payload.get("status")).lower() in ("released", "unpin", "unpinned")
    if release_requested:
        rec["status"] = "released"
        rec["released_at_nonce"] = int(env.nonce)
        rec["released_at_height"] = int(_height(state))
        if operator_id:
            size_bytes = _as_int(rec.get("size_bytes"), 0)
            if size_bytes > 0:
                _release_pin_accounting(state, pin_id, operator_id, int(size_bytes))
    elif ok_bool:
        rec["status"] = "confirmed"
        rec["confirmed_at_nonce"] = int(env.nonce)
        rec["confirmed_at_height"] = int(_height(state))

        if operator_id:
            size_bytes = _as_int(rec.get("size_bytes"), 0)
            if size_bytes > 0:
                already_ok = False
                for item_any in s.get("pin_confirms", []):
                    if not isinstance(item_any, dict):
                        continue
                    if str(item_any.get("pin_id") or "").strip() != pin_id:
                        continue
                    if str(item_any.get("operator_id") or "").strip() != operator_id:
                        continue
                    if bool(item_any.get("ok")):
                        already_ok = True
                        break
                if not already_ok and _pin_accounting_marker_set(state, _pin_operator_key(pin_id, operator_id, "used")):
                    _adjust_storage_accounting(state, operator_id, used_delta=int(size_bytes))
    else:
        rec["status"] = "confirm_failed"
        rec["failed_at_nonce"] = int(env.nonce)
        rec["failed_at_height"] = int(_height(state))
        if operator_id:
            size_bytes = _as_int(rec.get("size_bytes"), 0)
            if size_bytes > 0:
                _release_pin_accounting(state, pin_id, operator_id, int(size_bytes))

    rec["confirm_payload"] = payload
    pins[pin_id] = rec

    s["pin_confirms"].append(
        {
            "pin_id": pin_id,
            "cid": cid,
            "operator_id": operator_id or None,
            "ok": bool(ok_bool),
            "at_nonce": int(env.nonce),
            "at_height": int(_height(state)),
            "payload": payload,
        }
    )

    return {"applied": "IPFS_PIN_CONFIRM", "pin_id": pin_id, "ok": bool(ok_bool), "receipt": True}


# ---------------------------------------------------------------------------
# Dispatcher entrypoint
# ---------------------------------------------------------------------------


def apply_storage(state: Json, env: TxEnvelope) -> Json | None:
    t = str(getattr(env, "tx_type", "") or "").strip()

    if t == "STORAGE_OFFER_CREATE":
        return _apply_storage_offer_create(state, env)
    if t == "STORAGE_OFFER_WITHDRAW":
        return _apply_storage_offer_withdraw(state, env)

    if t == "STORAGE_LEASE_CREATE":
        return _apply_storage_lease_create(state, env)
    if t == "STORAGE_LEASE_RENEW":
        return _apply_storage_lease_renew(state, env)
    if t == "STORAGE_LEASE_REVOKE":
        return _apply_storage_lease_revoke(state, env)

    if t == "STORAGE_PROOF_SUBMIT":
        return _apply_storage_proof_submit(state, env)

    if t == "STORAGE_CHALLENGE_ISSUE":
        return _apply_storage_challenge_issue(state, env)
    if t == "STORAGE_CHALLENGE_RESPOND":
        return _apply_storage_challenge_respond(state, env)
    if t == "STORAGE_CAPACITY_PROOF_VERIFY":
        return _apply_storage_capacity_proof_verify(state, env)

    if t == "STORAGE_PAYOUT_EXECUTE":
        return _apply_storage_payout_execute(state, env)
    if t == "STORAGE_REPORT_ANCHOR":
        return _apply_storage_report_anchor(state, env)

    if t == "IPFS_PIN_REQUEST":
        return _apply_ipfs_pin_request(state, env)
    if t == "IPFS_PIN_CONFIRM":
        return _apply_ipfs_pin_confirm(state, env)

    return None
