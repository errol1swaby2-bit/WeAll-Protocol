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
from typing import Any, Dict, List, Optional

from weall.runtime.tx_admission import TxEnvelope
from weall.util.ipfs_cid import validate_ipfs_cid

Json = Dict[str, Any]


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


def _operator_has_capacity(state: Json, operator_id: str, size_bytes: int) -> bool:
    """Capacity gate.

    Semantics:
      - capacity_bytes <= 0 means "unspecified/unlimited" (bootstrap-friendly).
      - used_bytes missing defaults to 0.
      - if size_bytes <= 0 (unknown), treat as eligible.
    """
    if not operator_id:
        return False
    if size_bytes <= 0:
        return True

    s = _ensure_storage(state)
    ops_any = s.get("operators")
    if not isinstance(ops_any, dict):
        return True

    rec_any = ops_any.get(operator_id)
    if not isinstance(rec_any, dict):
        return True

    cap = _as_int(rec_any.get("capacity_bytes"), 0)
    if cap <= 0:
        return True

    used = _as_int(rec_any.get("used_bytes"), 0)
    return (used + int(size_bytes)) <= int(cap)


def _operator_id_from_env(env: TxEnvelope, payload: Json) -> str:
    """
    Enforces operator_id == signer account id.
    If payload includes operator_id, it MUST match env.signer (fail-closed).
    """
    hinted = _as_str(_pick(payload, "operator_id", "operator") or "").strip()
    if hinted and hinted != env.signer:
        raise StorageApplyError(
            "invalid_payload",
            "operator_id_must_equal_signer_account_id",
            {"operator_id": hinted, "signer": env.signer},
        )
    return env.signer


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


def _enabled_operator_ids(state: Json) -> List[str]:
    """
    Deterministic list of enabled operator account IDs.

    Source:
      - state["storage"]["operators"][account_id]["enabled"] == True
    """
    s = _ensure_storage(state)
    ops_any = s.get("operators")
    if not isinstance(ops_any, dict):
        return []

    out: List[str] = []
    for k, rec_any in ops_any.items():
        acc = _as_str(k).strip()
        if not acc:
            continue
        rec = rec_any if isinstance(rec_any, dict) else {}
        if bool(rec.get("enabled", True)):
            out.append(acc)

    out.sort()
    return out


def _eligible_operator_ids_for_size(state: Json, size_bytes: int) -> List[str]:
    """Enabled operators that also pass capacity gating."""
    base = _enabled_operator_ids(state)
    if size_bytes <= 0:
        return base
    return [op for op in base if _operator_has_capacity(state, op, int(size_bytes))]


def _select_targets_for_cid(cid: str, operator_ids: List[str], n: int) -> List[str]:
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

    targets: List[str] = []
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
        raise StorageApplyError("forbidden", "only_operator_account_can_withdraw", {"offer_id": offer_id})

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
        raise StorageApplyError("invalid_state", "offer_missing_operator_id", {"offer_id": offer_id})

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
        raise StorageApplyError("forbidden", "only_operator_account_can_revoke", {"lease_id": lease_id})

    already = rec.get("status") == "revoked"
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
        raise StorageApplyError("forbidden", "only_operator_account_can_submit_proof", {"lease_id": lease_id})

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

    challenge_id = _mk_id("challenge", env, _pick(payload, "challenge_id", "id"))

    lease_id = _as_str(_pick(payload, "lease_id") or "").strip()
    if not lease_id:
        raise StorageApplyError("invalid_payload", "missing_lease_id", {"tx_type": env.tx_type})

    lease = s["leases"].get(lease_id)
    if not isinstance(lease, dict):
        raise StorageApplyError("not_found", "lease_not_found", {"lease_id": lease_id})

    operator_id = _as_str(lease.get("operator_id") or lease.get("operator") or "").strip()
    if not operator_id:
        raise StorageApplyError("invalid_state", "lease_missing_operator_id", {"lease_id": lease_id})

    hinted_op = _as_str(_pick(payload, "operator_id", "operator") or "").strip()
    if hinted_op and hinted_op != operator_id:
        raise StorageApplyError(
            "invalid_payload",
            "operator_id_must_equal_lease_operator_account_id",
            {"operator_id": hinted_op, "lease_operator_id": operator_id, "lease_id": lease_id},
        )

    account_id = _as_str(_pick(payload, "account_id", "lessee") or "").strip() or _as_str(lease.get("lessee")).strip()

    challenges = s["challenges"]
    if challenge_id in challenges:
        return {"applied": "STORAGE_CHALLENGE_ISSUE", "challenge_id": challenge_id, "deduped": True}

    challenges[challenge_id] = {
        "challenge_id": challenge_id,
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

    operator_id = _as_str(rec.get("operator_id") or "").strip()
    if not bool(getattr(env, "system", False)) and operator_id and operator_id != env.signer:
        raise StorageApplyError("forbidden", "only_operator_account_can_respond", {"challenge_id": challenge_id})

    already = rec.get("status") == "responded"
    rec["status"] = "responded"
    rec["responded_at_nonce"] = int(env.nonce)
    rec["responded_at_height"] = int(_height(state))
    rec["response_payload"] = payload
    challenges[challenge_id] = rec
    return {"applied": "STORAGE_CHALLENGE_RESPOND", "challenge_id": challenge_id, "deduped": already}


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

    if ok_bool:
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
                if not already_ok:
                    ops_any = s.get("operators")
                    if isinstance(ops_any, dict):
                        op_rec_any = ops_any.get(operator_id)
                        op_rec = op_rec_any if isinstance(op_rec_any, dict) else {"account_id": operator_id}
                        used = _as_int(op_rec.get("used_bytes"), 0)
                        op_rec["used_bytes"] = int(max(0, used + int(size_bytes)))
                        if "capacity_bytes" not in op_rec:
                            op_rec["capacity_bytes"] = 0
                        ops_any[operator_id] = op_rec
    else:
        rec["status"] = "confirm_failed"
        rec["failed_at_nonce"] = int(env.nonce)
        rec["failed_at_height"] = int(_height(state))

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

def apply_storage(state: Json, env: TxEnvelope) -> Optional[Json]:
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

    if t == "STORAGE_PAYOUT_EXECUTE":
        return _apply_storage_payout_execute(state, env)
    if t == "STORAGE_REPORT_ANCHOR":
        return _apply_storage_report_anchor(state, env)

    if t == "IPFS_PIN_REQUEST":
        return _apply_ipfs_pin_request(state, env)
    if t == "IPFS_PIN_CONFIRM":
        return _apply_ipfs_pin_confirm(state, env)

    return None
