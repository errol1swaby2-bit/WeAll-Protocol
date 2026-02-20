# src/weall/runtime/apply/treasury.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.econ_phase import deny_if_econ_disabled, deny_if_econ_time_locked
from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class TreasuryApplyError(Exception):
    code: str
    reason: str
    details: Optional[Json] = None

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}"


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _require_system_env(env: TxEnvelope) -> None:
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise TreasuryApplyError("forbidden", "system_tx_required", {"tx_type": env.tx_type, "signer": env.signer})


def _ensure_treasury_root(state: Json) -> Json:
    t = state.get("treasury")
    if not isinstance(t, dict):
        t = {}
        state["treasury"] = t
    t.setdefault("programs", {})
    t.setdefault("spends", {})
    t.setdefault("audit_anchors", [])
    t.setdefault("params", {})
    return t


def _ensure_wallets(state: Json) -> Json:
    root = state.get("treasury_wallets")
    if not isinstance(root, dict):
        root = {}
        state["treasury_wallets"] = root
    return root


def _ensure_treasury_policy(state: Json) -> Json:
    root = state.get("treasury_policy")
    if not isinstance(root, dict):
        root = {}
        state["treasury_policy"] = root
    return root


def _ensure_spends_expired(state: Json) -> List[Json]:
    root = state.get("treasury_spends_expired")
    if not isinstance(root, list):
        root = []
        state["treasury_spends_expired"] = root
    return root


def _apply_treasury_params_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    deny_if_econ_time_locked(state)
    deny_if_econ_disabled(state, tx_type="TREASURY_PARAMS_SET")

    payload = _as_dict(env.payload)
    tre = _ensure_treasury_root(state)

    params = tre.get("params")
    if not isinstance(params, dict):
        params = {}
    params.update(payload)
    tre["params"] = params

    return {"applied": "TREASURY_PARAMS_SET"}


def _apply_treasury_spend_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise TreasuryApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    tre = _ensure_treasury_root(state)
    spends = tre.get("spends")
    if not isinstance(spends, dict):
        spends = {}
        tre["spends"] = spends

    if spend_id in spends:
        raise TreasuryApplyError("conflict", "spend_id_exists", {"spend_id": spend_id})

    spends[spend_id] = {
        "spend_id": spend_id,
        "status": "proposed",
        "proposed_by": _as_str(env.signer).strip(),
        "payload": payload,
        "signatures": {},
        "created_at_nonce": int(env.nonce),
    }

    return {"applied": "TREASURY_SPEND_PROPOSE", "spend_id": spend_id}


def _apply_treasury_spend_sign(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise TreasuryApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    tre = _ensure_treasury_root(state)
    spends = tre.get("spends")
    if not isinstance(spends, dict):
        spends = {}
        tre["spends"] = spends

    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise TreasuryApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    sigs = s.get("signatures")
    if not isinstance(sigs, dict):
        sigs = {}
    sigs[_as_str(env.signer).strip()] = {"at_nonce": int(env.nonce)}
    s["signatures"] = sigs
    spends[spend_id] = s

    return {"applied": "TREASURY_SPEND_SIGN", "spend_id": spend_id}


def _apply_treasury_spend_cancel(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise TreasuryApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    tre = _ensure_treasury_root(state)
    spends = tre.get("spends")
    if not isinstance(spends, dict):
        spends = {}
        tre["spends"] = spends

    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise TreasuryApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status in ("executed", "canceled", "cancelled"):
        return {"applied": "TREASURY_SPEND_CANCEL", "spend_id": spend_id, "deduped": True}

    s["status"] = "canceled"
    s["canceled_by"] = _as_str(env.signer).strip()
    s["canceled_at_nonce"] = int(env.nonce)
    spends[spend_id] = s

    return {"applied": "TREASURY_SPEND_CANCEL", "spend_id": spend_id}


def _apply_treasury_spend_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    deny_if_econ_time_locked(state)
    deny_if_econ_disabled(state, tx_type="TREASURY_SPEND_EXECUTE")

    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise TreasuryApplyError("invalid_payload", "missing_spend_id", {"tx_type": env.tx_type})

    tre = _ensure_treasury_root(state)
    spends = tre.get("spends")
    if not isinstance(spends, dict):
        spends = {}
        tre["spends"] = spends

    s = spends.get(spend_id)
    if not isinstance(s, dict):
        raise TreasuryApplyError("not_found", "spend_not_found", {"spend_id": spend_id})

    status = _as_str(s.get("status")).strip().lower()
    if status == "executed":
        return {"applied": "TREASURY_SPEND_EXECUTE", "spend_id": spend_id, "deduped": True}
    if status in ("canceled", "cancelled"):
        raise TreasuryApplyError("forbidden", "spend_canceled", {"spend_id": spend_id})

    s["status"] = "executed"
    s["executed_at_nonce"] = int(env.nonce)
    spends[spend_id] = s

    return {"applied": "TREASURY_SPEND_EXECUTE", "spend_id": spend_id}


# --- Missing canon coverage additions -------------------------------------


def _apply_treasury_wallet_create(state: Json, env: TxEnvelope) -> Json:
    """
    Canon: TREASURY_WALLET_CREATE
    Allow user or system to create a named treasury wallet record (MVP storage only).
    """
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id") or payload.get("id")).strip()
    if not wallet_id:
        raise TreasuryApplyError("invalid_payload", "missing_wallet_id", {})

    wallets = _ensure_wallets(state)
    if wallet_id in wallets:
        raise TreasuryApplyError("conflict", "wallet_exists", {"wallet_id": wallet_id})

    wallets[wallet_id] = {
        "wallet_id": wallet_id,
        "created_by": _as_str(env.signer).strip(),
        "created_at_nonce": int(env.nonce),
        "signers": [],
        "policy": {},
        "meta": payload,
        "status": "open",
    }
    return {"applied": "TREASURY_WALLET_CREATE", "wallet_id": wallet_id}


def _apply_treasury_signer_add(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    signer = _as_str(payload.get("signer") or payload.get("account") or payload.get("account_id")).strip()
    if not wallet_id or not signer:
        raise TreasuryApplyError("invalid_payload", "missing_fields", {"wallet_id": wallet_id, "signer": signer})

    wallets = _ensure_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})

    signers = w.get("signers")
    if not isinstance(signers, list):
        signers = []
    if signer not in signers:
        signers.append(signer)
    w["signers"] = signers
    w["signer_last_updated_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "TREASURY_SIGNER_ADD", "wallet_id": wallet_id, "signer": signer}


def _apply_treasury_signer_remove(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    wallet_id = _as_str(payload.get("wallet_id") or payload.get("treasury_id")).strip()
    signer = _as_str(payload.get("signer") or payload.get("account") or payload.get("account_id")).strip()
    if not wallet_id or not signer:
        raise TreasuryApplyError("invalid_payload", "missing_fields", {"wallet_id": wallet_id, "signer": signer})

    wallets = _ensure_wallets(state)
    w = wallets.get(wallet_id)
    if not isinstance(w, dict):
        raise TreasuryApplyError("not_found", "wallet_not_found", {"wallet_id": wallet_id})

    signers = w.get("signers")
    if not isinstance(signers, list):
        signers = []
    w["signers"] = [s for s in signers if str(s).strip() != signer]
    w["signer_last_updated_at_nonce"] = int(env.nonce)
    wallets[wallet_id] = w
    return {"applied": "TREASURY_SIGNER_REMOVE", "wallet_id": wallet_id, "signer": signer}


def _apply_treasury_policy_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        policy = payload

    root = _ensure_treasury_policy(state)
    root.update(policy)
    root["set_at_nonce"] = int(env.nonce)
    return {"applied": "TREASURY_POLICY_SET"}


def _apply_treasury_spend_expire(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    spend_id = _as_str(payload.get("spend_id")).strip()
    if not spend_id:
        raise TreasuryApplyError("invalid_payload", "missing_spend_id", {})

    expired = _ensure_spends_expired(state)
    expired.append({"spend_id": spend_id, "at_nonce": int(env.nonce), "payload": payload})
    return {"applied": "TREASURY_SPEND_EXPIRE", "spend_id": spend_id}


# --- Program + audit canon coverage (already present) ---------------------


def _ensure_programs(state: Json) -> Json:
    root = state.get("treasury_programs")
    if not isinstance(root, dict):
        root = {}
        state["treasury_programs"] = root
    return root


def _apply_treasury_program_create(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    program_id = _as_str(payload.get("program_id")).strip()
    if not program_id:
        raise TreasuryApplyError("invalid_payload", "missing_program_id", {})
    programs = _ensure_programs(state)
    if program_id in programs:
        raise TreasuryApplyError("conflict", "program_already_exists", {"program_id": program_id})
    programs[program_id] = {
        "program_id": program_id,
        "status": "open",
        "created_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "TREASURY_PROGRAM_CREATE", "program_id": program_id}


def _apply_treasury_program_update(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    program_id = _as_str(payload.get("program_id")).strip()
    if not program_id:
        raise TreasuryApplyError("invalid_payload", "missing_program_id", {})
    programs = _ensure_programs(state)
    pr = programs.get(program_id)
    if not isinstance(pr, dict):
        raise TreasuryApplyError("not_found", "program_not_found", {"program_id": program_id})
    if _as_str(pr.get("status")) == "closed":
        raise TreasuryApplyError("forbidden", "program_closed", {"program_id": program_id})
    pr["updated_at_nonce"] = int(env.nonce)
    pr["payload"] = payload
    programs[program_id] = pr
    return {"applied": "TREASURY_PROGRAM_UPDATE", "program_id": program_id}


def _apply_treasury_program_close(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    program_id = _as_str(payload.get("program_id")).strip()
    if not program_id:
        raise TreasuryApplyError("invalid_payload", "missing_program_id", {})
    programs = _ensure_programs(state)
    pr = programs.get(program_id)
    if not isinstance(pr, dict):
        raise TreasuryApplyError("not_found", "program_not_found", {"program_id": program_id})
    if _as_str(pr.get("status")) == "closed":
        return {"applied": "TREASURY_PROGRAM_CLOSE", "program_id": program_id, "deduped": True}
    pr["status"] = "closed"
    pr["closed_at_nonce"] = int(env.nonce)
    programs[program_id] = pr
    return {"applied": "TREASURY_PROGRAM_CLOSE", "program_id": program_id}


def _ensure_audit_anchors(state: Json) -> List[Json]:
    root = state.get("treasury_audit_anchors")
    if not isinstance(root, list):
        root = []
        state["treasury_audit_anchors"] = root
    return root


def _apply_treasury_audit_anchor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    anchor = _as_str(payload.get("anchor") or payload.get("cid") or payload.get("hash")).strip()
    if not anchor:
        raise TreasuryApplyError("invalid_payload", "missing_anchor", {})
    anchors = _ensure_audit_anchors(state)
    anchors.append({"at_nonce": int(env.nonce), "anchor": anchor, "payload": payload})
    return {"applied": "TREASURY_AUDIT_ANCHOR_SET", "anchor": anchor}


TREASURY_TX_TYPES: Set[str] = {
    "TREASURY_PARAMS_SET",
    "TREASURY_SPEND_PROPOSE",
    "TREASURY_SPEND_SIGN",
    "TREASURY_SPEND_CANCEL",
    "TREASURY_SPEND_EXECUTE",
    "TREASURY_SPEND_EXPIRE",
    "TREASURY_WALLET_CREATE",
    "TREASURY_SIGNER_ADD",
    "TREASURY_SIGNER_REMOVE",
    "TREASURY_POLICY_SET",
    "TREASURY_PROGRAM_CREATE",
    "TREASURY_PROGRAM_UPDATE",
    "TREASURY_PROGRAM_CLOSE",
    "TREASURY_AUDIT_ANCHOR_SET",
}


def apply_treasury(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = _as_str(env.tx_type).strip().upper()
    if t not in TREASURY_TX_TYPES:
        return None

    if t == "TREASURY_PARAMS_SET":
        return _apply_treasury_params_set(state, env)
    if t == "TREASURY_SPEND_PROPOSE":
        return _apply_treasury_spend_propose(state, env)
    if t == "TREASURY_SPEND_SIGN":
        return _apply_treasury_spend_sign(state, env)
    if t == "TREASURY_SPEND_CANCEL":
        return _apply_treasury_spend_cancel(state, env)
    if t == "TREASURY_SPEND_EXECUTE":
        return _apply_treasury_spend_execute(state, env)

    if t == "TREASURY_SPEND_EXPIRE":
        return _apply_treasury_spend_expire(state, env)
    if t == "TREASURY_WALLET_CREATE":
        return _apply_treasury_wallet_create(state, env)
    if t == "TREASURY_SIGNER_ADD":
        return _apply_treasury_signer_add(state, env)
    if t == "TREASURY_SIGNER_REMOVE":
        return _apply_treasury_signer_remove(state, env)
    if t == "TREASURY_POLICY_SET":
        return _apply_treasury_policy_set(state, env)

    if t == "TREASURY_PROGRAM_CREATE":
        return _apply_treasury_program_create(state, env)
    if t == "TREASURY_PROGRAM_UPDATE":
        return _apply_treasury_program_update(state, env)
    if t == "TREASURY_PROGRAM_CLOSE":
        return _apply_treasury_program_close(state, env)
    if t == "TREASURY_AUDIT_ANCHOR_SET":
        return _apply_treasury_audit_anchor_set(state, env)

    return None


__all__ = ["TreasuryApplyError", "apply_treasury"]
