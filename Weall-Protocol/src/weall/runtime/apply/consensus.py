from __future__ import annotations

"""Consensus domain apply semantics.

This module implements:
- Validator lifecycle txs
- Block propose/attest/finalize receipts
- Epoch and slashing scaffolding

It publishes a stable "public surface" used by the executor + tests:
- state["validators"]["registry"]
- state["validators"]["last_heartbeat_ms"]
- state["roles"]["validators"]["active_set"]
- state["block_attestations"][block_id][validator] = {...}
- state["finalized"] = {"block_id": str|None, "height": int}
- state["slashing"] = {"proposals":{},"votes":{},"executions":{},"events":[]}

NOTE: This is still an MVP consensus implementation. The intent is:
- every canon tx type is *claimed* at apply-time (canon coverage)
- security-critical invariants (e.g. finality attestations) can be enforced
  at apply-time (fail-closed) via params.
"""

from dataclasses import dataclass
from typing import Any

from weall.ledger.roles_schema import canonicalize_account_set, ensure_roles_schema
from weall.runtime.apply.reputation import apply_reputation_delta_system
from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    normalize_consensus_phase,
)
from weall.runtime.bft_hotstuff import (
    validator_set_hash as _canonical_validator_set_hash,
)
from weall.runtime.proposer_selection import select_proposer
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class ConsensusApplyError(RuntimeError):
    code: str
    reason: str
    details: dict[str, Any]


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _ensure_root_dict(state: Json, key: str) -> Json:
    v = state.get(key)
    if not isinstance(v, dict):
        v = {}
        state[key] = v
    return v


def _get_params(state: Json) -> Json:
    p = state.get("params")
    return p if isinstance(p, dict) else {}


def _enforce_proposer(state: Json) -> bool:
    p = _get_params(state)
    v = p.get("enforce_proposer")
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _enforce_finality_attestations(state: Json) -> bool:
    """If enabled, BLOCK_FINALIZE apply enforces attestation threshold.

    Production default is True (fail-closed) if param is unset.
    Tests may explicitly set params.enforce_finality_attestations = False.
    """

    p = _get_params(state)
    v = p.get("enforce_finality_attestations")
    if isinstance(v, bool):
        return v
    if v is None:
        return True
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _blocks_per_epoch(state: Json) -> int:
    p = _get_params(state)
    bpe = p.get("blocks_per_epoch")
    try:
        v = int(bpe)
    except Exception:
        v = 0
    return v if v > 0 else 0


def _chain_id(state: Json) -> str:
    p = _get_params(state)
    cid = p.get("chain_id")
    return _as_str(cid) or "weall"


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise ConsensusApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_consensus(state: Json) -> Json:
    c = _ensure_root_dict(state, "consensus")
    for k in (
        "validators_by_account",
        "validators",
        "validator_set",
        "blocks_by_id",
        "epochs",
        "slashes_by_id",
        "attestations_by_validator",
        "proposer_by_height",
    ):
        if not isinstance(c.get(k), dict):
            c[k] = {}

    validators = c.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        c["validators"] = validators
    if not isinstance(validators.get("registry"), dict):
        validators["registry"] = {}
    c["validators"] = validators

    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {}
        c["epochs"] = ep
    ep.setdefault("current", 0)
    ep.setdefault("events", [])
    c["epochs"] = ep

    phase = c.get("phase")
    if not isinstance(phase, dict):
        phase = {}
    current_vs = c.get("validator_set") if isinstance(c.get("validator_set"), dict) else {}
    active_count = len(_as_list(current_vs.get("active_set")))
    phase["current"] = normalize_consensus_phase(phase.get("current"), validator_count=active_count)
    if not isinstance(phase.get("history"), list):
        phase["history"] = []
    pending_phase = phase.get("pending")
    if pending_phase is not None and not isinstance(pending_phase, dict):
        phase["pending"] = None
    c["phase"] = phase

    return c


def _ensure_validators_root(state: Json) -> Json:
    v = _ensure_root_dict(state, "validators")
    if not isinstance(v.get("registry"), dict):
        v["registry"] = {}
    if not isinstance(v.get("last_heartbeat_ms"), dict):
        v["last_heartbeat_ms"] = {}
    if not isinstance(v.get("performance_reports"), list):
        v["performance_reports"] = []
    return v


def _ensure_slashing_root(state: Json) -> Json:
    sl = state.get("slashing")
    if not isinstance(sl, dict):
        sl = {}
        state["slashing"] = sl
    if not isinstance(sl.get("proposals"), dict):
        sl["proposals"] = {}
    if not isinstance(sl.get("votes"), dict):
        sl["votes"] = {}
    if not isinstance(sl.get("executions"), dict):
        sl["executions"] = {}
    if not isinstance(sl.get("events"), list):
        sl["events"] = []
    return sl


def _ensure_roles_validators_active_set(state: Json) -> list[str]:
    ensure_roles_schema(state)
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators

    out = canonicalize_account_set(validators.get("active_set"))
    validators["active_set"] = out
    return out


def _set_active_set(state: Json, accounts: list[str]) -> None:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators

    validators["active_set"] = canonicalize_account_set(accounts)


def _phase_root(state: Json) -> Json:
    c = _ensure_consensus(state)
    phase = c.get("phase")
    if not isinstance(phase, dict):
        phase = {}
        c["phase"] = phase
    if not isinstance(phase.get("history"), list):
        phase["history"] = []
    phase["current"] = normalize_consensus_phase(
        phase.get("current"), validator_count=len(_ensure_roles_validators_active_set(state))
    )
    if phase.get("pending") is not None and not isinstance(phase.get("pending"), dict):
        phase["pending"] = None
    return phase


def _phase_for_active_set(active_set: list[str], *, bft_requested: bool = False) -> str:
    normalized_count = len([_as_str(x) for x in active_set if _as_str(x)])
    if bft_requested:
        if normalized_count < int(BFT_MIN_VALIDATORS):
            raise ConsensusApplyError(
                "invalid_payload",
                "bft_activation_requires_minimum_validator_count",
                {"validator_count": int(normalized_count), "minimum": int(BFT_MIN_VALIDATORS)},
            )
        return CONSENSUS_PHASE_BFT_ACTIVE
    return normalize_consensus_phase("", validator_count=normalized_count)


def _record_phase_transition(
    state: Json, *, new_phase: str, activation_epoch: int, validator_set_hash: str, reason: str
) -> None:
    phase = _phase_root(state)
    current = normalize_consensus_phase(
        phase.get("current"), validator_count=len(_ensure_roles_validators_active_set(state))
    )
    next_phase = normalize_consensus_phase(
        new_phase, validator_count=len(_ensure_roles_validators_active_set(state))
    )
    phase["current"] = next_phase
    if current != next_phase:
        history = phase.get("history")
        assert isinstance(history, list)
        history.append(
            {
                "from": current,
                "to": next_phase,
                "activation_epoch": int(activation_epoch),
                "validator_set_hash": _as_str(validator_set_hash or ""),
                "reason": _as_str(reason or ""),
            }
        )
        phase["history"] = history
    c = _ensure_consensus(state)
    c["phase"] = phase


# ------------------- Validators -------------------


def _ensure_consensus_validator_registry(state: Json) -> Json:
    c = _ensure_consensus(state)
    validators = c.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        c["validators"] = validators
    reg = validators.get("registry")
    if not isinstance(reg, dict):
        reg = {}
        validators["registry"] = reg
    return reg


def _registry_record(state: Json, account: str) -> Json:
    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)
    rec = reg.get(account)
    if not isinstance(rec, dict):
        rec = {"account": account}
        reg[account] = rec
    return rec


def _sync_validator_registry_membership(state: Json) -> None:
    active = set(_ensure_roles_validators_active_set(state))
    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)
    creg = _ensure_consensus_validator_registry(state)
    c = _ensure_consensus(state)
    vs = c.get("validator_set") if isinstance(c.get("validator_set"), dict) else {}
    current_epoch = _as_int(vs.get("epoch"), 0)
    for account, rec in list(reg.items()):
        if not isinstance(rec, dict):
            rec = {"account": str(account).strip()}
        acct = _as_str(rec.get("account") or account)
        if not acct:
            continue
        approved_epoch = _as_int(rec.get("approved_activation_epoch"), 0)
        if acct in active:
            rec["active"] = True
            rec["status"] = "active"
            if approved_epoch > 0 and not rec.get("effective_epoch"):
                rec["effective_epoch"] = int(approved_epoch)
        else:
            rec["active"] = False
            status = _as_str(rec.get("status") or "")
            effective_epoch = _as_int(rec.get("effective_epoch"), 0)
            if status == "pending_activation" and approved_epoch > 0 and current_epoch >= approved_epoch:
                rec["status"] = "observer"
            elif status == "pending_suspension" and effective_epoch > 0 and current_epoch >= effective_epoch:
                rec["status"] = "suspended"
            elif status == "pending_removal" and effective_epoch > 0 and current_epoch >= effective_epoch:
                rec["status"] = "removed"
            elif not status:
                rec["status"] = "observer"
        reg[acct] = rec
        pk = _as_str(rec.get("pubkey") or "")
        if pk:
            crec = creg.get(acct) if isinstance(creg.get(acct), dict) else {}
            crec["pubkey"] = pk
            creg[acct] = crec
    vroot["registry"] = reg


def _validator_registry_lifecycle_record(state: Json, account: str) -> Json:
    rec = _registry_record(state, account)
    rec["account"] = account
    rec.setdefault("status", "observer")
    rec.setdefault("active", False)
    return rec


def _apply_validator_register(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account") or env.signer)
    pubkey = _as_str(payload.get("pubkey"))

    # Consensus membership must not be mutable by ordinary user-origin txs.
    _require_system_env(env)

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if not pubkey:
        raise ConsensusApplyError("invalid_payload", "missing_pubkey", {"tx_type": env.tx_type})

    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)

    existed = account in reg
    prior = reg.get(account) if isinstance(reg.get(account), dict) else {}
    reg[account] = {
        "account": account,
        "pubkey": pubkey,
        "node_id": _as_str(payload.get("node_id") or prior.get("node_id") or ""),
        "endpoints": list(payload.get("endpoints")) if isinstance(payload.get("endpoints"), list) else ([] if not _as_str(payload.get("endpoint")) else [_as_str(payload.get("endpoint"))]),
        # Registration alone must not activate consensus power. Activation is
        # handled separately via deterministic validator-set updates.
        "status": _as_str(prior.get("status") or "observer") or "observer",
        "active": bool(prior.get("active", False)),
        "approved_activation_epoch": _as_int(prior.get("approved_activation_epoch"), 0) or None,
        "effective_epoch": _as_int(prior.get("effective_epoch"), 0) or None,
    }
    vroot["registry"] = reg
    creg = _ensure_consensus_validator_registry(state)
    crec = creg.get(account) if isinstance(creg.get(account), dict) else {}
    crec["pubkey"] = pubkey
    creg[account] = crec

    return {
        "applied": "VALIDATOR_REGISTER",
        "account": account,
        "existed": existed,
        "status": _as_str(reg[account].get("status") or "observer"),
        "active": bool(reg[account].get("active", False)),
    }


def _apply_validator_candidate_register(state: Json, env: TxEnvelope) -> Json:
    _ensure_roles_validators_active_set(state)
    payload = _as_dict(env.payload)
    account = _as_str(env.signer)
    pubkey = _as_str(payload.get("pubkey"))
    node_id = _as_str(payload.get("node_id"))
    endpoints_raw = payload.get("endpoints")
    endpoint = _as_str(payload.get("endpoint"))
    endpoints = [_as_str(x) for x in endpoints_raw if _as_str(x)] if isinstance(endpoints_raw, list) else ([] if not endpoint else [endpoint])
    metadata_hash = _as_str(payload.get("metadata_hash"))

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_signer_account", {"tx_type": env.tx_type})
    if not pubkey:
        raise ConsensusApplyError("invalid_payload", "missing_pubkey", {"tx_type": env.tx_type})
    if not node_id:
        raise ConsensusApplyError("invalid_payload", "missing_node_id", {"tx_type": env.tx_type})
    if not endpoints:
        raise ConsensusApplyError("invalid_payload", "missing_endpoints", {"tx_type": env.tx_type})

    rec = _validator_registry_lifecycle_record(state, account)
    status = _as_str(rec.get("status") or "observer")
    if status in {"pending_activation", "active", "suspended"} and _as_str(rec.get("pubkey") or pubkey) != pubkey:
        raise ConsensusApplyError(
            "forbidden",
            "validator_record_conflict",
            {"account": account, "existing_status": status},
        )

    rec["pubkey"] = pubkey
    rec["node_id"] = node_id
    rec["endpoints"] = endpoints
    rec["metadata_hash"] = metadata_hash
    rec["registered_tx_id"] = _as_str(getattr(env, "txid", None) or "")
    rec["registered_at_height"] = _as_int(state.get("height"), 0)
    rec["poh_tier_snapshot"] = 3
    if status not in {"pending_activation", "active", "suspended"}:
        rec["status"] = "candidate"
    rec["active"] = False

    creg = _ensure_consensus_validator_registry(state)
    crec = creg.get(account) if isinstance(creg.get(account), dict) else {}
    crec["pubkey"] = pubkey
    creg[account] = crec

    return {
        "applied": "VALIDATOR_CANDIDATE_REGISTER",
        "account": account,
        "status": _as_str(rec.get("status") or "candidate"),
        "node_id": node_id,
        "endpoints": list(endpoints),
    }


def _apply_validator_candidate_approve(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account"))
    activate_at_epoch = _as_int(payload.get("activate_at_epoch"), 0)
    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if activate_at_epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_activate_at_epoch", {"tx_type": env.tx_type})

    rec = _validator_registry_lifecycle_record(state, account)
    pubkey = _as_str(rec.get("pubkey") or payload.get("pubkey") or "")
    if not pubkey:
        raise ConsensusApplyError("invalid_payload", "candidate_missing_pubkey", {"account": account})
    status = _as_str(rec.get("status") or "")
    if status not in {"candidate", "observer", "pending_activation"}:
        raise ConsensusApplyError("forbidden", "validator_not_candidate", {"account": account, "status": status})

    current_active = canonicalize_account_set(_ensure_roles_validators_active_set(state) + [account])
    set_hash = _set_pending_validator_set(
        state,
        active_set=current_active,
        activate_at_epoch=int(activate_at_epoch),
    )
    rec["status"] = "pending_activation"
    rec["approved_activation_epoch"] = int(activate_at_epoch)
    rec["requested_activation_epoch"] = int(activate_at_epoch)
    rec["effective_epoch"] = int(activate_at_epoch)
    rec["active"] = False

    creg = _ensure_consensus_validator_registry(state)
    crec = creg.get(account) if isinstance(creg.get(account), dict) else {}
    crec["pubkey"] = pubkey
    creg[account] = crec

    return {
        "applied": "VALIDATOR_CANDIDATE_APPROVE",
        "account": account,
        "status": "pending_activation",
        "activate_at_epoch": int(activate_at_epoch),
        "validator_set_hash": str(set_hash),
    }


def _apply_validator_suspend(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account"))
    effective_epoch = _as_int(payload.get("effective_epoch"), 0)
    reason = _as_str(payload.get("reason"))
    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if effective_epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_effective_epoch", {"tx_type": env.tx_type})

    rec = _validator_registry_lifecycle_record(state, account)
    rec["suspension"] = {
        "reason": reason,
        "effective_epoch": int(effective_epoch),
    }
    current_active = _ensure_roles_validators_active_set(state)
    if account not in current_active:
        rec["status"] = "suspended"
        rec["active"] = False
        rec["effective_epoch"] = int(effective_epoch)
        return {
            "applied": "VALIDATOR_SUSPEND",
            "account": account,
            "status": "suspended",
            "effective_epoch": int(effective_epoch),
        }

    next_active = canonicalize_account_set([acct for acct in current_active if _as_str(acct) != account])
    set_hash = _set_pending_validator_set(
        state,
        active_set=next_active,
        activate_at_epoch=int(effective_epoch),
    )
    rec["status"] = "pending_suspension"
    rec["active"] = True
    rec["effective_epoch"] = int(effective_epoch)
    return {
        "applied": "VALIDATOR_SUSPEND",
        "account": account,
        "status": "pending_suspension",
        "effective_epoch": int(effective_epoch),
        "validator_set_hash": str(set_hash),
    }


def _apply_validator_remove(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account"))
    effective_epoch = _as_int(payload.get("effective_epoch"), 0)
    reason = _as_str(payload.get("reason"))
    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if effective_epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_effective_epoch", {"tx_type": env.tx_type})

    rec = _validator_registry_lifecycle_record(state, account)
    rec["removal"] = {
        "reason": reason,
        "effective_epoch": int(effective_epoch),
    }
    current_active = _ensure_roles_validators_active_set(state)
    if account not in current_active:
        rec["status"] = "removed"
        rec["active"] = False
        rec["effective_epoch"] = int(effective_epoch)
        return {
            "applied": "VALIDATOR_REMOVE",
            "account": account,
            "status": "removed",
            "effective_epoch": int(effective_epoch),
        }

    next_active = canonicalize_account_set([acct for acct in current_active if _as_str(acct) != account])
    set_hash = _set_pending_validator_set(
        state,
        active_set=next_active,
        activate_at_epoch=int(effective_epoch),
    )
    rec["status"] = "pending_removal"
    rec["active"] = True
    rec["effective_epoch"] = int(effective_epoch)
    return {
        "applied": "VALIDATOR_REMOVE",
        "account": account,
        "status": "pending_removal",
        "effective_epoch": int(effective_epoch),
        "validator_set_hash": str(set_hash),
    }


def _apply_validator_deregister(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    # Production invariant: deregister must be explicit and self-authored.
    account = _as_str(payload.get("account"))

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if _as_str(env.signer) and account != _as_str(env.signer):
        raise ConsensusApplyError(
            "forbidden",
            "account_must_match_signer",
            {"tx_type": env.tx_type, "account": account, "signer": _as_str(env.signer)},
        )

    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)

    existed = account in reg
    if account in reg:
        rec = reg.get(account)
        if isinstance(rec, dict):
            rec["active"] = False
            rec["status"] = "removed"
            reg[account] = rec

    vroot["registry"] = reg

    active = _ensure_roles_validators_active_set(state)
    if account in active:
        active = [x for x in active if _as_str(x) != account]
        _set_active_set(state, active)

    return {"applied": "VALIDATOR_DEREGISTER", "account": account, "existed": existed}


def _validator_set_hash(accounts: list[str]) -> str:
    return _canonical_validator_set_hash([str(x).strip() for x in accounts if str(x).strip()])


def _bump_validator_epoch(state: Json, active_set: list[str]) -> None:
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    if not isinstance(vs, dict):
        vs = {}
    epoch = _as_int(vs.get("epoch"), 0) + 1
    vs["epoch"] = int(epoch)
    vs["active_set"] = canonicalize_account_set(active_set)
    vs["set_hash"] = _validator_set_hash(active_set)
    pending = vs.get("pending")
    if isinstance(pending, dict):
        cur_epoch = _as_int(vs.get("epoch"), 0)
        act_epoch = _as_int(pending.get("activate_at_epoch"), 0)
        if act_epoch > 0 and act_epoch <= cur_epoch:
            vs.pop("pending", None)
    c["validator_set"] = vs
    _sync_validator_registry_membership(state)


def _set_pending_validator_set(
    state: Json,
    *,
    active_set: list[str],
    activate_at_epoch: int,
    pending_phase: str = "",
) -> str:
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    if not isinstance(vs, dict):
        vs = {}
    canonical_active_set = canonicalize_account_set(active_set)
    set_hash = _validator_set_hash(canonical_active_set)
    phase_name = (
        normalize_consensus_phase(pending_phase, validator_count=len(canonical_active_set))
        if _as_str(pending_phase)
        else ""
    )
    pending = vs.get("pending")
    if isinstance(pending, dict):
        pending_epoch = _as_int(pending.get("activate_at_epoch"), 0)
        pending_hash = _as_str(pending.get("set_hash") or "")
        existing_phase = (
            normalize_consensus_phase(
                pending.get("phase"), validator_count=len(canonical_active_set)
            )
            if _as_str(pending.get("phase"))
            else ""
        )
        if pending_epoch == int(activate_at_epoch) and pending_hash == set_hash:
            if existing_phase == phase_name:
                return set_hash
            raise ConsensusApplyError(
                "invalid_payload",
                "validator_set_pending_phase_conflict",
                {
                    "existing_activate_at_epoch": int(pending_epoch),
                    "existing_validator_set_hash": pending_hash,
                    "existing_consensus_phase": existing_phase,
                    "activate_at_epoch": int(activate_at_epoch),
                    "validator_set_hash": set_hash,
                    "consensus_phase": phase_name,
                },
            )
        raise ConsensusApplyError(
            "invalid_payload",
            "validator_set_pending_update_exists",
            {
                "existing_activate_at_epoch": int(pending_epoch),
                "existing_validator_set_hash": pending_hash,
                "existing_consensus_phase": existing_phase,
                "activate_at_epoch": int(activate_at_epoch),
                "validator_set_hash": set_hash,
                "consensus_phase": phase_name,
            },
        )
    vs["pending"] = {
        "active_set": list(canonical_active_set),
        "activate_at_epoch": int(activate_at_epoch),
        "set_hash": set_hash,
    }
    if phase_name:
        vs["pending"]["phase"] = phase_name
    c["validator_set"] = vs
    pending_accounts = set(canonical_active_set)
    reg = _ensure_validators_root(state).get("registry")
    assert isinstance(reg, dict)
    current_active = set(_ensure_roles_validators_active_set(state))
    for acct in pending_accounts - current_active:
        rec = _validator_registry_lifecycle_record(state, acct)
        if _as_str(rec.get("status") or "") not in {"active", "suspended", "removed"}:
            rec["status"] = "pending_activation"
        rec["approved_activation_epoch"] = int(activate_at_epoch)
        rec["effective_epoch"] = int(activate_at_epoch)
        rec["active"] = False
    return set_hash


def _activate_pending_validator_set_for_epoch(state: Json, epoch: int) -> Json | None:
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    if not isinstance(vs, dict):
        return None
    pending = vs.get("pending")
    if not isinstance(pending, dict):
        return None
    act_epoch = _as_int(pending.get("activate_at_epoch"), 0)
    if act_epoch <= 0 or int(epoch) != act_epoch:
        return None
    out = canonicalize_account_set(pending.get("active_set"))
    _set_active_set(state, out)
    _bump_validator_epoch(state, out)
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    assert isinstance(vs, dict)
    pending_phase = (
        normalize_consensus_phase(pending.get("phase"), validator_count=len(out))
        if _as_str(pending.get("phase"))
        else _phase_for_active_set(out)
    )
    vs.pop("pending", None)
    c["validator_set"] = vs
    _record_phase_transition(
        state,
        new_phase=pending_phase,
        activation_epoch=int(act_epoch),
        validator_set_hash=_as_str(vs.get("set_hash") or ""),
        reason="validator_set_activation",
    )
    return {
        "active_set": out,
        "validator_epoch": int(vs.get("epoch") or 0),
        "validator_set_hash": _as_str(vs.get("set_hash") or ""),
        "activate_at_epoch": int(act_epoch),
        "consensus_phase": pending_phase,
    }


def _apply_validator_set_update(state: Json, env: TxEnvelope) -> Json:
    # Receipt-only, system-origin in canon.
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError(
            "forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type}
        )

    payload = _as_dict(env.payload)
    out = canonicalize_account_set(payload.get("active_set"))

    activate_at_epoch = _as_int(payload.get("activate_at_epoch"), 0)
    activate_bft_at_epoch = _as_int(payload.get("activate_bft_at_epoch"), 0)
    current_epoch = _as_int(_ensure_consensus(state).get("epochs", {}).get("current"), 0)
    pending_phase = ""
    if activate_bft_at_epoch > 0:
        if activate_at_epoch <= 0:
            activate_at_epoch = int(activate_bft_at_epoch)
        if int(activate_bft_at_epoch) != int(activate_at_epoch):
            raise ConsensusApplyError(
                "invalid_payload",
                "activate_bft_at_epoch_must_match_activate_at_epoch",
                {
                    "activate_at_epoch": int(activate_at_epoch),
                    "activate_bft_at_epoch": int(activate_bft_at_epoch),
                },
            )
        pending_phase = _phase_for_active_set(out, bft_requested=True)
    if activate_at_epoch > 0:
        if int(current_epoch) > 0 and int(activate_at_epoch) <= int(current_epoch):
            raise ConsensusApplyError(
                "invalid_payload",
                "validator_set_activate_at_epoch_must_be_future",
                {"activate_at_epoch": int(activate_at_epoch), "current_epoch": int(current_epoch)},
            )
        set_hash = _set_pending_validator_set(
            state,
            active_set=out,
            activate_at_epoch=int(activate_at_epoch),
            pending_phase=pending_phase,
        )
        out_meta = {
            "applied": "VALIDATOR_SET_UPDATE",
            "active_set": out,
            "pending": True,
            "activate_at_epoch": int(activate_at_epoch),
            "validator_set_hash": str(set_hash),
        }
        if pending_phase:
            out_meta["consensus_phase"] = pending_phase
        return out_meta

    _set_active_set(state, out)
    _bump_validator_epoch(state, out)
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    assert isinstance(vs, dict)
    consensus_phase = _phase_for_active_set(out)
    _record_phase_transition(
        state,
        new_phase=consensus_phase,
        activation_epoch=int(vs.get("epoch") or 0),
        validator_set_hash=_as_str(vs.get("set_hash") or ""),
        reason="validator_set_update",
    )

    return {
        "applied": "VALIDATOR_SET_UPDATE",
        "active_set": out,
        "validator_epoch": int(vs.get("epoch") or 0),
        "validator_set_hash": _as_str(vs.get("set_hash") or ""),
        "consensus_phase": consensus_phase,
    }


def _apply_validator_heartbeat(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    # Production invariant: heartbeat must be explicit and self-authored.
    account = _as_str(payload.get("account"))
    ts_ms = _as_int(payload.get("ts_ms"), 0)

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if _as_str(env.signer) and account != _as_str(env.signer):
        raise ConsensusApplyError(
            "forbidden",
            "account_must_match_signer",
            {"tx_type": env.tx_type, "account": account, "signer": _as_str(env.signer)},
        )
    if ts_ms <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_ts_ms", {"tx_type": env.tx_type})

    vroot = _ensure_validators_root(state)
    hb = vroot.get("last_heartbeat_ms")
    assert isinstance(hb, dict)
    hb[account] = int(ts_ms)
    vroot["last_heartbeat_ms"] = hb

    return {"applied": "VALIDATOR_HEARTBEAT", "account": account, "ts_ms": int(ts_ms)}


def _apply_validator_performance_report(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account") or payload.get("validator") or env.signer)
    ts_ms = _as_int(payload.get("ts_ms"), 0)
    report = _as_dict(payload.get("report")) if "report" in payload else {}

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})

    vroot = _ensure_validators_root(state)
    reports = vroot.get("performance_reports")
    assert isinstance(reports, list)

    rec = {
        "account": account,
        "ts_ms": int(ts_ms) if ts_ms else None,
        "report": report,
        "payload": payload,
    }
    reports.append(rec)
    vroot["performance_reports"] = reports

    return {"applied": "VALIDATOR_PERFORMANCE_REPORT", "account": account}


# ------------------- Blocks / Attestations -------------------


def _ensure_block_attestations(state: Json) -> Json:
    ba = state.get("block_attestations")
    if not isinstance(ba, dict):
        ba = {}
        state["block_attestations"] = ba
    return ba


def _ensure_finalized(state: Json) -> Json:
    f = state.get("finalized")
    if not isinstance(f, dict):
        f = {"block_id": None, "height": 0}
        state["finalized"] = f
    if "block_id" not in f:
        f["block_id"] = None
    if "height" not in f:
        f["height"] = 0
    return f


def _apply_block_propose(state: Json, env: TxEnvelope) -> Json:
    # BLOCK_PROPOSE can be applied in both user-tx and system-receipt contexts.
    # In user context, env.parent is optional.

    payload = _as_dict(env.payload)
    block_id = _as_str(payload.get("block_id") or payload.get("id"))
    height = _as_int(payload.get("height"), 0)
    proposer = _as_str(payload.get("proposer") or env.signer)

    if not block_id:
        raise ConsensusApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})
    if height <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_height", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    blocks = c.get("blocks_by_id")
    assert isinstance(blocks, dict)

    existed = block_id in blocks
    blocks[block_id] = {
        "block_id": block_id,
        "height": int(height),
        "proposer": proposer,
        "payload": payload,
        "parent": _as_str(env.parent),
    }
    c["blocks_by_id"] = blocks

    # Optionally enforce deterministic proposer selection if enabled.
    if _enforce_proposer(state):
        active = _ensure_roles_validators_active_set(state)
        expected = select_proposer(active, height=int(height), chain_id=_chain_id(state))
        if expected and proposer and proposer != expected:
            raise ConsensusApplyError(
                "invalid_block",
                "bad_proposer",
                {
                    "expected": expected,
                    "got": proposer,
                    "height": int(height),
                    "block_id": block_id,
                },
            )

    return {
        "applied": "BLOCK_PROPOSE",
        "block_id": block_id,
        "height": int(height),
        "existed": existed,
    }


def _apply_block_attest(state: Json, env: TxEnvelope) -> Json:
    # BLOCK_ATTEST is a validator action (user tx). It may also appear as a system receipt.
    # Parent is optional at apply-layer.

    payload = _as_dict(env.payload)
    block_id = _as_str(payload.get("block_id") or payload.get("id"))
    validator = _as_str(payload.get("validator") or env.signer)
    att = _as_str(payload.get("attestation") or payload.get("vote") or "yes")

    height = _as_int(payload.get("height"), 0)
    rnd = _as_int(payload.get("round"), 0)

    if not block_id:
        raise ConsensusApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})
    if not validator:
        raise ConsensusApplyError("invalid_payload", "missing_validator", {"tx_type": env.tx_type})

    # Equivocation detection: a validator must not attest two different blocks
    # for the same (height, round). This is protocol-provable and can be punished.
    if height > 0:
        c = _ensure_consensus(state)
        av = c.get("attestations_by_validator")
        assert isinstance(av, dict)

        per_v = av.get(validator)
        if not isinstance(per_v, dict):
            per_v = {}
        key = f"{int(height)}:{int(rnd)}"
        prior = per_v.get(key)
        if isinstance(prior, str) and prior and prior != block_id:
            sid = f"equivocation:{validator}:{int(height)}:{int(rnd)}"
            sl = _ensure_slashing_root(state)
            execs = sl.get("executions")
            assert isinstance(execs, dict)

            if sid not in execs:
                execs[sid] = {
                    "slash_id": sid,
                    "type": "equivocation",
                    "validator": validator,
                    "height": int(height),
                    "round": int(rnd),
                    "block_id_1": prior,
                    "block_id_2": block_id,
                    "at_nonce": int(env.nonce),
                    "payload": payload,
                }
                ev = sl.get("events")
                assert isinstance(ev, list)
                ev.append({"tx_type": "SLASH_EXECUTE", "slash_id": sid, "type": "equivocation"})
                sl["events"] = ev
                sl["executions"] = execs

                # Executor boundary: also queue an explicit SYSTEM receipt for SLASH_EXECUTE.
                # This does not replace the immediate recording above (tests rely on it),
                # but provides a clean production path for the block/system phase.
                due = (
                    int(height) + 1 if int(height) > 0 else int(_as_int(state.get("height"), 0)) + 1
                )
                if due <= 0:
                    due = 1
                enqueue_system_tx(
                    state,
                    tx_type="SLASH_EXECUTE",
                    payload={
                        "slash_id": sid,
                        "account": validator,
                        "reason": "equivocation",
                        "height": int(height),
                        "round": int(rnd),
                        "block_id_1": prior,
                        "block_id_2": block_id,
                    },
                    due_height=int(due),
                    signer="SYSTEM",
                    once=True,
                    parent=sid,
                    phase="post",
                )

                apply_reputation_delta_system(
                    state,
                    account_id=validator,
                    delta=-25.0,
                    reason="equivocation",
                    evidence={
                        "source": "consensus",
                        "event": "EQUIVOCATION",
                        "slash_id": sid,
                        "payload": payload,
                    },
                    at_nonce=int(env.nonce),
                )
        else:
            per_v[key] = block_id
            av[validator] = per_v
            c["attestations_by_validator"] = av

    ba = _ensure_block_attestations(state)
    per = ba.get(block_id)
    if not isinstance(per, dict):
        per = {}
    existed = validator in per
    per[validator] = {
        "validator": validator,
        "attestation": att,
        "payload": payload,
        "parent": _as_str(env.parent),
    }
    ba[block_id] = per

    return {
        "applied": "BLOCK_ATTEST",
        "block_id": block_id,
        "validator": validator,
        "existed": existed,
    }


def _apply_block_finalize(state: Json, env: TxEnvelope) -> Json:
    # Receipt-only, system-origin in canon, but can be applied in tests.
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError(
            "forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type}
        )

    payload = _as_dict(env.payload)
    block_id = _as_str(payload.get("block_id") or payload.get("id"))
    height = _as_int(payload.get("height"), 0)

    if not block_id:
        raise ConsensusApplyError("invalid_payload", "missing_block_id", {"tx_type": env.tx_type})
    if height <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_height", {"tx_type": env.tx_type})

    if _enforce_finality_attestations(state):
        ba = _ensure_block_attestations(state)
        per = ba.get(block_id)
        if not isinstance(per, dict):
            raise ConsensusApplyError(
                "invalid_block", "missing_attestations", {"block_id": block_id}
            )

        active = _ensure_roles_validators_active_set(state)
        if len(active) == 0:
            raise ConsensusApplyError("invalid_block", "no_active_validators", {})

        yes = 0
        for v in active:
            rec = per.get(v)
            if isinstance(rec, dict) and _as_str(rec.get("attestation")).lower() in (
                "yes",
                "y",
                "true",
                "1",
            ):
                yes += 1

        # Very simple threshold for MVP: > 2/3.
        needed = (2 * len(active)) // 3 + 1
        if yes < needed:
            raise ConsensusApplyError(
                "invalid_block",
                "finality_threshold_not_met",
                {"yes": yes, "needed": needed, "active": len(active), "block_id": block_id},
            )

    f = _ensure_finalized(state)
    existed = _as_str(f.get("block_id")) == block_id
    f["block_id"] = block_id
    f["height"] = int(height)
    state["finalized"] = f

    # Epoch queueing (deterministic):
    # - After finalizing height 1, open epoch 1 at due height 2
    # - After every blocks_per_epoch finalizations, close/open epoch at due height (height+1)
    bpe = _blocks_per_epoch(state)
    if int(height) == 1:
        enqueue_system_tx(
            state, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=2, phase="post"
        )

    if bpe > 0 and int(height) > 0 and int(height) % int(bpe) == 0:
        c = _ensure_consensus(state)
        ep = c.get("epochs")
        if not isinstance(ep, dict):
            ep = {"current": 0, "events": []}
        cur_epoch = _as_int(ep.get("current"), 0) or 1
        due = int(height) + 1
        enqueue_system_tx(
            state, tx_type="EPOCH_CLOSE", payload={"epoch": cur_epoch}, due_height=due, phase="post"
        )
        enqueue_system_tx(
            state,
            tx_type="EPOCH_OPEN",
            payload={"epoch": cur_epoch + 1},
            due_height=due,
            phase="post",
        )

    return {
        "applied": "BLOCK_FINALIZE",
        "block_id": block_id,
        "height": int(height),
        "existed": existed,
    }


# ------------------- Epochs -------------------


def _epoch_events(ep: Json) -> list[Json]:
    events = ep.get("events")
    return list(events) if isinstance(events, list) else []


def _epoch_has_event(ep: Json, *, epoch: int, event: str) -> bool:
    want_epoch = int(epoch)
    want_event = str(event).strip().lower()
    for item in _epoch_events(ep):
        if not isinstance(item, dict):
            continue
        if _as_int(item.get("epoch"), 0) != want_epoch:
            continue
        if str(item.get("event") or "").strip().lower() == want_event:
            return True
    return False


def _apply_epoch_open(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch = _as_int(payload.get("epoch"), 0)
    if epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_epoch", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    validators = c.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        c["validators"] = validators
    if not isinstance(validators.get("registry"), dict):
        validators["registry"] = {}
    c["validators"] = validators

    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {"current": 0, "events": []}

    current_epoch = _as_int(ep.get("current"), 0)
    expected_epoch = 1 if current_epoch <= 0 else current_epoch + 1
    if int(epoch) != int(expected_epoch):
        raise ConsensusApplyError(
            "invalid_payload",
            "epoch_open_must_advance_sequentially",
            {
                "epoch": int(epoch),
                "current_epoch": int(current_epoch),
                "expected_epoch": int(expected_epoch),
            },
        )
    if current_epoch > 0 and not _epoch_has_event(ep, epoch=current_epoch, event="close"):
        raise ConsensusApplyError(
            "invalid_payload",
            "epoch_open_requires_previous_epoch_close",
            {"epoch": int(epoch), "current_epoch": int(current_epoch)},
        )
    if _epoch_has_event(ep, epoch=epoch, event="open"):
        raise ConsensusApplyError(
            "invalid_payload",
            "epoch_already_open",
            {"epoch": int(epoch)},
        )

    vs = c.get("validator_set")
    if isinstance(vs, dict):
        pending = vs.get("pending")
        if isinstance(pending, dict):
            pending_epoch = _as_int(pending.get("activate_at_epoch"), 0)
            if pending_epoch > 0 and int(epoch) > int(pending_epoch):
                raise ConsensusApplyError(
                    "invalid_payload",
                    "epoch_open_skips_pending_validator_set_activation",
                    {"epoch": int(epoch), "activate_at_epoch": int(pending_epoch)},
                )

    ep["current"] = int(epoch)
    events = _epoch_events(ep)
    events.append({"event": "open", "epoch": int(epoch)})
    ep["events"] = events

    c["epochs"] = ep
    out = {"applied": "EPOCH_OPEN", "epoch": int(epoch)}
    pending_meta = _activate_pending_validator_set_for_epoch(state, int(epoch))
    if isinstance(pending_meta, dict):
        out["validator_set_activated"] = pending_meta
    return out


def _apply_epoch_close(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch = _as_int(payload.get("epoch"), 0)
    if epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_epoch", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    validators = c.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        c["validators"] = validators
    if not isinstance(validators.get("registry"), dict):
        validators["registry"] = {}
    c["validators"] = validators

    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {"current": 0, "events": []}

    current_epoch = _as_int(ep.get("current"), 0)
    if current_epoch <= 0 or int(epoch) != int(current_epoch):
        raise ConsensusApplyError(
            "invalid_payload",
            "epoch_close_must_match_current_epoch",
            {"epoch": int(epoch), "current_epoch": int(current_epoch)},
        )
    if _epoch_has_event(ep, epoch=epoch, event="close"):
        raise ConsensusApplyError(
            "invalid_payload",
            "epoch_already_closed",
            {"epoch": int(epoch)},
        )

    events = _epoch_events(ep)
    events.append({"event": "close", "epoch": int(epoch)})
    ep["events"] = events

    c["epochs"] = ep
    return {"applied": "EPOCH_CLOSE", "epoch": int(epoch)}


# ------------------- Slashing -------------------


def _apply_slash_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    slash_id = _as_str(
        payload.get("slash_id") or payload.get("id") or f"slash:{env.signer}:{env.nonce}"
    )
    account = _as_str(payload.get("account") or payload.get("target") or payload.get("validator"))

    sl = _ensure_slashing_root(state)
    props = sl.get("proposals")
    assert isinstance(props, dict)

    existed = slash_id in props
    props[slash_id] = {
        "slash_id": slash_id,
        "account": account,
        "payload": payload,
        "proposer": _as_str(env.signer),
    }
    sl["proposals"] = props
    return {"applied": "SLASH_PROPOSE", "slash_id": slash_id, "existed": existed}


def _apply_slash_vote(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id"))
    voter = _as_str(env.signer)
    vote = _as_str(payload.get("vote") or payload.get("attestation") or "").strip().lower()

    if not slash_id:
        raise ConsensusApplyError("invalid_payload", "missing_slash_id", {"tx_type": env.tx_type})
    if not vote:
        raise ConsensusApplyError("invalid_payload", "missing_vote", {"tx_type": env.tx_type})

    sl = _ensure_slashing_root(state)
    votes = sl.get("votes")
    assert isinstance(votes, dict)

    per = votes.get(slash_id)
    if not isinstance(per, dict):
        per = {}
    existed = voter in per
    per[voter] = vote
    votes[slash_id] = per
    sl["votes"] = votes

    return {
        "applied": "SLASH_VOTE",
        "slash_id": slash_id,
        "voter": voter,
        "vote": vote,
        "existed": existed,
    }


def _apply_slash_execute(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError(
            "forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type}
        )

    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id"))
    account = _as_str(payload.get("account"))
    reason = _as_str(payload.get("reason") or payload.get("type") or "")

    if not slash_id:
        raise ConsensusApplyError("invalid_payload", "missing_slash_id", {"tx_type": env.tx_type})

    sl = _ensure_slashing_root(state)
    execs = sl.get("executions")
    assert isinstance(execs, dict)

    existed = slash_id in execs
    if not existed:
        execs[slash_id] = {
            "slash_id": slash_id,
            "account": account,
            "reason": reason,
            "payload": payload,
            "parent": _as_str(env.parent),
        }
        sl["executions"] = execs

        ev = sl.get("events")
        assert isinstance(ev, list)
        ev.append(
            {"tx_type": "SLASH_EXECUTE", "slash_id": slash_id, "account": account, "reason": reason}
        )
        sl["events"] = ev

    return {"applied": "SLASH_EXECUTE", "slash_id": slash_id, "existed": existed}


def _apply_slash_legacy(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    sl = _ensure_slashing_root(state)
    ev = sl.get("events")
    assert isinstance(ev, list)
    ev.append({"tx_type": "SLASH", "payload": payload})
    sl["events"] = ev
    return {"applied": "SLASH", "legacy": True}


# ------------------- Router -------------------


CONSENSUS_TX_TYPES = {
    "VALIDATOR_REGISTER",
    "VALIDATOR_CANDIDATE_REGISTER",
    "VALIDATOR_CANDIDATE_APPROVE",
    "VALIDATOR_SUSPEND",
    "VALIDATOR_REMOVE",
    "VALIDATOR_DEREGISTER",
    "VALIDATOR_SET_UPDATE",
    "VALIDATOR_HEARTBEAT",
    "VALIDATOR_PERFORMANCE_REPORT",
    "BLOCK_PROPOSE",
    "BLOCK_ATTEST",
    "BLOCK_FINALIZE",
    "EPOCH_OPEN",
    "EPOCH_CLOSE",
    "SLASH_PROPOSE",
    "SLASH_VOTE",
    "SLASH_EXECUTE",
    "SLASH",
}


def apply_consensus(state: Json, env: TxEnvelope) -> Json | None:
    t = _as_str(env.tx_type).strip().upper()
    if t not in CONSENSUS_TX_TYPES:
        return None

    if t == "VALIDATOR_REGISTER":
        return _apply_validator_register(state, env)
    if t == "VALIDATOR_CANDIDATE_REGISTER":
        return _apply_validator_candidate_register(state, env)
    if t == "VALIDATOR_CANDIDATE_APPROVE":
        return _apply_validator_candidate_approve(state, env)
    if t == "VALIDATOR_SUSPEND":
        return _apply_validator_suspend(state, env)
    if t == "VALIDATOR_REMOVE":
        return _apply_validator_remove(state, env)
    if t == "VALIDATOR_DEREGISTER":
        return _apply_validator_deregister(state, env)
    if t == "VALIDATOR_SET_UPDATE":
        return _apply_validator_set_update(state, env)
    if t == "VALIDATOR_HEARTBEAT":
        return _apply_validator_heartbeat(state, env)
    if t == "VALIDATOR_PERFORMANCE_REPORT":
        return _apply_validator_performance_report(state, env)
    if t == "BLOCK_PROPOSE":
        return _apply_block_propose(state, env)
    if t == "BLOCK_ATTEST":
        return _apply_block_attest(state, env)
    if t == "BLOCK_FINALIZE":
        return _apply_block_finalize(state, env)
    if t == "EPOCH_OPEN":
        return _apply_epoch_open(state, env)
    if t == "EPOCH_CLOSE":
        return _apply_epoch_close(state, env)
    if t == "SLASH_PROPOSE":
        return _apply_slash_propose(state, env)
    if t == "SLASH_VOTE":
        return _apply_slash_vote(state, env)
    if t == "SLASH_EXECUTE":
        return _apply_slash_execute(state, env)
    if t == "SLASH":
        return _apply_slash_legacy(state, env)

    return None
