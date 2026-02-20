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
from typing import Any, Dict, List, Optional

from weall.ledger.roles_schema import ensure_roles_schema
from weall.runtime.proposer_selection import select_proposer
from weall.runtime.apply.reputation import apply_reputation_delta_system
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class ConsensusApplyError(RuntimeError):
    code: str
    reason: str
    details: Dict[str, Any]


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_list(v: Any) -> List[Any]:
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
        "validator_set",
        "blocks_by_id",
        "epochs",
        "slashes_by_id",
        "attestations_by_validator",
        "proposer_by_height",
    ):
        if not isinstance(c.get(k), dict):
            c[k] = {}

    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {}
        c["epochs"] = ep
    ep.setdefault("current", 0)
    ep.setdefault("events", [])
    c["epochs"] = ep

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


def _ensure_roles_validators_active_set(state: Json) -> List[str]:
    ensure_roles_schema(state)
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators

    active_set = validators.get("active_set")
    if not isinstance(active_set, list):
        active_set = []
        validators["active_set"] = active_set

    out: List[str] = []
    seen: set[str] = set()
    for x in active_set:
        s = _as_str(x)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)

    validators["active_set"] = out
    return out


def _set_active_set(state: Json, accounts: List[str]) -> None:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators

    out: List[str] = []
    seen: set[str] = set()
    for x in accounts:
        s = _as_str(x)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)

    validators["active_set"] = out


# ------------------- Validators -------------------


def _apply_validator_register(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account") or env.signer)
    pubkey = _as_str(payload.get("pubkey"))

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
    if not pubkey:
        raise ConsensusApplyError("invalid_payload", "missing_pubkey", {"tx_type": env.tx_type})

    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)

    existed = account in reg
    reg[account] = {"account": account, "pubkey": pubkey, "active": True}
    vroot["registry"] = reg

    # Keep roles.active_set as a best-effort mirror
    active = _ensure_roles_validators_active_set(state)
    if account not in active:
        active.append(account)
        _set_active_set(state, active)

    return {"applied": "VALIDATOR_REGISTER", "account": account, "existed": existed}


def _apply_validator_deregister(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account") or env.signer)

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})

    vroot = _ensure_validators_root(state)
    reg = vroot.get("registry")
    assert isinstance(reg, dict)

    existed = account in reg
    if account in reg:
        rec = reg.get(account)
        if isinstance(rec, dict):
            rec["active"] = False
            reg[account] = rec

    vroot["registry"] = reg

    active = _ensure_roles_validators_active_set(state)
    if account in active:
        active = [x for x in active if _as_str(x) != account]
        _set_active_set(state, active)

    return {"applied": "VALIDATOR_DEREGISTER", "account": account, "existed": existed}


def _apply_validator_set_update(state: Json, env: TxEnvelope) -> Json:
    # Receipt-only, system-origin in canon.
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

    payload = _as_dict(env.payload)
    active_set = _as_list(payload.get("active_set"))
    out: List[str] = []
    seen: set[str] = set()
    for x in active_set:
        s = _as_str(x)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)

    _set_active_set(state, out)
    c = _ensure_consensus(state)
    vs = c.get("validator_set")
    assert isinstance(vs, dict)
    vs["active_set"] = out
    c["validator_set"] = vs

    return {"applied": "VALIDATOR_SET_UPDATE", "active_set": out}


def _apply_validator_heartbeat(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    account = _as_str(payload.get("account") or env.signer)
    ts_ms = _as_int(payload.get("ts_ms"), 0)

    if not account:
        raise ConsensusApplyError("invalid_payload", "missing_account", {"tx_type": env.tx_type})
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

    rec = {"account": account, "ts_ms": int(ts_ms) if ts_ms else None, "report": report, "payload": payload}
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
                {"expected": expected, "got": proposer, "height": int(height), "block_id": block_id},
            )

    return {"applied": "BLOCK_PROPOSE", "block_id": block_id, "height": int(height), "existed": existed}


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
                due = int(height) + 1 if int(height) > 0 else int(_as_int(state.get("height"), 0)) + 1
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
                    evidence={"source": "consensus", "event": "EQUIVOCATION", "slash_id": sid, "payload": payload},
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
    per[validator] = {"validator": validator, "attestation": att, "payload": payload, "parent": _as_str(env.parent)}
    ba[block_id] = per

    return {"applied": "BLOCK_ATTEST", "block_id": block_id, "validator": validator, "existed": existed}


def _apply_block_finalize(state: Json, env: TxEnvelope) -> Json:
    # Receipt-only, system-origin in canon.
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

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
            raise ConsensusApplyError("invalid_block", "missing_attestations", {"block_id": block_id})

        active = _ensure_roles_validators_active_set(state)
        if len(active) == 0:
            raise ConsensusApplyError("invalid_block", "no_active_validators", {})

        yes = 0
        for v in active:
            rec = per.get(v)
            if isinstance(rec, dict) and _as_str(rec.get("attestation")).lower() in ("yes", "y", "true", "1"):
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
        enqueue_system_tx(state, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=2, phase="post")

    if bpe > 0 and int(height) > 0 and int(height) % int(bpe) == 0:
        c = _ensure_consensus(state)
        ep = c.get("epochs")
        if not isinstance(ep, dict):
            ep = {"current": 0, "events": []}
        cur_epoch = _as_int(ep.get("current"), 0) or 1
        due = int(height) + 1
        enqueue_system_tx(state, tx_type="EPOCH_CLOSE", payload={"epoch": cur_epoch}, due_height=due, phase="post")
        enqueue_system_tx(state, tx_type="EPOCH_OPEN", payload={"epoch": cur_epoch + 1}, due_height=due, phase="post")

    return {"applied": "BLOCK_FINALIZE", "block_id": block_id, "height": int(height), "existed": existed}


# ------------------- Epochs -------------------


def _apply_epoch_open(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch = _as_int(payload.get("epoch"), 0)
    if epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_epoch", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {"current": 0, "events": []}

    ep["current"] = int(epoch)
    events = ep.get("events")
    if not isinstance(events, list):
        events = []
    events.append({"event": "open", "epoch": int(epoch)})
    ep["events"] = events

    c["epochs"] = ep
    return {"applied": "EPOCH_OPEN", "epoch": int(epoch)}


def _apply_epoch_close(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    epoch = _as_int(payload.get("epoch"), 0)
    if epoch <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_epoch", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    ep = c.get("epochs")
    if not isinstance(ep, dict):
        ep = {"current": 0, "events": []}

    events = ep.get("events")
    if not isinstance(events, list):
        events = []
    events.append({"event": "close", "epoch": int(epoch)})
    ep["events"] = events

    c["epochs"] = ep
    return {"applied": "EPOCH_CLOSE", "epoch": int(epoch)}


# ------------------- Slashing -------------------


def _apply_slash_propose(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id") or "")
    if not slash_id:
        # Still "claimed" for canon coverage even if payload is empty.
        slash_id = f"slash:{_as_str(env.signer) or 'unknown'}:{_as_int(getattr(env, 'nonce', 0), 0)}"

    sl = _ensure_slashing_root(state)
    props = sl.get("proposals")
    assert isinstance(props, dict)

    existed = slash_id in props
    props[slash_id] = {"slash_id": slash_id, "proposer": _as_str(env.signer), "payload": payload}
    sl["proposals"] = props

    return {"applied": "SLASH_PROPOSE", "slash_id": slash_id, "existed": existed}


def _apply_slash_vote(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id") or "")
    if not slash_id:
        # Claim without strict payload requirements.
        slash_id = f"slash:unknown:{_as_int(getattr(env, 'nonce', 0), 0)}"

    voter = _as_str(payload.get("voter") or env.signer)
    vote = _as_str(payload.get("vote") or payload.get("choice") or "yes")

    sl = _ensure_slashing_root(state)
    votes = sl.get("votes")
    assert isinstance(votes, dict)

    per = votes.get(slash_id)
    if not isinstance(per, dict):
        per = {}
    per[voter] = vote
    votes[slash_id] = per
    sl["votes"] = votes

    return {"applied": "SLASH_VOTE", "slash_id": slash_id, "voter": voter, "vote": vote}


def _apply_slash_execute(state: Json, env: TxEnvelope) -> Json:
    # Receipt-only, system-origin in canon.
    _require_system_env(env)
    if not env.parent:
        raise ConsensusApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": env.tx_type})

    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id") or "")
    if not slash_id:
        # Parent might be an id (or just a tx type in tests). Keep it deterministic.
        slash_id = f"exec:{_as_str(env.parent)}:{_as_int(getattr(env, 'nonce', 0), 0)}"

    sl = _ensure_slashing_root(state)
    execs = sl.get("executions")
    assert isinstance(execs, dict)

    existed = slash_id in execs
    execs[slash_id] = {"slash_id": slash_id, "payload": payload, "parent": _as_str(env.parent)}
    sl["executions"] = execs

    ev = sl.get("events")
    assert isinstance(ev, list)
    ev.append({"tx_type": "SLASH_EXECUTE", "slash_id": slash_id, "parent": _as_str(env.parent)})
    sl["events"] = ev

    # Consensus-proven penalty: executing a slash indicates verified misbehavior.
    target = _as_str(payload.get("account") or payload.get("validator") or payload.get("target") or "")
    if target:
        apply_reputation_delta_system(
            state,
            account_id=target,
            delta=-25.0,
            reason="slash_execute",
            evidence={
                "source": "consensus",
                "event": "SLASH_EXECUTE",
                "slash_id": slash_id,
                "parent": _as_str(env.parent),
                "payload": payload,
            },
            at_nonce=int(env.nonce),
        )

    return {"applied": "SLASH_EXECUTE", "slash_id": slash_id, "existed": existed}


def _apply_slash_legacy(state: Json, env: TxEnvelope) -> Json:
    """Legacy/system slash record sink (kept for backward compatibility)."""
    _require_system_env(env)
    payload = _as_dict(env.payload)
    slash_id = _as_str(payload.get("slash_id") or payload.get("id"))
    account = _as_str(payload.get("account"))
    reason = _as_str(payload.get("reason"))
    if not slash_id or not account:
        raise ConsensusApplyError("invalid_payload", "missing_slash_fields", {"tx_type": env.tx_type})

    c = _ensure_consensus(state)
    sl = c.get("slashes_by_id")
    assert isinstance(sl, dict)
    existed = slash_id in sl
    sl[slash_id] = {"account": account, "reason": reason}
    c["slashes_by_id"] = sl

    return {"applied": "SLASH", "slash_id": slash_id, "account": account, "existed": existed}


# ------------------- Proposer selection -------------------


def _apply_proposer_select(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    height = _as_int(payload.get("height"), 0)
    if height <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_height", {"tx_type": env.tx_type})

    active = _ensure_roles_validators_active_set(state)
    proposer = select_proposer(active, height=height, chain_id=_chain_id(state))

    c = _ensure_consensus(state)
    pbh = c.get("proposer_by_height")
    assert isinstance(pbh, dict)
    existed = str(height) in pbh
    pbh[str(height)] = proposer
    c["proposer_by_height"] = pbh

    return {"applied": "PROPOSER_SELECT", "height": int(height), "proposer": proposer, "existed": existed}


# ------------------- Epoch scheduler hooks (system queue) -------------------


def _apply_epoch_tick(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    height = _as_int(payload.get("height"), 0)
    if height <= 0:
        raise ConsensusApplyError("invalid_payload", "missing_height", {"tx_type": env.tx_type})

    # MVP epoch schedule: open at height 2; then every 10 blocks close/open.
    if height == 1:
        enqueue_system_tx(state, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=2, phase="post")

    if height > 0 and height % 10 == 0:
        c = _ensure_consensus(state)
        ep = c.get("epochs")
        if not isinstance(ep, dict):
            ep = {"current": 0, "events": []}
        k = _as_int(ep.get("current"), 0)
        due = int(height) + 1
        enqueue_system_tx(state, tx_type="EPOCH_CLOSE", payload={"epoch": k}, due_height=due, phase="post")
        enqueue_system_tx(state, tx_type="EPOCH_OPEN", payload={"epoch": k + 1}, due_height=due, phase="post")

    return {"applied": "EPOCH_TICK", "height": int(height)}


# ------------------- Router -------------------


CONSENSUS_TX_TYPES = {
    "VALIDATOR_REGISTER",
    "VALIDATOR_DEREGISTER",
    "VALIDATOR_SET_UPDATE",
    "VALIDATOR_HEARTBEAT",
    "VALIDATOR_PERFORMANCE_REPORT",
    "BLOCK_PROPOSE",
    "BLOCK_ATTEST",
    "BLOCK_FINALIZE",
    "PROPOSER_SELECT",
    "EPOCH_TICK",
    "EPOCH_OPEN",
    "EPOCH_CLOSE",
    "SLASH_PROPOSE",
    "SLASH_VOTE",
    "SLASH_EXECUTE",
    "SLASH",
}


def apply_consensus(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = _as_str(env.tx_type).strip().upper()
    if t not in CONSENSUS_TX_TYPES:
        return None

    if t == "VALIDATOR_REGISTER":
        return _apply_validator_register(state, env)
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
    if t == "PROPOSER_SELECT":
        return _apply_proposer_select(state, env)
    if t == "EPOCH_TICK":
        return _apply_epoch_tick(state, env)
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
