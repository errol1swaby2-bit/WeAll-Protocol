from __future__ import annotations

import copy
import json
import random
from typing import Any, Dict, Iterable, List

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = Dict[str, Any]


def _stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _clone(obj: Any) -> Any:
    return copy.deepcopy(obj)


def _env(
    tx_type: str,
    payload: Json | None = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    env: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "sig",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        env["parent"] = parent
    elif system:
        env["parent"] = f"p:{max(0, int(nonce) - 1)}"
    return env


def _gov_state() -> Json:
    return {
        "params": {
            "system_signer": "SYSTEM",
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "height": 10,
        "time": 1,
        "accounts": {
            "alice": {"balance": 100, "nonce": 0, "poh_tier": 3},
            "bob": {"balance": 100, "nonce": 0, "poh_tier": 3},
            "carol": {"balance": 100, "nonce": 0, "poh_tier": 3},
        },
    }


def _treasury_state() -> Json:
    return {
        "params": {
            "system_signer": "SYSTEM",
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "height": 4,
        "time": 1,
        "accounts": {
            "alice": {"balance": 1000, "nonce": 0, "poh_tier": 3},
            "bob": {"balance": 1000, "nonce": 0, "poh_tier": 3},
            "carol": {"balance": 1000, "nonce": 0, "poh_tier": 3},
        },
    }


def _mk_poh_state() -> Json:
    st: Json = {
        "params": {"system_signer": "SYSTEM"},
        "chain_id": "test",
        "height": 1,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 1, "banned": False, "locked": False, "reputation": 0.0},
        },
    }
    for i in range(1, 11):
        st["accounts"][f"j{i}"] = {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 0.9}
    return st


def _open_tier3_case(st: Json) -> str:
    m0 = apply_tx(st, _env("POH_TIER2_REQUEST_OPEN", {"account_id": "alice", "target_tier": 3}, signer="alice", nonce=1))
    assert m0 and m0["applied"] == "POH_TIER2_REQUEST_OPEN"
    case_id = str(m0["case_id"])
    m1 = apply_tx(
        st,
        _env(
            "POH_TIER3_INIT",
            {"case_id": case_id, "account_id": "alice", "session_commitment": "sc:1", "ts_ms": 1},
            signer="SYSTEM",
            nonce=2,
            system=True,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )
    assert m1 and m1["applied"] == "POH_TIER3_INIT"
    m2 = apply_tx(
        st,
        _env(
            "POH_TIER3_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": [f"j{i}" for i in range(1, 11)]},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_TIER3_INIT",
        ),
    )
    assert m2 and m2["applied"] == "POH_TIER3_JUROR_ASSIGN"
    return case_id


def _tier3_action_groups(case_id: str) -> tuple[List[Json], List[Json], List[Json]]:
    accepts: List[Json] = []
    attendance: List[Json] = []
    verdict_ops: List[Json] = []
    nonce = 10
    for i in range(1, 11):
        jid = f"j{i}"
        accepts.append(_env("POH_TIER3_JUROR_ACCEPT", {"case_id": case_id, "ts_ms": nonce}, signer=jid, nonce=nonce))
        nonce += 1
        attendance.append(
            _env(
                "POH_TIER3_ATTENDANCE_MARK",
                {"case_id": case_id, "juror_id": jid, "attended": True, "session_commitment": "sc:1", "ts_ms": nonce},
                signer=jid,
                nonce=nonce,
            )
        )
        nonce += 1
    verdicts = [("j1", "pass"), ("j2", "pass"), ("j3", "fail")]
    for jid, verdict in verdicts:
        verdict_ops.append(
            _env(
                "POH_TIER3_VERDICT_SUBMIT",
                {"case_id": case_id, "verdict": verdict, "session_commitment": "sc:1", "ts_ms": nonce},
                signer=jid,
                nonce=nonce,
            )
        )
        nonce += 1
    return accepts, attendance, verdict_ops


def _apply_ops(st: Json, ops: Iterable[Json]) -> None:
    for op in ops:
        apply_tx(st, _clone(op))


def test_priority4_governance_execute_queue_is_deterministic_and_replay_deduped() -> None:
    base = _gov_state()
    action_payload = {
        "proposal_id": "prop-q",
        "title": "queue",
        "body": "queue",
        "kind": "generic",
        "actions": [
            {"tx_type": "VALIDATOR_SET_UPDATE", "payload": {"active_set": ["v2", "v1", "v1"], "activate_at_epoch": 7}},
            {"tx_type": "TREASURY_PARAMS_SET", "payload": {"timelock_blocks": 5}},
        ],
    }

    st_a = _clone(base)
    st_b = _clone(base)

    apply_tx(st_a, _env("GOV_PROPOSAL_CREATE", _clone(action_payload), signer="alice", nonce=1))
    apply_tx(st_b, _env("GOV_PROPOSAL_CREATE", _clone(action_payload), signer="alice", nonce=1))

    exec_env = _env(
        "GOV_EXECUTE",
        {"proposal_id": "prop-q", "actions": _clone(action_payload["actions"]), "_parent_ref": "txid:prop-q"},
        signer="SYSTEM",
        nonce=2,
        system=True,
        parent="txid:prop-q",
    )
    apply_tx(st_a, exec_env)
    apply_tx(st_b, _clone(exec_env))

    assert _stable(st_a.get("system_queue")) == _stable(st_b.get("system_queue"))
    qids_before = [str(it["queue_id"]) for it in st_a.get("system_queue", [])]
    assert len(qids_before) == len(set(qids_before))

    # Exact replay of the same GOV_EXECUTE must not duplicate queued follow-up work.
    apply_tx(st_a, _clone(exec_env))
    qids_after = [str(it["queue_id"]) for it in st_a.get("system_queue", [])]
    assert qids_after == qids_before


def test_priority4_treasury_signature_permutations_converge() -> None:
    def _build(sign_order: List[str]) -> Json:
        st = _treasury_state()
        apply_tx(st, _env("TREASURY_CREATE", {"treasury_id": "t1"}, signer="alice", nonce=1))
        apply_tx(
            st,
            _env(
                "TREASURY_SIGNERS_SET",
                {"treasury_id": "t1", "signers": ["alice", "bob", "alice"], "threshold": 2},
                signer="alice",
                nonce=2,
            ),
        )
        apply_tx(
            st,
            _env(
                "TREASURY_SPEND_PROPOSE",
                {"treasury_id": "t1", "spend_id": "s1", "to": "carol", "amount": 25},
                signer="alice",
                nonce=3,
            ),
        )
        next_nonce = 10
        for signer in sign_order:
            out = apply_tx(
                st,
                _env("TREASURY_SPEND_SIGN", {"treasury_id": "t1", "spend_id": "s1"}, signer=signer, nonce=next_nonce),
            )
            assert out and out["applied"] == "TREASURY_SPEND_SIGN"
            next_nonce += 1
        return st

    st_ab = _build(["alice", "bob"])
    st_ba = _build(["bob", "alice"])

    spend_ab = st_ab["treasury"]["spends"]["s1"]
    spend_ba = st_ba["treasury"]["spends"]["s1"]

    assert spend_ab["allowed_signers"] == ["alice", "bob"]
    assert spend_ba["allowed_signers"] == ["alice", "bob"]
    assert sorted(spend_ab["signatures"].keys()) == ["alice", "bob"]
    assert sorted(spend_ba["signatures"].keys()) == ["alice", "bob"]
    assert spend_ab["threshold"] == spend_ba["threshold"] == 2
    assert spend_ab["status"] == spend_ba["status"] == "proposed"
    assert spend_ab["earliest_execute_height"] == spend_ba["earliest_execute_height"]


def test_priority4_validator_pending_update_replay_is_idempotent() -> None:
    st = {
        "params": {"system_signer": "SYSTEM"},
        "consensus": {"epochs": {"current": 3}},
        "roles": {"validators": {"active_set": ["v0"]}},
    }
    env = _env(
        "VALIDATOR_SET_UPDATE",
        {"active_set": ["v2", "v1", "v2"], "activate_at_epoch": 5},
        signer="SYSTEM",
        nonce=1,
        system=True,
        parent="txid:gov-exec",
    )

    out1 = apply_tx(st, _clone(env))
    out2 = apply_tx(st, _clone(env))
    assert out1["pending"] is True
    assert out2["pending"] is True
    assert out1["validator_set_hash"] == out2["validator_set_hash"]
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == ["v2", "v1"]
    assert pending["activate_at_epoch"] == 5


def test_priority4_poh_tier3_permutation_fuzz_converges() -> None:
    rng = random.Random(428)
    reference: str | None = None

    for _ in range(8):
        st = _mk_poh_state()
        case_id = _open_tier3_case(st)
        accepts, attendance, verdict_ops = _tier3_action_groups(case_id)
        rng.shuffle(accepts)
        rng.shuffle(attendance)
        rng.shuffle(verdict_ops)
        _apply_ops(st, accepts)
        _apply_ops(st, attendance)
        _apply_ops(st, verdict_ops)
        out = apply_tx(
            st,
            _env(
                "POH_TIER3_FINALIZE",
                {"case_id": case_id, "ts_ms": 999},
                signer="SYSTEM",
                nonce=999,
                system=True,
                parent="POH_TIER3_VERDICT_SUBMIT",
            ),
        )
        assert out["applied"] == "POH_TIER3_FINALIZE"
        assert out["outcome"] == "pass"
        assert out["tier_awarded"] == 3
        assert st["accounts"]["alice"]["poh_tier"] == 3
        case = st["poh"]["tier3_cases"][case_id]
        assert case["status"] == "awarded"
        assert case["outcome"] == "pass"
        stable_case = _stable(case)
        if reference is None:
            reference = stable_case
        else:
            assert stable_case == reference


def test_priority4_cross_domain_queue_id_is_stable() -> None:
    st1: Json = {}
    st2: Json = {}
    q1 = enqueue_system_tx(
        st1,
        tx_type="GOV_EXECUTION_RECEIPT",
        payload={"proposal_id": "p1", "ok": True, "_parent_ref": "txid:p1"},
        due_height=7,
        signer="SYSTEM",
        parent="txid:p1",
        phase="post",
        once=True,
    )
    q2 = enqueue_system_tx(
        st2,
        tx_type="GOV_EXECUTION_RECEIPT",
        payload={"proposal_id": "p1", "ok": True, "_parent_ref": "txid:p1"},
        due_height=7,
        signer="SYSTEM",
        parent="txid:p1",
        phase="post",
        once=True,
    )
    assert q1 == q2
    assert len(st1["system_queue"]) == 1
    assert enqueue_system_tx(
        st1,
        tx_type="GOV_EXECUTION_RECEIPT",
        payload={"proposal_id": "p1", "ok": True, "_parent_ref": "txid:p1"},
        due_height=7,
        signer="SYSTEM",
        parent="txid:p1",
        phase="post",
        once=True,
    ) == q1
    assert len(st1["system_queue"]) == 1
