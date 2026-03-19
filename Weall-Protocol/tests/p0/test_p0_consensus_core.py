# tests/p0/test_p0_consensus_core.py
from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError

Json = dict[str, Any]


def _stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _clone(state: Json) -> Json:
    return copy.deepcopy(state)


def _env(
    tx_type: str,
    payload: dict[str, Any] | None = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> Json:
    e: Json = {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }
    if parent is not None:
        e["parent"] = parent
    return e


def _assert_apply_error(e: ApplyError, code: str, reason: str) -> None:
    assert e.code == code
    assert e.reason == reason


def test_block_propose_records_block_and_is_idempotent(base_state) -> None:
    st = _clone(base_state)

    block_id = "b0"
    env1 = _env(
        "BLOCK_PROPOSE",
        {"block_id": block_id, "height": 1, "parent": "genesis", "payload": {"txs": []}},
        signer="alice",
        nonce=1,
    )
    out1 = apply_tx(st, env1)
    assert out1["applied"] == "BLOCK_PROPOSE"
    assert out1.get("block_id") == block_id
    assert out1.get("height") == 1
    assert "consensus" in st
    assert "blocks_by_id" in st["consensus"]
    assert block_id in st["consensus"]["blocks_by_id"]

    snap = _stable(st["consensus"]["blocks_by_id"][block_id])
    out2 = apply_tx(st, env1)
    assert out2["applied"] == "BLOCK_PROPOSE"
    assert out2.get("block_id") == block_id
    assert _stable(st["consensus"]["blocks_by_id"][block_id]) == snap


def test_block_propose_missing_required_fields_rejected(base_state) -> None:
    st = _clone(base_state)

    with pytest.raises(ApplyError) as ei1:
        apply_tx(st, _env("BLOCK_PROPOSE", {"height": 1}, signer="alice", nonce=1))
    _assert_apply_error(ei1.value, "invalid_payload", "missing_block_id")

    with pytest.raises(ApplyError) as ei2:
        apply_tx(st, _env("BLOCK_PROPOSE", {"block_id": "b1"}, signer="alice", nonce=2))
    _assert_apply_error(ei2.value, "invalid_payload", "missing_height")


def test_validator_heartbeat_records_timestamp(base_state) -> None:
    st = _clone(base_state)

    env = _env(
        "VALIDATOR_HEARTBEAT",
        {"account": "alice", "ts_ms": 123456789},
        signer="alice",
        nonce=1,
    )
    out = apply_tx(st, env)
    assert out["applied"] == "VALIDATOR_HEARTBEAT"
    assert st["validators"]["last_heartbeat_ms"]["alice"] == 123456789


def test_validator_heartbeat_missing_fields_rejected(base_state) -> None:
    st = _clone(base_state)

    with pytest.raises(ApplyError) as ei1:
        apply_tx(st, _env("VALIDATOR_HEARTBEAT", {"ts_ms": 1}, signer="alice", nonce=1))
    _assert_apply_error(ei1.value, "invalid_payload", "missing_account")

    with pytest.raises(ApplyError) as ei2:
        apply_tx(st, _env("VALIDATOR_HEARTBEAT", {"account": "alice"}, signer="alice", nonce=2))
    _assert_apply_error(ei2.value, "invalid_payload", "missing_ts_ms")


def test_validator_heartbeat_account_must_match_signer(base_state) -> None:
    st = _clone(base_state)

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            st, _env("VALIDATOR_HEARTBEAT", {"account": "alice", "ts_ms": 1}, signer="bob", nonce=1)
        )
    _assert_apply_error(ei.value, "forbidden", "account_must_match_signer")


def test_validator_deregister_marks_inactive_when_present(base_state) -> None:
    st = _clone(base_state)

    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})
    st["validators"]["registry"]["alice"] = {"active": True}

    st.setdefault("roles", {})
    st["roles"].setdefault("validators", {})
    st["roles"]["validators"].setdefault("active_set", ["alice", "bob"])

    out = apply_tx(st, _env("VALIDATOR_DEREGISTER", {"account": "alice"}, signer="alice", nonce=1))
    assert out["applied"] == "VALIDATOR_DEREGISTER"
    assert st["validators"]["registry"]["alice"]["active"] is False
    assert "alice" not in st["roles"]["validators"]["active_set"]


def test_validator_deregister_missing_account_rejected(base_state) -> None:
    st = _clone(base_state)
    with pytest.raises(ApplyError) as ei:
        apply_tx(st, _env("VALIDATOR_DEREGISTER", {}, signer="alice", nonce=1))
    _assert_apply_error(ei.value, "invalid_payload", "missing_account")


def test_validator_deregister_account_must_match_signer(base_state) -> None:
    st = _clone(base_state)

    # Seed registry for alice so we can prove a malicious bob cannot deregister her.
    st.setdefault("validators", {})
    st["validators"].setdefault("registry", {})
    st["validators"]["registry"]["alice"] = {"active": True}

    with pytest.raises(ApplyError) as ei:
        apply_tx(st, _env("VALIDATOR_DEREGISTER", {"account": "alice"}, signer="bob", nonce=1))
    _assert_apply_error(ei.value, "forbidden", "account_must_match_signer")

    # Ensure no state change happened
    assert st["validators"]["registry"]["alice"]["active"] is True


def test_slash_propose_records_proposal_and_is_idempotent(base_state) -> None:
    st = _clone(base_state)

    slash_id = "slash-1"
    env1 = _env(
        "SLASH_PROPOSE",
        {"slash_id": slash_id, "target": "bob", "evidence": {"kind": "equivocation"}},
        signer="alice",
        nonce=1,
    )
    out1 = apply_tx(st, env1)
    assert out1["applied"] == "SLASH_PROPOSE"
    assert "slashing" in st
    assert "proposals" in st["slashing"]
    assert slash_id in st["slashing"]["proposals"]

    snap = _stable(st["slashing"]["proposals"][slash_id])
    out2 = apply_tx(st, env1)
    assert out2["applied"] == "SLASH_PROPOSE"
    assert _stable(st["slashing"]["proposals"][slash_id]) == snap


def test_slash_vote_records_vote_per_voter_overwrites(base_state) -> None:
    st = _clone(base_state)

    slash_id = "slash-2"
    apply_tx(
        st,
        _env(
            "SLASH_PROPOSE",
            {"slash_id": slash_id, "target": "bob", "evidence": {"kind": "equivocation"}},
            signer="alice",
            nonce=1,
        ),
    )

    out1 = apply_tx(
        st, _env("SLASH_VOTE", {"slash_id": slash_id, "vote": "yes"}, signer="carol", nonce=1)
    )
    assert out1["applied"] == "SLASH_VOTE"
    assert st["slashing"]["votes"][slash_id]["carol"] == "yes"

    out2 = apply_tx(
        st, _env("SLASH_VOTE", {"slash_id": slash_id, "vote": "no"}, signer="carol", nonce=2)
    )
    assert out2["applied"] == "SLASH_VOTE"
    assert st["slashing"]["votes"][slash_id]["carol"] == "no"
