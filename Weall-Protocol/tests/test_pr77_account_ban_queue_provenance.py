"""PR77: queued SYSTEM ACCOUNT_BAN is not itself severe-sanction authority.

The queue/emitter/binding contract is tested with actual canonical tx metadata;
the constructed queue item deliberately lacks authenticated case provenance.
These are synthetic node/ledger tests, NOT historical replay or BFT proof.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

import weall.runtime.block_builder as block_builder
from scripts.pr77_v2_semantic_review_packet import build_packet
from weall.runtime.domain_apply import (
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.errors import ApplyError
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    build_system_queue_lookup,
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex

ROOT = Path(__file__).resolve().parents[1]


def _canon() -> TxIndex:
    return TxIndex.load_from_file(str(ROOT / "generated" / "tx_index.json"))


def _state(*, clock_enabled: bool, height: int = 20) -> dict:
    return {
        "height": height,
        "chain_id": "pr77-synthetic-queue-ban",
        "tip": "",
        "tip_hash": "",
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "params": {},
        "accounts": {
            "@target": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
                "reputation": "0",
                "reputation_milli": 0,
                "keys": [],
            }
        },
        "reputation": {"bans": {}},
        "system_queue": [],
    }


def _queued(*, clock_enabled: bool = True, height: int = 20) -> tuple[dict, TxIndex, TxEnvelope]:
    state = _state(clock_enabled=clock_enabled, height=height)
    canon = _canon()
    enqueue_system_tx(
        state,
        tx_type="ACCOUNT_BAN",
        payload={"account_id": "@target", "reason": "no-authenticated-case-producer"},
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent="synthetic-unverified-dispute-resolution",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon, next_height=height + 1, phase="post")
    assert len(emitted) == 1
    assert emitted[0].tx_type == "ACCOUNT_BAN"
    return state, canon, emitted[0]


def test_a_valid_system_queue_id_is_not_constitutional_ban_authorization() -> None:
    state, canon, emitted = _queued()
    assert emitted.system is True
    assert emitted.signer == "SYSTEM"
    assert emitted.payload["_system_queue_id"] == state["system_queue"][0]["queue_id"]
    assert validate_system_tx_queue_binding(
        state, canon, emitted, next_height=21, phase="post"
    ) == (True, "")
    assert validate_system_tx_queue_binding(
        state,
        canon,
        emitted,
        next_height=21,
        phase="post",
        queue_objects_by_id=build_system_queue_lookup(state),
    ) == (True, "")

    # A deterministic queue record, even one with a matching parent string,
    # says nothing about authenticated juror panels or appeal finality.
    for applier in (apply_tx_atomic_meta, apply_tx_atomic_meta_deepcopy):
        snapshot = copy.deepcopy(state)
        before = copy.deepcopy(snapshot)
        root = compute_state_root(snapshot)
        with pytest.raises(ApplyError) as error:
            applier(snapshot, copy.deepcopy(emitted))
        assert error.value.code == "forbidden"
        assert error.value.reason == "severe_sanction_authorization_unimplemented"
        assert snapshot == before
        assert compute_state_root(snapshot) == root


def _mutated(
    original: TxEnvelope,
    *,
    payload_change: dict | None = None,
    discard: str = "",
    signer: str | None = None,
    parent: str | None = None,
    tx_type: str | None = None,
) -> TxEnvelope:
    payload = copy.deepcopy(original.payload)
    if discard:
        payload.pop(discard, None)
    if payload_change:
        payload.update(payload_change)
    return TxEnvelope(
        tx_type=tx_type or original.tx_type,
        signer=signer or original.signer,
        nonce=original.nonce,
        payload=payload,
        sig=original.sig,
        system=True,
        parent=original.parent if parent is None else parent,
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing_queue_id", "missing_system_queue_id"),
        ("unknown_queue_id", "unknown_system_queue_id"),
        ("forged_target", "system_queue_payload_mismatch"),
        ("forged_appeal", "system_queue_payload_mismatch"),
        ("wrong_height", "system_payload_due_height_mismatch"),
        ("wrong_parent", "system_queue_parent_mismatch"),
        ("wrong_signer", "system_queue_signer_mismatch"),
        ("wrong_type", "system_queue_tx_type_mismatch"),
    ],
)
def test_forged_system_ban_receipt_fails_queue_binding(
    mutation: str, expected: str
) -> None:
    state, canon, emitted = _queued()
    if mutation == "missing_queue_id":
        forged = _mutated(emitted, discard="_system_queue_id")
    elif mutation == "unknown_queue_id":
        forged = _mutated(emitted, payload_change={"_system_queue_id": "missing-queue"})
    elif mutation == "forged_target":
        forged = _mutated(emitted, payload_change={"account_id": "@other"})
    elif mutation == "forged_appeal":
        forged = _mutated(emitted, payload_change={"appeal_approved": True})
    elif mutation == "wrong_height":
        forged = _mutated(emitted, payload_change={"_due_height": 22})
    elif mutation == "wrong_parent":
        forged = _mutated(emitted, parent="forged-parent")
    elif mutation == "wrong_signer":
        forged = _mutated(emitted, signer="@forger")
    else:
        forged = _mutated(emitted, tx_type="ACCOUNT_REINSTATE")

    before = copy.deepcopy(state)
    ok, why = validate_system_tx_queue_binding(
        state, canon, forged, next_height=21, phase="post"
    )
    assert (ok, why) == (False, expected)
    assert state == before


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_queue_phase_and_height_binding_does_not_bypass_application(
    clock_enabled: bool,
) -> None:
    state, canon, emitted = _queued(clock_enabled=clock_enabled)
    before = copy.deepcopy(state)
    assert validate_system_tx_queue_binding(
        state, canon, emitted, next_height=20, phase="post"
    ) == (False, "system_queue_due_height_mismatch")
    assert validate_system_tx_queue_binding(
        state, canon, emitted, next_height=21, phase="pre"
    ) == (False, "system_queue_phase_mismatch")
    assert state == before

    result_state = copy.deepcopy(state)
    if clock_enabled:
        with pytest.raises(ApplyError, match="severe_sanction_authorization_unimplemented"):
            apply_tx_atomic_meta(result_state, emitted)
        assert result_state == state
    else:
        result = apply_tx_atomic_meta(result_state, emitted)
        assert result["applied"] == "ACCOUNT_BAN"
        assert result_state["accounts"]["@target"]["banned"] is True


def test_account_ban_v2_drift_bound_to_queue_authority_distinction() -> None:
    packet = build_packet()
    row = next(row for row in packet["transactions"] if row["tx_type"] == "ACCOUNT_BAN")
    assert row["archive_matches_accepted_digest"] is True
    assert row["archived_implementation_source"] == row["current_implementation_source"]
    assert row["changed_field_names"] == ["failure_codes", "state_reads"]
    assert row["failure_code_deltas"] == {
        "added": [
            {"code": "conflicting_receipt", "reason": "duplicate_ban_receipt_conflict"},
            {"code": "forbidden", "reason": "severe_sanction_authorization_unimplemented"},
        ],
        "removed": [],
    }
    assert row["signed_off_for_current_digest"] is False
    assert row["historical_replay_proven"] is False


def test_node_builder_rejects_queue_bound_ban_without_severe_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, canon, emitted = _queued(clock_enabled=True, height=0)
    assert validate_system_tx_queue_binding(
        state, canon, emitted, next_height=1, phase="post"
    ) == (True, "")
    # The leader candidate builder starts from the pre-emission canonical
    # snapshot, not the already-emitted queue marker.
    state["system_queue"][0].pop("emitted_height", None)
    executor = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=state["chain_id"],
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    executor._ledger_store.write_state_snapshot(copy.deepcopy(state))
    executor.state = executor._ledger_store.read()
    before = copy.deepcopy(executor.state)
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)

    block, new_state, applied, invalid, error = executor.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert block is None
    assert new_state is None
    assert applied == []
    assert invalid == []
    assert "severe_sanction_authorization_unimplemented" in error
    assert executor.state == before
