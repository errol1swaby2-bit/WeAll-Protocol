from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.apply.groups import apply_groups
from weall.runtime.group_treasury_scheduler import maybe_enqueue_group_spend_execute
from weall.runtime.system_tx_engine import (
    SystemQueueCorruptionError,
    build_system_queue_lookup,
    enqueue_system_tx,
    system_tx_emitter,
)
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(
        str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")
    )


def test_late_group_treasury_threshold_schedules_execute_at_current_apply_height() -> None:
    state = {"height": 10, "system_queue": []}
    spend = {
        "spend_id": "late-spend",
        "group_id": "g1",
        "status": "proposed",
        "allowed_signers": ["alice"],
        "threshold": 1,
        "signatures": {"alice": {}},
        "earliest_execute_height": 5,
    }

    queue_id = maybe_enqueue_group_spend_execute(state, spend=spend)

    assert queue_id
    assert len(state["system_queue"]) == 1
    assert state["system_queue"][0]["due_height"] == 11
    emitted = system_tx_emitter(state, _tx_index(), next_height=11, phase="post")
    assert len(emitted) == 1
    assert emitted[0].tx_type == "GROUP_TREASURY_SPEND_EXECUTE"
    assert emitted[0].payload["_system_queue_id"] == queue_id


def test_late_group_treasury_sign_path_does_not_create_historical_due_work() -> None:
    state = {
        "height": 10,
        "system_queue": [],
        "group_treasury_spends": {
            "late-spend": {
                "spend_id": "late-spend",
                "group_id": "g1",
                "status": "proposed",
                "allowed_signers": ["alice"],
                "threshold": 1,
                "signatures": {},
                "earliest_execute_height": 5,
            }
        },
    }

    result = apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_TREASURY_SPEND_SIGN",
            signer="alice",
            nonce=1,
            payload={"spend_id": "late-spend"},
        ),
    )

    assert result["applied"] == "GROUP_TREASURY_SPEND_SIGN"
    assert state["system_queue"][0]["due_height"] == 11
    emitted = system_tx_emitter(state, _tx_index(), next_height=11, phase="post")
    assert [env.tx_type for env in emitted] == ["GROUP_TREASURY_SPEND_EXECUTE"]


def test_past_due_unemitted_system_work_fails_closed() -> None:
    state = {"height": 10, "system_queue": []}
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=10,
        phase="post",
    )

    with pytest.raises(SystemQueueCorruptionError, match="system_queue_item_past_due"):
        system_tx_emitter(state, _tx_index(), next_height=11, phase="pre")

    assert state["system_queue"][0].get("emitted_height") is None


def test_duplicate_queue_id_is_canonical_corruption() -> None:
    state = {"system_queue": []}
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=11,
        phase="post",
    )
    duplicate = dict(state["system_queue"][0])
    state["system_queue"].append(duplicate)

    with pytest.raises(SystemQueueCorruptionError, match="system_queue_duplicate_queue_id"):
        build_system_queue_lookup(state)


def test_queue_id_must_commit_to_queue_item_contents() -> None:
    state = {"system_queue": []}
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=11,
        phase="post",
    )
    state["system_queue"][0]["payload"] = {"epoch": 2}

    with pytest.raises(SystemQueueCorruptionError, match="system_queue_item_queue_id_mismatch"):
        build_system_queue_lookup(state)


def test_queue_lookup_does_not_initialize_missing_canonical_state() -> None:
    state: dict = {}

    assert build_system_queue_lookup(state) == {}
    assert "system_queue" not in state


def test_enqueue_rejects_invalid_schedule_coordinates() -> None:
    with pytest.raises(ValueError, match="system_queue_due_height_invalid"):
        enqueue_system_tx({}, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=0)
    with pytest.raises(ValueError, match="system_queue_phase_invalid"):
        enqueue_system_tx(
            {}, tx_type="EPOCH_OPEN", payload={"epoch": 1}, due_height=1, phase="later"
        )
