from __future__ import annotations

from pathlib import Path

from weall.runtime.reputation_events import (
    append_reputation_event,
    append_reputation_reversal_event,
    derive_role_eligibility,
    effective_reputation_events_for_eligibility,
    registry_payload,
)
from weall.runtime.system_tx_engine import (
    LINEAGE_WITNESS_PAYLOAD_KEY,
    bind_same_block_system_lineage,
    enqueue_system_tx,
    system_tx_emitter,
    validate_same_block_single_tx_lineage,
)
from weall.runtime.tx_id import compute_tx_id_from_envelope
from weall.tx.canon import load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]


def _index():
    return load_tx_index_json(ROOT / "generated" / "tx_index.json")


def _tx_id(ch: str) -> str:
    return "tx:" + ch * 64


def _reward_state() -> dict:
    return {
        "height": 29,
        "time": 1,
        "params": {
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "roles": {
            "node_operators": {"active_set": []},
            "jurors": {"active_set": []},
            "creators": {"active_set": []},
        },
        "economics": {"monetary_policy": {"issued": 0}},
        "system_queue": [],
    }


def test_p2_cons_006_and_econ_001_live_reward_chain_gets_exact_parent_witnesses() -> None:
    idx = _index()
    state = _reward_state()
    finalize = {
        "tx_type": "BLOCK_FINALIZE",
        "tx_id": _tx_id("a"),
        "system": True,
        "payload": {"block_id": "B1", "height": 1},
    }

    rebound = bind_same_block_system_lineage(
        state,
        idx,
        next_height=30,
        phase="post",
        prior_txs=[finalize],
        chain_id="chain-A",
        proposer="@validator",
    )
    assert rebound >= 2

    emitted = system_tx_emitter(
        state,
        idx,
        next_height=30,
        phase="post",
        proposer="@validator",
    )
    by_type = {env.tx_type: env for env in emitted}
    assert set(by_type) >= {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}

    mint = by_type["BLOCK_REWARD_MINT"]
    distribute = by_type["BLOCK_REWARD_DISTRIBUTE"]
    mint_witness = mint.payload[LINEAGE_WITNESS_PAYLOAD_KEY]
    assert mint_witness == {
        "version": 1,
        "kind": "SINGLE_TX",
        "parent_tx_type": "BLOCK_FINALIZE",
        "parent_tx_id": finalize["tx_id"],
        "same_block_position": 0,
    }

    mint_id = compute_tx_id_from_envelope("chain-A", mint)
    dist_witness = distribute.payload[LINEAGE_WITNESS_PAYLOAD_KEY]
    assert dist_witness == {
        "version": 1,
        "kind": "SINGLE_TX",
        "parent_tx_type": "BLOCK_REWARD_MINT",
        "parent_tx_id": mint_id,
        "same_block_position": 1,
    }

    mint_json = mint.to_json()
    mint_json["tx_id"] = mint_id
    assert validate_same_block_single_tx_lineage(idx, mint, prior_txs=[finalize]) == (True, "")
    assert validate_same_block_single_tx_lineage(
        idx, distribute, prior_txs=[finalize, mint_json]
    ) == (True, "")

    # system_tx_emitter schedules rewards again internally; semantic de-duplication
    # must keep the already witness-bound queue stable instead of recreating an
    # unbound sibling with the old queue-id.
    assert len(state["system_queue"]) == 2


def test_p2_econ_001_dormant_allocation_receipts_bind_to_exact_finalize_parent() -> None:
    idx = _index()
    state = _reward_state()
    state["params"]["economics_enabled"] = False
    finalize = {
        "tx_type": "BLOCK_FINALIZE",
        "tx_id": _tx_id("b"),
        "system": True,
        "payload": {"block_id": "B1", "height": 1},
    }
    enqueue_system_tx(
        state,
        tx_type="CREATOR_REWARD_ALLOCATE",
        payload={"allocation_id": "creator:1", "account_id": "@creator", "amount": 1},
        due_height=30,
        phase="post",
    )
    enqueue_system_tx(
        state,
        tx_type="TREASURY_REWARD_ALLOCATE",
        payload={"allocation_id": "treasury:1", "treasury_id": "protocol", "amount": 1},
        due_height=30,
        phase="post",
    )

    rebound = bind_same_block_system_lineage(
        state,
        idx,
        next_height=30,
        phase="post",
        prior_txs=[finalize],
        chain_id="chain-A",
        proposer="",
    )
    assert rebound == 2
    emitted = system_tx_emitter(state, idx, next_height=30, phase="post", proposer="")
    allocations = {x.tx_type: x for x in emitted}
    for tx_type in ("CREATOR_REWARD_ALLOCATE", "TREASURY_REWARD_ALLOCATE"):
        witness = allocations[tx_type].payload[LINEAGE_WITNESS_PAYLOAD_KEY]
        assert witness["parent_tx_type"] == "BLOCK_FINALIZE"
        assert witness["parent_tx_id"] == finalize["tx_id"]
        assert witness["same_block_position"] == 0


def test_p2_rep_002_reversal_removes_active_critical_disqualification() -> None:
    state: dict = {"height": 1, "time": 1}
    bad = append_reputation_event(
        state,
        actor_id="@validator",
        event_code="VALIDATOR_DOUBLE_SIGN",
        source_flow="validator",
        source_tx_id="slash-1",
        source_object_id="block-1",
        occurred_at_block=1,
        occurred_at_time=1,
    )
    before = derive_role_eligibility(state, "@validator")
    assert before["validator_operator"]["eligible"] is False
    assert "disqualifying_event:VALIDATOR_DOUBLE_SIGN" in before["validator_operator"]["reasons"]

    reversal = append_reputation_reversal_event(
        state,
        original_event_id=bad["event_id"],
        actor_id="@appeal-reviewer",
        source_tx_id="appeal-1",
        source_object_id="appeal-1",
        occurred_at_block=2,
        occurred_at_time=2,
    )
    after = derive_role_eligibility(state, "@validator")
    assert after["validator_operator"]["eligible"] is True
    assert after["validator_operator"]["reasons"] == ["eligible"]

    active_ids = {
        ev["event_id"]
        for ev in effective_reputation_events_for_eligibility(state["reputation"]["events"])
    }
    assert bad["event_id"] not in active_ids
    assert reversal["event_id"] in active_ids


def test_p2_rep_002_reversal_of_reversal_reactivates_original_semantics() -> None:
    state: dict = {"height": 1, "time": 1}
    bad = append_reputation_event(
        state,
        actor_id="@validator",
        event_code="VALIDATOR_INVALID_BLOCK",
        source_tx_id="bad-block",
        source_object_id="block-2",
        occurred_at_block=1,
    )
    first = append_reputation_reversal_event(
        state,
        original_event_id=bad["event_id"],
        actor_id="@reviewer",
        source_tx_id="appeal-2",
        source_object_id="appeal-2",
        occurred_at_block=2,
    )
    append_reputation_reversal_event(
        state,
        original_event_id=first["event_id"],
        actor_id="@reviewer",
        source_tx_id="appeal-3",
        source_object_id="appeal-3",
        occurred_at_block=3,
    )
    eligibility = derive_role_eligibility(state, "@validator")
    assert eligibility["validator_operator"]["eligible"] is False
    assert (
        "disqualifying_event:VALIDATOR_INVALID_BLOCK"
        in eligibility["validator_operator"]["reasons"]
    )


def test_p2_rep_003_unparameterized_decay_and_farming_are_truthfully_inactive() -> None:
    registry = registry_payload()
    by_code = {row["event_code"]: row for row in registry["events"]}

    juror = by_code["DISPUTE_JUROR_VOTED_ON_TIME"]
    assert juror["decay_policy"] == "positive_cap_per_epoch"
    assert juror["farming_policy"] == "cap_positive_dispute_participation_per_epoch"
    assert juror["policy_enforcement"]["decay"] == "metadata_only_not_runtime_enforced"
    assert juror["policy_enforcement"]["farming"] == "metadata_only_not_runtime_enforced"

    timeout = by_code["DISPUTE_JUROR_TIMED_OUT"]
    assert timeout["decay_policy"] == "recoverable_by_timely_reviews"
    assert timeout["policy_enforcement"]["decay"] == "metadata_only_not_runtime_enforced"

    assert registry["determinism"]["decay_runtime_enforced"] is False
    assert registry["determinism"]["farming_policy_runtime_enforced"] is False
