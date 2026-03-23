from __future__ import annotations

from copy import deepcopy

from weall.runtime.helper_executor import HelperExecutionError, HelperExecutor
from weall.runtime.helper_planner import (
    build_helper_plan,
    normalize_validators,
    partition_conflict_lanes,
    validator_set_hash,
)
from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt


def _validators():
    return ["validator-c", "validator-a", "validator-b", "validator-a"]


def _helper_secrets():
    return {
        "validator-a": "secret-a",
        "validator-b": "secret-b",
        "validator-c": "secret-c",
    }


def _txs():
    return [
        {
            "tx_id": "tx-2",
            "received_ms": 20,
            "signer": "bob",
            "nonce": 1,
            "delta": 7,
            "tx_type": "PAY",
            "conflict_keys": ["acct:bob"],
        },
        {
            "tx_id": "tx-1",
            "received_ms": 10,
            "signer": "alice",
            "nonce": 1,
            "delta": 5,
            "tx_type": "PAY",
            "conflict_keys": ["acct:alice"],
        },
    ]


def _base_state():
    return {"balances": {}, "nonces": {}}


def test_deterministic_planner_same_inputs_same_plan():
    plan1 = build_helper_plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    plan2 = build_helper_plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=list(reversed(_validators())),
        txs=list(reversed(_txs())),
    )
    assert plan1.to_canonical_dict() == plan2.to_canonical_dict()
    assert plan1.plan_hash() == plan2.plan_hash()


def test_validator_normalization_sort_and_dedup():
    assert normalize_validators(_validators()) == [
        "validator-a",
        "validator-b",
        "validator-c",
    ]


def test_partition_conflict_lanes_is_stable():
    lanes1 = partition_conflict_lanes(_txs())
    lanes2 = partition_conflict_lanes(list(reversed(_txs())))
    assert [lane_id for lane_id, _ in lanes1] == [lane_id for lane_id, _ in lanes2]


def test_receipt_verification_passes_for_exact_context():
    vhash = validator_set_hash(normalize_validators(_validators()))
    receipt = sign_helper_receipt(
        chain_id="weall",
        height=10,
        validator_epoch=3,
        validator_set_hash=vhash,
        parent_block_id="parent-1",
        lane_id="lane-1",
        ordered_tx_ids=["tx-1", "tx-2"],
        input_state_hash="in",
        output_state_hash="out",
        helper_id="validator-a",
        shared_secret="secret-a",
    )
    assert verify_helper_receipt(
        receipt,
        shared_secret="secret-a",
        expected_chain_id="weall",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash=vhash,
        expected_parent_block_id="parent-1",
        expected_lane_id="lane-1",
        expected_helper_id="validator-a",
    )


def test_receipt_replay_rejected_across_height():
    vhash = validator_set_hash(normalize_validators(_validators()))
    receipt = sign_helper_receipt(
        chain_id="weall",
        height=10,
        validator_epoch=3,
        validator_set_hash=vhash,
        parent_block_id="parent-1",
        lane_id="lane-1",
        ordered_tx_ids=["tx-1"],
        input_state_hash="in",
        output_state_hash="out",
        helper_id="validator-a",
        shared_secret="secret-a",
    )
    assert not verify_helper_receipt(
        receipt,
        shared_secret="secret-a",
        expected_chain_id="weall",
        expected_height=11,
        expected_validator_epoch=3,
        expected_validator_set_hash=vhash,
        expected_parent_block_id="parent-1",
        expected_lane_id="lane-1",
        expected_helper_id="validator-a",
    )


def test_helper_execution_and_verification_roundtrip():
    executor = HelperExecutor(_helper_secrets())
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    base_state = _base_state()

    lane_map = {lane_id: lane_txs for lane_id, lane_txs in partition_conflict_lanes(_txs())}
    for lane in plan.lanes:
        result = executor.execute_lane(
            chain_id=plan.chain_id,
            height=plan.height,
            parent_block_id=plan.parent_block_id,
            validator_epoch=plan.validator_epoch,
            validator_set_hash=plan.validator_set_hash,
            lane_id=lane.lane_id,
            helper_id=lane.helper_id,
            state=base_state,
            lane_txs=lane_map[lane.lane_id],
        )
        assert executor.verify_lane_result(
            result,
            chain_id=plan.chain_id,
            height=plan.height,
            validator_epoch=plan.validator_epoch,
            validator_set_hash=plan.validator_set_hash,
            parent_block_id=plan.parent_block_id,
        )


def test_missing_helper_fallback_keeps_execution_deterministic():
    executor = HelperExecutor(_helper_secrets())
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    lane_id, lane_txs = partition_conflict_lanes(_txs())[0]
    lane = next(l for l in plan.lanes if l.lane_id == lane_id)

    direct = executor.execute_lane(
        chain_id=plan.chain_id,
        height=plan.height,
        parent_block_id=plan.parent_block_id,
        validator_epoch=plan.validator_epoch,
        validator_set_hash=plan.validator_set_hash,
        lane_id=lane.lane_id,
        helper_id=lane.helper_id,
        state=_base_state(),
        lane_txs=lane_txs,
    )
    fallback = executor.fallback_execute_lane(
        chain_id=plan.chain_id,
        height=plan.height,
        parent_block_id=plan.parent_block_id,
        validator_epoch=plan.validator_epoch,
        validator_set_hash=plan.validator_set_hash,
        lane_id=lane.lane_id,
        helper_id=lane.helper_id,
        state=_base_state(),
        lane_txs=lane_txs,
    )
    assert direct.output_state_hash == fallback.output_state_hash
    assert direct.ordered_tx_ids == fallback.ordered_tx_ids


def test_serial_vs_helper_equivalence_for_independent_lanes():
    executor = HelperExecutor(_helper_secrets())
    txs = _txs()
    base_state = _base_state()

    serial = deepcopy(base_state)
    for tx in sorted(txs, key=lambda t: (t["received_ms"], t["tx_id"])):
        serial = executor._apply_tx(serial, tx)

    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=txs,
    )
    lane_map = {lane_id: lane_txs for lane_id, lane_txs in partition_conflict_lanes(txs)}
    results = []
    for lane in plan.lanes:
        results.append(
            executor.execute_lane(
                chain_id=plan.chain_id,
                height=plan.height,
                parent_block_id=plan.parent_block_id,
                validator_epoch=plan.validator_epoch,
                validator_set_hash=plan.validator_set_hash,
                lane_id=lane.lane_id,
                helper_id=lane.helper_id,
                state=base_state,
                lane_txs=lane_map[lane.lane_id],
            )
        )

    merged = executor.merge_lane_results(results, base_state=base_state)
    assert merged == serial


def test_merge_conflict_fails_closed():
    executor = HelperExecutor(_helper_secrets())
    conflict_txs = [
        {
            "tx_id": "tx-1",
            "received_ms": 10,
            "signer": "alice",
            "nonce": 1,
            "delta": 5,
            "tx_type": "PAY",
            "conflict_keys": ["acct:alice"],
        },
        {
            "tx_id": "tx-2",
            "received_ms": 20,
            "signer": "alice",
            "nonce": 1,
            "delta": 7,
            "tx_type": "PAY",
            "conflict_keys": ["acct:alice-OTHER"],
        },
    ]
    base_state = _base_state()
    plan = executor.plan(
        chain_id="weall",
        height=11,
        parent_block_id="parent-2",
        validator_epoch=3,
        validators=_validators(),
        txs=conflict_txs,
    )
    lane_map = {lane_id: lane_txs for lane_id, lane_txs in partition_conflict_lanes(conflict_txs)}
    results = []
    for lane in plan.lanes:
        results.append(
            executor.execute_lane(
                chain_id=plan.chain_id,
                height=plan.height,
                parent_block_id=plan.parent_block_id,
                validator_epoch=plan.validator_epoch,
                validator_set_hash=plan.validator_set_hash,
                lane_id=lane.lane_id,
                helper_id=lane.helper_id,
                state=base_state,
                lane_txs=lane_map[lane.lane_id],
            )
        )

    try:
        executor.merge_lane_results(results, base_state=base_state)
    except HelperExecutionError as exc:
        assert "merge conflict" in str(exc)
    else:
        raise AssertionError("expected merge conflict fail-closed behavior")
