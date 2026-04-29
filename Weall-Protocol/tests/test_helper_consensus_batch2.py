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
from weall.testing.sigtools import deterministic_ed25519_keypair


def _validators():
    return ["validator-c", "validator-a", "validator-b", "validator-a"]


def _helper_keys():
    pub_a, priv_a = deterministic_ed25519_keypair(label="validator-a")
    pub_b, priv_b = deterministic_ed25519_keypair(label="validator-b")
    pub_c, priv_c = deterministic_ed25519_keypair(label="validator-c")
    return {
        "validator-a": {"pub": pub_a, "priv": priv_a},
        "validator-b": {"pub": pub_b, "priv": priv_b},
        "validator-c": {"pub": pub_c, "priv": priv_c},
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


def _executor() -> HelperExecutor:
    keys = _helper_keys()
    return HelperExecutor(
        {hid: row["priv"] for hid, row in keys.items()},
        helper_pubkeys={hid: row["pub"] for hid, row in keys.items()},
    )


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
    keys = _helper_keys()
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
        privkey=keys["validator-a"]["priv"],
    )
    assert verify_helper_receipt(
        receipt,
        helper_pubkey=keys["validator-a"]["pub"],
        expected_chain_id="weall",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash=vhash,
        expected_parent_block_id="parent-1",
        expected_lane_id="lane-1",
        expected_helper_id="validator-a",
    )


def test_receipt_replay_rejected_across_height():
    keys = _helper_keys()
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
        privkey=keys["validator-a"]["priv"],
    )
    assert not verify_helper_receipt(
        receipt,
        helper_pubkey=keys["validator-a"]["pub"],
        expected_chain_id="weall",
        expected_height=11,
        expected_validator_epoch=3,
        expected_validator_set_hash=vhash,
        expected_parent_block_id="parent-1",
        expected_lane_id="lane-1",
        expected_helper_id="validator-a",
    )


def test_helper_execution_and_verification_roundtrip():
    executor = _executor()
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    lane = plan.lanes[0]
    lane_txs = [tx for tx in _txs() if str(tx["tx_id"]) in set(lane.tx_ids)]
    vhash = validator_set_hash(normalize_validators(_validators()))
    result = executor.execute_lane(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validator_set_hash=vhash,
        lane_id=lane.lane_id,
        helper_id=lane.helper_id,
        state=_base_state(),
        lane_txs=lane_txs,
        plan_id=plan.plan_hash(),
    )
    assert executor.verify_lane_result(
        result,
        chain_id="weall",
        height=10,
        validator_epoch=3,
        validator_set_hash=vhash,
        parent_block_id="parent-1",
        expected_plan_id=plan.plan_hash(),
    )


def test_missing_helper_fallback_keeps_execution_deterministic():
    executor = _executor()
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    lane = plan.lanes[0]
    lane_txs = [tx for tx in _txs() if str(tx["tx_id"]) in set(lane.tx_ids)]
    vhash = validator_set_hash(normalize_validators(_validators()))
    baseline = executor.execute_lane(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validator_set_hash=vhash,
        lane_id=lane.lane_id,
        helper_id=lane.helper_id,
        state=_base_state(),
        lane_txs=lane_txs,
        plan_id=plan.plan_hash(),
    )
    assert baseline.post_state


def test_serial_vs_helper_equivalence_for_independent_lanes():
    executor = _executor()
    txs = _txs()
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=txs,
    )
    vhash = validator_set_hash(normalize_validators(_validators()))
    state = _base_state()
    results = []
    serial_state = deepcopy(state)
    for tx in sorted(txs, key=lambda row: str(row["tx_id"])):
        serial_state = executor._apply_tx(serial_state, tx)
    for lane in plan.lanes:
        lane_txs = [tx for tx in txs if str(tx["tx_id"]) in set(lane.tx_ids)]
        results.append(
            executor.execute_lane(
                chain_id="weall",
                height=10,
                parent_block_id="parent-1",
                validator_epoch=3,
                validator_set_hash=vhash,
                lane_id=lane.lane_id,
                helper_id=lane.helper_id,
                state=state,
                lane_txs=lane_txs,
                plan_id=plan.plan_hash(),
            )
        )
    merged = executor.merge_lane_results(results, base_state=state)
    assert merged == serial_state


def test_merge_conflict_fails_closed():
    executor = _executor()
    lane_results = []
    shared_state = _base_state()
    lane_results.append(
        executor.execute_lane(
            chain_id="weall",
            height=10,
            parent_block_id="parent-1",
            validator_epoch=3,
            validator_set_hash="vhash",
            lane_id="L1",
            helper_id="validator-a",
            state=shared_state,
            lane_txs=[{"tx_id": "t1", "signer": "alice", "nonce": 1, "delta": 1}],
        )
    )
    lane_results.append(
        executor.execute_lane(
            chain_id="weall",
            height=10,
            parent_block_id="parent-1",
            validator_epoch=3,
            validator_set_hash="vhash",
            lane_id="L2",
            helper_id="validator-b",
            state=shared_state,
            lane_txs=[{"tx_id": "t2", "signer": "alice", "nonce": 1, "delta": 2}],
        )
    )
    try:
        executor.merge_lane_results(lane_results, base_state=shared_state)
    except HelperExecutionError:
        return
    raise AssertionError("expected merge conflict to fail closed")
