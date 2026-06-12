from __future__ import annotations

from copy import deepcopy

from weall.runtime.helper_executor import HelperExecutionError, HelperExecutor
from weall.runtime.helper_planner import build_helper_plan, normalize_validators, validator_set_hash
from weall.runtime.helper_receipts import sign_helper_receipt, verify_helper_receipt
from weall.testing.sigtools import deterministic_ed25519_keypair


def _validators() -> list[str]:
    return ["validator-c", "validator-a", "validator-b", "validator-a"]


def _keys() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for helper_id in ("validator-a", "validator-b", "validator-c"):
        pub, priv = deterministic_ed25519_keypair(label=f"helper-consensus::{helper_id}")
        out[helper_id] = {"pub": pub, "priv": priv}
    return out


def _executor() -> HelperExecutor:
    keys = _keys()
    return HelperExecutor(
        {helper_id: row["priv"] for helper_id, row in keys.items()},
        helper_pubkeys={helper_id: row["pub"] for helper_id, row in keys.items()},
    )


def _txs() -> list[dict]:
    return [
        {"tx_id": "tx-2", "received_ms": 20, "signer": "bob", "nonce": 1, "delta": 7, "conflict_keys": ["acct:bob"]},
        {"tx_id": "tx-1", "received_ms": 10, "signer": "alice", "nonce": 1, "delta": 5, "conflict_keys": ["acct:alice"]},
    ]


def _state() -> dict:
    return {"balances": {}, "nonces": {}}


def test_serial_helper_equivalence() -> None:
    executor = _executor()
    txs = _txs()
    validators = normalize_validators(_validators())
    vhash = validator_set_hash(validators)
    plan = executor.plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=txs,
    )
    plan_id = plan.plan_hash()
    base = _state()

    serial = deepcopy(base)
    for tx in sorted(txs, key=lambda row: str(row["tx_id"])):
        serial = executor._apply_tx(serial, tx)

    lane_results = []
    for lane in plan.lanes:
        lane_txs = [tx for tx in txs if str(tx["tx_id"]) in set(lane.tx_ids)]
        lane_results.append(
            executor.execute_lane(
                chain_id="weall",
                height=10,
                parent_block_id="parent-1",
                validator_epoch=3,
                validator_set_hash=vhash,
                lane_id=lane.lane_id,
                helper_id=lane.helper_id,
                state=base,
                lane_txs=lane_txs,
                plan_id=plan_id,
            )
        )

    assert executor.merge_lane_results(lane_results, base_state=base) == serial


def test_deterministic_planner() -> None:
    left = build_helper_plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=_validators(),
        txs=_txs(),
    )
    right = build_helper_plan(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validators=list(reversed(_validators())),
        txs=list(reversed(_txs())),
    )

    assert left.to_canonical_dict() == right.to_canonical_dict()
    assert left.plan_hash() == right.plan_hash()


def test_receipt_replay_rejection() -> None:
    keys = _keys()
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
        plan_id="plan-1",
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
        expected_ordered_tx_ids=["tx-1"],
        expected_plan_id="plan-1",
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
        expected_ordered_tx_ids=["tx-1"],
        expected_plan_id="plan-1",
    )
    assert not verify_helper_receipt(
        receipt,
        helper_pubkey=keys["validator-a"]["pub"],
        expected_chain_id="weall",
        expected_height=10,
        expected_validator_epoch=3,
        expected_validator_set_hash=vhash,
        expected_parent_block_id="parent-2",
        expected_lane_id="lane-1",
        expected_helper_id="validator-a",
        expected_ordered_tx_ids=["tx-1"],
        expected_plan_id="plan-1",
    )


def test_missing_helper_fallback() -> None:
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

    missing_executor = HelperExecutor({}, helper_pubkeys={})
    try:
        missing_executor.execute_lane(
            chain_id="weall",
            height=10,
            parent_block_id="parent-1",
            validator_epoch=3,
            validator_set_hash=vhash,
            lane_id=lane.lane_id,
            helper_id=lane.helper_id,
            state=_state(),
            lane_txs=lane_txs,
            plan_id=plan.plan_hash(),
        )
    except HelperExecutionError as exc:
        assert "missing helper signing material" in str(exc)
    else:  # pragma: no cover - defensive guard for future helper executor rewrites
        raise AssertionError("missing helper must fail closed before receipt acceptance")

    fallback = executor.fallback_execute_lane(
        chain_id="weall",
        height=10,
        parent_block_id="parent-1",
        validator_epoch=3,
        validator_set_hash=vhash,
        lane_id=lane.lane_id,
        helper_id=lane.helper_id,
        state=_state(),
        lane_txs=lane_txs,
        plan_id=plan.plan_hash(),
    )
    assert executor.verify_lane_result(
        fallback,
        chain_id="weall",
        height=10,
        validator_epoch=3,
        validator_set_hash=vhash,
        parent_block_id="parent-1",
        expected_plan_id=plan.plan_hash(),
    )


def test_crash_recovery_equivalence() -> None:
    executor = _executor()
    txs = _txs()
    validators = _validators()
    vhash = validator_set_hash(normalize_validators(validators))
    first_plan = executor.plan(
        chain_id="weall",
        height=42,
        parent_block_id="parent-crash",
        validator_epoch=8,
        validators=validators,
        txs=txs,
    )
    replay_plan = executor.plan(
        chain_id="weall",
        height=42,
        parent_block_id="parent-crash",
        validator_epoch=8,
        validators=list(reversed(validators)),
        txs=list(reversed(txs)),
    )
    assert first_plan.plan_hash() == replay_plan.plan_hash()

    def run(plan) -> dict:
        results = []
        for lane in plan.lanes:
            lane_txs = [tx for tx in txs if str(tx["tx_id"]) in set(lane.tx_ids)]
            results.append(
                executor.execute_lane(
                    chain_id="weall",
                    height=42,
                    parent_block_id="parent-crash",
                    validator_epoch=8,
                    validator_set_hash=vhash,
                    lane_id=lane.lane_id,
                    helper_id=lane.helper_id,
                    state=_state(),
                    lane_txs=lane_txs,
                    plan_id=plan.plan_hash(),
                )
            )
        return executor.merge_lane_results(results, base_state=_state())

    assert run(first_plan) == run(replay_plan)
