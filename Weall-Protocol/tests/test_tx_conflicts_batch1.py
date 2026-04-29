from weall.runtime.helper_planner import partition_conflict_lanes
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflicts import BarrierClass, TxFamily, build_conflict_descriptor


def test_balance_transfer_builds_scoped_parallel_descriptor() -> None:
    tx = {
        "tx_id": "tx-1",
        "tx_type": "BALANCE_TRANSFER",
        "signer": "alice",
        "payload": {"from_account_id": "alice", "to_account_id": "bob"},
    }
    descriptor = build_conflict_descriptor(tx)
    assert descriptor.family == TxFamily.ECONOMICS
    assert descriptor.barrier_class == BarrierClass.SCOPED_PARALLEL
    assert "economics:balance:alice" in descriptor.write_keys
    assert "economics:balance:bob" in descriptor.write_keys


def test_authority_sensitive_poh_tier_set_fails_into_identity_lane_with_authority_keys() -> None:
    tx = {
        "tx_id": "tx-2",
        "tx_type": "POH_TIER_SET",
        "signer": "juror-1",
        "payload": {"account_id": "alice", "case_id": "case-1"},
    }
    access = build_tx_access_set(tx)
    assert access.family == "POH"
    assert access.lane_hint == "IDENTITY"
    assert "authority:poh:alice" in access.writes
    assert "poh:user:alice" in access.writes


def test_global_barrier_consensus_tx_isolated_in_helper_partition() -> None:
    txs = [
        {
            "tx_id": "tx-a",
            "received_ms": 1,
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "alice",
            "payload": {"post_id": "post-1"},
        },
        {
            "tx_id": "tx-b",
            "received_ms": 2,
            "tx_type": "VALIDATOR_SET_UPDATE",
            "signer": "validator-a",
            "payload": {"validator_id": "validator-a"},
        },
        {
            "tx_id": "tx-c",
            "received_ms": 3,
            "tx_type": "CONTENT_POST_CREATE",
            "signer": "bob",
            "payload": {"post_id": "post-2"},
        },
    ]
    lanes = partition_conflict_lanes(txs)
    lane_ids = [lane_id for lane_id, _ in lanes]
    assert any(lane_id.startswith("SERIAL:tx-b") for lane_id in lane_ids)
