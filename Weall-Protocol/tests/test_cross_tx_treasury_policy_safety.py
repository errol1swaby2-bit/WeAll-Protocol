from weall.runtime.conflict_lanes import plan_conflict_lanes
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflict_audit_samples import build_conflict_probe_tx


TREASURY_POLICY_SERIAL_TYPES = {
    "TREASURY_SIGNER_ADD",
    "TREASURY_SIGNER_REMOVE",
    "TREASURY_POLICY_SET",
    "GROUP_TREASURY_POLICY_SET",
}


def test_treasury_policy_bridge_txs_fail_closed_to_serial_batch142() -> None:
    for tx_type in sorted(TREASURY_POLICY_SERIAL_TYPES):
        access = build_tx_access_set(build_conflict_probe_tx(tx_type, seed="1"))
        assert access.lane_hint == "SERIAL", tx_type
        assert any(key.startswith("authority:") for key in access.writes), tx_type


def test_treasury_policy_set_is_not_parallelized_with_same_wallet_signer_mutation_batch142() -> None:
    wallet_id = "wallet-shared"
    plan = plan_conflict_lanes(
        [
            build_conflict_probe_tx(
                "TREASURY_POLICY_SET",
                seed="2",
                payload_overrides={"wallet_id": wallet_id, "treasury_id": wallet_id},
            ),
            build_conflict_probe_tx(
                "TREASURY_SIGNER_ADD",
                seed="3",
                payload_overrides={"wallet_id": wallet_id, "treasury_id": wallet_id, "signer": "acct-signer"},
            ),
        ]
    )
    serial_lane_ids = {
        lane.lane_id
        for lane in plan.lanes
        if lane.lane_id.startswith("SERIAL")
        and (
            "treasury_policy_set-2" in lane.tx_ids
            or "treasury_signer_add-3" in lane.tx_ids
        )
    }
    assert len(serial_lane_ids) == 2


def test_group_treasury_policy_set_is_not_parallelized_with_group_treasury_create_batch142() -> None:
    group_id = "group-shared"
    plan = plan_conflict_lanes(
        [
            build_conflict_probe_tx(
                "GROUP_TREASURY_POLICY_SET",
                seed="4",
                payload_overrides={"group_id": group_id},
            ),
            build_conflict_probe_tx(
                "GROUP_TREASURY_CREATE",
                seed="5",
                payload_overrides={"group_id": group_id},
            ),
        ]
    )
    lane_map = {lane.lane_id: lane.tx_ids for lane in plan.lanes}
    assert any(
        lane_id.startswith("SERIAL") and "group_treasury_policy_set-4" in tx_ids
        for lane_id, tx_ids in lane_map.items()
    )
