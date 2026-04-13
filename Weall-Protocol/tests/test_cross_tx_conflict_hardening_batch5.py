from weall.runtime.conflict_lanes import plan_conflict_lanes
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflict_audit_samples import build_conflict_probe_tx


def test_group_signers_set_promotes_to_serial_when_it_mutates_group_and_treasury_batch5() -> None:
    tx = build_conflict_probe_tx(
        "GROUP_SIGNERS_SET",
        seed="1",
        payload_overrides={"group_id": "group-1", "treasury_id": "", "signers": ["a", "b"], "threshold": 2},
    )
    access = build_tx_access_set(tx)
    assert "treasury:wallet:TREASURY_GROUP::group-1" in access.writes
    assert access.lane_hint == "SERIAL"


def test_group_emissary_finalize_promotes_to_serial_when_it_syncs_treasury_signers_batch5() -> None:
    tx = build_conflict_probe_tx(
        "GROUP_EMISSARY_ELECTION_FINALIZE",
        seed="1",
        payload_overrides={"group_id": "group-2", "treasury_id": "", "election_id": "e-1"},
    )
    access = build_tx_access_set(tx)
    assert "treasury:wallet:TREASURY_GROUP::group-2" in access.writes
    assert access.lane_hint == "SERIAL"


def test_role_emissary_seat_promotes_to_serial_when_protocol_treasury_is_resynced_batch5() -> None:
    tx = build_conflict_probe_tx(
        "ROLE_EMISSARY_SEAT",
        seed="1",
        payload_overrides={"account_id": "acct-emissary"},
    )
    access = build_tx_access_set(tx)
    assert "treasury:wallet:TREASURY_PROTOCOL" in access.writes
    assert access.lane_hint == "SERIAL"


def test_cross_domain_group_and_treasury_updates_are_not_parallelized_batch5() -> None:
    plan = plan_conflict_lanes(
        [
            build_conflict_probe_tx(
                "GROUP_SIGNERS_SET",
                seed="1",
                payload_overrides={"group_id": "group-9", "treasury_id": "", "signers": ["a", "b"], "threshold": 2},
            ),
            build_conflict_probe_tx(
                "TREASURY_SIGNERS_SET",
                seed="2",
                payload_overrides={"treasury_id": "TREASURY_GROUP::group-9", "signers": ["a", "b"], "threshold": 2},
            ),
        ]
    )
    lane_map = {lane.lane_id: lane.tx_ids for lane in plan.lanes}
    assert any(lane_id.startswith("SERIAL") and "group_signers_set-1" in tx_ids for lane_id, tx_ids in lane_map.items())


