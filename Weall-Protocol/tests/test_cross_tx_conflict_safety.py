from weall.runtime.conflict_lanes import plan_conflict_lanes
from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflict_audit_samples import build_conflict_probe_tx


def test_content_escalate_to_dispute_promotes_to_serial_when_it_crosses_content_and_dispute_domains_batch140() -> None:
    tx = build_conflict_probe_tx(
        "CONTENT_ESCALATE_TO_DISPUTE",
        seed="1",
        payload_overrides={"target_type": "content", "target_id": "post-1", "reason": "spam"},
    )
    access = build_tx_access_set(tx)
    assert "content:post:post-1" in access.writes
    assert "dispute:case:case-1" in access.writes
    assert access.lane_hint == "SERIAL"



def test_content_escalate_to_dispute_is_not_parallelized_alongside_content_flag_batch140() -> None:
    plan = plan_conflict_lanes(
        [
            build_conflict_probe_tx(
                "CONTENT_ESCALATE_TO_DISPUTE",
                seed="1",
                payload_overrides={"target_type": "content", "target_id": "post-serial", "reason": "spam"},
            ),
            build_conflict_probe_tx(
                "CONTENT_FLAG",
                seed="2",
                payload_overrides={"target_type": "content", "target_id": "post-serial", "reason": "abuse"},
            ),
        ]
    )
    lane_map = {lane.lane_id: lane.tx_ids for lane in plan.lanes}
    assert any(
        lane_id.startswith("SERIAL") and "content_escalate_to_dispute-1" in tx_ids
        for lane_id, tx_ids in lane_map.items()
    )
