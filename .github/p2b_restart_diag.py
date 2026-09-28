from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from helper_audit_testkit import lane_setup
from test_helper_materialized_merge_restart import _materialized_result
from weall.runtime.helper_merge import verify_materialized_lane_result


def main() -> None:
    txs = [
        {
            "tx_id": "c1",
            "tx_type": "CONTENT_POST_CREATE",
            "payload": {"account_id": "alice", "post_id": "1"},
        },
        {
            "tx_id": "i1",
            "tx_type": "ACCOUNT_REGISTER",
            "payload": {"account_id": "alice"},
        },
    ]
    lane_plans, plan_id = lane_setup(txs=txs)
    helper_lanes = tuple(
        sorted(
            (plan for plan in lane_plans if str(plan.helper_id or "")),
            key=lambda item: item.lane_id,
        )
    )
    for index, lane in enumerate(helper_lanes, 1):
        result = _materialized_result(
            lane_plan=lane,
            value=f"value-{index}",
            seed_byte=60 + index,
            plan_id=plan_id,
        )
        status = verify_materialized_lane_result(
            result,
            expected_lane_plan=lane,
            accepted_certificate=result.cert,
        )
        reads = sorted({path for access in lane.access_sets for path in access.reads})
        writes = sorted({path for access in lane.access_sets for path in access.writes})
        print(
            {
                "lane_id": lane.lane_id,
                "helper_id": lane.helper_id,
                "tx_ids": lane.tx_ids,
                "namespace_prefixes": lane.namespace_prefixes,
                "planned_reads": reads,
                "planned_writes": writes,
                "result_delta_paths": [op.path for op in result.delta_ops],
                "verification_ok": status.ok,
                "verification_code": status.code,
            }
        )
        if not status.ok:
            raise SystemExit(f"unexpected_verifier_rejection:{lane.lane_id}:{status.code}")


if __name__ == "__main__":
    main()
