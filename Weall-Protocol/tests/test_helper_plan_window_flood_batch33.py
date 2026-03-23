from __future__ import annotations

from weall.runtime.helper_dispatch import HelperCertificateStore
from weall.runtime.helper_replay_guard import HelperRateBudget
from weall.runtime.helper_certificates import sign_helper_certificate


def test_helper_plan_window_closed_rejects_late_artifacts_batch33() -> None:
    store = HelperCertificateStore(
        budget=HelperRateBudget(per_helper_per_window=10, per_plan_total=10, window_ms=1000),
        plan_timeout_ms=50,
    )
    store.open_plan_window(plan_id="plan-1", now_ms=1000)
    cert = sign_helper_certificate(
        chain_id="c1",
        height=1,
        validator_epoch=1,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        helper_id="h1",
        lane_tx_ids=("t1",),
        descriptor_hash="d1",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1200,
    )
    decision = store.accept_certificate(cert, now_ms=1200)
    assert decision.accepted is False
    assert decision.reason == "plan_window_closed"
