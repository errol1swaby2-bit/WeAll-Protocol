from __future__ import annotations

from weall.runtime.helper_dispatch import HelperCertificateStore
from weall.runtime.helper_replay_guard import HelperRateBudget
from weall.runtime.helper_certificates import sign_helper_certificate


def test_helper_plan_window_rate_budget_batch33() -> None:
    store = HelperCertificateStore(
        budget=HelperRateBudget(per_helper_per_window=2, per_plan_total=10, window_ms=1000),
        plan_timeout_ms=5000,
    )
    store.open_plan_window(plan_id="plan-1", now_ms=1000)

    cert1 = sign_helper_certificate(
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
        issued_ms=1001,
    )
    cert2 = sign_helper_certificate(
        chain_id="c1",
        height=1,
        validator_epoch=1,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L2",
        helper_id="h1",
        lane_tx_ids=("t2",),
        descriptor_hash="d2",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1002,
    )
    cert3 = sign_helper_certificate(
        chain_id="c1",
        height=1,
        validator_epoch=1,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L3",
        helper_id="h1",
        lane_tx_ids=("t3",),
        descriptor_hash="d3",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1003,
    )

    assert store.accept_certificate(cert1, now_ms=1001).accepted is True
    assert store.accept_certificate(cert2, now_ms=1002).accepted is True
    decision = store.accept_certificate(cert3, now_ms=1003)
    assert decision.accepted is False
    assert decision.reason == "helper_rate_budget_exceeded"
