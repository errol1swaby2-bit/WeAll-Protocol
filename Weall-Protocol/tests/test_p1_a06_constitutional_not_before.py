from __future__ import annotations

from types import SimpleNamespace

from weall.runtime import block_admission, block_replay, block_time_admission
from weall.runtime.block_time_admission import BlockTimeVerdict
from weall.runtime.constitutional_clock import (
    ConstitutionalClockPolicy,
    expected_block_time_ms,
    not_before_ms,
)


def _positive_clock() -> ConstitutionalClockPolicy:
    return ConstitutionalClockPolicy(
        enabled=True,
        target_block_interval_ms=1_000,
        empty_blocks_enabled=True,
        procedure_time_source="finalized_block_height",
        block_time_derivation="genesis_time_plus_height_times_interval",
        no_fast_forward=True,
        no_height_skip=True,
        allowed_clock_skew_ms=100,
        genesis_time_ms=1_000_000,
    )


def test_a06_f002_shared_clock_rejects_before_slot_and_accepts_at_boundary(
    monkeypatch,
) -> None:
    policy = _positive_clock()
    monkeypatch.setattr(
        block_time_admission,
        "runtime_block_clock_policy",
        lambda **_kwargs: policy,
    )
    height = 3
    ts_ms = expected_block_time_ms(policy, height=height)
    boundary = not_before_ms(policy, height=height)

    early = block_time_admission.validate_block_timestamp(
        state={},
        height=height,
        block_ts_ms=ts_ms,
        chain_floor_ms=0,
        max_block_time_advance_ms=60_000,
        enforce_not_before=True,
        now_ms=boundary - 1,
    )
    assert early.ok is False
    assert early.code == "before_constitutional_slot"

    at_slot = block_time_admission.validate_block_timestamp(
        state={},
        height=height,
        block_ts_ms=ts_ms,
        chain_floor_ms=0,
        max_block_time_advance_ms=60_000,
        enforce_not_before=True,
        now_ms=boundary,
    )
    assert at_slot.ok is True


def test_a06_f002_bft_admission_enforces_not_before(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_validate(**kwargs):
        observed.update(kwargs)
        return BlockTimeVerdict(
            False,
            "before_constitutional_slot",
            "local_clock_before_constitutional_slot",
            {"height": kwargs["height"]},
        )

    monkeypatch.setattr(block_admission, "validate_block_timestamp", fake_validate)
    monkeypatch.setattr(
        block_admission,
        "_validate_helper_execution_metadata",
        lambda _block, _state: (True, None),
    )

    ok, reject = block_admission.admit_bft_block(
        block={"header": {"height": 1, "block_ts_ms": 1_001_000}},
        state={"height": 0},
        bft_enabled=True,
    )

    assert ok is False
    assert reject is not None
    assert reject.code == "bft_block_time_before_constitutional_slot"
    assert observed["enforce_not_before"] is True


class _ReplayHarness:
    def __init__(self) -> None:
        self.state = {"height": 0, "tip_hash": ""}
        self.chain_id = "weall-positive-clock-test"

    def chain_time_floor_ms(self) -> int:
        return 0


def test_a06_f002_follower_replay_enforces_not_before(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_validate(**kwargs):
        observed.update(kwargs)
        return BlockTimeVerdict(
            False,
            "before_constitutional_slot",
            "local_clock_before_constitutional_slot",
            {"height": kwargs["height"]},
        )

    monkeypatch.setattr(block_replay, "validate_block_timestamp", fake_validate)
    monkeypatch.setattr(
        block_replay,
        "ensure_block_hash",
        lambda block: (dict(block), "synthetic-block-hash"),
    )
    monkeypatch.setattr(
        block_replay,
        "RuntimeContext",
        SimpleNamespace(
            from_executor=lambda _executor: SimpleNamespace(
                scheduler_set=SimpleNamespace(),
                tx_execution_set=SimpleNamespace(
                    apply_tx_atomic_meta=lambda *_args, **_kwargs: None
                ),
            )
        ),
    )

    meta = block_replay.apply_block(
        _ReplayHarness(),
        {
            "header": {
                "chain_id": "weall-positive-clock-test",
                "height": 1,
                "block_ts_ms": 1_001_000,
                "prev_block_hash": "",
            }
        },
    )

    assert meta.ok is False
    assert meta.error == "bad_block:ts_before_constitutional_slot"
    assert observed["enforce_not_before"] is True
