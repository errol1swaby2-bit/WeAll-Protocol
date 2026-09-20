from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from weall.runtime import bft_outbound
from weall.runtime import bft_runtime_adapter as adapter
from weall.runtime.bft_hotstuff import HotStuffBFT


class _TimeoutExecutor:
    def __init__(self, *, view: int = 2, last_progress_ms: int = 1_000, timeout_ms: int = 10_000):
        self._bft = HotStuffBFT(chain_id="pby")
        self._bft.view = int(view)
        self._bft.last_progress_ms = int(last_progress_ms)
        self._bft.timeout_base_ms = int(timeout_ms)
        self._bft.timeout_backoff_exp = 0
        self._bft.timeout_backoff_cap = 4
        self.calls = 0
        self.handled = 0

    def _local_validator_account(self) -> str:
        return "v2"

    def _active_validators(self) -> list[str]:
        return ["v1", "v2", "v3", "v4"]

    def bft_make_timeout(self, *, view: int):
        self.calls += 1
        self._bft.note_timeout_emitted(view=int(view))
        return {"t": "TIMEOUT", "view": int(view), "signer": "v2"}

    def bft_handle_timeout(self, timeout_json):
        self.handled += 1
        return None

    def bft_timeout_check(self, now_ms: int | None = None):
        return adapter.bft_timeout_check(self, now_ms=now_ms)


def test_drive_timeouts_must_respect_pacemaker_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    ex = _TimeoutExecutor(last_progress_ms=1_000, timeout_ms=10_000)

    assert adapter.bft_drive_timeouts(ex, now_ms=5_000) == []
    assert ex.calls == 0


def test_same_view_timeout_must_not_be_resigned_on_repeated_network_ticks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_AUTOTIMEOUT", "1")
    ex = _TimeoutExecutor(last_progress_ms=0, timeout_ms=10_000)

    first = adapter.bft_drive_timeouts(ex, now_ms=10_000)
    second = adapter.bft_drive_timeouts(ex, now_ms=20_000)

    assert len(first) == 1
    assert second == []
    assert ex.calls == 1


def test_timeout_check_must_honor_durable_same_view_emission_cursor() -> None:
    ex = _TimeoutExecutor(view=2, last_progress_ms=0, timeout_ms=10_000)
    ex._bft.last_timeout_view = 2

    assert adapter.bft_timeout_check(ex, now_ms=50_000) is None
    assert ex.calls == 0


@dataclass
class _OutboxItem:
    kind: str
    payload: dict


def test_restart_hints_must_recover_timeout_cursor_from_pending_exact_outbox_artifact() -> None:
    ex = SimpleNamespace()
    ex._bft = HotStuffBFT(chain_id="pby")
    ex._bft.last_timeout_view = -1
    ex._bft_journal = SimpleNamespace(bootstrap_state=lambda: {"last_view": 0})
    ex._bft_outbox_store = SimpleNamespace(
        pending=lambda: [_OutboxItem(kind="timeout", payload={"view": 7})]
    )

    bft_outbound._restore_bft_restart_hints(ex)

    assert ex._bft.last_timeout_view == 7


def test_next_view_timeout_remains_emittable_after_prior_view_timeout() -> None:
    ex = _TimeoutExecutor(view=3, last_progress_ms=0, timeout_ms=10_000)
    ex._bft.last_timeout_view = 2

    out = adapter.bft_timeout_check(ex, now_ms=50_000)

    assert isinstance(out, dict)
    assert out["view"] == 3
    assert ex.calls == 1


def test_timeout_artifact_must_be_durably_enqueued_before_cursor_is_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    ex = SimpleNamespace()
    ex.chain_id = "pby"
    ex._bft = HotStuffBFT(chain_id="pby")
    ex._validator_signing_permitted = lambda: True
    ex._bft_phase_allows_artifact_processing = lambda: True
    ex._local_validator_identity = lambda: ("v2", "pk-v2", "sk-v2")
    ex._current_validator_epoch = lambda: 4
    ex._current_validator_set_hash = lambda: "set-4"
    ex._current_consensus_phase = lambda: "bft_active"
    ex._bft_enqueue_outbound = lambda kind, payload: events.append("enqueue")
    ex._persist_bft_state = lambda: events.append("persist")
    ex._bft_record_event = lambda event, **payload: events.append(str(event))

    monkeypatch.setattr(adapter, "_local_validator_sig_profile", lambda _self: "pq-mldsa-v1")
    monkeypatch.setattr(adapter, "sign_signature_for_profile", lambda **_kwargs: "deadbeef")

    out = adapter.bft_make_timeout(ex, view=4)

    assert isinstance(out, dict)
    assert events == ["enqueue", "persist", "bft_timeout_emitted"]
    assert ex._bft.last_timeout_view == 4
