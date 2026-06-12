from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.protocol_time import protocol_time_height
from weall.runtime.reputation_events import append_reputation_event


class _FakePool:
    def size(self) -> int:
        return 0

    def peek(self, limit: int = 50):
        return []


class _FakeExecutor:
    node_id = "@height-truth-node"
    mempool = _FakePool()
    attestation_pool = _FakePool()

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "height-truth-test",
            "height": 42,
            "tip": "42:block",
            "tip_hash": "hash42",
            "tip_ts_ms": 1_700_000_000_042,
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindex-height-truth"


def test_protocol_time_surface_is_height_based_without_wall_clock_ms() -> None:
    state = {"height": 42, "tip": "42:block", "tip_hash": "hash42", "tip_ts_ms": 1_700_000_000_042}
    payload = protocol_time_height(state)
    assert payload == {
        "clock": "block_height",
        "height": 42,
        "current_height": 42,
        "next_height": 43,
        "wall_clock_ms_in_protocol_truth": False,
        "tip": "42:block",
        "tip_hash": "hash42",
    }
    assert "ts_ms" not in payload
    assert "tip_ts_ms" not in payload


def test_status_truth_surfaces_use_protocol_height_not_status_timestamp() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    status = client.get("/v1/status").json()
    assert status["ok"] is True
    assert "ts_ms" not in status
    assert status["protocol_time"]["clock"] == "block_height"
    assert status["protocol_time"]["height"] == 42
    assert status["protocol_time"]["next_height"] == 43
    assert status["protocol_time"]["wall_clock_ms_in_protocol_truth"] is False

    launch = client.get("/v1/status/launch-matrix").json()
    assert launch["ok"] is True
    assert "ts_ms" not in launch
    assert launch["protocol_time"]["height"] == 42
    assert launch["protocol_time"]["clock"] == "block_height"

    capabilities = client.get("/v1/status/testnet-capabilities").json()
    assert capabilities["ok"] is True
    assert "ts_ms" not in capabilities
    assert capabilities["protocol_time"]["height"] == 42
    assert capabilities["protocol_time"]["clock"] == "block_height"


def test_reputation_event_ignores_wall_clock_adjacent_time_inputs() -> None:
    state: dict[str, object] = {"height": 77, "time": 1_700_000_000}
    event = append_reputation_event(
        state,  # type: ignore[arg-type]
        actor_id="@juror",
        event_code="DISPUTE_JUROR_TIMED_OUT",
        source_flow="dispute",
        source_tx_id="tx-1",
        source_object_id="disp-1:@juror",
        occurred_at_block=77,
        occurred_at_time=1_700_000_000_000,
    )
    assert event["occurred_at_block"] == 77
    assert event["occurred_at_time"] == 77
    assert event["protocol_time_height"] == 77
    assert event["protocol_time_basis"] == "block_height"

    duplicate = append_reputation_event(
        state,  # type: ignore[arg-type]
        actor_id="@juror",
        event_code="DISPUTE_JUROR_TIMED_OUT",
        source_flow="dispute",
        source_tx_id="tx-1",
        source_object_id="disp-1:@juror",
        occurred_at_block=77,
        occurred_at_time=99_999_999_999,
    )
    assert duplicate["deduped"] is True
    assert duplicate["event_id"] == event["event_id"]
