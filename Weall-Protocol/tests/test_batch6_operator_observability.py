from __future__ import annotations

import time

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def __init__(self, n: int = 0) -> None:
        self._n = int(n)

    def size(self) -> int:
        return self._n

    def peek(self, limit: int = 50):
        return []


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "@validator-4"
        self.mempool = _FakePool(3)
        self.attestation_pool = _FakePool(1)
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "batch6-observability",
            "height": 22,
            "tip": "22:block",
            "tip_hash": "tiphash22",
            "tip_ts_ms": int(time.time() * 1000),
            "finalized": {"height": 20, "block_id": "20:block"},
            "roles": {
                "validators": {
                    "active_set": ["@validator-1", "@validator-2", "@validator-3", "@validator-4"]
                }
            },
            "bft": {
                "view": 8,
                "high_qc": {
                    "block_id": "21:block",
                    "parent_id": "20:block",
                    "view": 7,
                    "votes": [{"s": "a"}, {"s": "b"}, {"s": "c"}],
                },
                "locked_qc": {
                    "block_id": "20:block",
                    "parent_id": "19:block",
                    "view": 6,
                    "votes": [{"s": "a"}, {"s": "b"}, {"s": "c"}],
                },
            },
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "meta": {
                "production_consensus_profile_hash": "profilehash-batch6",
                "schema_version": "3",
                "tx_index_hash": "txindexhash-batch6",
                "reputation_scale": 1000,
                "max_block_future_drift_ms": 15000,
                "clock_skew_warn_ms": 5000,
            },
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash-batch6"

    def bft_diagnostics(self) -> dict[str, object]:
        return {
            "view": 8,
            "high_qc_id": "21:block",
            "locked_qc_id": "20:block",
            "finalized_block_id": "20:block",
            "tip_block_id": "22:block",
            "tip_height": 22,
            "finalized_height": 20,
            "pending_remote_blocks": ["22:block"],
            "pending_remote_blocks_count": 1,
            "pending_candidates": [],
            "pending_candidates_count": 0,
            "pending_missing_qcs": [],
            "pending_missing_qcs_count": 0,
            "pending_fetch_requests": ["21:block"],
            "pending_fetch_requests_count": 1,
            "pending_artifacts_pruned": False,
            "pacemaker_timeout_ms": 4000,
            "stalled": True,
            "stall_reason": "waiting_for_parent",
            "tip_ts_ms": int(time.time() * 1000),
            "clock_skew_ahead_ms": 0,
            "clock_skew_warning": False,
            "protocol_profile_hash": "profilehash-batch6",
            "schema_version": "3",
            "tx_index_hash": "txindexhash-batch6",
            "reputation_scale": 1000,
            "max_block_future_drift_ms": 15000,
            "clock_skew_warn_ms": 5000,
            "journal_tail": [{"event": "bft_fetch_waiting"}],
        }


def test_status_consensus_exposes_operator_stall_diagnostics(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-4")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    r = client.get("/v1/status/consensus")
    assert r.status_code == 200
    body = r.json()

    assert body["ok"] is True
    assert body["current_leader"] == "@validator-1"
    assert body["next_leader"] == "@validator-2"
    assert body["diagnostics"]["stalled"] is True
    assert body["diagnostics"]["stall_reason"] == "waiting_for_parent"
    assert body["diagnostics"]["pending_fetch_requests_count"] == 1
    assert body["diagnostics"]["pending_artifacts_pruned"] is False
    assert body["runtime_profile"]["protocol_profile_hash"] == "profilehash-batch6"
    assert body["runtime_profile"]["reputation_scale"] == 1000


def test_status_operator_and_readyz_surface_consensus_diagnostics(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-4")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    ro = client.get("/v1/status/operator")
    assert ro.status_code == 200
    operator = ro.json()
    assert operator["consensus"]["stalled"] is True
    assert operator["consensus"]["stall_reason"] == "waiting_for_parent"
    assert operator["runtime_profile"]["protocol_profile_hash"] == "profilehash-batch6"

    rr = client.get("/v1/readyz")
    assert rr.status_code == 200
    readyz = rr.json()
    assert readyz["ok"] is True
    assert readyz["consensus_diagnostics"]["stall_reason"] == "waiting_for_parent"
    assert readyz["consensus_diagnostics"]["pending_fetch_requests_count"] == 1
    assert readyz["consensus_diagnostics"]["pending_artifacts_pruned"] is False
