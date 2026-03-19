from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


class _FakePool:
    def __init__(self, items=None) -> None:
        self._items = list(items or [])

    def size(self) -> int:
        return len(self._items)


class _FakeExecutor:
    def __init__(self) -> None:
        self.chain_id = "obs-test"
        self.node_id = "@validator-2"
        self.mempool = _FakePool([{"tx_id": "tx:1"}, {"tx_id": "tx:2"}])
        self.attestation_pool = _FakePool([{"att_id": "att:1"}])
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "obs-test",
            "height": 17,
            "tip": "17:block",
            "tip_hash": "hash17",
            "tip_ts_ms": 1700000000017,
            "finalized": {"height": 15, "block_id": "15:block"},
            "roles": {
                "validators": {
                    "active_set": ["@validator-1", "@validator-2", "@validator-3", "@validator-4"]
                }
            },
            "bft": {
                "view": 6,
                "high_qc": {
                    "block_id": "16:block",
                    "parent_id": "15:block",
                    "view": 5,
                    "votes": [{"s": "a"}, {"s": "b"}, {"s": "c"}],
                },
                "locked_qc": {
                    "block_id": "15:block",
                    "parent_id": "14:block",
                    "view": 4,
                    "votes": [{"s": "a"}, {"s": "b"}, {"s": "c"}],
                },
            },
            "meta": {
                "schema_version": "1",
                "tx_index_hash": "txindexhash-obs",
            },
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash-obs"

    def bft_diagnostics(self) -> dict[str, object]:
        return {
            "view": 6,
            "high_qc_id": "16:block",
            "locked_qc_id": "15:block",
            "finalized_block_id": "15:block",
            "pending_remote_blocks_count": 1,
            "pending_candidates_count": 0,
            "pending_missing_qcs_count": 0,
            "pending_fetch_requests_count": 1,
            "pending_artifacts_pruned": False,
            "stalled": True,
            "stall_reason": "waiting_for_parent",
            "stalled_since_ts_ms": 1000,
            "stalled_for_ms": 250,
            "last_progress_ts_ms": 900,
            "last_view_advanced_ts_ms": 800,
            "last_qc_observed_ts_ms": 850,
            "last_timeout_emitted_ts_ms": 950,
            "last_fetch_requested_ts_ms": 1000,
            "last_fetch_satisfied_ts_ms": 0,
            "clock_skew_warning": False,
            "clock_skew_ahead_ms": 0,
            "median_time_past_ms": 1700000000000,
            "chain_time_floor_ms": 1700000000017,
            "timestamp_rule": "chain_time_successor_only",
            "uses_wall_clock_future_guard": False,
            "pacemaker_timeout_ms": 2000,
            "protocol_profile_hash": "profilehash",
            "reputation_scale": 1000,
            "max_block_future_drift_ms": 0,
            "max_block_time_advance_ms": 1,
            "clock_skew_warn_ms": 30000,
            "recent_rejection_summary": {
                "count": 2,
                "by_reason": {"chain_id_mismatch": 1, "missing_parent": 1},
                "by_message_type": {"proposal": 2},
                "latest": {
                    "ts_ms": 1111,
                    "message_type": "proposal",
                    "reason": "missing_parent",
                    "block_id": "blk-2",
                },
            },
            "journal_tail": [],
        }

    def bft_operator_forensics(self) -> dict[str, object]:
        return {
            "ok": True,
            "chain_id": "obs-test",
            "node_id": "@validator-2",
            "diagnostics": self.bft_diagnostics(),
            "recent_rejection_summary": self.bft_diagnostics()["recent_rejection_summary"],
            "recent_rejections": [
                {
                    "ts_ms": 1111,
                    "message_type": "proposal",
                    "reason": "missing_parent",
                    "block_id": "blk-2",
                },
                {
                    "ts_ms": 1100,
                    "message_type": "proposal",
                    "reason": "chain_id_mismatch",
                    "block_id": "blk-1",
                },
            ],
            "recent_key_events": [
                {
                    "ts_ms": 1200,
                    "event": "bft_fetch_requested",
                    "payload": {"block_id": "parent-1"},
                },
            ],
            "pending_fetch_request_descriptors": [
                {
                    "block_id": "parent-1",
                    "block_hash": "hash-parent-1",
                    "reason": "missing_parent",
                    "child_block_id": "blk-2",
                }
            ],
            "pending_outbound_messages": [
                {"kind": "vote", "payload": {"block_id": "blk-2", "view": 6}}
            ],
            "journal_tail": [],
        }


class _FakeNetNode:
    def peers_debug(self) -> dict[str, object]:
        return {
            "ok": True,
            "enabled": True,
            "counts": {
                "peers_total": 2,
                "peers_established": 1,
                "peers_identity_verified": 1,
                "peers_banned": 0,
            },
            "peers": [],
        }


def test_status_consensus_forensics_endpoint_exposes_operator_debug(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-2")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app)

    r = client.get("/v1/status/consensus/forensics")
    assert r.status_code == 200
    body = r.json()

    assert body["ok"] is True
    assert body["chain_id"] == "obs-test"
    assert body["node_id"] == "@validator-2"
    assert body["diagnostics"]["stall_reason"] == "waiting_for_parent"
    assert body["diagnostics"]["stalled_for_ms"] == 250
    assert body["recent_rejection_summary"]["count"] == 2
    assert body["recent_rejection_summary"]["latest"]["reason"] == "missing_parent"
    assert body["pending_fetch_request_descriptors"][0]["block_id"] == "parent-1"
    assert body["pending_outbound_messages"][0]["kind"] == "vote"


def test_executor_recent_rejection_summary_is_derived_from_journal(tmp_path) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        chain_id="weall:test",
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )

    ex._bft_record_event(
        "bft_message_rejected",
        message_type="proposal",
        reason="missing_parent",
        summary={"block_id": "blk-2", "block_hash": "hash-2", "view": 4, "signer": "@validator-2"},
    )
    ex._bft_record_event(
        "bft_message_rejected",
        message_type="proposal",
        reason="missing_parent",
        summary={"block_id": "blk-3", "block_hash": "hash-3", "view": 5, "signer": "@validator-3"},
    )
    ex._bft_record_event(
        "bft_message_rejected",
        message_type="qc",
        reason="chain_id_mismatch",
        summary={"block_id": "blk-4", "block_hash": "hash-4", "view": 6, "signer": "@validator-4"},
    )

    summary = ex.bft_recent_rejection_summary(limit=10)
    assert summary["count"] == 3
    assert summary["by_reason"]["missing_parent"] == 2
    assert summary["by_message_type"]["proposal"] == 2
    assert summary["latest"]["reason"] == "chain_id_mismatch"

    diag = ex.bft_diagnostics()
    assert diag["recent_rejection_summary"]["count"] == 3
    assert diag["recent_rejection_summary"]["by_reason"]["missing_parent"] == 2
