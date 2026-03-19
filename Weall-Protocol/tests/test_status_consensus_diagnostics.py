from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def __init__(self, items=None) -> None:
        self._items = list(items or [])

    def size(self) -> int:
        return len(self._items)

    def peek(self, limit: int = 50):
        return self._items[:limit]

    def fetch_for_block(self, _block_id: str, limit: int = 50):
        return self._items[:limit]


class _FakeExecutor:
    def __init__(self) -> None:
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


class _FakeNetNode:
    def peers_debug(self) -> dict[str, object]:
        return {
            "ok": True,
            "enabled": True,
            "counts": {
                "peers_total": 2,
                "peers_established": 1,
                "peers_identity_verified": 1,
                "peers_banned": 1,
            },
            "peers": [
                {
                    "peer_id": "p1",
                    "established": True,
                    "identity_verified": True,
                    "strikes": 0,
                    "banned": False,
                },
                {
                    "peer_id": "p2",
                    "established": False,
                    "identity_verified": False,
                    "strikes": 3,
                    "banned": True,
                },
            ],
        }


def test_status_consensus_exposes_bft_diagnostics(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-2")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app)

    r = client.get("/v1/status/consensus")
    assert r.status_code == 200
    body = r.json()

    assert body["ok"] is True
    assert body["chain_id"] == "obs-test"
    assert body["height"] == 17
    assert body["finalized_height"] == 15
    assert body["active_validator_count"] == 4
    assert body["quorum_threshold"] == 3
    assert body["view"] == 6
    assert body["current_leader"] == "@validator-3"
    assert body["local_is_active_validator"] is True
    assert body["local_is_expected_leader"] is False
    assert body["high_qc"]["block_id"] == "16:block"
    assert body["high_qc"]["vote_count"] == 3
    assert body["locked_qc"]["block_id"] == "15:block"
    assert body["peer_counts"]["peers_total"] == 2
    assert body["tx_index_hash"] == "txindexhash-obs"

    fp = body["startup_fingerprint"]
    assert fp["chain_id"] == "obs-test"
    assert fp["node_id"] == "@validator-2"
    assert fp["schema_version"] == "1"
    assert fp["tx_index_hash"] == "txindexhash-obs"
    assert isinstance(fp["fingerprint"], str)
    assert len(fp["fingerprint"]) == 64


def test_status_operator_exposes_runtime_and_peer_diagnostics(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_ENABLE_PUBLIC_DEBUG", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator-2")
    monkeypatch.setenv("WEALL_DB_PATH", "./data/test-weall.db")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    monkeypatch.setenv("WEALL_BFT_UNSAFE_AUTOCOMMIT", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app)

    r = client.get("/v1/status/operator")
    assert r.status_code == 200
    body = r.json()

    assert body["ok"] is True
    assert body["db_path"] == "./data/test-weall.db"
    assert body["mempool_size"] == 2
    assert body["attestation_pool_size"] == 1
    assert body["block_loop"]["running"] is True
    assert body["net"]["enabled"] is True
    assert body["net"]["peer_counts"]["peers_established"] == 1
    assert len(body["net"]["peers"]) == 2
    assert body["consensus"]["bft_enabled"] is True
    assert body["consensus"]["validator_account"] == "@validator-2"

    # Batch 4: operator surfaces should expose the effective production posture,
    # not the unsafe raw env override values.
    assert body["consensus"]["profile_enforced"] is True
    assert body["consensus"]["qc_less_blocks_allowed"] is False
    assert body["consensus"]["unsafe_autocommit"] is False
    assert body["consensus"]["sigverify_required"] is True
    assert body["consensus"]["trusted_anchor_required"] is True

    posture = body["consensus"]["effective_posture"]
    assert posture["profile_enforced"] is True
    assert posture["qc_less_blocks_allowed"] is False
    assert posture["unsafe_autocommit_allowed"] is False
    assert posture["sigverify_required"] is True

    fp = body["startup_fingerprint"]
    assert fp["chain_id"] == "obs-test"
    assert fp["node_id"] == "@validator-2"
    assert fp["schema_version"] == "1"
    assert fp["tx_index_hash"] == "txindexhash-obs"
    assert isinstance(fp["fingerprint"], str)
    assert len(fp["fingerprint"]) == 64
