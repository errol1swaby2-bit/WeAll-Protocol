from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import runtime_startup_fingerprint


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, *, node_id: str = "@n1", chain_id: str = "chain-time") -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    db_path = str(tmp_path / f"{node_id.strip('@')}.db")
    return WeAllExecutor(db_path=db_path, node_id=node_id, chain_id=chain_id, tx_index_path=tx_index_path)


def test_bft_diagnostics_expose_chain_time_floor_and_median(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    ex = _make_executor(tmp_path)

    blk1, st1, applied1, invalid1, err1 = ex.build_block_candidate(allow_empty=True, force_ts_ms=1_000)
    assert err1 == ""
    meta1 = ex.commit_block_candidate(block=blk1, new_state=st1, applied_ids=applied1, invalid_ids=invalid1)
    assert meta1.ok is True

    blk2, st2, applied2, invalid2, err2 = ex.build_block_candidate(allow_empty=True, force_ts_ms=2_000)
    assert err2 == ""
    meta2 = ex.commit_block_candidate(block=blk2, new_state=st2, applied_ids=applied2, invalid_ids=invalid2)
    assert meta2.ok is True

    blk3, st3, applied3, invalid3, err3 = ex.build_block_candidate(allow_empty=True, force_ts_ms=4_000)
    assert err3 == ""
    meta3 = ex.commit_block_candidate(block=blk3, new_state=st3, applied_ids=applied3, invalid_ids=invalid3)
    assert meta3.ok is True

    diag = ex.bft_diagnostics()
    assert diag["tip_ts_ms"] == 4_000
    assert diag["median_time_past_ms"] == 2_000
    assert diag["chain_time_floor_ms"] == 4_000
    assert diag["timestamp_rule"] == "chain_time_successor_only"
    assert diag["uses_wall_clock_future_guard"] is False
    assert diag["max_block_time_advance_ms"] > 0


def test_status_operator_exposes_timestamp_rule(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    ex = _make_executor(tmp_path, node_id="@validator-1", chain_id="chain-time-status")

    app = create_app(boot_runtime=False)
    app.state.executor = ex
    client = TestClient(app)

    r = client.get("/v1/status/operator")
    assert r.status_code == 200
    body = r.json()
    assert body["consensus"]["timestamp_rule"] == "chain_time_successor_only"
    assert body["consensus"]["uses_wall_clock_future_guard"] is False
    assert body["runtime_profile"]["timestamp_rule"] == "chain_time_successor_only"
    assert int(body["runtime_profile"]["max_block_time_advance_ms"]) > 0


def test_runtime_startup_fingerprint_commits_timestamp_rule() -> None:
    fp = runtime_startup_fingerprint(
        chain_id="weall-prod",
        node_id="node-1",
        tx_index_hash="abc123",
        schema_version="1",
        bft_enabled=True,
        validator_epoch=7,
        validator_set_hash="sethash-7",
    )
    assert fp["timestamp_rule"] == "chain_time_successor_only"
    assert isinstance(fp["fingerprint"], str)
    assert len(fp["fingerprint"]) == 64
