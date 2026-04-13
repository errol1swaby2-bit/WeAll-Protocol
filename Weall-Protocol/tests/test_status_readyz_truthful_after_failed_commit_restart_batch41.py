from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _app_with_executor(executor: WeAllExecutor):
    app = create_app(boot_runtime=False)
    app.state.executor = executor
    return TestClient(app)


def test_status_and_readyz_remain_durable_after_failed_commit_restart_batch41(
    tmp_path: Path, monkeypatch
) -> None:
    """
    New coverage: operator surfaces must report only durable state after a failed
    commit attempt, both before and after restart.
    """
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@status-node",
        chain_id="batch41-status-readyz-after-failed-commit",
        tx_index_path=tx_index_path,
    )

    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user1",
            "nonce": 1,
            "payload": {"pubkey": "k:user1"},
        }
    )
    assert sub["ok"] is True
    tx_id = str(sub["tx_id"])

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""

    monkeypatch.setenv("WEALL_TEST_FAILPOINTS", "block_commit_after_ledger_state")
    meta = ex.commit_block_candidate(
        block=blk,
        new_state=st2,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is False
    monkeypatch.delenv("WEALL_TEST_FAILPOINTS", raising=False)

    client = _app_with_executor(ex)
    status = client.get("/v1/status")
    readyz = client.get("/v1/readyz")
    assert status.status_code == 200
    assert readyz.status_code == 200

    body = status.json()
    rz = readyz.json()
    assert int(body["height"]) == 0
    assert int(rz["height"]) == 0
    assert str(body["tip"] or "") == ""
    assert str(rz["tip"] or "") == ""
    assert ex.get_tx_status(tx_id)["status"] == "pending"

    ex2 = WeAllExecutor(
        db_path=db_path,
        node_id="@status-node",
        chain_id="batch41-status-readyz-after-failed-commit",
        tx_index_path=tx_index_path,
    )
    client2 = _app_with_executor(ex2)
    status2 = client2.get("/v1/status")
    readyz2 = client2.get("/v1/readyz")
    assert status2.status_code == 200
    assert readyz2.status_code == 200

    body2 = status2.json()
    rz2 = readyz2.json()
    assert int(body2["height"]) == 0
    assert int(rz2["height"]) == 0
    assert str(body2["tip"] or "") == ""
    assert str(rz2["tip"] or "") == ""
    assert ex2.get_tx_status(tx_id)["status"] == "pending"
