from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root


ROOT = Path(__file__).resolve().parents[1]


def _executor(db_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(db_path),
        node_id="@lifecycle-node",
        chain_id="p1-a17-clean-lifecycle",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )


def _client(executor: WeAllExecutor) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = executor
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _registration(account: str) -> dict:
    return {
        "chain_id": "p1-a17-clean-lifecycle",
        "tx_type": "ACCOUNT_REGISTER",
        "signer": account,
        "nonce": 1,
        "payload": {"pubkey": f"k:{account}"},
    }


def test_a17_f003_api_commit_restart_state_equivalence_and_continuation(
    tmp_path: Path,
) -> None:
    """Bounded clean lifecycle proof using the public API and durable executor DB.

    This intentionally proves a local/in-process ASGI node lifecycle, not an
    external-network or cross-machine production claim.
    """

    db_path = tmp_path / "lifecycle.sqlite"

    first = _executor(db_path)
    with _client(first) as client:
        submit = client.post("/v1/tx/submit", json=_registration("@alice"))
        assert submit.status_code == 200, submit.text
        tx1 = str(submit.json()["tx_id"])

        pending = client.get(f"/v1/tx/status/{tx1}")
        assert pending.status_code == 200, pending.text
        assert pending.json()["status"] == "pending"

        committed = first.produce_block(max_txs=1)
        assert committed.ok is True

        status = client.get(f"/v1/tx/status/{tx1}")
        assert status.status_code == 200, status.text
        assert status.json()["status"] == "confirmed"

        before = first.read_state()
        before_height = int(before["height"])
        before_tip = str(before["tip"])
        before_root = compute_state_root(before)
        before_status = first.get_tx_status(tx1)
        assert before_status["status"] == "confirmed"

    # The TestClient context above is the API shutdown boundary. Reconstruct the
    # executor and app from only the persisted DB to model restart.
    restarted = _executor(db_path)
    after = restarted.read_state()

    assert int(after["height"]) == before_height
    assert str(after["tip"]) == before_tip
    assert compute_state_root(after) == before_root
    assert restarted.get_tx_status(tx1) == before_status

    with _client(restarted) as client:
        persisted = client.get(f"/v1/tx/status/{tx1}")
        assert persisted.status_code == 200, persisted.text
        assert persisted.json()["status"] == "confirmed"
        assert int(persisted.json()["height"]) == before_height

        submit2 = client.post("/v1/tx/submit", json=_registration("@bob"))
        assert submit2.status_code == 200, submit2.text
        tx2 = str(submit2.json()["tx_id"])

        assert client.get(f"/v1/tx/status/{tx2}").json()["status"] == "pending"

        continued = restarted.produce_block(max_txs=1)
        assert continued.ok is True
        assert continued.height == before_height + 1

        final_status = client.get(f"/v1/tx/status/{tx2}")
        assert final_status.status_code == 200, final_status.text
        assert final_status.json()["status"] == "confirmed"

    final_state = restarted.read_state()
    assert int(final_state["height"]) == before_height + 1
    assert str(final_state["tip"]) != before_tip
    assert compute_state_root(final_state) != before_root
    assert "@alice" in (final_state.get("accounts") or {})
    assert "@bob" in (final_state.get("accounts") or {})
