from __future__ import annotations

import json
import os
import subprocess
import sys
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

_CHILD = r"""
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root

phase = sys.argv[1]
db_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])
prior_path = Path(sys.argv[4])
root = Path.cwd()


def executor():
    return WeAllExecutor(
        db_path=str(db_path),
        node_id="@lifecycle-process-node",
        chain_id="p1-a17-process-lifecycle",
        tx_index_path=str(root / "generated" / "tx_index.json"),
    )


def client(ex):
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def registration(account):
    return {
        "chain_id": "p1-a17-process-lifecycle",
        "tx_type": "ACCOUNT_REGISTER",
        "signer": account,
        "nonce": 1,
        "payload": {"pubkey": f"k:{account}"},
    }


ex = executor()
if phase == "first":
    with client(ex) as api:
        submitted = api.post("/v1/tx/submit", json=registration("@alice"))
        assert submitted.status_code == 200, submitted.text
        tx_id = str(submitted.json()["tx_id"])
        assert api.get(f"/v1/tx/status/{tx_id}").json()["status"] == "pending"

        block = ex.produce_block(max_txs=1)
        assert block.ok is True
        status = api.get(f"/v1/tx/status/{tx_id}").json()
        assert status["status"] == "confirmed"

    state = ex.read_state()
    payload = {
        "height": int(state["height"]),
        "tip": str(state["tip"]),
        "state_root": compute_state_root(state),
        "tx_id": tx_id,
        "tx_status": ex.get_tx_status(tx_id),
    }
elif phase == "second":
    prior = json.loads(prior_path.read_text(encoding="utf-8"))
    state = ex.read_state()
    assert int(state["height"]) == int(prior["height"])
    assert str(state["tip"]) == str(prior["tip"])
    assert compute_state_root(state) == str(prior["state_root"])
    assert ex.get_tx_status(str(prior["tx_id"])) == prior["tx_status"]

    with client(ex) as api:
        persisted = api.get(f"/v1/tx/status/{prior['tx_id']}")
        assert persisted.status_code == 200, persisted.text
        assert persisted.json()["status"] == "confirmed"

        submitted = api.post("/v1/tx/submit", json=registration("@bob"))
        assert submitted.status_code == 200, submitted.text
        tx2 = str(submitted.json()["tx_id"])
        block = ex.produce_block(max_txs=1)
        assert block.ok is True
        assert block.height == int(prior["height"]) + 1
        assert api.get(f"/v1/tx/status/{tx2}").json()["status"] == "confirmed"

    final = ex.read_state()
    payload = {
        "height": int(final["height"]),
        "tip": str(final["tip"]),
        "state_root": compute_state_root(final),
        "tx_id": tx2,
        "accounts": sorted((final.get("accounts") or {}).keys()),
    }
else:
    raise SystemExit(f"unknown phase: {phase}")

out_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
"""


def _run_lifecycle_process(
    *,
    phase: str,
    db_path: Path,
    out_path: Path,
    prior_path: Path,
) -> dict:
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("WEALL_"):
            env.pop(name, None)
    env["WEALL_MODE"] = "test"
    env["WEALL_API_BOOT_RUNTIME"] = "0"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD,
            phase,
            str(db_path),
            str(out_path),
            str(prior_path),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(out_path.read_text(encoding="utf-8"))


def test_a17_f003_process_restart_reloads_committed_state_and_continues(
    tmp_path: Path,
) -> None:
    """Fresh OS processes prove persisted API/commit/restart/continuation semantics."""

    db_path = tmp_path / "process-lifecycle.sqlite"
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    first = _run_lifecycle_process(
        phase="first",
        db_path=db_path,
        out_path=first_path,
        prior_path=first_path,
    )
    second = _run_lifecycle_process(
        phase="second",
        db_path=db_path,
        out_path=second_path,
        prior_path=first_path,
    )

    assert second["height"] == first["height"] + 1
    assert second["tip"] != first["tip"]
    assert second["state_root"] != first["state_root"]
    assert "@alice" in second["accounts"]
    assert "@bob" in second["accounts"]

