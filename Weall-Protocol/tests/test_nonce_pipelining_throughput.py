from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor
from weall.runtime.mempool import compute_tx_id

ROOT = Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str = "weall-nonce-pipeline") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{chain_id}.db"),
        node_id="node-nonce-pipeline",
        chain_id=chain_id,
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )


def _client(tmp_path: Path, monkeypatch, *, chain_id: str = "weall-nonce-pipeline") -> tuple[TestClient, Path]:
    queue_path = tmp_path / "observer_tx_queue.json"
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(queue_path))
    app = create_app(boot_runtime=False)
    app.state.executor = _executor(tmp_path, chain_id=chain_id)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False), queue_path


def test_executor_accepts_contiguous_future_nonce_pending_in_mempool(tmp_path: Path) -> None:
    ex = _executor(tmp_path)

    registered = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@pipeline",
            "nonce": 1,
            "payload": {"pubkey": "k:pipeline"},
        }
    )
    assert registered.get("ok") is True
    meta = ex.produce_block(max_txs=10, allow_empty=False)
    assert meta.ok is True

    device = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@pipeline",
            "nonce": 2,
            "payload": {
                "device_id": "browser:pipeline",
                "device_type": "browser",
                "label": "Browser",
                "pubkey": "k:pipeline:device",
            },
        },
        ingress="mempool",
    )
    assert device.get("ok") is True

    # Before nonce pipelining, this would be rejected as bad_nonce because the
    # account's confirmed nonce is still 1. It is safe because nonce 2 is already
    # live in the mempool and block replay will still apply 2 before 3.
    second_device = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@pipeline",
            "nonce": 3,
            "payload": {
                "device_id": "browser:pipeline:second",
                "device_type": "browser",
                "label": "Second browser",
                "pubkey": "k:pipeline:device:second",
            },
        },
        ingress="mempool",
    )
    assert second_device.get("ok") is True, second_device

    block_meta = ex.produce_block(max_txs=10, allow_empty=False)
    assert block_meta.ok is True
    state = ex.read_state()
    account = state["accounts"]["@pipeline"]
    assert account["nonce"] == 3
    assert "browser:pipeline" in account["devices"]["by_id"]
    assert "browser:pipeline:second" in account["devices"]["by_id"]


def test_executor_rejects_gapped_future_nonce_without_contiguous_pending_mempool(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@gap",
            "nonce": 1,
            "payload": {"pubkey": "k:gap"},
        }
    ).get("ok") is True
    assert ex.produce_block(max_txs=10, allow_empty=False).ok is True

    gap = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_SESSION_KEY_ISSUE",
            "signer": "@gap",
            "nonce": 3,
            "payload": {"session_key": "session:gap", "ttl_s": 3600},
        },
        ingress="mempool",
    )
    assert gap.get("ok") is False
    assert gap.get("error") == "bad_nonce"


def test_account_nonce_status_includes_observer_queue_cursor(tmp_path: Path, monkeypatch) -> None:
    client, queue_path = _client(tmp_path, monkeypatch)
    ex: WeAllExecutor = client.app.state.executor  # type: ignore[attr-defined]
    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@queued",
            "nonce": 1,
            "payload": {"pubkey": "k:queued"},
        }
    ).get("ok") is True
    assert ex.produce_block(max_txs=10, allow_empty=False).ok is True

    queued_env: dict[str, Any] = {
        "tx_type": "ACCOUNT_SESSION_KEY_ISSUE",
        "signer": "@queued",
        "nonce": 2,
        "payload": {"session_key": "session:queued", "ttl_s": 3600},
        "chain_id": "weall-nonce-pipeline",
    }
    tx_id = compute_tx_id(queued_env, chain_id="weall-nonce-pipeline")
    queue_path.write_text(
        json.dumps(
            {
                "version": 2,
                "records": [
                    {
                        "tx_id": tx_id,
                        "chain_id": "weall-nonce-pipeline",
                        "envelope": queued_env,
                        "created_ms": 1,
                        "updated_ms": 1,
                        "attempts": 1,
                        "upstream_status": "accepted",
                        "local_state_synced": False,
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    res = client.get("/v1/accounts/%40queued/nonce")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["chain_nonce"] == 1
    assert body["observer_queue_pending_max_nonce"] == 2
    assert body["nonce_cursor"] == 2
    assert body["next_nonce"] == 3


def test_frontend_async_verification_pipelines_native_sequence_without_intermediate_nonce_waits() -> None:
    page = (ROOT.parent / "web" / "src" / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")
    assert "beginNonceSequence" in page
    assert "submitSignedTxInSequence" in page
    assert "request-open nonce yet. Evidence was not submitted" not in page
    assert "evidence-declare nonce yet. Evidence binding was not submitted" not in page
    assert "Mempool admission now accepts nonce N+1 when nonce" in page


def test_frontend_nonce_reservation_uses_pending_aware_account_nonce_endpoint() -> None:
    session_src = (ROOT.parent / "web" / "src" / "auth" / "session.ts").read_text(encoding="utf-8")
    api_src = (ROOT.parent / "web" / "src" / "api" / "weall.ts").read_text(encoding="utf-8")
    assert "weall.accountNonce(acct, base)" in session_src
    assert "nonce_cursor" in session_src
    assert "/v1/accounts/${encodeURIComponent(account)}/nonce" in api_src
