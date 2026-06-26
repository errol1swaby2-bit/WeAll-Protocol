from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from weall.api.errors import ApiError

from weall.api.routes_public_parts.mempool import router as mempool_router
from weall.runtime.bft_hotstuff import quorum_threshold
from weall.runtime.executor import WeAllExecutor
from weall.runtime.genesis_config import load_genesis


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def test_quorum_threshold_uses_integer_only_math_batch135() -> None:
    assert quorum_threshold(0) == 0
    assert quorum_threshold(1) == 1
    assert quorum_threshold(2) == 2
    assert quorum_threshold(3) == 2
    assert quorum_threshold(4) == 3
    assert quorum_threshold(5) == 4
    assert quorum_threshold(7) == 5
    assert quorum_threshold(10_001) == ((2 * 10_001) + 2) // 3


def test_load_genesis_rejects_missing_chain_id_batch135(tmp_path: Path) -> None:
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps({"validators": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="genesis_config_missing_chain_id"):
        load_genesis(str(genesis_path))


def _mempool_test_app(executor: WeAllExecutor) -> FastAPI:
    app = FastAPI()

    @app.exception_handler(ApiError)
    async def _handle_api_error(_request: Request, exc: ApiError):
        return JSONResponse(
            status_code=int(exc.status_code),
            content={"ok": False, "error": str(exc.code), "message": str(exc.message), "details": exc.details},
        )

    app.include_router(mempool_router, prefix="/v1")
    app.state.executor = executor
    app.state.mempool = executor.mempool
    return app


def test_public_mempool_submit_enforces_same_schema_contract_as_tx_submit_batch135(
    tmp_path: Path,
) -> None:
    executor = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@node",
        chain_id="chain-A",
        tx_index_path=_tx_index_path(),
    )
    client = TestClient(_mempool_test_app(executor), raise_server_exceptions=False)

    response = client.post(
        "/v1/mempool/submit",
        json={
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": 7},
            "sig": "deadbeef",
            "chain_id": "chain-A",
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["error"] == "invalid_tx"


def test_public_mempool_submit_rejects_known_tx_missing_required_payload_field_batch135(
    tmp_path: Path,
) -> None:
    executor = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@node",
        chain_id="chain-A",
        tx_index_path=_tx_index_path(),
    )
    client = TestClient(_mempool_test_app(executor), raise_server_exceptions=False)

    response = client.post(
        "/v1/mempool/submit",
        json={
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {},
            "sig": "deadbeef",
            "chain_id": "chain-A",
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["error"] == "invalid_tx"
