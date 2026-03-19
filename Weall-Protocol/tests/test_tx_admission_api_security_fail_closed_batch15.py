from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.security import RateLimitMiddleware, RequestSizeLimitMiddleware
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    for name in (
        "WEALL_MAX_TX_PAYLOAD_BYTES",
        "WEALL_MAX_TX_PAYLOAD_DEPTH",
        "WEALL_MAX_TX_PAYLOAD_LIST_LEN",
        "WEALL_MAX_TX_PAYLOAD_DICT_KEYS",
        "WEALL_MAX_TX_PAYLOAD_STR_LEN",
        "WEALL_MAX_TX_PAYLOAD_NODES",
        "WEALL_MAX_REQUEST_BYTES",
        "WEALL_MAX_JSON_BYTES",
        "WEALL_IPFS_MAX_UPLOAD_BYTES",
        "WEALL_MEDIA_MULTIPART_OVERHEAD_BYTES",
        "WEALL_RL_TTL_S",
        "WEALL_RL_MAX_KEYS",
        "WEALL_RL_PRUNE_EVERY",
    ):
        monkeypatch.delenv(name, raising=False)


def _env() -> TxEnvelope:
    return TxEnvelope(tx_type="PEER_ADVERTISE", signer="@alice", nonce=1, payload={"endpoint": "tcp://node:9000"}, sig="sig")


def _ledger() -> dict:
    return {"accounts": {"@alice": {"nonce": 0}}}


def _canon() -> TxIndex:
    return TxIndex({"PEER_ADVERTISE": {}})


@pytest.mark.parametrize(
    "name",
    [
        "WEALL_MAX_TX_PAYLOAD_BYTES",
        "WEALL_MAX_TX_PAYLOAD_DEPTH",
        "WEALL_MAX_TX_PAYLOAD_LIST_LEN",
        "WEALL_MAX_TX_PAYLOAD_DICT_KEYS",
        "WEALL_MAX_TX_PAYLOAD_STR_LEN",
        "WEALL_MAX_TX_PAYLOAD_NODES",
    ],
)
def test_tx_admission_rejects_invalid_explicit_payload_limit_env_in_prod(monkeypatch, name):
    monkeypatch.setenv(name, "bogus")
    with pytest.raises(ValueError, match=fr"invalid_integer_env:{name}"):
        admit_tx(_env(), _ledger(), _canon(), context="mempool")


def test_request_size_limit_rejects_invalid_explicit_env_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "bogus")
    app = create_app(boot_runtime=False)
    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_MAX_REQUEST_BYTES"):
        app.build_middleware_stack()


def test_request_size_limit_rejects_invalid_media_limit_env_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_IPFS_MAX_UPLOAD_BYTES", "bogus")
    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware)

    @app.post("/v1/media/upload")
    async def _upload():
        return {"ok": True}

    client = TestClient(app)
    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_IPFS_MAX_UPLOAD_BYTES"):
        client.post("/v1/media/upload", data=b"x")


@pytest.mark.parametrize("name", ["WEALL_RL_TTL_S", "WEALL_RL_MAX_KEYS", "WEALL_RL_PRUNE_EVERY"])
def test_rate_limit_rejects_invalid_explicit_env_in_prod(monkeypatch, name):
    monkeypatch.setenv(name, "bogus")
    app = create_app(boot_runtime=False)
    with pytest.raises(ValueError, match=fr"invalid_integer_env:{name}"):
        app.build_middleware_stack()


def test_invalid_explicit_limit_envs_still_fall_back_in_dev(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MAX_TX_PAYLOAD_BYTES", "bogus")
    monkeypatch.setenv("WEALL_MAX_REQUEST_BYTES", "bogus")
    monkeypatch.setenv("WEALL_RL_MAX_KEYS", "bogus")

    verdict = admit_tx(_env(), _ledger(), _canon(), context="mempool")
    assert verdict.ok is True

    app = create_app(boot_runtime=False)
    assert app is not None
