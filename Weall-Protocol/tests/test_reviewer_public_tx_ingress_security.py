from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from pathlib import Path
import pytest

from weall.api.app import app
from weall.runtime.executor import WeAllExecutor
from weall.crypto.sig import sign_tx_envelope_dict

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def client_with_executor(tmp_path: Path) -> TestClient:
    previous = getattr(app.state, "executor", None)
    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="reviewer-public-ingress",
        chain_id="weall-dev",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    app.state.executor = ex
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    if previous is not None:
        app.state.executor = previous
    elif hasattr(app.state, "executor"):
        delattr(app.state, "executor")


def _account_register_tx(
    account: str = "@reviewer-ingress", *, chain_id: str = "weall-dev"
) -> tuple[dict, str]:
    seed = bytes.fromhex("11" * 32)
    sk = MLDSA65PrivateKey.from_seed_bytes(seed)
    pubkey = sk.public_key().public_bytes_raw().hex()
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": account,
        "nonce": 1,
        "chain_id": chain_id,
        "payload": {"pubkey": pubkey},
    }
    return sign_tx_envelope_dict(tx=tx, privkey=seed.hex()), pubkey


def test_public_tx_submit_rejects_wrong_chain_id_before_signature(client_with_executor: TestClient) -> None:
    r = client_with_executor.post(
            "/v1/tx/submit",
            json={
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@wrong-chain",
                "nonce": 1,
                "chain_id": "not-this-chain",
                "payload": {"pubkey": "a" * 64},
            },
    )

    assert r.status_code == 403
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "chain_id_mismatch"


def test_public_tx_submit_rejects_missing_signature_in_prod_default(client_with_executor: TestClient) -> None:
    r = client_with_executor.post(
            "/v1/tx/submit",
            json={
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@missing-sig",
                "nonce": 1,
                "chain_id": "weall-dev",
                "payload": {"pubkey": "b" * 64},
            },
        )

    assert r.status_code == 403
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "missing_sig"


def test_public_tx_submit_rejects_system_signer_even_with_schema_valid_user_tx(client_with_executor: TestClient) -> None:
    r = client_with_executor.post(
            "/v1/tx/submit",
            json={
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "SYSTEM",
                "nonce": 1,
                "chain_id": "weall-dev",
                "payload": {"pubkey": "c" * 64},
                "sig": "00",
            },
        )

    assert r.status_code == 403
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "system_tx_forbidden"


def test_public_tx_submit_accepts_signed_account_register_then_status_is_explicit(client_with_executor: TestClient) -> None:
    tx, _pubkey = _account_register_tx("@reviewer-ingress-signed")
    r = client_with_executor.post("/v1/tx/submit", json=tx)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["status"] in {"accepted", "already_known"}
    tx_id = body["tx_id"]

    status = client_with_executor.get(f"/v1/tx/status/{tx_id}")
    assert status.status_code == 200
    status_body = status.json()

    assert status_body["ok"] is True
    assert status_body["status"] in {"pending", "confirmed", "unknown"}
