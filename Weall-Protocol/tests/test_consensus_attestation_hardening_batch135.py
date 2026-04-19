from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.crypto.sig import sign_tx_envelope_dict
from weall.ledger.state import LedgerView
from weall.runtime.block_admission import admit_block_txs
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


VALIDATOR_PRIVKEY = "11" * 32
VALIDATOR_PUBKEY = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"


def _tx_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


class _FakePool:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, env: dict) -> dict:
        self.items.append(dict(env))
        return {"ok": True, "att_id": f"att:{len(self.items)}"}

    def size(self) -> int:
        return len(self.items)


class _FakeExecutor:
    def __init__(self) -> None:
        self.chain_id = "weall-test"
        self.attestation_pool = _FakePool()
        self.tx_index = _tx_index()

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "height": 1,
            "tip": "b1",
            "accounts": {
                "val1": {
                    "nonce": 0,
                    "banned": False,
                    "locked": False,
                    "pubkey": VALIDATOR_PUBKEY,
                    "keys": [{"pubkey": VALIDATOR_PUBKEY, "active": True}],
                }
            },
            "roles": {"validators": {"active_set": ["val1"]}},
            "params": {"require_signatures": True, "chain_id": self.chain_id},
            "blocks": {"b1": {"block_id": "b1", "height": 1, "prev_block_id": "gen"}},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def submit_attestation(self, env: dict) -> dict:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}
        tx_type = str(env.get("tx_type") or "").strip().upper()
        if tx_type != "BLOCK_ATTEST":
            return {"ok": False, "error": "invalid_tx_type", "reason": "attestation_requires_block_attest"}
        payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
        block_id = str(payload.get("block_id") or payload.get("id") or "").strip()
        if not block_id:
            return {"ok": False, "error": "invalid_payload", "reason": "missing_block_id"}
        normalized = dict(env)
        normalized["block_id"] = block_id
        return self.attestation_pool.add(normalized)


def _make_signed_attestation(*, signer: str = "val1", payload: dict | None = None) -> dict:
    body = {
        "tx_type": "BLOCK_ATTEST",
        "chain_id": "weall-test",
        "signer": signer,
        "nonce": 1,
        "payload": payload or {"block_id": "b1", "height": 1, "round": 0},
        "system": False,
    }
    return sign_tx_envelope_dict(tx=body, privkey=VALIDATOR_PRIVKEY, encoding="hex")


def test_public_attestation_endpoint_requires_valid_signature_and_binds_validator() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    body = _make_signed_attestation()
    response = client.post("/v1/consensus/attest/submit", json=body)

    assert response.status_code == 200
    out = response.json()
    assert out["ok"] is True

    stored = app.state.executor.attestation_pool.items[0]
    assert stored["payload"]["validator"] == "val1"


def test_public_attestation_endpoint_rejects_payload_validator_mismatch() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    body = _make_signed_attestation(
        payload={"block_id": "b1", "height": 1, "round": 0, "validator": "val2"}
    )
    response = client.post("/v1/consensus/attest/submit", json=body)

    assert response.status_code == 403
    out = response.json()
    assert out["error"]["code"] == "validator_mismatch"


def test_public_attestation_endpoint_rejects_forged_signature() -> None:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    body = _make_signed_attestation()
    body["sig"] = "00" * 64
    response = client.post("/v1/consensus/attest/submit", json=body)

    assert response.status_code == 403
    out = response.json()
    assert out["error"]["code"] == "bad_sig"


def test_block_admission_rejects_duplicate_system_tx_ids() -> None:
    ledger = LedgerView.from_ledger({"chain_id": "weall-test", "accounts": {}, "params": {}, "roles": {}})
    tx_index = _tx_index()

    env1 = TxEnvelope(
        tx_type="ACCOUNT_UNLOCK",
        signer="SYSTEM",
        nonce=0,
        payload={"target": "alice"},
        sig="",
        parent="unlock:alice",
        system=True,
    )
    env2 = TxEnvelope(
        tx_type="ACCOUNT_UNLOCK",
        signer="SYSTEM",
        nonce=0,
        payload={"target": "alice"},
        sig="",
        parent="unlock:alice",
        system=True,
    )

    ok, block_reject, rejects = admit_block_txs([env1, env2], ledger, tx_index, verify_signatures=True)
    assert ok is True
    assert block_reject is None
    assert rejects[0] is None
    assert rejects[1] is not None
    assert rejects[1].reason == "duplicate_tx_id_in_block"
