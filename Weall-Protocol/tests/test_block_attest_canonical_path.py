from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.api.routes_public_parts import consensus as consensus_route
from weall.ledger.state import LedgerView
from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus
from weall.runtime.executor import WeAllExecutor
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.tx_schema import validate_tx_envelope


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_ledger_view_validator_authority_prefers_explicit_consensus_set() -> None:
    state = {
        "accounts": {"stale": {}, "live": {}},
        "roles": {"validators": {"active_set": ["stale"]}},
        "consensus": {"validator_set": {"active_set": ["live"]}},
    }
    assert LedgerView.from_ledger(state).get_active_validator_set() == ["live"]

    state["consensus"]["validator_set"]["active_set"] = []
    assert LedgerView.from_ledger(state).get_active_validator_set() == []


def test_submit_attestation_uses_canonical_mempool_and_executes_in_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_MODE", "test")

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@node",
        chain_id="att-test",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    state = ex.state
    state["chain_id"] = "att-test"
    state.setdefault("params", {})["chain_id"] = "att-test"
    state.setdefault("accounts", {})["val1"] = {
        "nonce": 0,
        "banned": False,
        "locked": False,
        "pubkey": "k:val1",
    }
    # Deliberately contradictory legacy role state: explicit consensus wins.
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = []
    state.setdefault("consensus", {}).setdefault("validator_set", {})["active_set"] = ["val1"]
    state["height"] = 1
    state["tip"] = "b1"
    state.setdefault("blocks", {})["b1"] = {
        "height": 1,
        "prev_block_id": "gen",
        "block_ts_ms": 1,
    }
    ex._ledger_store.write(state)

    env = {
        "tx_type": "BLOCK_ATTEST",
        "chain_id": "att-test",
        "signer": "val1",
        "nonce": 1,
        "payload": {"block_id": "b1", "height": 1, "round": 0},
        "system": False,
        "sig": "",
    }
    result = ex.submit_attestation(env)

    assert result["ok"] is True
    tx_id = str(result["tx_id"])
    assert tx_id.startswith("tx:")
    assert ex.mempool.contains(tx_id) is True
    assert ex.attestation_pool.size() == 0

    pending = ex.mempool.peek(limit=10)
    assert len(pending) == 1
    # The canonical signed payload is not augmented with an unsigned validator field.
    assert pending[0]["payload"] == {"block_id": "b1", "height": 1, "round": 0}

    meta = ex.produce_block(max_txs=10)
    assert meta.ok is True
    assert meta.applied_count == 1
    committed = ex.read_state()
    assert committed["block_attestations"]["b1"]["val1"]["attestation"] == "yes"
    assert committed["accounts"]["val1"]["nonce"] == 1
    assert ex.mempool.contains(tx_id) is False


def test_block_attest_replay_rejects_unknown_block_and_height_mismatch_without_mutation() -> None:
    state = {
        "height": 2,
        "blocks": {"b2": {"height": 2, "prev_block_id": "b1"}},
        "consensus": {
            "validator_set": {"active_set": ["val1"]},
            "attestations_by_validator": {},
        },
        "block_attestations": {},
    }

    unknown = TxEnvelope(
        tx_type="BLOCK_ATTEST",
        signer="val1",
        nonce=1,
        payload={"block_id": "ghost", "height": 2, "round": 0},
        sig="",
        system=False,
    )
    before = repr(state)
    with pytest.raises(ConsensusApplyError, match="unknown_attested_block"):
        apply_consensus(state, unknown)
    assert repr(state) == before

    mismatch = TxEnvelope(
        tx_type="BLOCK_ATTEST",
        signer="val1",
        nonce=1,
        payload={"block_id": "b2", "height": 999, "round": 0},
        sig="",
        system=False,
    )
    before = repr(state)
    with pytest.raises(ConsensusApplyError, match="attested_block_height_mismatch"):
        apply_consensus(state, mismatch)
    assert repr(state) == before


def test_validator_attester_uses_pending_aware_nonce_and_emits_schema_valid_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import validator_attester as svc

    calls: list[tuple[str, str, dict | None]] = []

    def fake_http(method: str, url: str, body: dict | None = None) -> dict:
        calls.append((method, url, body))
        if method == "GET" and url.endswith("/v1/status"):
            return {
                "ok": True,
                "tip": "b7",
                "height": 7,
                "tip_round": 3,
                "chain_id": "att-chain",
                # These are intentionally present to prove they are not copied
                # into the strict BLOCK_ATTEST payload.
                "tip_proposal_id": "proposal:7",
                "justified_block_id": "b5",
                "justified_height": 5,
                "finalized_block_id": "b4",
                "finalized_height": 4,
            }
        if method == "GET" and "/v1/accounts/val1/nonce" in url:
            return {"ok": True, "nonce": 4, "nonce_cursor": 8, "next_nonce": 9}
        if method == "POST" and url.endswith("/v1/consensus/attest/submit"):
            return {"ok": True, "tx_id": "tx:attest"}
        raise AssertionError((method, url, body))

    monkeypatch.setattr(svc, "_http_json", fake_http)
    monkeypatch.setattr(
        svc,
        "sign_tx_envelope_dict",
        lambda *, tx, privkey, encoding: {**tx, "sig": "test-signature"},
    )
    monkeypatch.setenv("WEALL_MODE", "prod")

    rc = svc.run_attester_loop(
        producer_url="http://producer",
        signer="val1",
        privkey="private-key",
        poll_seconds=0.001,
        encoding="hex",
        once=True,
        verbose=False,
    )
    assert rc == 0

    posted = [body for method, url, body in calls if method == "POST"]
    assert len(posted) == 1
    tx = posted[0]
    assert isinstance(tx, dict)
    assert tx["nonce"] == 9
    assert tx["payload"] == {"block_id": "b7", "height": 7, "round": 3}
    validate_tx_envelope(tx)


def test_public_attestation_route_preserves_signed_envelope_and_returns_canonical_tx_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Pool:
        def size(self) -> int:
            return 1

    class _Executor:
        chain_id = "att-route"
        mempool = _Pool()

        def __init__(self) -> None:
            self.submitted: dict | None = None

        def read_state(self) -> dict:
            return {
                "chain_id": self.chain_id,
                "accounts": {"val1": {"nonce": 0, "pubkey": "k"}},
                "roles": {"validators": {"active_set": []}},
                "consensus": {"validator_set": {"active_set": ["val1"]}},
                "params": {"chain_id": self.chain_id},
            }

        def submit_attestation(self, env: dict) -> dict:
            self.submitted = dict(env)
            return {"ok": True, "tx_id": "tx:canonical"}

    ex = _Executor()
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    monkeypatch.setattr(consensus_route, "verify_tx_signature", lambda _state, _body: True)

    body = {
        "tx_type": "BLOCK_ATTEST",
        "chain_id": "att-route",
        "signer": "val1",
        "nonce": 1,
        "payload": {"block_id": "b1", "height": 1, "round": 0},
        "system": False,
        "sig": "signed-original",
    }
    response = TestClient(app).post("/v1/consensus/attest/submit", json=body)
    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "tx_id": "tx:canonical",
        "status": "accepted",
        "mempool_size": 1,
        "block_id": "b1",
    }
    assert ex.submitted == body


def test_public_attestation_route_rejects_stale_role_validator_when_consensus_set_excludes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Executor:
        chain_id = "att-route"

        def read_state(self) -> dict:
            return {
                "chain_id": self.chain_id,
                "accounts": {"stale": {"nonce": 0, "pubkey": "k"}, "live": {"nonce": 0}},
                "roles": {"validators": {"active_set": ["stale"]}},
                "consensus": {"validator_set": {"active_set": ["live"]}},
                "params": {"chain_id": self.chain_id},
            }

        def submit_attestation(self, env: dict) -> dict:  # pragma: no cover - must not run
            raise AssertionError(env)

    app = create_app(boot_runtime=False)
    app.state.executor = _Executor()
    monkeypatch.setattr(consensus_route, "verify_tx_signature", lambda _state, _body: True)
    body = {
        "tx_type": "BLOCK_ATTEST",
        "chain_id": "att-route",
        "signer": "stale",
        "nonce": 1,
        "payload": {"block_id": "b1", "height": 1, "round": 0},
        "system": False,
        "sig": "signed-original",
    }
    response = TestClient(app).post("/v1/consensus/attest/submit", json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "not_validator"
