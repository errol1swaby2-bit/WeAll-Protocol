from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.executor import WeAllExecutor
from weall.runtime.mempool import compute_tx_id

ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, _limit: int | None = None) -> bytes:
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")


class _FakeExecutor:
    chain_id = "batch362"

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state

    def tx_index_hash(self) -> str:
        return "batch362-tx-index"


def _client_with_executor(ex: Any) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _real_client(tmp_path: Path) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = WeAllExecutor(
        db_path=str(tmp_path / "observer-362.db"),
        node_id="observer-362",
        chain_id="weall-observer-362",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _signed_account_register(account: str, *, chain_id: str = "weall-observer-362") -> dict[str, Any]:
    seed = bytes.fromhex("62" * 32)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": account,
        "nonce": 1,
        "chain_id": chain_id,
        "payload": {"pubkey": pubkey},
    }
    return sign_tx_envelope_dict(tx=tx, privkey=seed.hex())


def _read_outbox(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _state() -> dict[str, Any]:
    return {
        "chain_id": "batch362",
        "accounts": {"@alice": {"nonce": 0, "poh_tier": 2}},
        "groups_by_id": {
            "g1": {
                "id": "g1",
                "name": "Big group",
                "members": {f"@member{i:03d}": {"role": "member"} for i in range(6)},
            }
        },
        "group_roles_by_id": {
            "g1": {
                "group_id": "g1",
                "members": {f"@role_member{i:03d}": {"role": "member"} for i in range(4)},
            }
        },
        "gov_proposals_by_id": {
            "p1": {
                "proposal_id": "p1",
                "stage": "voting",
                "votes": {f"@voter{i:03d}": {"vote": "yes" if i % 2 else "no"} for i in range(5)},
                "poll_votes": {f"@poll{i:03d}": {"vote": "yes"} for i in range(3)},
            }
        },
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "stage": "open",
                "jurors": {f"@juror{i:03d}": {"status": "assigned"} for i in range(5)},
                "votes": {f"@juror{i:03d}": {"vote": "yes"} for i in range(5)},
                "evidence": [{"evidence_id": f"e{i}"} for i in range(4)],
                "appeals": [{"appeal_id": f"a{i}"} for i in range(2)],
            }
        },
    }


def test_upstream_manifest_top_level_chain_and_hash_are_enforced_batch362(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")
    monkeypatch.setenv("WEALL_EXPECTED_UPSTREAM_MANIFEST_HASH", "expected-manifest")

    tx = _signed_account_register("@observer_362_manifest")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-362")

    calls: list[str] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        if req.full_url.endswith("/v1/chain/identity"):
            return _FakeResponse({"ok": True, "chain_id": "weall-observer-362"})
        if req.full_url.endswith("/v1/chain/manifest"):
            return _FakeResponse({"ok": True, "chain_id": "weall-observer-362", "manifest_hash": "wrong-manifest"})
        raise AssertionError("tx forwarding must not happen after manifest hash mismatch")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)
    with _real_client(tmp_path) as client:
        assert client.post("/v1/tx/submit", json=tx).status_code == 200
        drained = client.post("/v1/observer/edge/outbox/drain", headers={"X-WeAll-Operator-Token": "edge-secret"})

    assert drained.status_code == 200, drained.text
    result = drained.json()["result"]["results"][0]["results"][0]
    assert result["error"] == "upstream_manifest_hash_mismatch"
    assert calls == [
        "https://genesis.example.test/v1/chain/identity",
        "https://genesis.example.test/v1/chain/manifest",
    ]
    assert _read_outbox(outbox)["records"][0]["tx_id"] == tx_id


def test_observer_outbox_autodrain_worker_retries_without_manual_route_batch362(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", "0")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))
    monkeypatch.setenv("WEALL_TX_OUTBOX_AUTODRAIN", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_DRAIN_INTERVAL_S", "0.25")
    monkeypatch.setenv("WEALL_TX_OUTBOX_DRAIN_BATCH", "10")

    tx = _signed_account_register("@observer_362_autodrain")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-362")

    calls: list[str] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        return _FakeResponse({"ok": True, "tx_id": tx_id, "status": "accepted"})

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)
    with _real_client(tmp_path) as client:
        submit = client.post("/v1/tx/submit", json=tx)
        assert submit.status_code == 200, submit.text
        deadline = time.time() + 3.0
        while time.time() < deadline:
            rows = _read_outbox(outbox)["records"]
            if rows and rows[0].get("upstream_status") == "accepted":
                break
            time.sleep(0.05)

    stored = _read_outbox(outbox)
    assert stored["records"][0]["upstream_status"] == "accepted"
    assert calls == ["https://genesis.example.test/v1/tx/submit"]


def test_detail_endpoints_cannot_bypass_bounded_vote_and_member_routes_batch362() -> None:
    with _client_with_executor(_FakeExecutor(_state())) as client:
        groups = client.get("/v1/groups")
        assert groups.status_code == 200, groups.text
        g0 = groups.json()["items"][0]
        assert g0["members"] == {"redacted": True, "count": 6}
        assert g0["roles"]["members"] == {"redacted": True, "count": 4}

        group_detail = client.get("/v1/groups/g1")
        assert group_detail.status_code == 200, group_detail.text
        assert group_detail.json()["group"]["members"] == {"redacted": True, "count": 6}

        proposal = client.get("/v1/gov/proposals/p1")
        assert proposal.status_code == 200, proposal.text
        p1 = proposal.json()["proposal"]
        assert "votes" not in p1
        assert "poll_votes" not in p1
        assert p1["votes_redacted"] is True
        assert p1["counts_total"] == {"poll_votes": 3, "votes": 5}

        dispute = client.get("/v1/disputes/d1")
        assert dispute.status_code == 200, dispute.text
        d1 = dispute.json()["dispute"]
        assert "votes" not in d1
        assert "jurors" not in d1
        assert "evidence" not in d1
        assert "appeals" not in d1
        assert d1["counts_total"] == {"jurors": 5, "votes": 5, "evidence": 4, "appeals": 2}

        # Dedicated paginated routes remain the only normal way to fetch large maps.
        votes = client.get("/v1/gov/proposals/p1/votes?limit=2")
        assert votes.status_code == 200, votes.text
        assert len(votes.json()["votes"]) == 2
        members = client.get("/v1/groups/g1/members?limit=2")
        assert members.status_code == 200, members.text
        assert len(members.json()["members"]) == 2
