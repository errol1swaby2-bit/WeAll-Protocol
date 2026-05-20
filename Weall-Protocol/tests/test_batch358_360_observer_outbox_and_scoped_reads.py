from __future__ import annotations

import json
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
CID = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"


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
    chain_id = "batch360"

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state

    def tx_index_hash(self) -> str:
        return "batch360-tx-index"


def _client_with_executor(ex: Any) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = ex
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _signed_account_register(account: str, *, chain_id: str = "weall-observer-outbox") -> dict[str, Any]:
    seed = bytes.fromhex("58" * 32)
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


def _real_executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "observer-edge.db"),
        node_id="observer-edge",
        chain_id="weall-observer-outbox",
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )


def _read_outbox(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_observer_tx_outbox_survives_upstream_outage_and_retries_batch358(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "observer-outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_MODE", "1")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", "0")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))

    tx = _signed_account_register("@observer_outbox_user")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-outbox")

    def upstream_down(_req, timeout=0):  # noqa: ANN001
        raise OSError("simulated upstream outage")

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", upstream_down)
    with _client_with_executor(_real_executor(tmp_path)) as client:
        res = client.post("/v1/tx/submit", json=tx)
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["ok"] is True
        assert body["tx_id"] == tx_id
        assert body["upstream_propagation"]["accepted"] is False
        status = client.get(f"/v1/tx/status/{tx_id}").json()
        assert status["status"] == "pending"
        assert status["outbound_propagation"]["upstream_status"] == "pending"

    stored = _read_outbox(outbox)
    assert len(stored["records"]) == 1
    assert stored["records"][0]["tx_id"] == tx_id

    calls: list[str] = []

    def upstream_accept(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        return _FakeResponse({"ok": True, "tx_id": tx_id, "status": "accepted"})

    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-token")
    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", upstream_accept)
    with _client_with_executor(_real_executor(tmp_path)) as client:
        drained = client.post("/v1/observer/edge/outbox/drain", headers={"X-WeAll-Operator-Token": "edge-token"})
        assert drained.status_code == 200, drained.text
        assert drained.json()["result"]["accepted"] is True

    stored = _read_outbox(outbox)
    assert stored["records"][0]["upstream_status"] == "accepted"
    assert stored["records"][0]["attempts"] >= 1
    assert calls == ["https://genesis.example.test/v1/tx/submit"]


def test_observer_upstream_tx_id_mismatch_remains_pending_batch358(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "observer-outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", "0")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))

    tx = _signed_account_register("@observer_mismatch_user")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _FakeResponse({"ok": True, "tx_id": "tx:wrong", "status": "accepted"})

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)
    with _client_with_executor(_real_executor(tmp_path)) as client:
        res = client.post("/v1/tx/submit", json=tx)
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["upstream_propagation"]["accepted"] is False
        result = body["upstream_propagation"]["results"][0]["results"][0]
        assert result["error"] == "upstream_tx_id_mismatch"

    stored = _read_outbox(outbox)
    assert stored["records"][0]["upstream_status"] == "pending"


def test_local_observer_status_reconciles_upstream_confirmation_batch359(tmp_path: Path, monkeypatch) -> None:
    outbox = tmp_path / "observer-outbox.json"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRED", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_VERIFY_IDENTITY", "0")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT", "1")
    monkeypatch.setenv("WEALL_TX_OUTBOX_PATH", str(outbox))

    tx = _signed_account_register("@observer_confirm_user")
    tx_id = compute_tx_id(tx, chain_id="weall-observer-outbox")

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        if req.full_url.endswith("/v1/tx/submit"):
            return _FakeResponse({"ok": True, "tx_id": tx_id, "status": "accepted"})
        if req.full_url.endswith(f"/v1/tx/status/{tx_id}"):
            return _FakeResponse({"ok": True, "tx_id": tx_id, "status": "confirmed", "height": 7, "block_id": "block:7"})
        raise AssertionError(req.full_url)

    monkeypatch.setattr("weall.api.routes_public_parts.tx.urllib.request.urlopen", fake_urlopen)
    with _client_with_executor(_real_executor(tmp_path)) as client:
        submit = client.post("/v1/tx/submit", json=tx)
        assert submit.status_code == 200, submit.text
        status = client.get(f"/v1/tx/status/{tx_id}")
        assert status.status_code == 200, status.text
        body = status.json()
        assert body["status"] == "confirmed"
        assert body["source"] == "upstream_reconciled"
        assert body["height"] == 7
        assert body["outbound_propagation"]["upstream_status"] == "confirmed"


def _state() -> dict[str, Any]:
    return {
        "chain_id": "batch360",
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@alice": {"active": True, "ttl_s": 0}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@bob": {"active": True, "ttl_s": 0}}},
        },
        "content": {
            "posts": {
                "post:public": {"post_id": "post:public", "author": "@alice", "body": "public", "visibility": "public", "media": ["media:1"], "created_nonce": 10},
                "post:private": {"post_id": "post:private", "author": "@alice", "body": "private", "visibility": "private", "media": ["media:1"], "created_nonce": 11},
            },
            "comments": {
                "comment:public": {"comment_id": "comment:public", "post_id": "post:public", "author": "@bob", "body": "ok", "created_nonce": 12},
                "comment:private": {"comment_id": "comment:private", "post_id": "post:private", "author": "@bob", "body": "hidden", "created_nonce": 13},
            },
            "media": {"media:1": {"payload": {"cid": CID, "mime": "image/png", "size_bytes": 12}}},
            "reactions": {},
        },
        "groups_by_id": {
            "g1": {"id": "g1", "members": {f"@u{i:03d}": {"role": "member"} for i in range(5)}}
        },
        "gov_proposals_by_id": {
            "p1": {"proposal_id": "p1", "stage": "voting", "votes": {f"@v{i:03d}": {"vote": "yes" if i % 2 else "no"} for i in range(5)}, "poll_votes": {}}
        },
        "disputes_by_id": {
            "d1": {"id": "d1", "stage": "open", "votes": {f"@j{i:03d}": {"vote": "yes" if i % 2 else "no"} for i in range(5)}}
        },
        "messaging": {
            "threads_by_id": {"dm:1": {"thread_id": "dm:1", "members": ["@alice", "@bob"], "message_ids": ["m1", "m2"], "last_message_id": "m2", "last_message_at_nonce": 2}},
            "messages_by_id": {"m1": {"message_id": "m1", "thread_id": "dm:1", "sender": "@alice", "to": "@bob", "body": "one", "created_at_nonce": 1}, "m2": {"message_id": "m2", "thread_id": "dm:1", "sender": "@bob", "to": "@alice", "body": "two", "created_at_nonce": 2}},
            "inbox_by_account": {"@alice": {"threads": ["dm:1"]}, "@bob": {"threads": ["dm:1"]}},
        },
    }


def _auth(account: str) -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": f"sk:{account}"}


def test_content_detail_hides_non_public_content_batch360() -> None:
    with _client_with_executor(_FakeExecutor(_state())) as client:
        public = client.get("/v1/content/post:public")
        assert public.status_code == 200, public.text
        assert public.json()["content"]["media"][0]["fetch_path"].startswith("/v1/media/proxy/")
        assert client.get("/v1/content/post:private").status_code == 404
        assert client.get("/v1/content/comment:private").status_code == 404


def test_group_members_and_vote_maps_are_paginated_batch360() -> None:
    with _client_with_executor(_FakeExecutor(_state())) as client:
        members = client.get("/v1/groups/g1/members?limit=2")
        assert members.status_code == 200, members.text
        assert len(members.json()["members"]) == 2
        assert members.json()["next_cursor"]

        proposal_votes = client.get("/v1/gov/proposals/p1/votes?limit=2")
        assert proposal_votes.status_code == 200, proposal_votes.text
        assert len(proposal_votes.json()["votes"]) == 2
        assert proposal_votes.json()["counts_total"]["votes"] == 5
        assert proposal_votes.json()["next_cursor"]

        dispute_votes = client.get("/v1/disputes/d1/votes?limit=2")
        assert dispute_votes.status_code == 200, dispute_votes.text
        assert len(dispute_votes.json()["votes"]) == 2
        assert dispute_votes.json()["counts_total"]["votes"] == 5
        assert dispute_votes.json()["next_cursor"]


def test_message_thread_list_omits_full_message_ids_batch360() -> None:
    with _client_with_executor(_FakeExecutor(_state())) as client:
        listing = client.get("/v1/messages/threads", headers=_auth("@alice"))
        assert listing.status_code == 200, listing.text
        thread = listing.json()["threads"][0]
        assert thread["message_count"] == 2
        assert "message_ids" not in thread
        detail = client.get("/v1/messages/threads/dm:1?limit=1", headers=_auth("@alice"))
        assert detail.status_code == 200, detail.text
        assert len(detail.json()["messages"]) == 1
        assert detail.json()["next_cursor"]
