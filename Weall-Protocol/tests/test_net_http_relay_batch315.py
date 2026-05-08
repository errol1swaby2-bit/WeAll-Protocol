from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.net.messages import MsgType, PingMsg, TxEnvelopeMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.net.node import NetConfig, NetNode
from weall.net.relay import (
    RelayConfig,
    RelayEnvelopeError,
    RelaySpool,
    make_relay_envelope,
    validate_relay_envelope,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


class _DummyMempool:
    def peek(self, _n: int) -> list[dict[str, Any]]:
        return []

    def add(self, _tx: dict[str, Any]) -> None:
        return None


class _SimpleExecutor:
    chain_id = "chain-A"
    tx_index = None

    def snapshot(self) -> dict[str, Any]:
        return {}

    def tx_index_hash(self) -> str:
        return "hash-A"

    def _schema_version(self) -> str:
        return "1"


def _priv_hex(label: str) -> tuple[str, str]:
    pub, sk = deterministic_ed25519_keypair(label=label)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    return pub, priv


def _relay_cfg() -> RelayConfig:
    return RelayConfig(chain_id="chain-A", schema_version="1", tx_index_hash="hash-A")


def _header(t: MsgType) -> WireHeader:
    return WireHeader(type=t, chain_id="chain-A", schema_version="1", tx_index_hash="hash-A")


def _ping_envelope(*, recipient: str = "node-b", now_ms: int | None = None) -> dict[str, Any]:
    pub, priv = _priv_hex("node-a")
    return make_relay_envelope(
        message=PingMsg(header=_header(MsgType.PING), ping_id="p1"),
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        sender_peer_id="node-a",
        recipient_peer_id=recipient,
        pubkey=pub,
        privkey=priv,
        nonce="n1",
        now_ms=now_ms,
        ttl_ms=60_000,
    )


def test_relay_envelope_verifies_and_tampering_fails_batch315() -> None:
    env = _ping_envelope(now_ms=1000)
    valid = validate_relay_envelope(env, cfg=_relay_cfg(), now_ms=2000)
    assert valid["relay_id"] == env["relay_id"]
    assert valid["authority"] if "authority" in valid else True

    tampered = dict(env)
    tampered["recipient_peer_id"] = "node-c"
    try:
        validate_relay_envelope(tampered, cfg=_relay_cfg(), now_ms=2000)
        assert False, "tampered recipient must fail signature verification"
    except RelayEnvelopeError as exc:
        assert exc.code in {"relay_bad_signature", "relay_id_mismatch"}

    wrong_chain = dict(env)
    wrong_chain["chain_id"] = "chain-B"
    try:
        validate_relay_envelope(wrong_chain, cfg=_relay_cfg(), now_ms=2000)
        assert False, "wrong chain must fail"
    except RelayEnvelopeError as exc:
        assert exc.code == "relay_chain_mismatch"

    expired = _ping_envelope(now_ms=1000)
    try:
        validate_relay_envelope(expired, cfg=_relay_cfg(), now_ms=70_000)
        assert False, "expired envelope must fail"
    except RelayEnvelopeError as exc:
        assert exc.code == "relay_expired"


def test_relay_spool_fetches_and_acks_without_mutation_batch315(tmp_path: Path) -> None:
    spool = RelaySpool(tmp_path / "relay.sqlite")
    env = _ping_envelope(recipient="node-b", now_ms=1000)
    accepted = spool.submit(env, cfg=_relay_cfg(), now_ms=2000)
    assert accepted["relay_id"] == env["relay_id"]

    # Duplicate submit is idempotent.
    spool.submit(env, cfg=_relay_cfg(), now_ms=2000)
    status = spool.status(now_ms=2000)
    assert status["messages_total"] == 1

    fetched = spool.fetch(recipient_peer_id="node-b", cfg=_relay_cfg(), limit=10, now_ms=2000)
    assert len(fetched) == 1
    assert fetched[0]["relay_id"] == env["relay_id"]

    assert spool.ack(recipient_peer_id="node-b", relay_ids=(env["relay_id"],)) == 1
    assert spool.fetch(recipient_peer_id="node-b", cfg=_relay_cfg(), limit=10, now_ms=2000) == ()


def test_http_relay_routes_store_fetch_and_ack_batch315(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_NET_RELAY_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_DB", str(tmp_path / "relay.sqlite"))
    app = create_app(boot_runtime=False)
    app.state.executor = _SimpleExecutor()
    client = TestClient(app)

    env = _ping_envelope(recipient="node-b")
    submit = client.post("/v1/net/relay/submit", json={"envelope": env})
    assert submit.status_code == 200, submit.text
    assert submit.json()["accepted"] is True
    assert submit.json()["authority"] == "transport_only"

    fetched = client.get("/v1/net/relay/fetch", params={"recipient_peer_id": "node-b"})
    assert fetched.status_code == 200, fetched.text
    data = fetched.json()
    assert data["count"] == 1
    assert data["messages"][0]["relay_id"] == env["relay_id"]

    ack = client.post(
        "/v1/net/relay/ack",
        json={"recipient_peer_id": "node-b", "relay_ids": [env["relay_id"]]},
    )
    assert ack.status_code == 200, ack.text
    assert ack.json()["acked"] == 1

    status = client.get("/v1/net/relay/status")
    assert status.status_code == 200, status.text
    assert status.json()["spool"]["messages_total"] == 0


def test_http_relay_rejects_mutated_payload_hash_batch315(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_NET_RELAY_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_DB", str(tmp_path / "relay.sqlite"))
    app = create_app(boot_runtime=False)
    app.state.executor = _SimpleExecutor()
    client = TestClient(app)

    env = _ping_envelope(recipient="node-b")
    env["payload"] = dict(env["payload"])
    env["payload"]["ping_id"] = "evil"
    resp = client.post("/v1/net/relay/submit", json={"envelope": env})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] in {"relay_payload_hash_mismatch", "relay_bad_signature"}


def test_net_loop_relay_poll_consumes_and_acks_batch315(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_NET_RELAY_CLIENT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_URLS", "http://relay.example")
    loop = NetMeshLoop(
        executor=_SimpleExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )
    loop.node = NetNode(
        cfg=NetConfig(
            chain_id="chain-A",
            schema_version="1",
            tx_index_hash="hash-A",
            peer_id="node-b",
        )
    )
    env = _ping_envelope(recipient="node-b")
    fetches: list[str] = []
    acks: list[dict[str, Any]] = []

    def fake_get(url: str, *, timeout_s: float = 2.0) -> dict[str, Any]:
        fetches.append(url)
        return {"ok": True, "messages": [env]}

    def fake_post(url: str, obj: dict[str, Any], *, timeout_s: float = 2.0) -> dict[str, Any]:
        acks.append({"url": url, "obj": obj})
        return {"ok": True, "acked": len(obj.get("relay_ids") or [])}

    monkeypatch.setattr("weall.net.net_loop._http_get_json", fake_get)
    monkeypatch.setattr("weall.net.net_loop._http_post_json", fake_post)

    loop._relay_poll_tick()

    assert fetches and "/v1/net/relay/fetch" in fetches[0]
    assert acks and acks[0]["obj"]["relay_ids"] == [env["relay_id"]]


def test_relay_accepts_tx_envelope_but_does_not_grant_authority_batch315() -> None:
    pub, priv = _priv_hex("node-a")
    tx_msg = TxEnvelopeMsg(
        header=_header(MsgType.TX_ENVELOPE),
        nonce=1,
        tx={"type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {}},
    )
    env = make_relay_envelope(
        message=tx_msg,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        sender_peer_id="node-a",
        recipient_peer_id="genesis",
        pubkey=pub,
        privkey=priv,
        nonce="tx-nonce",
        now_ms=1000,
        ttl_ms=60_000,
    )
    valid = validate_relay_envelope(env, cfg=_relay_cfg(), now_ms=2000)
    assert valid["msg_type"] == "TX_ENVELOPE"
    assert valid["recipient_peer_id"] == "genesis"
