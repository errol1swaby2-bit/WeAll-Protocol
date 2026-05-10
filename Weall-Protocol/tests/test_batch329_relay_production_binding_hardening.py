from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.net.messages import MsgType, PingMsg, WireHeader
from weall.net.net_loop import NetLoopConfig, NetLoopRuntimeError, NetMeshLoop
from weall.net.node import NetConfig, NetNode
from weall.net.relay import (
    RelayConfig,
    RelaySpool,
    make_relay_access_request,
    make_relay_envelope,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


class _SimpleExecutor:
    chain_id = "chain-A"
    tx_index = None

    def snapshot(self) -> dict[str, Any]:
        return {}

    def tx_index_hash(self) -> str:
        return "hash-A"

    def _schema_version(self) -> str:
        return "1"


class _DummyMempool:
    def peek(self, _n: int) -> list[dict[str, Any]]:
        return []

    def add(self, _tx: dict[str, Any]) -> None:
        return None


def _priv_hex(label: str) -> tuple[str, str]:
    pub, sk = deterministic_ed25519_keypair(label=label)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    return pub, priv


def _header(t: MsgType) -> WireHeader:
    return WireHeader(type=t, chain_id="chain-A", schema_version="1", tx_index_hash="hash-A")


def _strict_relay_cfg() -> RelayConfig:
    return RelayConfig(
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        allow_unbound_recipient_fetch=False,
        require_recipient_pubkey=True,
    )


def _loose_relay_cfg() -> RelayConfig:
    return RelayConfig(
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        allow_unbound_recipient_fetch=True,
        require_recipient_pubkey=False,
    )


def _ping_envelope(*, bind_recipient: bool, now_ms: int | None = None) -> dict[str, Any]:
    pub, priv = _priv_hex("node-a")
    recipient_pubkey = _priv_hex("node-b")[0] if bind_recipient else ""
    return make_relay_envelope(
        message=PingMsg(header=_header(MsgType.PING), ping_id="p1"),
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        sender_peer_id="node-a",
        recipient_peer_id="node-b",
        recipient_pubkey=recipient_pubkey,
        pubkey=pub,
        privkey=priv,
        nonce=f"n:{now_ms or 'now'}:{bind_recipient}",
        now_ms=now_ms,
        ttl_ms=60_000,
    )


def _access_request(request_type: str, *, recipient: str = "node-b", relay_ids: list[str] | None = None, now_ms: int = 2_000) -> dict[str, Any]:
    pub, priv = _priv_hex(recipient)
    return make_relay_access_request(
        request_type=request_type,
        chain_id="chain-A",
        schema_version="1",
        tx_index_hash="hash-A",
        recipient_peer_id=recipient,
        pubkey=pub,
        privkey=priv,
        nonce=f"{request_type}:{recipient}:{now_ms}",
        relay_ids=relay_ids or [],
        limit=10,
        now_ms=now_ms,
        ttl_ms=60_000,
    )


def _prod_client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_RELAY_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_DB", str(tmp_path / "relay.sqlite"))
    app = create_app(boot_runtime=False)
    app.state.executor = _SimpleExecutor()
    return TestClient(app)


def test_prod_relay_submit_requires_recipient_pubkey_even_if_unbound_env_enabled_batch329(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_NET_RELAY_ALLOW_UNBOUND_FETCH", "1")
    client = _prod_client(tmp_path, monkeypatch)

    status = client.get("/v1/net/relay/status")
    assert status.status_code == 200, status.text
    limits = status.json()["limits"]
    assert limits["allow_unbound_recipient_fetch"] is False
    assert limits["require_recipient_pubkey"] is True

    unbound = client.post("/v1/net/relay/submit", json={"envelope": _ping_envelope(bind_recipient=False)})
    assert unbound.status_code == 400, unbound.text
    assert unbound.json()["error"]["code"] == "relay_missing_recipient_pubkey"

    bound = client.post("/v1/net/relay/submit", json={"envelope": _ping_envelope(bind_recipient=True)})
    assert bound.status_code == 200, bound.text
    assert bound.json()["accepted"] is True


def test_prod_legacy_unsigned_fetch_is_disabled_even_if_compat_env_enabled_batch329(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_NET_RELAY_ALLOW_LEGACY_UNSIGNED_FETCH", "1")
    client = _prod_client(tmp_path, monkeypatch)

    response = client.get("/v1/net/relay/fetch", params={"recipient_peer_id": "node-b", "limit": 10})
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "relay_fetch_requires_signed_request"


def test_strict_authorized_fetch_and_ack_ignore_legacy_unbound_mailbox_rows_batch329(tmp_path: Path) -> None:
    spool = RelaySpool(tmp_path / "relay.sqlite")
    env = _ping_envelope(bind_recipient=False, now_ms=1_000)
    # Simulate a pre-hardening/non-production spool row. Production strict fetch
    # must not deliver or delete it through a signed recipient request.
    spool.submit(env, cfg=_loose_relay_cfg(), now_ms=2_000)

    fetched = spool.fetch_authorized(
        access_request=_access_request("fetch", now_ms=3_000),
        cfg=_strict_relay_cfg(),
        now_ms=3_000,
    )
    assert fetched == ()
    assert spool.ack_authorized(
        access_request=_access_request("ack", relay_ids=[env["relay_id"]], now_ms=4_000),
        cfg=_strict_relay_cfg(),
        now_ms=4_000,
    ) == 0

    status = spool.status(now_ms=4_000)
    assert status["messages_total"] == 1


def _relay_loop(monkeypatch, *, recipient_map: dict[str, str] | None = None) -> NetMeshLoop:
    node_pub, node_priv = _priv_hex("local-node")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_RELAY_CLIENT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_URLS", "https://relay.example")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", node_pub)
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", node_priv)
    if recipient_map is not None:
        monkeypatch.setenv("WEALL_NET_RELAY_RECIPIENT_PUBKEYS", json.dumps(recipient_map, sort_keys=True))
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
            peer_id="local-node",
        )
    )
    return loop


def test_prod_relay_client_refuses_to_submit_to_named_peer_without_recipient_pubkey_batch329(monkeypatch) -> None:
    loop = _relay_loop(monkeypatch)
    msg = PingMsg(header=_header(MsgType.PING), ping_id="out")

    try:
        loop._relay_submit_message(msg, recipients=["genesis"])
        assert False, "production relay client must require recipient pubkey binding"
    except NetLoopRuntimeError as exc:
        assert "relay_envelope_build_failed" in str(exc)
        assert getattr(exc.__cause__, "args", [""])[0] == "net_relay_missing_recipient_pubkey"


def test_prod_relay_client_submits_bound_envelopes_when_recipient_pubkey_map_exists_batch329(monkeypatch) -> None:
    genesis_pub = _priv_hex("genesis")[0]
    loop = _relay_loop(monkeypatch, recipient_map={"genesis": genesis_pub})
    sent: list[dict[str, Any]] = []

    def fake_post(url: str, obj: dict[str, Any], *, timeout_s: float = 2.0) -> dict[str, Any]:
        sent.append({"url": url, "obj": obj})
        return {"ok": True, "accepted": True}

    monkeypatch.setattr("weall.net.net_loop._http_post_json", fake_post)
    loop._relay_submit_message(PingMsg(header=_header(MsgType.PING), ping_id="out"), recipients=["genesis"])

    assert sent
    envelope = sent[0]["obj"]["envelope"]
    assert envelope["recipient_peer_id"] == "genesis"
    assert envelope["recipient_pubkey"] == genesis_pub
