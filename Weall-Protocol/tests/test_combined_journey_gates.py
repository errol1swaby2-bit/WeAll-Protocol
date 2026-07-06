from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from weall.net.messages import MsgType, PingMsg, WireHeader
from weall.net.relay import RelayConfig, RelaySpool, make_relay_access_request, make_relay_envelope
from weall.runtime.apply.economics import apply_economics
from weall.runtime.apply.governance import apply_governance
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission_types import TxEnvelope
from weall.testing.sigtools import deterministic_mldsa_keypair

ROOT = Path(__file__).resolve().parents[1]


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict[str, Any] | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope.from_json(
        {
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload or {},
            "sig": "sig",
            "system": bool(system),
            "parent": parent if parent is not None else (f"parent:{tx_type}:{nonce}" if system else None),
        }
    )


def _governance_wallet_state() -> dict[str, Any]:
    return {
        "height": 100,
        "time": 100,
        "chain_id": "weall-prod-batch337",
        "params": {
            "chain_id": "weall-prod-batch337",
            "mode": "prod",
            "economic_unlock_time": 1,
            "economics_enabled": False,
            "system_signer": "SYSTEM",
        },
        "accounts": {
            "@validator1": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
                "reputation": "10",
            },
            "@alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "balance": 250,
                "reputation": "10",
            },
            "@bob": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "balance": 5,
                "reputation": "10",
            },
        },
        "roles": {"validators": {"active_set": ["@validator1"], "by_id": {"@validator1": {"active": True}}}},
        "governance": {"proposals": {}},
        "system_queue": [],
    }


def _run_activation_and_transfer(state: dict[str, Any]) -> dict[str, Any]:
    proposal_id = "activate-economics-batch337"
    action = {"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enabled": True}}

    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@validator1",
            1,
            {
                "proposal_id": proposal_id,
                "title": "Activate economics",
                "body": "Enable WeCoin transfers after the genesis lock.",
                "rules": {"start_stage": "voting"},
                "actions": [action],
            },
        ),
    )
    apply_governance(state, _env("GOV_VOTE_CAST", "@validator1", 2, {"proposal_id": proposal_id, "vote": "yes"}))
    state["height"] = 101
    apply_governance(state, _env("GOV_VOTING_CLOSE", "SYSTEM", 3, {"proposal_id": proposal_id}, system=True))
    state["height"] = 102
    apply_governance(
        state,
        _env(
            "GOV_TALLY_PUBLISH",
            "SYSTEM",
            4,
            {"proposal_id": proposal_id, "passed": True, "yes": 1, "no": 0, "abstain": 0},
            system=True,
        ),
    )
    state["height"] = 103
    apply_governance(state, _env("GOV_EXECUTE", "SYSTEM", 5, {"proposal_id": proposal_id}, system=True, parent="gov-parent"))

    queued = [item for item in state.get("system_queue", []) if item.get("tx_type") == "ECONOMICS_ACTIVATION"]
    assert len(queued) == 1
    state["height"] = int(queued[0]["due_height"])
    emitted = [tx for tx in system_tx_emitter(state, None, next_height=state["height"], phase="post") if tx.tx_type == "ECONOMICS_ACTIVATION"]
    assert len(emitted) == 1
    apply_economics(state, emitted[0])
    assert state["params"]["economics_enabled"] is True

    apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 1, {"to": "@bob", "amount": 40}))
    return state


def test_governance_activation_then_wecoin_transfer_replays_identically() -> None:
    left = _run_activation_and_transfer(copy.deepcopy(_governance_wallet_state()))
    right = _run_activation_and_transfer(copy.deepcopy(_governance_wallet_state()))

    assert left["accounts"]["@alice"]["balance"] == 210
    assert left["accounts"]["@bob"]["balance"] == 45
    assert right["accounts"]["@alice"]["balance"] == 210
    assert right["accounts"]["@bob"]["balance"] == 45
    assert left["governance"] == right["governance"]
    assert left["system_queue"] == right["system_queue"]


def _priv_hex(label: str) -> tuple[str, str]:
    pub, sk = deterministic_mldsa_keypair(label=label)
    priv = sk.private_bytes_raw().hex()
    return pub, priv


def _relay_cfg() -> RelayConfig:
    return RelayConfig(
        chain_id="chain-observers",
        schema_version="1",
        tx_index_hash="h" * 64,
        require_recipient_pubkey=True,
        allow_unbound_recipient_fetch=False,
        max_fetch_limit=20,
    )


def _header() -> WireHeader:
    return WireHeader(type=MsgType.PING, chain_id="chain-observers", schema_version="1", tx_index_hash="h" * 64)


def test_relay_spool_handles_five_recipient_bound_observers_without_mailbox_leakage(tmp_path: Path) -> None:
    cfg = _relay_cfg()
    spool = RelaySpool(tmp_path / "relay.sqlite")
    genesis_pub, genesis_priv = _priv_hex("genesis")
    observer_keys = {f"observer-{i}": _priv_hex(f"observer-{i}") for i in range(5)}

    submitted_ids: dict[str, str] = {}
    for i, (observer_id, (observer_pub, _observer_priv)) in enumerate(observer_keys.items()):
        envelope = make_relay_envelope(
            message=PingMsg(header=_header(), ping_id=f"ping-{observer_id}"),
            chain_id=cfg.chain_id,
            schema_version=cfg.schema_version,
            tx_index_hash=cfg.tx_index_hash,
            sender_peer_id="genesis",
            recipient_peer_id=observer_id,
            recipient_pubkey=observer_pub,
            pubkey=genesis_pub,
            privkey=genesis_priv,
            nonce=f"genesis-to-{observer_id}",
            now_ms=10_000 + i,
            ttl_ms=60_000,
        )
        submitted_ids[observer_id] = spool.submit(envelope, cfg=cfg, now_ms=11_000 + i)["relay_id"]

    status = spool.status(now_ms=12_000)
    assert status["messages_total"] == 5
    assert {row["recipient_peer_id"]: row["count"] for row in status["by_recipient"]} == {observer_id: 1 for observer_id in observer_keys}

    for i, (observer_id, (observer_pub, observer_priv)) in enumerate(observer_keys.items()):
        fetch_req = make_relay_access_request(
            request_type="fetch",
            chain_id=cfg.chain_id,
            schema_version=cfg.schema_version,
            tx_index_hash=cfg.tx_index_hash,
            recipient_peer_id=observer_id,
            pubkey=observer_pub,
            privkey=observer_priv,
            nonce=f"fetch-{observer_id}",
            limit=20,
            now_ms=20_000 + i,
            ttl_ms=60_000,
        )
        fetched = spool.fetch_authorized(access_request=fetch_req, cfg=cfg, now_ms=21_000 + i)
        assert [item["recipient_peer_id"] for item in fetched] == [observer_id]
        assert [item["relay_id"] for item in fetched] == [submitted_ids[observer_id]]

        ack_req = make_relay_access_request(
            request_type="ack",
            chain_id=cfg.chain_id,
            schema_version=cfg.schema_version,
            tx_index_hash=cfg.tx_index_hash,
            recipient_peer_id=observer_id,
            pubkey=observer_pub,
            privkey=observer_priv,
            nonce=f"ack-{observer_id}",
            relay_ids=[submitted_ids[observer_id]],
            now_ms=30_000 + i,
            ttl_ms=60_000,
        )
        assert spool.ack_authorized(access_request=ack_req, cfg=cfg, now_ms=31_000 + i) == 1

    assert spool.status(now_ms=40_000)["messages_total"] == 0
