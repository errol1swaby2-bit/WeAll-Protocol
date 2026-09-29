from __future__ import annotations

from types import SimpleNamespace

import pytest

from weall.net.node import NetNode, _PeerRec
from weall.runtime.apply.content import ContentApplyError, apply_content
from weall.runtime.apply.dispute import (
    _record_deattributed_resolution_option,
    _select_deattributed_resolution,
)
from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.apply.storage import StorageApplyError, apply_storage
from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.runtime.tx_contracts import load_default_tx_index


def env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent=parent,
    )


def test_p1_sec002_key_revoke_uses_canonical_key_id() -> None:
    state = {
        "height": 9,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "banned": False,
                "locked": False,
                "keys": {
                    "by_id": {
                        "k1": {"key_id": "k1", "pubkey": "pk-1", "active": True, "revoked": False},
                        "k2": {"key_id": "k2", "pubkey": "pk-2", "active": True, "revoked": False},
                    }
                },
            }
        },
    }
    apply_identity(state, env("ACCOUNT_KEY_REVOKE", "@alice", 1, {"key_id": "k1"}))
    assert state["accounts"]["@alice"]["keys"]["by_id"]["k1"]["revoked"] is True
    assert state["accounts"]["@alice"]["keys"]["by_id"]["k2"]["revoked"] is False


def test_p1_content001_cross_account_media_mutation_is_rejected() -> None:
    cid1 = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"
    cid2 = "QmPChd2hVbrJ6iB9L4o5sJjv2gHb6fK2z6F1fZ5m6bY5Vt"
    state = {
        "height": 1,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
            "@bob": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
    }
    apply_content(state, env("CONTENT_MEDIA_DECLARE", "@alice", 1, {"media_id": "m1", "cid": cid1}))
    apply_content(state, env("CONTENT_POST_CREATE", "@alice", 2, {"post_id": "p1", "body": "x"}))
    with pytest.raises(ContentApplyError, match="not_author"):
        apply_content(
            state, env("CONTENT_MEDIA_BIND", "@bob", 1, {"media_id": "m1", "target_id": "p1"})
        )
    apply_content(
        state, env("CONTENT_MEDIA_BIND", "@alice", 3, {"media_id": "m1", "target_id": "p1"})
    )
    with pytest.raises(ContentApplyError, match="not_author"):
        apply_content(
            state, env("CONTENT_MEDIA_REPLACE", "@bob", 1, {"media_id": "m1", "new_cid": cid2})
        )
    with pytest.raises(ContentApplyError, match="not_author"):
        apply_content(state, env("CONTENT_MEDIA_UNBIND", "@bob", 1, {"binding_id": "bind:m1:p1"}))
    assert state["content"]["media"]["m1"]["cid"] == cid1
    assert "bind:m1:p1" in state["content"]["media_bindings"]


def test_p1_treas001_cancel_scope_must_match_stored_treasury() -> None:
    state = {
        "treasury": {
            "spends": {"s1": {"spend_id": "s1", "treasury_id": "treasury-a", "status": "proposed"}}
        }
    }
    with pytest.raises(TreasuryApplyError, match="treasury_id_mismatch"):
        apply_treasury(
            state,
            env(
                "TREASURY_SPEND_CANCEL",
                "@alice",
                1,
                {"treasury_id": "treasury-b", "spend_id": "s1"},
            ),
        )
    assert state["treasury"]["spends"]["s1"]["status"] == "proposed"


def test_p1_role001_suspension_is_durable_and_scheduler_cannot_reactivate() -> None:
    state = {
        "height": 10,
        "roles": {
            "node_operators": {
                "by_id": {
                    "@alice": {
                        "account_id": "@alice",
                        "enrolled": True,
                        "active": True,
                        "status": "active",
                    }
                },
                "active_set": ["@alice"],
            }
        },
        "accounts": {"@alice": {"poh_tier": 2, "reputation_milli": 10_000}},
    }
    apply_roles(
        state,
        env(
            "ROLE_NODE_OPERATOR_SUSPEND",
            "SYSTEM",
            11,
            {"account_id": "@alice"},
            system=True,
            parent="governance:suspend",
        ),
    )
    rec = state["roles"]["node_operators"]["by_id"]["@alice"]
    assert rec["suspended"] is True and rec["active"] is False
    assert schedule_node_operator_system_txs(state, next_height=11) == 0
    assert not any(
        item.get("tx_type") == "ROLE_NODE_OPERATOR_ACTIVATE"
        for item in state.get("system_queue", [])
    )
    with pytest.raises(RolesApplyError, match="node_operator_suspended"):
        apply_roles(
            state,
            env("ROLE_NODE_OPERATOR_ACTIVATE", "SYSTEM", 12, {"account_id": "@alice"}, system=True),
        )


def test_p1_stor001_user_offer_cannot_target_another_operator() -> None:
    state: dict = {}
    with pytest.raises(StorageApplyError, match="operator_must_match_signer"):
        apply_storage(
            state,
            env(
                "STORAGE_OFFER_CREATE",
                "@alice",
                1,
                {"offer_id": "o1", "operator_id": "@bob", "capacity_bytes": 1},
            ),
        )
    assert state == {}


def test_p1_cons004_reputation_consensus_payload_domain_is_integer_and_float_is_rejected() -> None:
    state = {
        "chain_id": "test",
        "height": 12,
        "params": {"content_reputation_maturity_blocks": 1, "post_reputation_delta_milli": 10},
        "accounts": {"@alice": {"nonce": 0, "poh_tier": 2, "reputation_milli": 0}},
        "content": {
            "posts": {
                "p1": {
                    "post_id": "p1",
                    "author": "@alice",
                    "visibility": "public",
                    "deleted": False,
                    "reputation_accrual": {
                        "kind": "post",
                        "source_id": "p1",
                        "account_id": "@alice",
                        "created_height": 10,
                        "matures_at_height": 11,
                        "delta_milli": 10,
                        "status": "pending",
                    },
                }
            },
            "flags": {},
        },
    }

    # P2-SEM-002 retires the noncanonical maturity-only producer. Its retirement
    # strengthens rather than weakens the P1-CONS-004 fixed-point requirement.
    assert schedule_reputation_accrual_system_txs(state, next_height=13) == 0
    assert not any(
        x.get("tx_type") == "REPUTATION_DELTA_APPLY" for x in state.get("system_queue", [])
    )

    canon = load_default_tx_index()
    good_payload = {
        "account_id": "@alice",
        "delta_milli": 10,
        "delta_id": "p1-cons004-canonical",
        "reason": "p1_cons004_integer_domain",
    }
    assert not any(isinstance(v, float) for v in good_payload.values())
    good = env(
        "REPUTATION_DELTA_APPLY",
        "SYSTEM",
        13,
        good_payload,
        system=True,
        parent="dispute:p1-cons004",
    )
    verdict = admit_tx(good, state, canon=canon, context="block")
    assert verdict.ok, (verdict.code, verdict.reason, verdict.details)

    bad_payload = dict(good_payload)
    bad_payload.pop("delta_milli", None)
    bad_payload["delta"] = 0.01
    bad = env(
        "REPUTATION_DELTA_APPLY",
        "SYSTEM",
        13,
        bad_payload,
        system=True,
        parent="dispute:p1-cons004",
    )
    rejected = admit_tx(bad, state, canon=canon, context="block")
    assert rejected.ok is False
    assert rejected.reason == "payload_float_not_allowed"


def test_p1_dispute001_ballot_resolution_actions_never_inherit_coarse_quorum() -> None:
    dispute: dict = {}
    _record_deattributed_resolution_option(
        dispute,
        choice="yes",
        resolution={
            "actions": [
                {
                    "tx_type": "ROLE_ELIGIBILITY_SET",
                    "payload": {"account_id": "unrelated", "eligible": False},
                }
            ]
        },
    )
    selected = _select_deattributed_resolution(dispute, winning_choice="yes")
    assert "actions" not in selected


class FakeSecurityStore:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}
        self.loads: list[str] = []

    def load(self, key: str):
        self.loads.append(key)
        return None

    def upsert(self, *, peer_id: str, strikes: int, banned_until_ms: int, score: float) -> None:
        self.rows[peer_id] = {
            "strikes": strikes,
            "banned_until_ms": banned_until_ms,
            "score": score,
        }


def test_p1_net001_replayable_hello_identity_cannot_acquire_durable_account_ban_key() -> None:
    store = FakeSecurityStore()
    node = object.__new__(NetNode)
    node._peer_security_store = store
    node.peer_policy = SimpleNamespace(max_strikes=3, ban_cooldown_ms=1_000)
    peer_id = "tcp://198.51.100.7:3030"
    transport_key = NetNode._peer_security_transport_key(peer_id)
    rec = _PeerRec(peer_id=peer_id, router=None, security_key=transport_key)
    rec.identity_ok = True
    rec.identity_account = "@victim"
    rec.identity_pubkey = "victim-pk"

    node._bind_authenticated_peer_security(rec, session_bound=False)
    assert rec.security_key == transport_key
    node._strike(rec, 1)
    assert transport_key in store.rows
    assert "identity-account:@victim" not in store.rows
    assert "identity-account:@victim" not in store.loads
