from __future__ import annotations

import pytest

from weall.ledger.migrations import migrate_state_dict
from weall.runtime.apply.identity import apply_identity
from weall.runtime.helper_certificates import HelperExecutionCertificate, sign_helper_certificate, verify_helper_certificate_signature
from weall.runtime.parallel_execution import LanePlan, merge_helper_lane_results
from weall.runtime.tx_admission_types import TxEnvelope


def test_helper_signature_verification_requires_pubkey_when_no_explicit_secret_batch124() -> None:
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=7,
            view=9,
            leader_id="@leader",
            helper_id="helper-1",
            validator_epoch=3,
            validator_set_hash="vset",
            lane_id="lane-a",
            tx_ids=("tx1",),
            tx_order_hash="order",
            receipts_root="",
            write_set_hash="",
            read_set_hash="",
            lane_delta_hash="",
            namespace_hash="ns",
        ),
        secret="shared-secret",
    )
    assert verify_helper_certificate_signature(cert, helper_pubkey=None) is False
    assert verify_helper_certificate_signature(cert, helper_pubkey=None, secret="shared-secret") is True


def test_merge_helper_lane_results_rejects_missing_pubkey_when_signature_enforced_batch124() -> None:
    tx = {"tx_id": "tx1", "tx_type": "CONTENT_POST_CREATE"}
    lane = LanePlan(
        lane_id="lane-a",
        helper_id="helper-1",
        txs=(tx,),
        tx_ids=("tx1",),
        namespace_prefixes=("content:post:tx1",),
    )
    cert = {
        "chain_id": "batch124",
        "block_height": 7,
        "view": 9,
        "leader_id": "@leader",
        "helper_id": "helper-1",
        "validator_epoch": 3,
        "validator_set_hash": "vset",
        "lane_id": "lane-a",
        "tx_ids": ["tx1"],
        "tx_order_hash": "d701ef20f57aac468ed22504a38c2bc0817b90320503d772a0445d7c2b30ce6f",
        "receipts_root": "",
        "write_set_hash": "",
        "read_set_hash": "",
        "lane_delta_hash": "",
        "namespace_hash": "8a3f6143aacbf59de055797d978e2ae0741ef700121ae48cbbdf3860297ce969",
        "helper_signature": "00" * 64,
    }
    result = merge_helper_lane_results(
        canonical_txs=[tx],
        lane_plans=(lane,),
        helper_certificates={lane.lane_id: cert},
        serial_executor=lambda txs, _ctx: ([{"tx_id": str(tx.get("tx_id") or ""), "ok": True, "path": "serial"} for tx in list(txs or [])], {}),
        leader_context={
            "chain_id": "batch124",
            "block_height": 7,
            "view": 9,
            "leader_id": "@leader",
            "validator_epoch": 3,
            "validator_set_hash": "vset",
            "helper_receipts": {lane.lane_id: [{"tx_id": "tx1", "ok": True, "path": "helper"}]},
            "enforce_helper_signature": True,
            "enforce_helper_namespace_hash": True,
            "enforce_helper_tx_order_hash": True,
        },
    )
    assert result.receipts == [{"tx_id": "tx1", "ok": True, "path": "serial"}]
    assert result.lane_decisions[0].fallback_reason == "helper_pubkey_missing"


def test_identity_apply_rejects_nonce_gaps_batch124() -> None:
    state = {
        "accounts": {
            "@alice": {
                "nonce": 1,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "reputation": "0",
                "reputation_milli": 0,
                "pubkey": "pk1",
                "keys": {"by_id": {"k1": {"pubkey": "pk1", "revoked": False}}},
            }
        }
    }
    env = TxEnvelope(
        tx_type="ACCOUNT_SESSION_KEY_ISSUE",
        signer="@alice",
        nonce=3,
        ts_ms=0,
        tx_id="tx-gap",
        payload={"pubkey": "pk2", "expires_at": 10},
    )
    with pytest.raises(Exception, match="bad_nonce"):
        apply_identity(state, env)


def test_migration_normalizes_reputation_to_string_and_units_batch124() -> None:
    st = migrate_state_dict({
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 3,
                "banned": False,
                "locked": False,
                "reputation": "1.25",
            }
        }
    })
    acct = st["accounts"]["@alice"]
    assert acct["reputation"] == "1.25"
    assert int(acct["reputation_milli"]) == 1250
