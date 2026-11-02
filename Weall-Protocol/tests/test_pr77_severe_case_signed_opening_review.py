"""Signed opening source-bound candidate: real ML-DSA and block hash, no S4 authority."""

from __future__ import annotations

import copy

import pytest

from tooling.severe_case_signed_opening_review import (
    SCHEMA,
    STATUS,
    review_signed_dispute_opening,
)
from weall.crypto.pq_mldsa import generate_mldsa65_keypair
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.block_hash import compute_block_hash, compute_receipts_root
from weall.runtime.block_id import compute_block_id
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "pr77-s4-source-candidate"
NETWORK = "pr77-local-network"


@pytest.fixture(scope="module")
def keypair() -> dict:
    return generate_mldsa65_keypair()


@pytest.fixture(autouse=True)
def crypto_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_CRYPTO_MODE", "closed-testnet")
    monkeypatch.delenv("WEALL_UNSAFE_DEV", raising=False)


def _fixture(keypair: dict) -> dict:
    tx = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "network_id": NETWORK,
            "tx_type": "DISPUTE_OPEN",
            "signer": "@alice",
            "nonce": 7,
            "payload": {
                "dispute_id": "d1",
                "target_type": "account",
                "target_id": "@bob",
                "reason": "Review only",
            },
        },
        privkey=keypair["privkey"],
    )
    tx_id = compute_tx_id_from_dict(CHAIN, tx)
    tx["tx_id"] = tx_id
    receipt = {
        "tx_id": tx_id,
        "tx_type": "DISPUTE_OPEN",
        "signer": "@alice",
        "nonce": 7,
        "ok": True,
    }
    header = {
        "chain_id": CHAIN,
        "height": 7,
        "block_ts_ms": 140000,
        "prev_block_hash": "e" * 64,
        "tx_ids": [tx_id],
        "receipts_root": compute_receipts_root(receipts=[receipt]),
        "state_root": "f" * 64,
    }
    block = {
        "height": 7,
        "block_ts_ms": 140000,
        "prev_block_hash": "e" * 64,
        "chain_id": CHAIN,
        "prev_block_id": "previous-synthetic-id",
        "proposer": "test-proposer",
        "header": header,
        "txs": [tx],
        "receipts": [receipt],
    }
    block["block_id"] = compute_block_id(
        chain_id=CHAIN,
        height=7,
        prev_block_id=block["prev_block_id"],
        prev_block_hash=header["prev_block_hash"],
        ts_ms=header["block_ts_ms"],
        node_id=block["proposer"],
        tx_ids=[tx_id],
        receipts_root=header["receipts_root"],
    )
    block["block_hash"] = compute_block_hash(header=header)
    return {
        "chain_id": CHAIN,
        "opening_tx_id": tx_id,
        "case": {
            "id": "d1",
            "target_type": "account",
            "target_id": "@bob",
            "opened_by": "@alice",
            "opened_at_height": 7,
            "opened_at_nonce": 7,
        },
        "block": block,
        "pre_state": {
            "chain_id": CHAIN,
            "network_id": NETWORK,
            "height": 6,
            "tip": block["prev_block_id"],
            "params": {"require_signatures": True},
            "accounts": {
                "@alice": {
                    "keys": [
                        {
                            "pubkey": keypair["pubkey"],
                            "sig_profile": "pq-mldsa-v1",
                            "active": True,
                        }
                    ]
                }
            },
        },
    }


def _review(f: dict) -> dict:
    return review_signed_dispute_opening(**f)


def test_genuine_pq_signature_and_self_bound_block_still_not_authority(keypair: dict) -> None:
    f = _fixture(keypair)
    before = copy.deepcopy(f)
    out = _review(f)
    assert out["schema"] == SCHEMA
    assert out["status"] == STATUS
    assert all(out["observations"].values())
    assert out["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert out["may_classify_canonical_case"] is False
    assert out["may_enqueue_account_ban"] is False
    assert f == before
    assert out == _review(copy.deepcopy(f))


@pytest.mark.parametrize(
    ("path", "value", "observation"),
    [
        (("block", "block_id"), "forged-block", "block_self_commitments_match"),
        (("block", "block_hash"), "bad-hash", "block_self_commitments_match"),
        (("pre_state", "height"), 7, "prestate_height_tip_chain_and_signature_policy_match"),
        (("pre_state", "tip"), "wrong-parent", "prestate_height_tip_chain_and_signature_policy_match"),
        (("pre_state", "chain_id"), "other-chain", "prestate_height_tip_chain_and_signature_policy_match"),
        (("case", "target_id"), "@charlie", "case_mutation_matches_signed_opening"),
        (("case", "opened_by"), "@other", "case_mutation_matches_signed_opening"),
        (("case", "opened_at_nonce"), 8, "case_mutation_matches_signed_opening"),
    ],
)
def test_mismatched_sources_fail_relevant_observation(
    keypair: dict, path: tuple[str, str], value: object, observation: str
) -> None:
    f = _fixture(keypair)
    f[path[0]][path[1]] = value
    out = _review(f)
    assert out["observations"][observation] is False
    assert out["may_enqueue_account_ban"] is False


def test_unsigned_dev_policy_cannot_bypass_real_crypto(
    keypair: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _fixture(keypair)
    f["block"]["txs"][0]["sig"] = "0" * 20
    f["block"]["txs"][0]["signature"]["sig"] = "0" * 20
    f["pre_state"]["params"]["require_signatures"] = False
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    out = _review(f)
    assert out["observations"]["prestate_height_tip_chain_and_signature_policy_match"] is False
    assert out["observations"]["signed_against_supplied_prestate_key"] is False
    assert out["may_classify_canonical_case"] is False


def test_signed_wrong_key_does_not_prove_sender(keypair: dict) -> None:
    f = _fixture(keypair)
    other = generate_mldsa65_keypair()
    f["pre_state"]["accounts"]["@alice"]["keys"][0]["pubkey"] = other["pubkey"]
    assert _review(f)["observations"]["signed_against_supplied_prestate_key"] is False


def test_claimed_verified_flags_cannot_bypass_invalid_signature(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["txs"][0]["sig"] = "00" * 64
    f["block"]["txs"][0]["signature"]["sig"] = "00" * 64
    f["block"]["txs"][0]["verified"] = True
    f["block"]["signature_verified"] = True
    f["pre_state"]["consensus_finalized"] = True
    out = _review(f)
    assert out["observations"]["signed_against_supplied_prestate_key"] is False
    assert out["may_enqueue_account_ban"] is False


def test_duplicate_or_rejected_receipt_fails(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["receipts"][0]["ok"] = False
    assert _review(f)["observations"]["opening_admitted_success_receipt_observed"] is False
    f = _fixture(keypair)
    f["block"]["receipts"].append(copy.deepcopy(f["block"]["receipts"][0]))
    assert _review(f)["observations"]["opening_admitted_success_receipt_observed"] is False


def test_extra_mutation_in_payload_invalidates_signed_origin(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["txs"][0]["payload"]["target_id"] = "@other"
    out = _review(f)
    assert out["observations"]["opening_is_exact_canonical_tx"] is False
    assert out["observations"]["signed_against_supplied_prestate_key"] is False
    assert out["may_classify_canonical_case"] is False


def test_swapping_network_breaks_prestate_context_and_signature(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["txs"][0]["network_id"] = "other-network"
    out = _review(f)
    assert out["observations"]["prestate_height_tip_chain_and_signature_policy_match"] is False
    assert out["observations"]["signed_against_supplied_prestate_key"] is False


def test_malformed_or_missing_shapes_fail_closed() -> None:
    out = review_signed_dispute_opening(
        case=[], block=[], pre_state=[], chain_id="", opening_tx_id=""
    )
    assert not any(out["observations"].values())
    assert out["may_classify_canonical_case"] is False
    assert out["may_enqueue_account_ban"] is False


def test_self_consistent_crypto_is_not_network_finality(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["justify_qc"] = {"allegedly_final": True}
    f["pre_state"]["historically_verified"] = True
    out = _review(f)
    assert all(out["observations"].values())
    assert "supplied_block_not_authenticated_as_network_finalized" in out["blocking_reasons"]
    assert out["constitutional_authorization"] == "NOT_ESTABLISHED"
