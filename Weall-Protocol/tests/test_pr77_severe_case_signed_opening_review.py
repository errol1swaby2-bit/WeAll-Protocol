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
            "reason": "Review only",
            "opened_by": "@alice",
            "opened_at_height": 6,
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
                    # Runtime account keys use a canonical by_id record
                    # with a profile-specific ML-DSA public key. A legacy
                    # list containing only "pubkey" is not this shape.
                    "keys": {
                        "by_id": {
                            "fixture-key": {
                                "pubkeys": {"mldsa": keypair["pubkey"]},
                                "sig_profile": "pq-mldsa-v1",
                                "active": True,
                            }
                        }
                    }
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
        (
            ("pre_state", "tip"),
            "wrong-parent",
            "prestate_height_tip_chain_and_signature_policy_match",
        ),
        (
            ("pre_state", "chain_id"),
            "other-chain",
            "prestate_height_tip_chain_and_signature_policy_match",
        ),
        (("case", "target_id"), "@charlie", "case_mutation_matches_signed_opening"),
        (("case", "opened_by"), "@other", "case_mutation_matches_signed_opening"),
        (("case", "opened_at_nonce"), 8, "case_mutation_matches_signed_opening"),
        (("case", "opened_at_height"), 7, "case_mutation_matches_signed_opening"),
        (("case", "opened_at_height"), 5, "case_mutation_matches_signed_opening"),
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
    f["pre_state"]["accounts"]["@alice"]["keys"]["by_id"]["fixture-key"]["pubkeys"][
        "mldsa"
    ] = other["pubkey"]
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


def test_actual_dispute_applier_marks_predecessor_height_not_block_height(
    keypair: dict,
) -> None:
    """Exercise the real domain applier, not a hand-written matching case."""
    from weall.runtime.apply.dispute import apply_dispute
    from weall.runtime.tx_admission_types import TxEnvelope

    f = _fixture(keypair)
    state = copy.deepcopy(f["pre_state"])
    # This is a domain-only controlled fixture; no authenticated PoH issuance
    # or network consensus is inferred from this manually seeded account.
    state["accounts"]["@alice"]["poh_tier"] = 2
    predecessor_state = copy.deepcopy(state)
    opening = TxEnvelope.from_json(f["block"]["txs"][0])
    result = apply_dispute(state, opening)
    assert result["applied"] == "DISPUTE_OPEN"
    case = state["disputes_by_id"]["d1"]
    assert case["opened_at_height"] == 6
    assert f["block"]["header"]["height"] == 7

    assert "d1" not in predecessor_state.get("disputes_by_id", {})
    f["pre_state"] = predecessor_state
    f["case"] = case
    observation = _review(f)
    assert all(observation["observations"].values())
    assert observation["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert observation["may_enqueue_account_ban"] is False


def _resign_and_rebind_opening(f: dict, keypair: dict, payload: dict) -> None:
    """Rebuild every signature/ID/receipt/block commitment after payload change."""
    tx = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "network_id": NETWORK,
            "tx_type": "DISPUTE_OPEN",
            "signer": "@alice",
            "nonce": 7,
            "payload": payload,
        },
        privkey=keypair["privkey"],
    )
    tx_id = compute_tx_id_from_dict(CHAIN, tx)
    tx["tx_id"] = tx_id
    f["opening_tx_id"] = tx_id
    block = f["block"]
    block["txs"] = [tx]
    block["receipts"] = [
        {
            "tx_id": tx_id,
            "tx_type": "DISPUTE_OPEN",
            "signer": "@alice",
            "nonce": 7,
            "ok": True,
        }
    ]
    header = block["header"]
    header["tx_ids"] = [tx_id]
    header["receipts_root"] = compute_receipts_root(receipts=block["receipts"])
    block["block_id"] = compute_block_id(
        chain_id=CHAIN,
        height=header["height"],
        prev_block_id=block["prev_block_id"],
        prev_block_hash=header["prev_block_hash"],
        ts_ms=header["block_ts_ms"],
        node_id=block["proposer"],
        tx_ids=[tx_id],
        receipts_root=header["receipts_root"],
    )
    block["block_hash"] = compute_block_hash(header=header)


def test_domain_generated_case_id_and_normalized_target_are_source_bound(
    keypair: dict,
) -> None:
    """Domain's _mk_id fallback and target normalization are canonical facts."""
    from weall.runtime.apply.dispute import apply_dispute
    from weall.runtime.tx_admission_types import TxEnvelope

    f = _fixture(keypair)
    _resign_and_rebind_opening(
        f,
        keypair,
        {
            "target_type": "ACCOUNT",
            "target_id": "  @bob  ",
            "reason": "  Review only  ",
        },
    )
    prior = copy.deepcopy(f["pre_state"])
    prior["accounts"]["@alice"]["poh_tier"] = 2
    post = copy.deepcopy(prior)
    apply_dispute(post, TxEnvelope.from_json(f["block"]["txs"][0]))
    case = post["disputes_by_id"]["dispute:@alice:7"]
    assert case["target_type"] == "account"
    assert case["target_id"] == "@bob"
    assert case["reason"] == "Review only"
    assert case["opened_at_height"] == 6
    f["pre_state"] = prior
    f["case"] = case
    verdict = _review(f)
    assert all(verdict["observations"].values())
    assert verdict["may_classify_canonical_case"] is False
    assert verdict["may_enqueue_account_ban"] is False

    altered = copy.deepcopy(f)
    altered["case"]["reason"] = "Substituted allegations"
    assert _review(altered)["observations"]["case_mutation_matches_signed_opening"] is False
    altered = copy.deepcopy(f)
    altered["case"]["id"] = "d1"
    assert _review(altered)["observations"]["case_mutation_matches_signed_opening"] is False


def test_signature_fields_and_preexisting_case_cannot_fake_opening(keypair: dict) -> None:
    f = _fixture(keypair)
    f["block"]["txs"][0]["signature"]["sig"] = "00" * 64
    assert _review(f)["observations"]["opening_is_exact_canonical_tx"] is False

    f = _fixture(keypair)
    f["pre_state"]["disputes_by_id"] = {"d1": {"id": "d1"}}
    assert _review(f)["observations"]["case_mutation_matches_signed_opening"] is False

    f = _fixture(keypair)
    f["block"]["txs"][0]["system"] = 0
    assert _review(f)["observations"]["opening_is_exact_canonical_tx"] is False
