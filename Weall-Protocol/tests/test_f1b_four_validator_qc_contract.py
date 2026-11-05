"""Issue #87: cryptographic four-validator QC preflight, NOT a live BFT proof.

These tests exercise real ML-DSA signatures, quorum verification, and the
in-memory HotStuff vote aggregator. They deliberately do not claim to boot
four authorized, independent validators, transport votes, finalize a real
transaction, or persist a committed failed-apply receipt. Those are separate
mandatory acceptance steps in issue #87.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.crypto.sig import sign_mldsa
from weall.runtime.bft_finality_bridge import finalized_target_from_justify_qc
from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    BftVote,
    HotStuffBFT,
    QuorumCert,
    canonical_vote_message,
    quorum_threshold,
    validator_set_hash,
    verify_qc,
)

VALIDATORS = ("@validator-a", "@validator-b", "@validator-c", "@validator-d")
CHAIN_ID = "issue-87-crypto-preflight"
VALIDATOR_EPOCH = 9
SET_HASH = validator_set_hash(list(VALIDATORS))
VIEW = 11
BLOCK_ID = "block-3"
BLOCK_HASH = "3" * 64
PARENT_ID = "block-2"

Keypairs = dict[str, tuple[str, str]]


@pytest.fixture(scope="module")
def keypairs() -> Keypairs:
    pairs: Keypairs = {}
    for signer in (*VALIDATORS, "@outsider"):
        private_key = MLDSA65PrivateKey.generate()
        pairs[signer] = (
            private_key.public_key().public_bytes_raw().hex(),
            private_key.private_bytes_raw().hex(),
        )
    return pairs


def _pubkeys(pairs: Keypairs) -> dict[str, str]:
    return {signer: pairs[signer][0] for signer in VALIDATORS}


def _signed_vote(
    pairs: Keypairs,
    signer: str,
    *,
    chain_id: str = CHAIN_ID,
    validator_epoch: int = VALIDATOR_EPOCH,
    set_hash: str = SET_HASH,
    view: int = VIEW,
    block_id: str = BLOCK_ID,
    block_hash: str = BLOCK_HASH,
    parent_id: str = PARENT_ID,
) -> dict[str, Any]:
    message = canonical_vote_message(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=block_hash,
        parent_id=parent_id,
        signer=signer,
        validator_epoch=validator_epoch,
        validator_set_hash=set_hash,
    )
    pubkey, private_key = pairs[signer]
    vote = BftVote(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=block_hash,
        parent_id=parent_id,
        signer=signer,
        pubkey=pubkey,
        sig=sign_mldsa(message=message, privkey=private_key, encoding="hex"),
        validator_epoch=validator_epoch,
        validator_set_hash=set_hash,
    )
    assert vote.verify() is True
    return vote.to_json()


def _accept(
    aggregator: HotStuffBFT, vote: dict[str, Any], keys: Keypairs
) -> QuorumCert | None:
    return aggregator.accept_vote(
        vote_json=vote,
        validators=list(VALIDATORS),
        vpub=_pubkeys(keys),
    )


def _certified_qc(keys: Keypairs) -> QuorumCert:
    aggregator = HotStuffBFT(chain_id=CHAIN_ID)
    for signer in VALIDATORS[:2]:
        assert _accept(aggregator, _signed_vote(keys, signer), keys) is None
    qc = _accept(aggregator, _signed_vote(keys, VALIDATORS[2]), keys)
    assert qc is not None
    assert verify_qc(qc=qc, validators=list(VALIDATORS), vpub=_pubkeys(keys))
    return qc


def test_three_of_four_distinct_mldsa_votes_form_verified_qc(
    keypairs: Keypairs,
) -> None:
    assert len(VALIDATORS) == BFT_MIN_VALIDATORS == 4
    assert quorum_threshold(len(VALIDATORS)) == 3
    aggregator = HotStuffBFT(chain_id=CHAIN_ID)

    for signer in VALIDATORS[:2]:
        vote = _signed_vote(keypairs, signer)
        assert _accept(aggregator, vote, keypairs) is None
        # Re-delivery of one signed vote must not count as a second validator.
        assert _accept(aggregator, vote, keypairs) is None

    qc = _accept(aggregator, _signed_vote(keypairs, VALIDATORS[2]), keypairs)
    assert qc is not None
    assert qc.chain_id == CHAIN_ID
    assert qc.validator_epoch == VALIDATOR_EPOCH
    assert qc.validator_set_hash == SET_HASH
    assert len({v["signer"] for v in qc.votes}) == 3
    assert verify_qc(qc=qc, validators=list(VALIDATORS), vpub=_pubkeys(keypairs))


def test_two_two_partition_has_no_qc_until_three_distinct_votes(
    keypairs: Keypairs,
) -> None:
    left = HotStuffBFT(chain_id=CHAIN_ID)
    right = HotStuffBFT(chain_id=CHAIN_ID)
    votes = [_signed_vote(keypairs, signer) for signer in VALIDATORS]

    for vote in votes[:2]:
        assert _accept(left, vote, keypairs) is None
    for vote in votes[2:]:
        assert _accept(right, vote, keypairs) is None

    left_qc = _accept(left, votes[2], keypairs)
    right_qc = _accept(right, votes[0], keypairs)
    assert left_qc is not None and right_qc is not None
    for qc in (left_qc, right_qc):
        assert verify_qc(qc=qc, validators=list(VALIDATORS), vpub=_pubkeys(keypairs))
        assert qc.block_id == BLOCK_ID
        assert qc.block_hash == BLOCK_HASH


@pytest.mark.parametrize(
    "fault",
    [
        "invalid_signature",
        "registered_key_mismatch",
        "wrong_chain",
        "wrong_epoch",
        "wrong_set_hash",
        "wrong_view",
        "wrong_block_hash",
        "outsider",
    ],
)
def test_bad_third_vote_cannot_create_verified_quorum(
    keypairs: Keypairs, fault: str
) -> None:
    aggregator = HotStuffBFT(chain_id=CHAIN_ID)
    for signer in VALIDATORS[:2]:
        assert _accept(aggregator, _signed_vote(keypairs, signer), keypairs) is None

    signer = VALIDATORS[2]
    overrides: dict[str, Any] = {}
    if fault == "wrong_chain":
        overrides["chain_id"] = "foreign-chain"
    elif fault == "wrong_epoch":
        overrides["validator_epoch"] = VALIDATOR_EPOCH + 1
    elif fault == "wrong_set_hash":
        overrides["set_hash"] = "f" * 64
    elif fault == "wrong_view":
        overrides["view"] = VIEW + 1
    elif fault == "wrong_block_hash":
        overrides["block_hash"] = "f" * 64
    elif fault == "outsider":
        signer = "@outsider"

    malformed = _signed_vote(keypairs, signer, **overrides)
    if fault == "invalid_signature":
        malformed["sig"] = "00"
    elif fault == "registered_key_mismatch":
        malformed["pubkey"] = keypairs[VALIDATORS[0]][0]
    assert _accept(aggregator, malformed, keypairs) is None


def test_verified_qc_on_third_block_derives_structural_finality(
    keypairs: Keypairs,
) -> None:
    qc = _certified_qc(keypairs)
    blocks = {
        "block-1": {"height": 1, "prev_block_id": ""},
        "block-2": {"height": 2, "prev_block_id": "block-1"},
        "block-3": {"height": 3, "prev_block_id": "block-2"},
    }
    # The following two APIs are *structural*, not independent QC verifiers.
    # Always verify the signed QC first; live ingress validation remains open.
    bft = HotStuffBFT(chain_id=CHAIN_ID)
    assert bft.observe_qc(blocks=blocks, qc=qc) == "block-1"
    assert bft.finalized_block_id == "block-1"
    assert finalized_target_from_justify_qc(
        {"blocks": blocks}, qc.to_json()
    ) == ("block-1", 1)


def test_qc_metadata_mutation_invalidates_cryptographic_quorum(
    keypairs: Keypairs,
) -> None:
    qc = _certified_qc(keypairs)
    vpub = _pubkeys(keypairs)
    for mutation in (
        {"chain_id": "foreign-chain"},
        {"validator_epoch": VALIDATOR_EPOCH + 1},
        {"validator_set_hash": "f" * 64},
        {"block_hash": "f" * 64},
        {"view": VIEW + 1},
    ):
        assert not verify_qc(
            qc=replace(qc, **mutation), validators=list(VALIDATORS), vpub=vpub
        )


def test_local_vote_record_rejects_same_view_equivocation() -> None:
    # In-memory anti-equivocation preflight only; durable restart is a later gate.
    validator = HotStuffBFT(chain_id=CHAIN_ID)
    assert validator.record_local_vote(
        view=VIEW, block_id=BLOCK_ID, block_hash=BLOCK_HASH
    )
    assert validator.record_local_vote(
        view=VIEW, block_id=BLOCK_ID, block_hash=BLOCK_HASH
    )
    assert not validator.record_local_vote(
        view=VIEW, block_id="conflicting-block", block_hash="f" * 64
    )
    assert not validator.record_local_vote(
        view=VIEW, block_id=BLOCK_ID, block_hash="f" * 64
    )
    assert not validator.record_local_vote(
        view=VIEW - 1, block_id=BLOCK_ID, block_hash=BLOCK_HASH
    )
