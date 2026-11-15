"""PR93 signed QC / stored three-block ancestry diagnostic; NEVER authorization."""

from __future__ import annotations

import copy
import importlib
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.crypto.sig import sign_mldsa
from weall.runtime.bft_hotstuff import (
    BftVote,
    QuorumCert,
    canonical_vote_message,
    validator_set_hash,
    verify_qc,
)
from weall.runtime.executor import WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
review = importlib.import_module("scripts.reputation_parent_finality_review")
review_persisted_reputation_parent_qc_chain = review.review_persisted_reputation_parent_qc_chain
VALIDATORS = ("@review-v1", "@review-v2", "@review-v3", "@review-v4")
EPOCH = 9
CHAIN = "pr93-signed-qc-history-review"


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("WEALL_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in (
        ("WEALL_MODE", "testnet"),
        ("WEALL_SIGVERIFY", "1"),
        ("WEALL_UNSAFE_DEV", "0"),
        ("WEALL_BFT_ENABLED", "0"),
        ("WEALL_NET_ENABLED", "0"),
        ("WEALL_NET_LOOP_AUTOSTART", "0"),
        ("WEALL_BLOCK_LOOP_AUTOSTART", "0"),
    ):
        monkeypatch.setenv(name, value)


def _bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[WeAllExecutor, list[dict], dict]:
    _configure(monkeypatch)
    executor = WeAllExecutor(
        db_path=str(tmp_path / "three-blocks.sqlite"),
        node_id="producer",
        chain_id=CHAIN,
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )
    for _ in range(3):
        receipt = executor.produce_block(max_txs=0, allow_empty=True)
        assert receipt.ok is True, receipt.error

    private_keys = {signer: MLDSA65PrivateKey.generate() for signer in VALIDATORS}
    pubkeys = {
        signer: private_keys[signer].public_key().public_bytes_raw().hex() for signer in VALIDATORS
    }
    set_hash = validator_set_hash(list(VALIDATORS))
    authority = {
        "validators": list(VALIDATORS),
        "validator_pubkeys": pubkeys,
        "validator_epoch": EPOCH,
        "validator_set_hash": set_hash,
    }
    certificates: list[dict] = []
    for height in (1, 2, 3):
        block = executor.get_block_by_height(height)
        assert isinstance(block, dict)
        votes = []
        for signer in VALIDATORS[:3]:
            message = canonical_vote_message(
                chain_id=CHAIN,
                view=height + 10,
                block_id=block["block_id"],
                block_hash=block["block_hash"],
                parent_id=block["prev_block_id"],
                signer=signer,
                validator_epoch=EPOCH,
                validator_set_hash=set_hash,
            )
            vote = BftVote(
                chain_id=CHAIN,
                view=height + 10,
                block_id=block["block_id"],
                block_hash=block["block_hash"],
                parent_id=block["prev_block_id"],
                signer=signer,
                pubkey=pubkeys[signer],
                sig=sign_mldsa(
                    message=message,
                    privkey=private_keys[signer].private_bytes_raw().hex(),
                    encoding="hex",
                ),
                validator_epoch=EPOCH,
                validator_set_hash=set_hash,
            )
            assert vote.verify()
            votes.append(vote.to_json())
        qc = QuorumCert(
            chain_id=CHAIN,
            view=height + 10,
            block_id=block["block_id"],
            block_hash=block["block_hash"],
            parent_id=block["prev_block_id"],
            votes=tuple(votes),
            validator_epoch=EPOCH,
            validator_set_hash=set_hash,
        )
        assert verify_qc(qc=qc, validators=list(VALIDATORS), vpub=pubkeys)
        certificates.append(qc.to_json())
    return executor, certificates, authority


def _report(executor: Any, certificates: Any, authority: Any) -> dict:
    return review_persisted_reputation_parent_qc_chain(
        executor=executor,
        parent_height=1,
        qc_triplet=certificates,
        pinned_validator_authority=authority,
        parent_queue_id="synthetic:unproven-dispute-parent",
    )


def test_three_real_sqlite_blocks_and_real_signatures_are_only_review_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor, qcs, authority = _bundle(tmp_path, monkeypatch)
    report = _report(executor, qcs, authority)
    observations = report["observations"]
    assert observations["three_stored_blocks_canonically_self_bound"] is True
    assert observations["three_stored_blocks_parent_linked"] is True
    assert observations["three_exact_signed_quorum_certificates_verified"] is True
    assert report["certificates_checked"] == 3
    assert report["cryptographic_three_chain_candidate"] is True
    assert observations["exact_parent_dispute_resolution_success_receipt"] is False
    assert observations["validator_registry_independently_authenticated"] is False
    assert report["independent_bft_finality_verified"] is False
    assert report["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert report["may_enqueue_reputation_delta"] is False
    assert report["may_ban_account"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "insufficient_quorum",
        "invalid_signature",
        "wrong_authority_pubkey",
        "wrong_set_hash",
        "wrong_epoch",
        "wrong_block_hash",
        "wrong_parent",
        "duplicate_signer",
        "wrong_chain",
        "nonincreasing_view",
        "missing_certificate",
    ],
)
def test_false_qc_history_does_not_produce_valid_three_chain_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    executor, qcs, authority = _bundle(tmp_path, monkeypatch)
    qcs = copy.deepcopy(qcs)
    authority = copy.deepcopy(authority)
    if fault == "insufficient_quorum":
        qcs[2]["votes"] = qcs[2]["votes"][:2]
    elif fault == "invalid_signature":
        qcs[2]["votes"][2]["sig"] = "00"
    elif fault == "wrong_authority_pubkey":
        authority["validator_pubkeys"][VALIDATORS[2]] = "fa" * 1952
    elif fault == "wrong_set_hash":
        authority["validator_set_hash"] = "f" * 64
    elif fault == "wrong_epoch":
        qcs[2]["validator_epoch"] = EPOCH + 1
    elif fault == "wrong_block_hash":
        qcs[2]["block_hash"] = "f" * 64
    elif fault == "wrong_parent":
        qcs[2]["parent_id"] = "wrong-parent"
    elif fault == "duplicate_signer":
        qcs[2]["votes"][2] = copy.deepcopy(qcs[2]["votes"][0])
    elif fault == "wrong_chain":
        qcs[2]["chain_id"] = "foreign-chain"
    elif fault == "nonincreasing_view":
        qcs[2]["view"] = qcs[1]["view"]
    else:
        qcs.pop()
    report = _report(executor, qcs, authority)
    assert report["cryptographic_three_chain_candidate"] is False
    assert report["independent_bft_finality_verified"] is False
    assert report["may_enqueue_reputation_delta"] is False
    assert report["may_ban_account"] is False
    assert report["blocking_reasons"]


class _CorruptHistoricalBlock:
    def __init__(self, original: WeAllExecutor):
        self.original = original
        self.chain_id = original.chain_id

    def read_state(self) -> dict:
        return self.original.read_state()

    def get_block_by_height(self, height: int) -> dict | None:
        block = copy.deepcopy(self.original.get_block_by_height(height))
        if height == 2 and isinstance(block, dict):
            block["prev_block_id"] = "foreign-history"
        return block


def test_changed_stored_parent_cannot_be_masked_by_valid_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor, qcs, authority = _bundle(tmp_path, monkeypatch)
    report = _report(_CorruptHistoricalBlock(executor), qcs, authority)
    assert report["cryptographic_three_chain_candidate"] is False
    assert report["may_ban_account"] is False
    assert report["blocking_reasons"]
