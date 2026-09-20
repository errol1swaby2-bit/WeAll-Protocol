from __future__ import annotations

import pytest

import weall.runtime.bft_hotstuff as hotstuff
from weall.runtime.bft_hotstuff import BftVote, HotStuffBFT

VALIDATORS = ["v1", "v2", "v3", "v4"]
VPUB = {signer: f"pk-{signer}" for signer in VALIDATORS}
CHAIN_ID = "pbx"
VIEW = 7
BLOCK_ID = "block-7"
BLOCK_HASH = "ab" * 32
PARENT_ID = "parent-6"


def _vote(
    signer: str,
    *,
    sig: str = "good",
    epoch: int = 4,
    set_hash: str = "set-4",
) -> dict:
    return {
        "t": "VOTE",
        "chain_id": CHAIN_ID,
        "view": VIEW,
        "block_id": BLOCK_ID,
        "block_hash": BLOCK_HASH,
        "parent_id": PARENT_ID,
        "signer": signer,
        "pubkey": VPUB[signer],
        "sig": sig,
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": epoch,
        "validator_set_hash": set_hash,
    }


def _restore(*votes: dict) -> HotStuffBFT:
    bft = HotStuffBFT(chain_id=CHAIN_ID)
    bft.load_from_state(
        {
            "bft": {
                "view": VIEW,
                "pending_votes": [
                    {
                        "view": VIEW,
                        "block_id": BLOCK_ID,
                        "block_hash": BLOCK_HASH,
                        "votes": list(votes),
                    }
                ],
            }
        }
    )
    return bft


def _install_fake_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BftVote, "verify", lambda self: self.sig == "good")

    def fake_verify_qc(
        *, qc, validators, vpub=None, validator_pubkeys=None, require_threshold=True
    ):
        del vpub, validator_pubkeys
        members = set(validators)
        good_signers = {
            str(vote.get("signer") or "")
            for vote in qc.votes
            if isinstance(vote, dict)
            and str(vote.get("signer") or "") in members
            and str(vote.get("sig") or "") == "good"
            and int(vote.get("validator_epoch") or 0) == int(qc.validator_epoch)
            and str(vote.get("validator_set_hash") or "") == str(qc.validator_set_hash or "")
            and str(vote.get("block_id") or "") == str(qc.block_id)
            and str(vote.get("block_hash") or "") == str(qc.block_hash)
            and str(vote.get("parent_id") or "") == str(qc.parent_id)
        }
        return len(good_signers) >= hotstuff.quorum_threshold(len(members))

    monkeypatch.setattr(hotstuff, "verify_qc", fake_verify_qc)


def _accept(bft: HotStuffBFT, signer: str, *, epoch: int = 4, set_hash: str = "set-4"):
    return bft.accept_vote(
        vote_json=_vote(signer, epoch=epoch, set_hash=set_hash),
        validators=VALIDATORS,
        vpub=VPUB,
    )


def test_bad_signature_restored_votes_must_not_squat_authentic_signer_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_crypto(monkeypatch)
    bft = _restore(_vote("v1", sig="bad"), _vote("v2", sig="bad"))

    assert _accept(bft, "v3") is None
    assert _accept(bft, "v1") is None
    qc = _accept(bft, "v4")

    assert qc is not None
    assert qc.block_id == BLOCK_ID
    assert {str(v.get("signer")) for v in qc.votes} == {"v1", "v3", "v4"}
    assert all(str(v.get("sig")) == "good" for v in qc.votes)


def test_old_epoch_restored_votes_must_not_block_current_epoch_quorum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_crypto(monkeypatch)
    bft = _restore(_vote("v1", epoch=3, set_hash="set-3"), _vote("v2", epoch=3, set_hash="set-3"))

    assert _accept(bft, "v3") is None
    assert _accept(bft, "v1") is None
    qc = _accept(bft, "v4")

    assert qc is not None
    assert all(int(v.get("validator_epoch") or 0) == 4 for v in qc.votes)


def test_wrong_set_hash_restored_votes_must_not_block_current_set_quorum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_crypto(monkeypatch)
    bft = _restore(_vote("v1", set_hash="stale-set"), _vote("v2", set_hash="stale-set"))

    assert _accept(bft, "v3") is None
    assert _accept(bft, "v1") is None
    qc = _accept(bft, "v4")

    assert qc is not None
    assert all(str(v.get("validator_set_hash") or "") == "set-4" for v in qc.votes)


def test_conflicting_parent_restored_vote_must_not_squat_authentic_signer_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_crypto(monkeypatch)
    stale = _vote("v1")
    stale["parent_id"] = "conflicting-parent"
    bft = _restore(stale, _vote("v2"))

    assert _accept(bft, "v3") is None
    qc = _accept(bft, "v1")

    assert qc is not None
    assert {str(v.get("signer")) for v in qc.votes} == {"v1", "v2", "v3"}
    assert all(str(v.get("parent_id") or "") == PARENT_ID for v in qc.votes)


def test_state_reload_without_pending_votes_must_clear_prior_vote_bucket() -> None:
    bft = _restore(_vote("v1"), _vote("v2"))
    assert bft._votes

    bft.load_from_state({"bft": {"view": VIEW}})

    assert bft._votes == {}


def test_valid_current_restored_votes_still_complete_quorum_after_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_crypto(monkeypatch)
    bft = _restore(_vote("v1"), _vote("v2"))

    qc = _accept(bft, "v3")

    assert qc is not None
    assert {str(v.get("signer")) for v in qc.votes} == {"v1", "v2", "v3"}
