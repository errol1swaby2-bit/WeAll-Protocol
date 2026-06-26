from __future__ import annotations

from collections import OrderedDict
from types import MethodType

from weall.runtime.bft_hotstuff import HotStuffBFT
from weall.runtime.executor import WeAllExecutor


def _make_executor(*, chain_id: str = "batch104") -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.chain_id = chain_id
    ex.node_id = "alice"
    ex.state = {"tip": "C1", "blocks": {"C1": {"prev_block_id": "B1", "height": 3}}}
    ex._bft = HotStuffBFT(chain_id=chain_id)
    ex._recent_bft_votes = OrderedDict()
    ex._recent_bft_timeouts = OrderedDict()
    ex._recent_bft_proposals = OrderedDict()
    ex._recent_bft_qcs = OrderedDict()
    ex._max_recent_bft_votes = 32
    ex._max_recent_bft_timeouts = 32
    ex._max_recent_bft_proposals = 32
    ex._max_recent_bft_qcs = 32
    ex._active_validators = MethodType(lambda self: ["alice"], ex)
    ex._validator_pubkeys = MethodType(lambda self: {"alice": "pub"}, ex)
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._bft_payload_phase_matches_current_security_model = MethodType(
        lambda self, payload: True, ex
    )
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ex._put_pending_missing_qc = MethodType(lambda self, qcj: None, ex)
    return ex


def test_duplicate_vote_is_suppressed_before_accept_vote_batch104() -> None:
    ex = _make_executor()
    calls = {"accept_vote": 0}

    def _accept_vote(self, *, vote_json, validators, vpub):
        calls["accept_vote"] += 1
        return None

    ex._bft.accept_vote = MethodType(_accept_vote, ex._bft)

    vote = {
        "t": "VOTE",
        "chain_id": "batch104",
        "view": 6,
        "block_id": "D2",
        "block_hash": "D2-h",
        "parent_id": "C2",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "sig",
        "validator_epoch": 1,
        "validator_set_hash": "sethash",
    }

    first = ex.bft_handle_vote(vote)
    second = ex.bft_handle_vote(vote)

    assert first is None
    assert second is None
    assert calls == {"accept_vote": 1}
    assert len(ex._recent_bft_votes) == 1


def test_duplicate_timeout_is_suppressed_before_accept_timeout_batch104() -> None:
    ex = _make_executor()
    calls = {"accept_timeout": 0}

    def _accept_timeout(self, *, timeout_json, validators, vpub):
        calls["accept_timeout"] += 1
        return None

    ex._bft.accept_timeout = MethodType(_accept_timeout, ex._bft)

    timeout = {
        "t": "TIMEOUT",
        "chain_id": "batch104",
        "view": 7,
        "high_qc_id": "C2",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "sig",
        "validator_epoch": 1,
        "validator_set_hash": "sethash",
    }

    first = ex.bft_handle_timeout(timeout)
    second = ex.bft_handle_timeout(timeout)

    assert first is None
    assert second is None
    assert calls == {"accept_timeout": 1}
    assert len(ex._recent_bft_timeouts) == 1
