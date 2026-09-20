from __future__ import annotations

from collections import OrderedDict
from types import MethodType, SimpleNamespace

import weall.runtime.bft_runtime_adapter as bft_adapter
from weall.runtime.bft_hotstuff import HotStuffBFT
from weall.runtime.executor import WeAllExecutor


def _make_executor(*, chain_id: str = "pb001br") -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.chain_id = chain_id
    ex.node_id = "alice"
    ex.state = {
        "tip": "C1",
        "height": 3,
        "blocks": {"C1": {"prev_block_id": "B1", "height": 3, "block_hash": "C1-h"}},
    }
    ex._bft = HotStuffBFT(chain_id=chain_id)
    ex._recent_bft_proposals = OrderedDict()
    ex._recent_bft_qcs = OrderedDict()
    ex._recent_bft_votes = OrderedDict()
    ex._recent_bft_timeouts = OrderedDict()
    ex._recent_bft_sender_budgets = OrderedDict()
    ex._max_recent_bft_proposals = 32
    ex._max_recent_bft_qcs = 32
    ex._max_recent_bft_votes = 32
    ex._max_recent_bft_timeouts = 32
    ex._max_recent_bft_sender_budgets = 32
    ex._bft_sender_budget_window_ms = 1_000
    ex._bft_sender_budget_per_window = 64
    ex._quarantined_remote_blocks = OrderedDict()
    ex._quarantined_remote_block_ids_by_hash = OrderedDict()
    ex._pending_remote_blocks = OrderedDict()
    ex._pending_remote_block_ids_by_hash = OrderedDict()
    ex._pending_candidates = OrderedDict()
    ex._pending_missing_qcs = OrderedDict()
    ex._pending_missing_qcs_by_hash = OrderedDict()

    ex._active_validators = MethodType(lambda self: ["alice"], ex)
    ex._local_validator_account = MethodType(lambda self: "", ex)
    ex._validator_pubkeys = MethodType(lambda self: {"alice": "pub"}, ex)
    ex._bft_artifact_shape_fast_fail = MethodType(lambda self, kind, payload: True, ex)
    ex._bft_payload_phase_matches_current_security_model = MethodType(
        lambda self, payload: True, ex
    )
    ex._is_conflicted_block_id = MethodType(lambda self, block_id: False, ex)
    ex._is_conflicted_block_hash = MethodType(lambda self, block_hash: False, ex)
    ex._block_identity_conflicts = MethodType(lambda self, block, **kwargs: False, ex)
    ex._quarantine_remote_block = MethodType(
        lambda self, block: self._quarantined_remote_blocks.__setitem__(
            str(block.get("block_id") or ""), dict(block)
        ),
        ex,
    )
    ex._drop_quarantined_remote_artifacts = MethodType(
        lambda self, bid: self._quarantined_remote_blocks.pop(str(bid or ""), None), ex
    )
    ex._promote_quarantined_remote_block = MethodType(
        lambda self, bid, block: self._pending_remote_blocks.__setitem__(
            str(bid or ""), dict(block or {})
        ),
        ex,
    )
    ex.bft_try_apply_pending_remote_blocks = MethodType(lambda self: [], ex)
    ex._consume_bft_sender_budget = MethodType(lambda self, payload: True, ex)
    return ex


def _proposal(*, signed: bool = False) -> dict:
    out = {
        "chain_id": "pb001br",
        "view": 6,
        "proposer": "alice",
        "block_id": "D1",
        "block_hash": "D1-h",
        "prev_block_id": "C1",
        "height": 4,
        "validator_epoch": 2,
        "validator_set_hash": "future-set",
        "header": {
            "chain_id": "pb001br",
            "height": 4,
            "prev_block_hash": "C1-h",
            "block_ts_ms": 4,
            "tx_ids": [],
            "receipts_root": "11" * 32,
        },
        "txs": [],
    }
    if signed:
        out["proposer_pubkey"] = "pub"
        out["proposer_sig"] = "signed-wire-artifact"
    return out


def test_future_epoch_proposal_is_rechecked_after_local_epoch_catches_up(monkeypatch) -> None:
    ex = _make_executor()
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "0")
    monkeypatch.setattr(bft_adapter, "_call_admit_bft_block", lambda **kwargs: (True, ""))

    ready = {"epoch": False}
    calls = {"epoch": 0}

    def _epoch_matches(self, payload):
        calls["epoch"] += 1
        return ready["epoch"]

    ex._bft_epoch_binding_matches = MethodType(_epoch_matches, ex)
    proposal = _proposal()

    assert ex.bft_on_proposal(proposal) is None
    assert calls["epoch"] == 1
    assert ex._recent_bft_proposals == {}

    ready["epoch"] = True
    assert ex.bft_on_proposal(proposal) is None
    assert calls["epoch"] == 2
    assert "D1" in ex._pending_remote_blocks
    assert len(ex._recent_bft_proposals) == 1
    assert ex.bft_artifact_was_accepted("proposal", proposal) is True


def test_signature_rejection_does_not_poison_exact_proposal_retry(monkeypatch) -> None:
    ex = _make_executor()
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    monkeypatch.setenv("WEALL_AUTOVOTE", "0")
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)

    ready = {"signature": False}
    calls = {"verify": 0}

    def _verify(**kwargs):
        calls["verify"] += 1
        return ready["signature"]

    monkeypatch.setattr(bft_adapter, "verify_proposal_json", _verify)
    monkeypatch.setattr(
        bft_adapter,
        "validate_received_block_commitments",
        lambda **kwargs: (
            True,
            "ok",
            SimpleNamespace(
                block_id="D1",
                block_hash="D1-h",
                advertised_block_hash="D1-h",
            ),
        ),
    )
    monkeypatch.setattr(bft_adapter, "_call_admit_bft_block", lambda **kwargs: (True, ""))

    proposal = _proposal(signed=True)
    assert ex.bft_on_proposal(proposal) is None
    assert calls["verify"] == 1
    assert ex._recent_bft_proposals == {}

    ready["signature"] = True
    assert ex.bft_on_proposal(proposal) is None
    assert calls["verify"] == 2
    assert "D1" in ex._pending_remote_blocks
    assert len(ex._recent_bft_proposals) == 1
    assert ex.bft_artifact_was_accepted("proposal", proposal) is True


def test_rejected_vote_is_not_cached_before_verified_admission(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ex._put_pending_missing_qc = MethodType(lambda self, qcj: None, ex)
    ready = {"verified": False}
    calls = {"accept": 0}

    def _accept_vote(self, *, vote_json, validators, vpub, verified_admission=None):
        calls["accept"] += 1
        if not ready["verified"]:
            return None
        assert verified_admission is not None
        assert verified_admission(dict(vote_json)) is True
        return None

    ex._bft.accept_vote = MethodType(_accept_vote, ex._bft)
    vote = {
        "t": "VOTE",
        "chain_id": "pb001br",
        "view": 6,
        "block_id": "D1",
        "block_hash": "D1-h",
        "parent_id": "C1",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "wire-vote",
        "validator_epoch": 2,
        "validator_set_hash": "future-set",
    }

    assert ex.bft_handle_vote(vote) is None
    assert ex._recent_bft_votes == {}
    ready["verified"] = True
    assert ex.bft_handle_vote(vote) is None
    assert calls["accept"] == 2
    assert len(ex._recent_bft_votes) == 1
    assert ex.bft_handle_vote(vote) is None
    assert calls["accept"] == 2


def test_rejected_timeout_is_not_cached_before_verified_admission(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ready = {"verified": False}
    calls = {"accept": 0}

    def _accept_timeout(self, *, timeout_json, validators, vpub, verified_admission=None):
        calls["accept"] += 1
        if not ready["verified"]:
            return None
        assert verified_admission is not None
        assert verified_admission(dict(timeout_json)) is True
        return None

    ex._bft.accept_timeout = MethodType(_accept_timeout, ex._bft)
    timeout = {
        "t": "TIMEOUT",
        "chain_id": "pb001br",
        "view": 7,
        "high_qc_id": "C1",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "wire-timeout",
        "validator_epoch": 2,
        "validator_set_hash": "future-set",
    }

    assert ex.bft_handle_timeout(timeout) is None
    assert ex._recent_bft_timeouts == {}
    ready["verified"] = True
    assert ex.bft_handle_timeout(timeout) is None
    assert calls["accept"] == 2
    assert len(ex._recent_bft_timeouts) == 1
    assert ex.bft_handle_timeout(timeout) is None
    assert calls["accept"] == 2
