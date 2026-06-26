from __future__ import annotations

from collections import OrderedDict
from types import MethodType

import weall.runtime.executor as executor_mod
from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _qc(chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def _make_executor(*, chain_id: str = "batch105") -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.chain_id = chain_id
    ex.node_id = "alice"
    ex.state = {
        "tip": "C1",
        "blocks": {
            "A": {"prev_block_id": "", "height": 1, "block_hash": "A-h"},
            "B1": {"prev_block_id": "A", "height": 2, "block_hash": "B1-h"},
            "C1": {"prev_block_id": "B1", "height": 3, "block_hash": "C1-h"},
            "B2": {"prev_block_id": "A", "height": 2, "block_hash": "B2-h"},
            "C2": {"prev_block_id": "B2", "height": 3, "block_hash": "C2-h"},
        },
    }
    ex._bft = HotStuffBFT(chain_id=chain_id)
    ex._quarantined_remote_blocks = OrderedDict()
    ex._quarantined_remote_block_ids_by_hash = OrderedDict()
    ex._pending_remote_blocks = OrderedDict()
    ex._pending_remote_block_ids_by_hash = OrderedDict()
    ex._pending_candidates = OrderedDict()
    ex._pending_missing_qcs = OrderedDict()
    ex._pending_missing_qcs_by_hash = OrderedDict()
    ex._recent_bft_proposals = OrderedDict()
    ex._recent_bft_qcs = OrderedDict()
    ex._recent_bft_votes = OrderedDict()
    ex._recent_bft_timeouts = OrderedDict()
    ex._recent_bft_sender_budgets = OrderedDict()
    ex._max_recent_bft_proposals = 64
    ex._max_recent_bft_qcs = 64
    ex._max_recent_bft_votes = 64
    ex._max_recent_bft_timeouts = 64
    ex._max_recent_bft_sender_budgets = 64
    ex._bft_sender_budget_window_ms = 60_000
    ex._bft_sender_budget_per_window = 2
    ex._active_validators = MethodType(lambda self: ["alice"], ex)
    ex._validator_pubkeys = MethodType(lambda self: {"alice": "pub"}, ex)
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._bft_payload_phase_matches_current_security_model = MethodType(
        lambda self, payload: True, ex
    )
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
    ex._is_conflicted_block_id = MethodType(lambda self, block_id: False, ex)
    ex._block_identity_conflicts = MethodType(lambda self, block: False, ex)
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
    ex._drop_pending_candidate_artifacts = MethodType(
        lambda self, bid: self._pending_remote_blocks.pop(str(bid or ""), None), ex
    )
    ex._put_pending_missing_qc = MethodType(
        lambda self, qcj: self._pending_missing_qcs.__setitem__(
            str(qcj.get("block_id") or ""), dict(qcj)
        ),
        ex,
    )
    ex._resolve_pending_block_identity = MethodType(lambda self, **kwargs: ("", None), ex)
    ex.bft_try_apply_pending_remote_blocks = MethodType(lambda self: [], ex)
    ex.bft_handle_qc = MethodType(lambda self, qcj: None, ex)
    ex.bft_commit_if_ready = MethodType(lambda self, qc: None, ex)
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ex._validate_remote_proposal_for_vote = MethodType(lambda self, proposal: False, ex)
    return ex


def test_proposal_sender_budget_drops_third_distinct_proposal_batch105(monkeypatch) -> None:
    ex = _make_executor()
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "0")

    calls = {"admit": 0}

    def _admit(block, state):
        calls["admit"] += 1
        return (True, "")

    monkeypatch.setattr(executor_mod, "admit_bft_block", _admit)

    base = {
        "chain_id": "batch105",
        "view": 0,
        "proposer": "alice",
        "prev_block_id": "C1",
        "height": 4,
    }

    for block_id in ["D1", "D2", "D3"]:
        proposal = dict(base)
        proposal["block_id"] = block_id
        proposal["block_hash"] = f"{block_id}-h"
        assert ex.bft_on_proposal(proposal) is None

    assert calls == {"admit": 2}
    assert len(ex._recent_bft_sender_budgets) == 1
    assert ex._recent_bft_sender_budgets["alice"][1] == 2


def test_qc_sender_budget_drops_third_distinct_qc_batch105() -> None:
    ex = _make_executor()
    calls = {"verify": 0}

    def _verify(self, qcj):
        calls["verify"] += 1
        return _qc(
            chain_id=str(qcj.get("chain_id") or "batch105"),
            view=int(qcj.get("view") or 0),
            block_id=str(qcj.get("block_id") or ""),
            parent_id=str(qcj.get("parent_id") or ""),
        )

    ex.bft_verify_qc_json = MethodType(_verify, ex)

    for idx in range(1, 4):
        qcj = {
            "t": "QC",
            "chain_id": "batch105",
            "view": idx,
            "block_id": f"D{idx}",
            "block_hash": f"D{idx}-h",
            "parent_id": "C1",
            "sender": "alice",
            "votes": [{"signer": "alice"}],
        }
        assert ex.bft_on_qc(qcj) is None

    assert calls == {"verify": 2}
    assert ex._recent_bft_sender_budgets["alice"][1] == 2


def test_vote_sender_budget_is_fair_across_senders_batch105() -> None:
    ex = _make_executor()
    ex._bft_sender_budget_per_window = 1
    calls = {"accept_vote": 0}

    def _accept_vote(self, *, vote_json, validators, vpub):
        calls["accept_vote"] += 1
        return None

    ex._bft.accept_vote = MethodType(_accept_vote, ex._bft)

    alice_vote_1 = {
        "t": "VOTE",
        "chain_id": "batch105",
        "view": 6,
        "block_id": "D1",
        "block_hash": "D1-h",
        "parent_id": "C1",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "sig1",
        "validator_epoch": 1,
        "validator_set_hash": "sethash",
    }
    alice_vote_2 = dict(alice_vote_1)
    alice_vote_2["block_id"] = "D2"
    alice_vote_2["block_hash"] = "D2-h"
    alice_vote_2["sig"] = "sig2"
    bob_vote = dict(alice_vote_1)
    bob_vote["signer"] = "bob"
    bob_vote["block_id"] = "D3"
    bob_vote["block_hash"] = "D3-h"
    bob_vote["sig"] = "sig3"

    assert ex.bft_handle_vote(alice_vote_1) is None
    assert ex.bft_handle_vote(alice_vote_2) is None
    assert ex.bft_handle_vote(bob_vote) is None

    assert calls == {"accept_vote": 2}
    assert ex._recent_bft_sender_budgets["alice"][1] == 1
    assert ex._recent_bft_sender_budgets["bob"][1] == 1


def test_timeout_sender_budget_drops_third_distinct_timeout_batch105() -> None:
    ex = _make_executor()
    calls = {"accept_timeout": 0}

    def _accept_timeout(self, *, timeout_json, validators, vpub):
        calls["accept_timeout"] += 1
        return None

    ex._bft.accept_timeout = MethodType(_accept_timeout, ex._bft)

    for view in [7, 8, 9]:
        timeout = {
            "t": "TIMEOUT",
            "chain_id": "batch105",
            "view": view,
            "high_qc_id": "C1",
            "signer": "alice",
            "pubkey": "pub",
            "sig": f"sig-{view}",
            "validator_epoch": 1,
            "validator_set_hash": "sethash",
        }
        assert ex.bft_handle_timeout(timeout) is None

    assert calls == {"accept_timeout": 2}
    assert ex._recent_bft_sender_budgets["alice"][1] == 2
