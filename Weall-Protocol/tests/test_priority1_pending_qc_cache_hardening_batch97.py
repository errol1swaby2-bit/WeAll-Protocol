from __future__ import annotations

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


def _make_executor(*, chain_id: str = "batch97") -> WeAllExecutor:
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
    ex._quarantined_remote_blocks = {}
    ex._pending_remote_blocks = {}
    ex._pending_candidates = {}
    ex._pending_missing_qcs = {}
    ex._pending_missing_qcs_by_hash = {}
    ex._active_validators = MethodType(lambda self: ["alice"], ex)
    ex._validator_pubkeys = MethodType(lambda self: {}, ex)
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

    def _put_pending_missing_qc(self, qcj):
        self._pending_missing_qcs[str(qcj.get("block_id") or "")] = dict(qcj)
        self._pending_missing_qcs_by_hash[str(qcj.get("block_hash") or "")] = dict(qcj)

    ex._put_pending_missing_qc = MethodType(_put_pending_missing_qc, ex)
    ex._bft_pending_block_json = MethodType(lambda self, bid: None, ex)
    ex.bft_try_apply_pending_remote_blocks = MethodType(lambda self: [], ex)
    ex._validate_remote_proposal_for_vote = MethodType(lambda self, proposal: True, ex)
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ex._block_height_hint = MethodType(lambda self, blk: int(blk.get("height") or 0), ex)
    ex.bft_make_vote_for_block = MethodType(
        lambda self, **kwargs: {
            "t": "VOTE",
            "view": int(kwargs["view"]),
            "block_id": str(kwargs["block_id"]),
            "block_hash": str(kwargs["block_hash"]),
            "parent_id": str(kwargs["parent_id"]),
        },
        ex,
    )
    return ex


def test_invalid_leader_proposal_drops_quarantine_and_does_not_cache_qc_batch97(monkeypatch) -> None:
    ex = _make_executor()
    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    justify = _qc("batch97", 5, "C2", "B2")
    ex.bft_verify_qc_json = MethodType(
        lambda self, qcj: justify if qcj == justify.to_json() else None,
        ex,
    )

    proposal = {
        "view": 6,
        "proposer": "mallory",
        "block": {
            "chain_id": "batch97",
            "block_id": "D2",
            "block_hash": "D2-h",
            "prev_block_id": "C2",
            "height": 4,
            "justify_qc": justify.to_json(),
        },
    }

    assert ex.bft_on_proposal(proposal) is None
    assert ex._quarantined_remote_blocks == {}
    assert ex._pending_remote_blocks == {}
    assert ex._pending_missing_qcs == {}


def test_unrelated_justify_qc_branch_is_rejected_without_cache_pollution_batch97(monkeypatch) -> None:
    ex = _make_executor()
    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    justify = _qc("batch97", 5, "C2", "B2")
    ex.bft_verify_qc_json = MethodType(
        lambda self, qcj: justify if qcj == justify.to_json() else None,
        ex,
    )

    proposal = {
        "chain_id": "batch97",
        "view": 6,
        "proposer": "alice",
        "block_id": "D1",
        "block_hash": "D1-h",
        "prev_block_id": "C1",
        "height": 4,
        "justify_qc": justify.to_json(),
    }

    assert ex.bft_on_proposal(proposal) is None
    assert ex._quarantined_remote_blocks == {}
    assert ex._pending_remote_blocks == {}
    assert ex._pending_missing_qcs == {}


def test_valid_justify_qc_is_cached_only_after_proposal_survives_checks_batch97(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft.locked_qc = _qc("batch97", 4, "C1", "B1")
    ex._bft.high_qc = _qc("batch97", 4, "C1", "B1")
    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    justify = _qc("batch97", 5, "C2", "B2")
    ex.bft_verify_qc_json = MethodType(
        lambda self, qcj: justify if qcj == justify.to_json() else None,
        ex,
    )

    proposal = {
        "chain_id": "batch97",
        "view": 6,
        "proposer": "alice",
        "block_id": "D2",
        "block_hash": "D2-h",
        "prev_block_id": "C2",
        "height": 4,
        "justify_qc": justify.to_json(),
    }

    vote = ex.bft_on_proposal(proposal)

    assert isinstance(vote, dict)
    assert vote.get("block_id") == "D2"
    assert "D2" in ex._pending_remote_blocks
    assert ex._pending_missing_qcs.get("C2", {}).get("block_hash") == "C2-h"
    assert ex._bft.high_qc is not None
    assert ex._bft.high_qc.block_id == "C2"
