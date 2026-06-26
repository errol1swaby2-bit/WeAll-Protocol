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


def _make_executor(*, chain_id: str = "batch103") -> WeAllExecutor:
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
    ex._max_recent_bft_proposals = 32
    ex._max_recent_bft_qcs = 32
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
    ex._drop_pending_candidate_artifacts = MethodType(
        lambda self, bid: self._pending_remote_blocks.pop(str(bid or ""), None), ex
    )

    def _put_pending_missing_qc(self, qcj):
        self._pending_missing_qcs[str(qcj.get("block_id") or "")] = dict(qcj)
        self._pending_missing_qcs_by_hash[str(qcj.get("block_hash") or "")] = dict(qcj)

    ex._put_pending_missing_qc = MethodType(_put_pending_missing_qc, ex)
    ex._resolve_pending_block_identity = MethodType(
        lambda self, block_id, block_hash: ("", None), ex
    )
    ex.bft_commit_if_ready = MethodType(lambda self, qc: None, ex)
    ex.bft_handle_qc = MethodType(lambda self, qcj: None, ex)
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


def test_duplicate_proposal_is_suppressed_before_revalidation_batch103(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft.locked_qc = _qc("batch103", 4, "C1", "B1")
    ex._bft.high_qc = _qc("batch103", 4, "C1", "B1")
    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    calls = {"verify": 0, "replay": 0}
    justify = _qc("batch103", 5, "C2", "B2")

    def _verify(self, qcj):
        calls["verify"] += 1
        return justify if qcj == justify.to_json() else None

    def _replay(self):
        calls["replay"] += 1
        return []

    ex.bft_verify_qc_json = MethodType(_verify, ex)
    ex.bft_try_apply_pending_remote_blocks = MethodType(_replay, ex)

    proposal = {
        "chain_id": "batch103",
        "view": 6,
        "proposer": "alice",
        "block_id": "D2",
        "block_hash": "D2-h",
        "prev_block_id": "C2",
        "height": 4,
        "justify_qc": justify.to_json(),
    }

    vote1 = ex.bft_on_proposal(proposal)
    vote2 = ex.bft_on_proposal(proposal)

    assert isinstance(vote1, dict)
    assert vote1.get("block_id") == "D2"
    assert vote2 is None
    assert calls == {"verify": 1, "replay": 1}
    assert list(ex._pending_remote_blocks.keys()) == ["D2"]


def test_duplicate_qc_is_suppressed_before_replay_batch103() -> None:
    ex = _make_executor()
    calls = {"verify": 0, "replay": 0}
    qc = _qc("batch103", 5, "C2", "B2")

    def _verify(self, qcj):
        calls["verify"] += 1
        return qc if qcj == qc.to_json() else None

    def _replay(self):
        calls["replay"] += 1
        return []

    ex.bft_verify_qc_json = MethodType(_verify, ex)
    ex.bft_try_apply_pending_remote_blocks = MethodType(_replay, ex)

    first = ex.bft_on_qc(qc.to_json())
    second = ex.bft_on_qc(qc.to_json())

    assert first is None
    assert second is None
    assert calls == {"verify": 1, "replay": 1}
    assert ex._pending_missing_qcs.get("C2", {}).get("block_hash") == "C2-h"
