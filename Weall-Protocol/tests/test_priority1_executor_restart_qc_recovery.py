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


def _make_executor(*, chain_id: str = "batch96") -> WeAllExecutor:
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
    ex._put_pending_missing_qc = MethodType(lambda self, qcj: None, ex)
    ex._drop_quarantined_remote_artifacts = MethodType(lambda self, bid: None, ex)
    ex._promote_quarantined_remote_block = MethodType(lambda self, bid, block: None, ex)
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


def test_executor_observes_verified_embedded_qc_before_vote_batch96(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft.locked_qc = _qc("batch96", 4, "C1", "B1")
    ex._bft.high_qc = _qc("batch96", 4, "C1", "B1")

    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    embedded_qc = _qc("batch96", 5, "C2", "B2")
    ex.bft_verify_qc_json = MethodType(
        lambda self, qcj: embedded_qc if qcj == embedded_qc.to_json() else None,
        ex,
    )

    proposal = {
        "view": 6,
        "proposer": "alice",
        "block": {
            "chain_id": "batch96",
            "block_id": "D2",
            "block_hash": "D2-h",
            "prev_block_id": "C2",
            "height": 4,
            "qc": embedded_qc.to_json(),
        },
    }

    vote = ex.bft_on_proposal(proposal)

    assert isinstance(vote, dict)
    assert vote.get("block_id") == "D2"
    assert ex._bft.high_qc is not None
    assert ex._bft.high_qc.block_id == "C2"
    assert ex._bft.last_voted_block_id == "D2"


def test_executor_rejects_unverified_explicit_justify_qc_batch96(monkeypatch) -> None:
    ex = _make_executor()
    ex._bft.locked_qc = _qc("batch96", 4, "C1", "B1")
    ex._bft.high_qc = _qc("batch96", 4, "C1", "B1")

    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")

    bad_justify = _qc("batch96", 9, "C2", "B2").to_json()
    ex.bft_verify_qc_json = MethodType(lambda self, qcj: None, ex)

    proposal = {
        "chain_id": "batch96",
        "view": 6,
        "proposer": "alice",
        "block_id": "D2",
        "block_hash": "D2-h",
        "prev_block_id": "C2",
        "height": 4,
        "justify_qc": bad_justify,
    }

    assert ex.bft_on_proposal(proposal) is None
    assert ex._bft.last_voted_block_id == ""


def test_executor_restart_uses_persisted_high_qc_recovery_without_explicit_justify_batch96(
    monkeypatch,
) -> None:
    ex = _make_executor()
    hs = HotStuffBFT(chain_id="batch96")
    hs.locked_qc = _qc("batch96", 4, "C1", "B1")
    hs.high_qc = _qc("batch96", 5, "C2", "B2")
    state = hs.export_state()
    ex._bft.load_from_state({"bft": state})

    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    ex.bft_verify_qc_json = MethodType(lambda self, qcj: None, ex)

    proposal = {
        "chain_id": "batch96",
        "view": 6,
        "proposer": "alice",
        "block_id": "D2",
        "block_hash": "D2-h",
        "prev_block_id": "C2",
        "height": 4,
    }

    vote = ex.bft_on_proposal(proposal)

    assert isinstance(vote, dict)
    assert vote.get("block_id") == "D2"
    assert ex._bft.last_voted_block_id == "D2"


def test_executor_restart_rejects_conflicting_high_qc_block_itself_batch96(monkeypatch) -> None:
    ex = _make_executor()
    hs = HotStuffBFT(chain_id="batch96")
    hs.locked_qc = _qc("batch96", 4, "C1", "B1")
    hs.high_qc = _qc("batch96", 5, "C2", "B2")
    ex._bft.load_from_state({"bft": hs.export_state()})

    monkeypatch.setattr(executor_mod, "admit_bft_block", lambda block, state: (True, ""))
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "1")
    ex.bft_verify_qc_json = MethodType(lambda self, qcj: None, ex)

    proposal = {
        "chain_id": "batch96",
        "view": 6,
        "proposer": "alice",
        "block_id": "C2",
        "block_hash": "C2-h",
        "prev_block_id": "B2",
        "height": 3,
    }

    assert ex.bft_on_proposal(proposal) is None
    assert ex._bft.last_voted_block_id == ""
