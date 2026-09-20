from __future__ import annotations

from collections import OrderedDict
from types import MethodType

import weall.runtime.bft_runtime_adapter as bft_adapter
from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _executor(*, chain_id: str = "pb001bad") -> WeAllExecutor:
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
    ex._recent_bft_admission_aliases = OrderedDict()
    ex._recent_bft_sender_budgets = OrderedDict()
    ex._max_recent_bft_proposals = 32
    ex._max_recent_bft_qcs = 32
    ex._max_recent_bft_votes = 32
    ex._max_recent_bft_timeouts = 32
    ex._max_recent_bft_admission_aliases = 32
    ex._max_recent_bft_sender_budgets = 32
    ex._bft_sender_budget_window_ms = 60_000
    ex._bft_sender_budget_per_window = 2

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
    ex._current_consensus_phase = MethodType(lambda self: "bft_active", ex)
    ex._bft_artifact_shape_fast_fail = MethodType(lambda self, kind, payload: True, ex)
    ex._bft_phase_allows_artifact_processing = MethodType(lambda self: True, ex)
    ex._bft_payload_phase_matches_current_security_model = MethodType(
        lambda self, payload: True, ex
    )
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
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
    ex._persist_bft_state = MethodType(lambda self: None, ex)
    ex._put_pending_missing_qc = MethodType(lambda self, qcj: None, ex)
    ex._resolve_pending_block_identity = MethodType(lambda self, **kwargs: ("", None), ex)
    ex.bft_handle_qc = MethodType(lambda self, qcj: None, ex)
    ex.bft_commit_if_ready = MethodType(lambda self, qc: None, ex)
    return ex


def _vote() -> dict:
    return {
        "t": "VOTE",
        "chain_id": "pb001bad",
        "view": 7,
        "block_id": "D1",
        "block_hash": "D1-h",
        "parent_id": "C1",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "captured-authentic-vote",
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": 2,
        "validator_set_hash": "set-2",
        "consensus_phase": "bft_active",
    }


def _timeout() -> dict:
    return {
        "t": "TIMEOUT",
        "chain_id": "pb001bad",
        "view": 7,
        "high_qc_id": "C1",
        "signer": "alice",
        "pubkey": "pub",
        "sig": "captured-authentic-timeout",
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": 2,
        "validator_set_hash": "set-2",
        "consensus_phase": "bft_active",
    }


def test_vote_unsigned_wire_aliases_do_not_spend_sender_budget_again() -> None:
    ex = _executor()
    calls = {"accept": 0}

    def _accept_vote(self, *, vote_json, validators, vpub, verified_admission=None):
        del validators, vpub
        calls["accept"] += 1
        assert verified_admission is not None
        assert verified_admission(dict(vote_json)) is True
        return None

    ex._bft.accept_vote = MethodType(_accept_vote, ex._bft)

    first = _vote()
    alias_one = dict(first, transport_noise="one")
    alias_two = dict(first, transport_noise="two")

    assert ex.bft_handle_vote(first) is None
    assert ex.bft_handle_vote(alias_one) is None
    assert ex.bft_handle_vote(alias_two) is None

    assert calls == {"accept": 1}
    assert ex._recent_bft_sender_budgets["alice"][1] == 1
    assert ex.bft_artifact_was_accepted("vote", alias_two) is True


def test_timeout_unsigned_wire_aliases_do_not_spend_sender_budget_again() -> None:
    ex = _executor()
    calls = {"accept": 0}

    def _accept_timeout(self, *, timeout_json, validators, vpub, verified_admission=None):
        del validators, vpub
        calls["accept"] += 1
        assert verified_admission is not None
        assert verified_admission(dict(timeout_json)) is True
        return None

    ex._bft.accept_timeout = MethodType(_accept_timeout, ex._bft)

    first = _timeout()
    alias_one = dict(first, transport_noise="one")
    alias_two = dict(first, transport_noise="two")

    assert ex.bft_handle_timeout(first) is None
    assert ex.bft_handle_timeout(alias_one) is None
    assert ex.bft_handle_timeout(alias_two) is None

    assert calls == {"accept": 1}
    assert ex._recent_bft_sender_budgets["alice"][1] == 1
    assert ex.bft_artifact_was_accepted("timeout", alias_two) is True


def test_qc_wire_and_proof_aliases_do_not_charge_embedded_validator_budget() -> None:
    ex = _executor()
    calls = {"verify": 0}

    def _verify(self, qcj):
        calls["verify"] += 1
        return QuorumCert(
            chain_id="pb001bad",
            view=7,
            block_id="D1",
            block_hash="D1-h",
            parent_id="C1",
            votes=({"signer": "alice"},),
            validator_epoch=2,
            validator_set_hash="set-2",
        )

    ex.bft_verify_qc_json = MethodType(_verify, ex)

    first = {
        "t": "QC",
        "chain_id": "pb001bad",
        "view": 7,
        "block_id": "D1",
        "block_hash": "D1-h",
        "parent_id": "C1",
        "votes": [{"signer": "alice", "sig": "proof-a"}],
        "validator_epoch": 2,
        "validator_set_hash": "set-2",
        "consensus_phase": "bft_active",
    }
    alias_one = dict(first, transport_noise="one")
    alias_one["votes"] = [{"signer": "alice", "sig": "proof-b", "noise": 1}]
    alias_two = dict(first, transport_noise="two")
    alias_two["votes"] = list(reversed(first["votes"]))

    assert ex.bft_on_qc(first) is None
    assert ex.bft_on_qc(alias_one) is None
    assert ex.bft_on_qc(alias_two) is None

    assert calls == {"verify": 1}
    assert ex._recent_bft_sender_budgets == {}
    assert ex.bft_artifact_was_accepted("qc", alias_one) is True


def test_equivalent_proposal_envelope_alias_is_acknowledged_after_canonical_dedupe(
    monkeypatch,
) -> None:
    ex = _executor()
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUTOVOTE", "0")
    monkeypatch.setattr(bft_adapter, "_call_admit_bft_block", lambda **kwargs: (True, ""))

    block = {
        "chain_id": "pb001bad",
        "view": 7,
        "proposer": "alice",
        "block_id": "D1",
        "block_hash": "D1-h",
        "prev_block_id": "C1",
        "height": 4,
        "validator_epoch": 2,
        "validator_set_hash": "set-2",
        "consensus_phase": "bft_active",
    }
    envelope = {
        "view": 7,
        "proposer": "alice",
        "block": dict(block),
        "transport_noise": "different-wire-shape",
    }

    assert ex.bft_on_proposal(block) is None
    assert ex.bft_artifact_was_accepted("proposal", block) is True
    assert ex.bft_artifact_was_accepted("proposal", envelope) is False

    assert ex.bft_on_proposal(envelope) is None
    assert ex.bft_artifact_was_accepted("proposal", envelope) is True
