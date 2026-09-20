from __future__ import annotations

from collections import OrderedDict
from types import MethodType

import weall.runtime.bft_runtime_adapter as bft_adapter
from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert
from weall.runtime.executor import WeAllExecutor


def _make_executor(*, chain_id: str = "pb001bq") -> WeAllExecutor:
    ex = WeAllExecutor.__new__(WeAllExecutor)
    ex.chain_id = chain_id
    ex.node_id = "alice"
    ex.state = {"tip": "P", "height": 0, "blocks": {}}
    ex._bft = HotStuffBFT(chain_id=chain_id)

    for name in (
        "_pending_remote_blocks",
        "_pending_remote_block_ids_by_hash",
        "_quarantined_remote_blocks",
        "_quarantined_remote_block_ids_by_hash",
        "_pending_candidates",
        "_pending_candidate_ids_by_hash",
        "_pending_missing_qcs",
        "_pending_missing_qcs_by_hash",
        "_known_block_hashes",
        "_known_block_ids_by_hash",
        "_conflicted_block_ids",
        "_conflicted_block_hashes",
    ):
        setattr(ex, name, OrderedDict())

    ex._max_pending_remote_blocks = 256
    ex._max_quarantined_remote_blocks = 64
    ex._max_pending_candidates = 128
    ex._max_pending_missing_qcs = 256
    ex._max_known_block_hashes = 4096
    ex._max_known_block_ids_by_hash = 4096
    ex._max_conflicted_block_ids = 256
    ex._max_conflicted_block_hashes = 256
    ex._max_missing_parent_fetches_per_call = 32
    ex._max_missing_qc_fetches_per_call = 32
    ex._missing_parent_fetch_cursor = 0
    ex._missing_qc_fetch_cursor = 0

    ex._active_validators = MethodType(lambda self: ["alice"], ex)
    ex._validator_pubkeys = MethodType(lambda self: {"alice": "pub"}, ex)
    ex._local_validator_account = MethodType(lambda self: "", ex)
    ex._bft_artifact_shape_fast_fail = MethodType(lambda self, *args, **kwargs: True, ex)
    ex._remember_recent_bft_proposal = MethodType(lambda self, payload: False, ex)
    ex._bft_payload_phase_matches_current_security_model = MethodType(
        lambda self, payload: True, ex
    )
    ex._bft_epoch_binding_matches = MethodType(lambda self, payload: True, ex)
    ex._is_conflicted_block_id = MethodType(lambda self, block_id: False, ex)
    ex._is_conflicted_block_hash = MethodType(lambda self, block_hash: False, ex)
    ex._block_identity_conflicts = MethodType(lambda self, block, *args, **kwargs: False, ex)
    ex._has_local_block = MethodType(lambda self, block_id: False, ex)
    ex._lookup_committed_block_hash_index = MethodType(lambda self, block_id: "", ex)
    ex._lookup_committed_block_id_by_hash = MethodType(lambda self, block_hash: "", ex)
    ex.get_block_by_id = MethodType(lambda self, block_id: None, ex)
    ex.get_latest_block = MethodType(lambda self: None, ex)
    ex._persist_pending_bft_artifact = MethodType(lambda self, **kwargs: None, ex)
    ex._delete_pending_bft_artifact = MethodType(lambda self, **kwargs: None, ex)
    ex.bft_try_apply_pending_remote_blocks = MethodType(lambda self: [], ex)
    return ex


def _forged_invalid_signature_proposal(chain_id: str, *, block_id: str, block_hash: str) -> dict:
    return {
        "chain_id": chain_id,
        "view": 0,
        "proposer": "alice",
        "block_id": block_id,
        "block_hash": block_hash,
        "prev_block_id": "P",
        "height": 1,
        "validator_epoch": 1,
        "validator_set_hash": "set",
        "header": {
            "chain_id": chain_id,
            "height": 1,
            "prev_block_hash": "",
            "block_ts_ms": 1,
            "tx_ids": [],
            "receipts_root": "11" * 32,
        },
        "txs": [],
        "proposer_pubkey": "pub",
        "proposer_sig": "00",
    }


def _install_qc_path(ex: WeAllExecutor, qc: QuorumCert) -> None:
    ex._has_recent_bft_qc = MethodType(lambda self, qcj: False, ex)
    ex.bft_verify_qc_json = MethodType(lambda self, qcj: qc, ex)
    ex._consume_bft_sender_budget = MethodType(lambda self, payload: True, ex)
    ex._record_recent_bft_qc = MethodType(lambda self, qcj: None, ex)
    ex.bft_handle_qc = MethodType(lambda self, qcj: None, ex)
    ex.bft_commit_if_ready = MethodType(lambda self, verified_qc: None, ex)

    def _put_pending_missing_qc(self: WeAllExecutor, qcj: dict) -> None:
        payload = dict(qcj)
        self._pending_missing_qcs[str(payload.get("block_id") or "")] = payload
        self._pending_missing_qcs_by_hash[str(payload.get("block_hash") or "")] = payload

    ex._put_pending_missing_qc = MethodType(_put_pending_missing_qc, ex)


def test_invalid_signature_quarantine_cannot_suppress_verified_qc_fetch(
    monkeypatch,
) -> None:
    ex = _make_executor()
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    monkeypatch.setenv("WEALL_AUTOVOTE", "0")
    monkeypatch.setattr(bft_adapter, "verify_proposal_json", lambda **kwargs: False)

    block_id = "victim"
    block_hash = "aa" * 32
    proposal = _forged_invalid_signature_proposal(
        ex.chain_id,
        block_id=block_id,
        block_hash=block_hash,
    )

    assert ex.bft_on_proposal(proposal) is None
    assert block_id in ex._quarantined_remote_blocks
    assert ex._bft_pending_block_json(block_id) is None

    qc = QuorumCert(
        chain_id=ex.chain_id,
        view=1,
        block_id=block_id,
        block_hash=block_hash,
        parent_id="P",
        votes=tuple(),
    )
    _install_qc_path(ex, qc)

    assert ex.bft_on_qc(qc.to_json()) is None
    assert block_id in ex._pending_missing_qcs
    assert ex._resolve_pending_block_identity(
        block_id=block_id,
        block_hash=block_hash,
    ) == (block_id, None)

    descriptors = ex.bft_pending_fetch_request_descriptors()
    assert descriptors == [
        {
            "block_id": block_id,
            "block_hash": block_hash,
            "reason": "missing_qc_block",
        }
    ]


def test_quarantine_cannot_create_block_identity_truth() -> None:
    ex = _make_executor()
    block_id = "victim"
    block_hash = "bb" * 32
    ex._quarantine_remote_block(
        {
            "block_id": block_id,
            "block_hash": block_hash,
            "height": 1,
            "prev_block_id": "P",
        }
    )

    assert ex._known_block_hash_for_id(block_id) == ""
    assert ex._known_block_id_for_hash(block_hash) == ""
    assert ex._known_block_hashes == {}
    assert ex._known_block_ids_by_hash == {}


def test_quarantine_is_not_replay_or_speculative_consensus_truth() -> None:
    ex = _make_executor()
    ex._quarantine_remote_block(
        {
            "block_id": "victim",
            "block_hash": "cc" * 32,
            "height": 1,
            "prev_block_id": "P",
        }
    )

    assert ex._ordered_pending_block_ids() == []
    assert "victim" not in ex._bft_speculative_blocks_map()
    assert ex._bft_pending_block_json("victim") is None
    assert ex._bft_pending_block_json_by_hash("cc" * 32) is None


def test_authenticated_promotion_restores_pending_resolution() -> None:
    ex = _make_executor()
    block = {
        "block_id": "verified",
        "block_hash": "dd" * 32,
        "height": 1,
        "prev_block_id": "P",
    }
    ex._quarantine_remote_block(block)
    ex._promote_quarantined_remote_block("verified", block=block)

    assert "verified" not in ex._quarantined_remote_blocks
    assert "verified" in ex._pending_remote_blocks
    assert ex._ordered_pending_block_ids() == ["verified"]
    assert ex._bft_pending_block_json("verified") == block
    assert ex._known_block_hash_for_id("verified") == "dd" * 32
    assert ex._known_block_id_for_hash("dd" * 32) == "verified"
