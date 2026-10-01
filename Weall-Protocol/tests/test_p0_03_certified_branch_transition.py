from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime import bft_votecheck
from weall.runtime.apply.consensus import _activate_pending_validator_set_for_epoch
from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_BFT_ACTIVE, HotStuffBFT, validator_set_hash
from weall.runtime.bft_pending_frontier_impl import _finalized_replay_path_ids
from weall.runtime.executor import WeAllExecutor


def test_hotstuff_validator_generation_reset_anchors_canonical_boundary() -> None:
    bft = HotStuffBFT(chain_id="p0-03")
    bft.view = 17
    bft.last_voted_view = 16
    bft.last_proposed_view = 15
    bft.finalized_block_id = "old-final"
    bft._votes[(16, "x", "hx")] = {"v1": {"signer": "v1"}}
    bft._timeouts[16] = {"v1": {"signer": "v1"}}
    bft.reset_for_validator_generation(finalized_block_id="boundary")
    assert bft.view == 0
    assert bft.high_qc is None
    assert bft.locked_qc is None
    assert bft.finalized_block_id == "boundary"
    assert bft.last_voted_view == -1
    assert bft.last_proposed_view == -1
    assert bft._votes == {}
    assert bft._timeouts == {}


def test_bft_membership_activation_preserves_bft_and_commits_transition_bridge() -> None:
    old = ["v1", "v2", "v3", "v4"]
    new = ["v1", "v2", "v3", "v4", "v5"]
    state = {
        "height": 40,
        "roles": {"validators": {"active_set": list(old)}},
        "validators": {"registry": {}},
        "consensus": {
            "epochs": {"current": 4, "events": []},
            "validators": {"registry": {}},
            "validator_set": {
                "epoch": 3,
                "active_set": list(old),
                "set_hash": validator_set_hash(old),
                "pending": {
                    "active_set": list(new),
                    "activate_at_epoch": 4,
                    "set_hash": validator_set_hash(new),
                },
            },
            "phase": {"current": CONSENSUS_PHASE_BFT_ACTIVE, "history": []},
        },
    }
    result = _activate_pending_validator_set_for_epoch(state, 4)
    assert isinstance(result, dict)
    vs = state["consensus"]["validator_set"]
    bridge = vs["transition_bridge"]
    assert state["consensus"]["phase"]["current"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert bridge["rule"] == "new_set_qc_over_canonical_boundary"
    assert bridge["boundary_height"] == 41
    assert bridge["transition_view"] == 0
    assert bridge["from_validator_epoch"] == 3
    assert bridge["from_validator_set_hash"] == validator_set_hash(old)
    assert bridge["to_validator_epoch"] == 4
    assert bridge["to_validator_set_hash"] == validator_set_hash(new)


def _executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "ledger.sqlite"),
        aux_db_path=str(tmp_path / "aux.sqlite"),
        node_id="node-a",
        chain_id="p0-03-branch",
        tx_index_path=str(Path("generated/tx_index.json")),
    )


def test_candidate_builder_can_extend_explicit_speculative_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    ex = _executor(tmp_path)
    ts1 = max(1, int(ex.chain_time_floor_ms()) + 1)
    b1, st1, _ids1, _bad1, err1 = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=ts1
    )
    assert err1 == "" and isinstance(b1, dict) and isinstance(st1, dict)
    b2, st2, _ids2, _bad2, err2 = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=ts1 + 1, base_state=st1
    )
    assert err2 == "" and isinstance(b2, dict) and isinstance(st2, dict)
    assert int(b2["height"]) == int(b1["height"]) + 1
    assert b2["prev_block_id"] == b1["block_id"]
    assert b2["prev_block_hash"] == b1["block_hash"]
    assert st2["tip"] == b2["block_id"]


def test_speculative_parent_state_reconstructs_promoted_pending_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "1")
    ex = _executor(tmp_path)
    ts1 = max(1, int(ex.chain_time_floor_ms()) + 1)
    b1, st1, ids1, bad1, err1 = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=ts1
    )
    assert err1 == "" and isinstance(b1, dict) and isinstance(st1, dict)
    committed = ex.commit_block_candidate(
        block=b1, new_state=st1, applied_ids=ids1, invalid_ids=bad1
    )
    assert committed.ok
    b2, _st2, _ids2, _bad2, err2 = ex.build_block_candidate(
        max_txs=0, allow_empty=True, force_ts_ms=ts1 + 1
    )
    assert err2 == "" and isinstance(b2, dict)
    ex._pending_remote_blocks[str(b2["block_id"])] = dict(b2)
    reconstructed = bft_votecheck._speculative_parent_state(ex, str(b2["block_id"]))
    assert isinstance(reconstructed, dict)
    assert reconstructed["tip"] == b2["block_id"]
    assert reconstructed["tip_hash"] == b2["block_hash"]


class _ReplayPathFake:
    def __init__(self) -> None:
        self.state = {"tip": "B0"}
        self._max_pending_remote_blocks = 16

    def _bft_speculative_blocks_map(self):
        return {
            "B0": {"prev_block_id": ""},
            "B1": {"prev_block_id": "B0"},
            "B2": {"prev_block_id": "B1"},
            "B3": {"prev_block_id": "B2"},
        }


def test_finalized_replay_path_excludes_post_finalized_descendants() -> None:
    fake = _ReplayPathFake()
    assert _finalized_replay_path_ids(fake, "B1") == {"B1"}
    assert _finalized_replay_path_ids(fake, "B3") == {"B1", "B2", "B3"}
