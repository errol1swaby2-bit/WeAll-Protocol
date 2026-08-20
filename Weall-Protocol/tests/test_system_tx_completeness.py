from __future__ import annotations

import copy
from pathlib import Path

import pytest

import weall.runtime.block_builder as block_builder
import weall.runtime.block_replay as block_replay
from weall.runtime.executor import WeAllExecutor
from weall.runtime.scheduler_pipeline import run_leader_pre_schedulers, run_replay_pre_schedulers
from weall.runtime.system_tx_engine import enqueue_system_tx


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, chain_id: str, state: dict) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]
    return ex


def _post_state() -> dict:
    return {
        "chain_id": "system-completeness-post",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {
            "@target": {"poh_tier": 1, "nonce": 1, "reputation_milli": 0},
            **{
                f"@j{i}": {"poh_tier": 2, "nonce": 1, "reputation_milli": 5000}
                for i in range(1, 12)
            },
        },
        "roles": {"jurors": {"active_set": [f"@j{i}" for i in range(1, 12)]}},
        "params": {"poh": {"live_min_rep_milli": 0}},
        "poh": {
            "live_cases": {
                "case-live": {
                    "case_id": "case-live",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                    "session_commitment": "session:cmt",
                    "room_commitment": "room:cmt",
                    "prompt_commitment": "prompt:cmt",
                }
            }
        },
    }


def _censored_candidate(monkeypatch, leader: WeAllExecutor) -> dict:
    real_emit = block_builder.emit_system_txs

    def _censor(*args, **kwargs):
        real_emit(*args, **kwargs)
        return []

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_builder, "emit_system_txs", _censor)
    block, _new_state, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    assert block.get("txs") == []
    return block


def test_follower_rejects_censored_due_post_system_receipt(tmp_path: Path, monkeypatch) -> None:
    state = _post_state()
    leader = _executor(tmp_path / "leader", chain_id=state["chain_id"], state=state)
    follower = _executor(tmp_path / "follower", chain_id=state["chain_id"], state=state)
    block = _censored_candidate(monkeypatch, leader)
    before = copy.deepcopy(follower.state)

    result = follower.apply_block(block)

    assert result.ok is False
    assert result.error == "bad_block:required_system_post_missing_duplicated_or_reordered"
    assert follower.state == before


def test_follower_rejects_censored_due_pre_system_receipt(tmp_path: Path, monkeypatch) -> None:
    state = {
        "chain_id": "system-completeness-pre",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {},
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="pre",
    )
    leader = _executor(tmp_path / "leader", chain_id=state["chain_id"], state=state)
    follower = _executor(tmp_path / "follower", chain_id=state["chain_id"], state=state)
    block = _censored_candidate(monkeypatch, leader)
    before = copy.deepcopy(follower.state)

    result = follower.apply_block(block)

    assert result.ok is False
    assert result.error == "bad_block:required_system_pre_missing_or_reordered"
    assert follower.state == before


def test_replay_pre_scheduler_matches_leader_governance_lifecycle() -> None:
    state = {
        "height": 1,
        "system_queue": [],
        "gov_proposals_by_id": {
            "p1": {
                "proposal_id": "p1",
                "stage": "draft",
                "created_at_height": 1,
                "rules": {"auto_lifecycle": True, "draft_period_blocks": 0},
            }
        },
    }
    leader = copy.deepcopy(state)
    follower = copy.deepcopy(state)

    run_leader_pre_schedulers(leader, next_height=2)
    run_replay_pre_schedulers(follower, next_height=2)

    assert follower == leader
    assert [item["tx_type"] for item in follower["system_queue"]] == ["GOV_STAGE_SET"]


def test_system_queue_lookup_validation_is_read_only_and_fail_closed() -> None:
    from weall.runtime.system_tx_engine import SystemQueueCorruptionError, build_system_queue_lookup

    state: dict = {"height": 0}
    before = copy.deepcopy(state)
    assert build_system_queue_lookup(state) == {}
    assert state == before

    with pytest.raises(SystemQueueCorruptionError, match="system_queue_not_list"):
        build_system_queue_lookup({"system_queue": {"queue_id": "not-a-list"}})
