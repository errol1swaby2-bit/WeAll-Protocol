from __future__ import annotations

import copy
from pathlib import Path

import weall.runtime.block_builder as block_builder
import weall.runtime.block_replay as block_replay
from weall.runtime.executor import WeAllExecutor
from weall.runtime.system_tx_engine import enqueue_system_tx


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, *, state: dict) -> WeAllExecutor:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=str(state["chain_id"]),
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    ex._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    ex.state = ex._ledger_store.read()  # type: ignore[attr-defined]
    return ex


def _base_state() -> dict:
    return {
        "chain_id": "post-phase-parity",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {},
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }


def _install_synthetic_late_post_scheduler(monkeypatch, *, replay_post) -> dict[str, int]:
    calls = {"replay_pre": 0, "replay_post": 0}

    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)
    monkeypatch.setattr(block_replay, "runtime_vrf_required", lambda: False)

    # This test isolates scheduler parity. Admission itself is covered by the
    # canonical SYSTEM queue/admission suites, so do not let signature policy
    # obscure which replay scheduler is called for a late-created post item.
    def admit_all(envs, *args, **kwargs):
        return True, None, [None for _ in envs]

    monkeypatch.setattr(block_builder, "admit_block_txs", admit_all)
    monkeypatch.setattr(block_replay, "admit_block_txs", admit_all)
    monkeypatch.setattr(block_builder, "run_leader_pre_schedulers", lambda *a, **k: None)

    def leader_post(state, *, next_height, scheduler_set=None):
        enqueue_system_tx(
            state,
            tx_type="EPOCH_OPEN",
            payload={"epoch": 1},
            due_height=next_height,
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )

    monkeypatch.setattr(block_builder, "run_leader_post_schedulers", leader_post)

    def follower_pre(state, *, next_height, scheduler_set=None):
        calls["replay_pre"] += 1
        if calls["replay_pre"] > 1:
            raise RuntimeError("pre_scheduler_reran_after_user_phase")

    def follower_post(state, *, next_height, scheduler_set=None):
        calls["replay_post"] += 1
        replay_post(state, next_height=next_height, scheduler_set=scheduler_set)

    monkeypatch.setattr(block_replay, "run_replay_pre_schedulers", follower_pre)
    monkeypatch.setattr(block_replay, "run_replay_post_schedulers", follower_post)
    return calls


def _enqueue_valid_post_epoch(state, *, next_height: int, scheduler_set=None) -> None:
    enqueue_system_tx(
        state,
        tx_type="EPOCH_OPEN",
        payload={"epoch": 1},
        due_height=next_height,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )


def test_follower_uses_post_scheduler_for_late_post_queue_item(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    state = _base_state()
    leader = _executor(tmp_path / "leader", state=state)
    follower = _executor(tmp_path / "follower", state=state)
    calls = _install_synthetic_late_post_scheduler(
        monkeypatch, replay_post=_enqueue_valid_post_epoch
    )

    block, _new_state, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    assert [tx.get("tx_type") for tx in block.get("txs", [])] == ["EPOCH_OPEN"]

    result = follower.apply_block(block)

    assert result.ok is True, result.error
    assert calls == {"replay_pre": 1, "replay_post": 1}
    assert follower.state["consensus"]["epochs"]["current"] == 1


def test_late_post_scheduler_failure_is_fail_closed_and_not_swallowed(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    state = _base_state()
    leader = _executor(tmp_path / "leader", state=state)
    follower = _executor(tmp_path / "follower", state=state)

    def boom_post(state, *, next_height, scheduler_set=None):
        raise RuntimeError("post_scheduler_failure")

    calls = _install_synthetic_late_post_scheduler(monkeypatch, replay_post=boom_post)
    block, _new_state, _applied, _invalid, err = leader.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert err == ""
    assert isinstance(block, dict)
    before = copy.deepcopy(follower.state)

    result = follower.apply_block(block)

    assert result.ok is False
    assert result.error == "bad_block:poh_schedule_failed:RuntimeError"
    assert calls == {"replay_pre": 1, "replay_post": 1}
    assert follower.state == before
