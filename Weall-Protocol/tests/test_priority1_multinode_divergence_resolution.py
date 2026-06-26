from __future__ import annotations

from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_two_partitioned_followers_rejoin_to_single_tip_batch56(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "rejoin"),
        rounds=12,
        validator_count=4,
        partition_target="v4",
        partition_rounds=(3, 4, 5),
        restart_target="v4",
        restart_every=4,
        chain_id="batch56-rejoin",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 12
    assert summary.partitioned_deliveries >= 3
    assert summary.healed_partition_events >= 3
    assert summary.rejoin_catchup_events >= 1
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_competing_delay_patterns_do_not_create_persistent_fork_batch56(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "delay"),
        rounds=14,
        validator_count=4,
        delay_target="v3",
        delay_child_first_every=2,
        restart_target="v4",
        restart_every=5,
        chain_id="batch56-delay",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 14
    assert summary.delayed_child_first_events >= 1
    assert summary.restart_events >= 2
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_epoch_bump_under_partition_heals_without_divergence_batch56(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "epoch"),
        rounds=16,
        validator_count=4,
        partition_target="v4",
        partition_rounds=(4, 5, 10),
        epoch_bump_rounds=(6, 12),
        stale_qc_replay_target="v2",
        restart_target="v4",
        restart_every=4,
        chain_id="batch56-epoch-heal",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 16
    assert summary.epoch_bump_events == 2
    assert summary.stale_qc_replay_attempts == 2
    assert summary.stale_qc_replay_rejections == 2
    assert summary.partitioned_deliveries >= 3
    assert summary.healed_partition_events >= 3
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_five_validator_partial_quorum_recovers_to_single_chain_batch56(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "five"),
        rounds=18,
        validator_count=5,
        partition_target="v5",
        partition_rounds=(4, 5, 11),
        stall_target="v4",
        stall_rounds=(7, 8),
        restart_target="v3",
        restart_every=6,
        epoch_bump_rounds=(9,),
        stale_qc_replay_target="v2",
        delay_child_first_every=0,
        chain_id="batch56-five",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 18
    assert len(summary.validator_ids) == 5
    assert summary.partitioned_deliveries >= 3
    assert summary.healed_partition_events >= 3
    assert summary.stalled_delivery_events >= 2
    assert summary.restart_events >= 3
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())
