from __future__ import annotations

from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_staggered_restarts_preserve_single_canonical_tip_batch57(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "staggered"),
        rounds=15,
        validator_count=4,
        restart_target="v4",
        restart_every=3,
        chain_id="batch57-staggered",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 15
    assert summary.restart_events >= 4
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_partition_then_restart_then_heal_converges_batch57(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "partition-restart-heal"),
        rounds=14,
        validator_count=4,
        partition_target="v4",
        partition_rounds=(3, 4, 5),
        restart_target="v4",
        restart_every=4,
        chain_id="batch57-partition-restart-heal",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 14
    assert summary.partitioned_deliveries >= 3
    assert summary.healed_partition_events >= 3
    assert summary.rejoin_catchup_events >= 1
    assert summary.restart_events >= 3
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_stall_plus_restart_recovers_without_divergence_batch57(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "stall-restart"),
        rounds=13,
        validator_count=4,
        stall_target="v4",
        stall_rounds=(4, 5, 6),
        restart_target="v4",
        restart_every=5,
        chain_id="batch57-stall-restart",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 13
    assert summary.stalled_delivery_events >= 1
    assert summary.restart_events >= 2
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_restart_only_path_keeps_chain_single_batch57(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path / "restart-only"),
        rounds=12,
        validator_count=4,
        restart_target="v4",
        restart_every=4,
        chain_id="batch57-restart-only",
    )
    assert summary.converged is True
    assert int(summary.leader_height) == 12
    assert summary.restart_events >= 2
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())
