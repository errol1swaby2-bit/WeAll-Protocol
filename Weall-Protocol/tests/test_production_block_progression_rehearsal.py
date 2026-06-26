from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_controlled_devnet_boot_uses_manifest_clock_and_empty_blocks() -> None:
    boot = _read("scripts/devnet_boot_genesis_node.sh")
    join = _read("scripts/devnet_boot_joining_node.sh")
    for src in (boot, join):
        assert "configs/chains/weall-controlled-devnet.json" in src
        assert "WEALL_CHAIN_MANIFEST_PATH" in src
        assert 'WEALL_PRODUCE_EMPTY_BLOCKS="${WEALL_PRODUCE_EMPTY_BLOCKS:-1}"' in src
        assert 'WEALL_POH_ASYNC_N_JURORS="${WEALL_POH_ASYNC_N_JURORS:-1}"' in src
        assert 'WEALL_POH_ASYNC_MIN_REVIEWS="${WEALL_POH_ASYNC_MIN_REVIEWS:-1}"' in src
        assert 'WEALL_POH_ASYNC_APPROVAL_THRESHOLD="${WEALL_POH_ASYNC_APPROVAL_THRESHOLD:-1}"' in src

    manifest = json.loads((ROOT / "configs/chains/weall-controlled-devnet.json").read_text())
    clock = manifest["constitutional_clock"]
    assert clock["enabled"] is True
    assert clock["empty_blocks_enabled"] is True
    assert clock["target_block_interval_ms"] == 20_000
    assert manifest["tx_index_hash"] == "123439e0b1aad73701697ab0fc20add446928c8ec5e510909af5666ab7f18a0c"


def test_rehearsal_waits_for_automatic_block_progression_not_manual_ticks() -> None:
    full = _read("scripts/devnet_full_onboarding_e2e.sh")
    assert "devnet_tx.py --api \"${api}\" tick" not in full
    assert "advancing system queue tick" not in full
    assert "waiting for automatic block production" in full
    assert 'WEALL_REHEARSAL_BLOCK_WAIT_POLL:-5' in full


def test_native_async_uses_genesis_single_reviewer_policy() -> None:
    native = _read("scripts/demo_native_async_tier1_e2e.sh")
    assert 'ASYNC_JUROR_COUNT="${WEALL_ASYNC_JUROR_COUNT:-${WEALL_POH_ASYNC_N_JURORS:-1}}"' in native
    assert 'WAIT_TIMEOUT="${WEALL_NATIVE_ASYNC_WAIT_TIMEOUT:-300}"' in native
    assert ">= 3" not in native
    assert "expected 3 assigned jurors" not in native
    assert 'if [[ "$idx" == "2" ]]' not in native
    assert 'verdict="reject"' not in native
    assert 'verdict="approve"' in native


def test_full_onboarding_runs_node2_before_tier2_and_live() -> None:
    full = _read("scripts/devnet_full_onboarding_e2e.sh")
    node2_pos = full.index("NODE2_AVAILABLE=0")
    tier2_pos = full.index('if [[ "${WEALL_DEVNET_RUN_TIER2:-0}" == "1" ]]')
    live_pos = full.index('if [[ "${WEALL_DEVNET_RUN_LIVE}" == "1" ]]')
    convergence_pos = full.index('if [[ "${NODE2_AVAILABLE}" == "1" ]]')
    assert node2_pos < tier2_pos < live_pos < convergence_pos
    assert "_run_tier2_devnet_flow" in full
