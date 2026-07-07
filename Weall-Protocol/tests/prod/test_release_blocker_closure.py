from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rehearse_release_blocker_closure_v1_5.py"


def _load_harness_module():
    spec = importlib.util.spec_from_file_location("batch616_release_blocker_closure", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_blocker_closure_rehearsal_keeps_public_claims_closed() -> None:
    mod = _load_harness_module()
    report = mod.run_harness()

    assert report["ok"] is True, report
    assert report["local_genesis_observer_promoted_validator_mempool"]["ok"] is True
    assert report["independent_process_validator_finality_restart"]["ok"] is True
    assert report["external_observer_bundle_signed_onboarding_surface"]["ok"] is True
    assert report["claims"]["controlled_multi_node_testnet_candidate"] is True
    assert report["claims"]["public_validator_ready"] is False
    assert report["claims"]["public_beta_ready"] is False
    assert report["claims"]["mainnet_ready"] is False
    assert report["claims"]["production_helper_execution_ready"] is False
