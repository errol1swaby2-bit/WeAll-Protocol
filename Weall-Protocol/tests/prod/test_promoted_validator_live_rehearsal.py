from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rehearse_genesis_observer_promoted_validator_mempool_v1_5.py"


def _load_harness_module():
    spec = importlib.util.spec_from_file_location("b615_rehearsal", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_promoted_observer_has_chain_backed_validator_production_preflight(tmp_path: Path) -> None:
    mod = _load_harness_module()
    report = mod.run_harness(work_dir=tmp_path / "validator-rehearsal")

    assert report["ok"] is True, report
    observer = report["observer_boot"]
    assert observer["observer_mode"] is True
    assert observer["validator_signing_permitted"] is False
    assert observer["observer_can_produce_block"] is False
    assert observer["observer_produce_error"] == "block_production_forbidden:observer_mode_env"

    promoted = report["promoted_validator"]
    lifecycle = promoted["lifecycle"]
    assert promoted["account_id"] == "@b615_promoted_validator"
    assert promoted["node_pubkey"] == "node-pubkey:b615-promoted"
    assert promoted["readiness_receipt_hash"].startswith("sha256:")
    assert lifecycle["effective_state"] == "production_service"
    assert lifecycle["startup_action"] == "allow"
    assert lifecycle["promotion_preflight_passed"] is True
    assert lifecycle["promotion_failure_reasons"] == []
    assert lifecycle["node_key_authorized"] is True
    assert lifecycle["poh_tier_actual"] >= lifecycle["poh_tier_required"] == 2
    assert lifecycle["reputation_actual_milli"] >= lifecycle["reputation_required_milli"]
    assert "validator" in lifecycle["service_roles_effective"]
    assert lifecycle["bft_enabled_effective"] is True
    assert lifecycle["signature_verification_effective"] is True
    assert lifecycle["trusted_anchor_effective"] is True
