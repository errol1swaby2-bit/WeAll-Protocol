from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gen_current_verified_claims.py"


def load_module():
    spec = importlib.util.spec_from_file_location("claims_under_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def fixtures(tmp_path: Path):
    tx = {"tx_types": ["ACCOUNT_CREATE"], "meta": {"version": "test", "law": "append-only"}}
    blockers = {"remaining_external_evidence_required_ids": ["AUD-633-P0-004"]}
    release = {
        "public_beta_ready": False,
        "mainnet_ready": False,
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics": False,
        },
    }
    performance = {
        "schema": "weall.current_performance_evidence.v1",
        "version": "1.0.0",
        "subject_scope": "repository-current",
        "current_scalar_tps_claim_allowed": False,
        "qualifying_benchmarks": [],
        "qualification_requirements": list(load_module().PERFORMANCE_REQUIRED_BENCHMARK_FIELDS),
        "historical_measurements_current_claim_eligible": False,
        "notes": [],
    }
    paths = {
        name: tmp_path / f"{name}.json" for name in ("tx", "blockers", "release", "performance")
    }
    for name, value in (
        ("tx", tx),
        ("blockers", blockers),
        ("release", release),
        ("performance", performance),
    ):
        write_json(paths[name], value)
    return paths, blockers, release, performance


def bind(module, paths, tmp_path: Path) -> None:
    module.ROOT = tmp_path
    module.TX_INDEX = paths["tx"]
    module.BLOCKERS = paths["blockers"]
    module.RELEASE = paths["release"]
    module.PERFORMANCE = paths["performance"]


def claim(payload: dict, claim_id: str) -> dict:
    return next(row for row in payload["claims"] if row["claim_id"] == claim_id)


def test_performance_registry_is_authority(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, _ = fixtures(tmp_path)
    bind(module, paths, tmp_path)
    row = claim(module.build(), "PERFORMANCE-001")
    assert row["evidence_location"] == ["evidence/performance/current_performance_evidence.json"]
    assert row["value"] == {
        "current_scalar_tps_claim_allowed": False,
        "qualifying_benchmark_count": 0,
    }


@pytest.mark.parametrize("key", ["public_beta_ready", "mainnet_ready"])
def test_missing_readiness_boolean_fails_closed(tmp_path: Path, key: str) -> None:
    module = load_module()
    paths, _, release, _ = fixtures(tmp_path)
    del release[key]
    write_json(paths["release"], release)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match=key):
        module.build()


def test_malformed_blocker_list_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, blockers, _, _ = fixtures(tmp_path)
    blockers["remaining_external_evidence_required_ids"] = "AUD-633-P0-004"
    write_json(paths["blockers"], blockers)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="must be a list"):
        module.build()


def test_missing_performance_registry_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, _ = fixtures(tmp_path)
    paths["performance"].unlink()
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="missing required JSON evidence"):
        module.build()


def test_scalar_claim_cannot_be_enabled_without_benchmark(tmp_path: Path) -> None:
    module = load_module()
    paths, _, _, performance = fixtures(tmp_path)
    performance["current_scalar_tps_claim_allowed"] = True
    write_json(paths["performance"], performance)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="without a qualifying benchmark"):
        module.build()


def test_non_boolean_claim_boundary_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    paths, _, release, _ = fixtures(tmp_path)
    release["claim_boundaries"]["live_economics"] = "false"
    write_json(paths["release"], release)
    bind(module, paths, tmp_path)
    with pytest.raises(SystemExit, match="must be boolean"):
        module.build()
