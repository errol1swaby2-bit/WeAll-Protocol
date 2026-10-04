from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gen_current_verified_claims.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("p0_claims_under_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_audit_status(path: Path, *, open_tracks: dict[str, str]) -> None:
    lines = [
        "# test audit status",
        "",
        "## Track status",
        "",
        "| Track | Findings | Current status | Branch work / remaining gate |",
        "| --- | --- | --- | --- |",
    ]
    for index in range(1, 13):
        track_id = f"P0-{index:02d}"
        status = open_tracks.get(track_id, "CLOSED — PATCHED AND PROVEN")
        lines.append(f"| {track_id} Test track | A{index:02d}-F001 | {status} | test detail |")
    lines += [
        "",
        "## Additional CI blockers discovered during closure",
        "",
        "none",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bind(module, tmp_path: Path, *, open_tracks: dict[str, str]) -> dict:
    tx = tmp_path / "tx.json"
    blockers = tmp_path / "blockers.json"
    release = tmp_path / "release.json"
    performance = tmp_path / "performance.json"
    audit = tmp_path / "audit.md"

    _write_json(
        tx,
        {"tx_types": ["ACCOUNT_CREATE"], "meta": {"version": "test", "law": "append-only"}},
    )
    _write_json(
        blockers,
        {"remaining_external_evidence_required_ids": ["AUD-633-P0-004"]},
    )
    release_payload = {
        "public_beta_ready": False,
        "mainnet_ready": False,
        "claim_boundaries": {
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics": False,
        },
    }
    _write_json(release, release_payload)
    _write_json(
        performance,
        {
            "schema": "weall.current_performance_evidence.v1",
            "version": "1.0.0",
            "subject_scope": "repository-current",
            "current_scalar_tps_claim_allowed": False,
            "qualifying_benchmarks": [],
            "qualification_requirements": list(module.PERFORMANCE_REQUIRED_BENCHMARK_FIELDS),
            "historical_measurements_current_claim_eligible": False,
            "notes": [],
        },
    )
    _write_audit_status(audit, open_tracks=open_tracks)

    module.ROOT = tmp_path
    module.TX_INDEX = tx
    module.BLOCKERS = blockers
    module.RELEASE = release
    module.PERFORMANCE = performance
    module.AUDIT_STATUS = audit
    return {"release": release, "release_payload": release_payload, "audit": audit}


def _claim(payload: dict, claim_id: str) -> dict:
    return next(row for row in payload["claims"] if row["claim_id"] == claim_id)


def test_open_p0_tracks_are_current_claim_input_and_machine_readable(tmp_path: Path) -> None:
    module = _load_module()
    _bind(module, tmp_path, open_tracks={"P0-03": "IMPLEMENTATION BLOCKER"})

    payload = module.build()
    audit_claim = _claim(payload, "AUDIT-P0-001")

    assert audit_claim["status"] == "OPEN_AUDIT_FINDINGS_BLOCK_STRONGER_CLAIMS"
    assert audit_claim["value"]["open_track_ids"] == ["P0-03"]
    assert audit_claim["value"]["open_high_finding_ids"] == ["A03-F001"]
    assert audit_claim["value"]["stronger_release_claims_blocked"] is True
    assert (
        "../docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md" in payload["generation_inputs"]
    )


def test_open_p0_track_rejects_enabled_release_boundary(tmp_path: Path) -> None:
    module = _load_module()
    bound = _bind(module, tmp_path, open_tracks={"P0-05": "IMPLEMENTATION BLOCKER"})
    release_payload = bound["release_payload"]
    release_payload["claim_boundaries"]["live_economics"] = True
    _write_json(bound["release"], release_payload)

    with pytest.raises(SystemExit, match="open P0 audit tracks block stronger release claims"):
        module.build()


def test_missing_p0_track_fails_closed(tmp_path: Path) -> None:
    module = _load_module()
    bound = _bind(module, tmp_path, open_tracks={})
    text = bound["audit"].read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines() if not line.startswith("| P0-12 ")) + "\n"
    bound["audit"].write_text(text, encoding="utf-8")

    with pytest.raises(SystemExit, match="track set mismatch"):
        module.build()


def test_all_closed_tracks_do_not_block_non_readiness_boundary(tmp_path: Path) -> None:
    module = _load_module()
    bound = _bind(module, tmp_path, open_tracks={})
    release_payload = bound["release_payload"]
    release_payload["claim_boundaries"]["live_economics"] = True
    _write_json(bound["release"], release_payload)

    payload = module.build()
    audit_claim = _claim(payload, "AUDIT-P0-001")
    assert audit_claim["status"] == "PROVEN_GENERATED_CURRENT"
    assert audit_claim["value"]["open_track_ids"] == []
    assert audit_claim["value"]["stronger_release_claims_blocked"] is False
