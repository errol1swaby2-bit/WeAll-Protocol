from __future__ import annotations

from pathlib import Path

PRODUCT_ROOT = Path.cwd()
GENERATOR = PRODUCT_ROOT / "Weall-Protocol" / "scripts" / "gen_current_verified_claims.py"
TEST_FILE = PRODUCT_ROOT / "Weall-Protocol" / "tests" / "test_p0_claim_audit_binding.py"
STATUS_LEDGER = PRODUCT_ROOT / "docs" / "audit" / "WeAll-A01-A20-P0-Closure-Status-20260930.md"


def patch_generator() -> None:
    text = GENERATOR.read_text(encoding="utf-8")
    if "AUDIT_STATUS =" in text:
        raise SystemExit("P0-12 generator patch appears already applied")

    old = 'PERFORMANCE = ROOT / "evidence" / "performance" / "current_performance_evidence.json"\n\nJSON_OUT'
    new = (
        'PERFORMANCE = ROOT / "evidence" / "performance" / "current_performance_evidence.json"\n'
        'AUDIT_STATUS = ROOT.parent / "docs" / "audit" / "WeAll-A01-A20-P0-Closure-Status-20260930.md"\n\nJSON_OUT'
    )
    if old not in text:
        raise SystemExit("generator performance constant anchor missing")
    text = text.replace(old, new, 1)
    text = text.replace('VERSION = "1.0.0"', 'VERSION = "1.1.0"', 1)

    marker = "\n\ndef _require_bool("
    if marker not in text:
        raise SystemExit("generator helper insertion anchor missing")
    insertion = '''

AUDIT_CLOSED_STATUS = "CLOSED — PATCHED AND PROVEN"
AUDIT_TRACK_IDS = tuple(f"P0-{index:02d}" for index in range(1, 13))
AUDIT_ALLOWED_STATUSES = {
    AUDIT_CLOSED_STATUS,
    "PATCHED / EVIDENCE PENDING",
    "PARTIAL",
    "DESIGN BLOCKER",
    "IMPLEMENTATION BLOCKER",
    "DESIGN + IMPLEMENTATION BLOCKER",
    "EVIDENCE GATE",
}


def _read_p0_audit_status(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"missing required P0 audit status: {path}")
    text = path.read_text(encoding="utf-8")
    start_marker = "## Track status"
    end_marker = "## Additional CI blockers discovered during closure"
    if start_marker not in text or end_marker not in text:
        raise SystemExit("P0 audit status is missing the canonical track-status section")
    section = text.split(start_marker, 1)[1].split(end_marker, 1)[0]

    tracks: dict[str, dict[str, Any]] = {}
    for raw_line in section.splitlines():
        if not raw_line.startswith("| P0-"):
            continue
        cells = [cell.strip() for cell in raw_line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise SystemExit(f"malformed P0 audit status row: {raw_line}")
        label, finding_cell, status, detail = cells
        track_id = label.split(" ", 1)[0]
        if track_id in tracks:
            raise SystemExit(f"duplicate P0 audit track: {track_id}")
        if status not in AUDIT_ALLOWED_STATUSES:
            raise SystemExit(f"unrecognized P0 audit status for {track_id}: {status}")
        findings = [item.strip() for item in finding_cell.split(",") if item.strip()]
        if not findings:
            raise SystemExit(f"P0 audit track {track_id} has no finding IDs")
        tracks[track_id] = {
            "status": status,
            "findings": findings,
            "detail": detail,
        }

    expected = set(AUDIT_TRACK_IDS)
    actual = set(tracks)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SystemExit(f"P0 audit status track set mismatch: missing={missing}, extra={extra}")

    open_track_ids = [
        track_id
        for track_id in AUDIT_TRACK_IDS
        if tracks[track_id]["status"] != AUDIT_CLOSED_STATUS
    ]
    open_finding_ids = sorted(
        {
            finding
            for track_id in open_track_ids
            for finding in tracks[track_id]["findings"]
        }
    )
    return {
        "tracks": tracks,
        "open_track_ids": open_track_ids,
        "open_finding_ids": open_finding_ids,
        "closed_track_ids": [
            track_id for track_id in AUDIT_TRACK_IDS if track_id not in open_track_ids
        ],
    }
'''
    text = text.replace(marker, insertion + marker, 1)

    old = '    performance = _read_json(PERFORMANCE)\n    performance_summary = _validate_performance_registry(performance)\n'
    new = (
        '    performance = _read_json(PERFORMANCE)\n'
        '    audit_status = _read_p0_audit_status(AUDIT_STATUS)\n'
        '    performance_summary = _validate_performance_registry(performance)\n'
    )
    if old not in text:
        raise SystemExit("generator build input anchor missing")
    text = text.replace(old, new, 1)

    old = '''    if boundaries.get("mainnet_ready") is not mainnet_ready:
        raise SystemExit("release evidence manifest mainnet_ready disagrees with claim_boundaries")

    claims: list[dict[str, Any]] = []
'''
    new = '''    if boundaries.get("mainnet_ready") is not mainnet_ready:
        raise SystemExit("release evidence manifest mainnet_ready disagrees with claim_boundaries")

    open_p0_track_ids = audit_status["open_track_ids"]
    if open_p0_track_ids:
        enabled_boundaries = sorted(key for key, value in boundaries.items() if value)
        if public_beta_ready or mainnet_ready or enabled_boundaries:
            raise SystemExit(
                "open P0 audit tracks block stronger release claims: "
                f"open={open_p0_track_ids}, enabled_boundaries={enabled_boundaries}, "
                f"public_beta_ready={public_beta_ready}, mainnet_ready={mainnet_ready}"
            )

    claims: list[dict[str, Any]] = []
'''
    if old not in text:
        raise SystemExit("generator audit gate anchor missing")
    text = text.replace(old, new, 1)

    marker = '''    claims.append(
        _claim(
            "TX-CANON-001",
'''
    insertion = '''    claims.append(
        _claim(
            "AUDIT-P0-001",
            "audit_gate",
            (
                "Open same-tree A01–A20 P0/HIGH findings block stronger release claims."
                if open_p0_track_ids
                else "The same-tree A01–A20 P0/HIGH closure ledger has no open tracks."
            ),
            (
                "OPEN_AUDIT_FINDINGS_BLOCK_STRONGER_CLAIMS"
                if open_p0_track_ids
                else "PROVEN_GENERATED_CURRENT"
            ),
            ["../docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"],
            value={
                "total_tracks": len(AUDIT_TRACK_IDS),
                "open_track_ids": list(open_p0_track_ids),
                "open_high_finding_ids": list(audit_status["open_finding_ids"]),
                "closed_track_ids": list(audit_status["closed_track_ids"]),
                "stronger_release_claims_blocked": bool(open_p0_track_ids),
            },
            notes=(
                "P0 is the audit program's mapping of every A01–A20 HIGH finding. "
                "The tracked closure ledger is now a required claim-generation input; "
                "an unresolved P0 track therefore cannot coexist with an enabled release boundary."
            ),
        )
    )

'''
    if marker not in text:
        raise SystemExit("generator claim insertion anchor missing")
    text = text.replace(marker, insertion + marker, 1)

    old = '''    return {
        "schema": SCHEMA,
        "version": VERSION,
        "tracked_manifest_is_commit_agnostic": True,
        "exact_commit_binding_required_for_final_audit": True,
        "generation_inputs": {
            str(path.relative_to(ROOT)): _sha256(path)
            for path in (TX_INDEX, BLOCKERS, RELEASE, PERFORMANCE)
        },
        "claims": claims,
    }
'''
    new = '''    generation_inputs = {
        str(path.relative_to(ROOT)): _sha256(path)
        for path in (TX_INDEX, BLOCKERS, RELEASE, PERFORMANCE)
    }
    generation_inputs[
        "../docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"
    ] = _sha256(AUDIT_STATUS)

    return {
        "schema": SCHEMA,
        "version": VERSION,
        "tracked_manifest_is_commit_agnostic": True,
        "exact_commit_binding_required_for_final_audit": True,
        "generation_inputs": generation_inputs,
        "claims": claims,
    }
'''
    if old not in text:
        raise SystemExit("generator return anchor missing")
    text = text.replace(old, new, 1)

    old = '    external = by_id["EXTERNAL-VALIDATION-001"]["value"]\n\n    lines += [\n'
    new = (
        '    external = by_id["EXTERNAL-VALIDATION-001"]["value"]\n'
        '    audit_gate = by_id["AUDIT-P0-001"]["value"]\n\n'
        '    lines += [\n'
    )
    if old not in text:
        raise SystemExit("generator markdown variable anchor missing")
    text = text.replace(old, new, 1)

    old = '''        f"- Remaining external-evidence blocker IDs: `{', '.join(external['remaining_external_evidence_required_ids'])}`.",
        "",
'''
    new = '''        f"- Remaining external-evidence blocker IDs: `{', '.join(external['remaining_external_evidence_required_ids'])}`.",
        f"- Open A01–A20 P0 audit tracks: `{', '.join(audit_gate['open_track_ids']) if audit_gate['open_track_ids'] else 'none'}`.",
        "",
'''
    if old not in text:
        raise SystemExit("generator markdown snapshot anchor missing")
    text = text.replace(old, new, 1)

    GENERATOR.write_text(text, encoding="utf-8")


def write_tests() -> None:
    TEST_FILE.write_text(
        '''from __future__ import annotations

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
    path.write_text(json.dumps(value, indent=2) + "\\n", encoding="utf-8")


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
    path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")


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
        "../docs/audit/WeAll-A01-A20-P0-Closure-Status-20260930.md"
        in payload["generation_inputs"]
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
    text = "\\n".join(
        line for line in text.splitlines() if not line.startswith("| P0-12 ")
    ) + "\\n"
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
''',
        encoding="utf-8",
    )


def patch_status_ledger() -> None:
    text = STATUS_LEDGER.read_text(encoding="utf-8")
    lines = text.splitlines()
    matched = False
    for index, line in enumerate(lines):
        if not line.startswith("| P0-12 Claim/evidence truth binding "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise SystemExit("malformed P0-12 ledger row")
        cells[2] = "CLOSED — PATCHED AND PROVEN"
        cells[3] = (
            "Current claim generation now consumes the canonical same-tree A01–A20 P0 closure ledger, "
            "enumerates open HIGH/P0 tracks and findings, hashes the ledger as a required generation input, "
            "and fails closed if any release claim boundary is enabled while a P0 track remains open. "
            "Dedicated malformed/missing-track and claim-promotion regressions pass."
        )
        lines[index] = "| " + " | ".join(cells) + " |"
        matched = True
        break
    if not matched:
        raise SystemExit("P0-12 ledger row not found")

    text = "\n".join(lines) + "\n"
    text = text.replace(
        "5. Implement P0-12 generalized same-tree audit-finding-to-claim binding, regenerate exact-head public evidence, and capture the final closure SHA/tree only after all remaining HIGH findings are actually resolved.\n",
        "5. After the remaining implementation/design tracks close, capture the final closure SHA/tree and regenerate final exact-head public evidence.\n",
        1,
    )
    STATUS_LEDGER.write_text(text, encoding="utf-8")


def main() -> None:
    patch_generator()
    write_tests()
    patch_status_ledger()


if __name__ == "__main__":
    main()
