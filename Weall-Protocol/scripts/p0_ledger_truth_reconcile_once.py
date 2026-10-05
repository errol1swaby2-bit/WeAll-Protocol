from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTO = ROOT / "Weall-Protocol"


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


gen = PROTO / "scripts" / "gen_current_verified_claims.py"
replace_once(
    gen,
    '''        tracks[track_id] = {\n            "status": status,\n            "findings": findings,\n            "detail": detail,\n        }\n''',
    '''        open_findings = list(findings)\n        marker = "Open findings:"\n        if status == AUDIT_CLOSED_STATUS:\n            open_findings = []\n        elif marker in detail:\n            explicit = detail.split(marker, 1)[1].split(".", 1)[0]\n            open_findings = [item.strip() for item in explicit.split(",") if item.strip()]\n            if not open_findings:\n                raise SystemExit(\n                    f"P0 audit status {track_id} declares an empty Open findings override"\n                )\n            if len(set(open_findings)) != len(open_findings):\n                raise SystemExit(\n                    f"P0 audit status {track_id} has duplicate Open findings IDs"\n                )\n            if not all(item.startswith("A") and "-F" in item for item in open_findings):\n                raise SystemExit(\n                    f"P0 audit status {track_id} has malformed Open findings IDs: {open_findings}"\n                )\n        tracks[track_id] = {\n            "status": status,\n            "findings": findings,\n            "open_findings": open_findings,\n            "detail": detail,\n        }\n''',
    "claims_track_parser",
)
replace_once(
    gen,
    '''    open_finding_ids = sorted(\n        {finding for track_id in open_track_ids for finding in tracks[track_id]["findings"]}\n    )\n''',
    '''    open_finding_ids = sorted(\n        {\n            finding\n            for track_id in open_track_ids\n            for finding in tracks[track_id]["open_findings"]\n        }\n    )\n''',
    "claims_open_findings",
)

ledger = ROOT / "docs" / "audit" / "WeAll-A01-A20-P0-Closure-Status-20260930.md"
replace_once(
    ledger,
    "A15-F001 still requires bounded consensus-visible ancestry/history architecture, and A15-F002 still requires a finite authenticated state-sync work/response envelope with amplification bounds.",
    "Open findings: A15-F001, A15-F002. A15-F001 still requires bounded consensus-visible ancestry/history architecture, and A15-F002 still requires a finite authenticated state-sync work/response envelope with amplification bounds.",
    "ledger_p0_10_open_findings",
)

tests = PROTO / "tests" / "test_current_verified_claims_fail_closed.py"
text = tests.read_text(encoding="utf-8")
if "test_partial_track_can_bind_explicit_open_finding_subset" in text:
    raise SystemExit("partial-track claim tests already present")
addition = r'''


def test_partial_track_can_bind_explicit_open_finding_subset(tmp_path: Path) -> None:
    module = load_module()
    rows = []
    for index in range(1, 13):
        track = f"P0-{index:02d}"
        if track == "P0-10":
            status = "PARTIAL"
            findings = "A15-F001..F003"
            detail = "A15-F003 closed. Open findings: A15-F001, A15-F002. Remaining architecture work."
        else:
            status = module.AUDIT_CLOSED_STATUS
            findings = f"A{index:02d}-F001"
            detail = "closed"
        rows.append(f"| {track} test | {findings} | {status} | {detail} |")
    audit = tmp_path / "audit.md"
    audit.write_text(
        "## Track status\n\n"
        "| Track | Findings | Current status | Branch work / remaining gate |\n"
        "| --- | --- | --- | --- |\n"
        + "\n".join(rows)
        + "\n\n## Additional CI blockers discovered during closure\n",
        encoding="utf-8",
    )
    parsed = module._read_p0_audit_status(audit)
    assert parsed["open_track_ids"] == ["P0-10"]
    assert parsed["open_finding_ids"] == ["A15-F001", "A15-F002"]


def test_partial_track_empty_open_finding_override_fails_closed(tmp_path: Path) -> None:
    module = load_module()
    rows = []
    for index in range(1, 13):
        track = f"P0-{index:02d}"
        status = "PARTIAL" if track == "P0-10" else module.AUDIT_CLOSED_STATUS
        detail = "Open findings: ." if track == "P0-10" else "closed"
        rows.append(f"| {track} test | A{index:02d}-F001 | {status} | {detail} |")
    audit = tmp_path / "audit.md"
    audit.write_text(
        "## Track status\n\n"
        "| Track | Findings | Current status | Branch work / remaining gate |\n"
        "| --- | --- | --- | --- |\n"
        + "\n".join(rows)
        + "\n\n## Additional CI blockers discovered during closure\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="empty Open findings override"):
        module._read_p0_audit_status(audit)
'''
tests.write_text(text + addition, encoding="utf-8")
