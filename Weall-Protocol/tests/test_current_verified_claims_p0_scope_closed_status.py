from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gen_current_verified_claims as claims


def test_scope_closed_p0_status_is_treated_as_closed() -> None:
    audit = claims._read_p0_audit_status(claims.AUDIT_STATUS)

    assert claims.AUDIT_CLOSED_STATUS == "CLOSED — PATCHED AND PROVEN"
    assert "CLOSED — SCOPE-CLOSED AND PROVEN" in claims.AUDIT_CLOSED_STATUSES
    assert audit["tracks"]["P0-06"]["status"] == "CLOSED — SCOPE-CLOSED AND PROVEN"
    assert audit["tracks"]["P0-06"]["open_findings"] == []
    assert "P0-06" in audit["closed_track_ids"]
    assert "P0-06" not in audit["open_track_ids"]
    assert "A08-F001" not in audit["open_finding_ids"]
    assert "A20-F001" not in audit["open_finding_ids"]
