from __future__ import annotations

from pathlib import Path

from weall.runtime.gate_expr import eval_gate

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB = REPO_ROOT.parent / "web"


def test_juror_gate_matches_account_alias_for_tier_and_role_batch276() -> None:
    state = {
        "accounts": {"@demo_tester": {"poh_tier": 2, "banned": False, "locked": False}},
        "roles": {
            "jurors": {
                "active_set": ["@demo_tester"],
                "by_id": {"@demo_tester": {"active": True, "status": "active"}},
            }
        },
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "jurors": {"@demo_tester": {"status": "assigned"}},
                "assigned_jurors": ["@demo_tester"],
            }
        },
    }

    ok, meta = eval_gate(
        "Juror",
        signer="demo_tester",
        state=state,
        payload={"dispute_id": "dispute:SYSTEM:0"},
    )

    assert ok is True, meta


def test_dispute_review_uses_canonical_dispute_id_and_resolves_flagged_media_batch276() -> None:
    review = (WEB / "src/pages/DisputeReview.tsx").read_text(encoding="utf-8")

    assert "const disputeId = String(dispute?.id || dispute?.dispute_id || id" in review
    assert '{ dispute_id: disputeId }' in review
    assert '{ dispute_id: disputeId, vote: "no"' in review
    assert '{ dispute_id: disputeId, vote: "yes"' in review
    assert "weall.stateSnapshot(apiBase).catch(() => null)" not in review
    assert "setMediaIndex" not in review
    assert "resolveContentMedia" not in review
    assert "contentMedia = asArray(contentObj?.media)" in review
    assert '<MediaGallery base={apiBase} media={contentMedia} title="Flagged media" compact />' in review
