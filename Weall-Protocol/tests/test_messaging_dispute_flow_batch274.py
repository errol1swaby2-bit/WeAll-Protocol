from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"

sys.path.insert(0, str(BACKEND / "src"))


def test_messaging_routes_are_removed_for_public_only_activity_surface() -> None:
    router = (WEB / "src/lib/router.ts").read_text(encoding="utf-8")
    app = (WEB / "src/App.tsx").read_text(encoding="utf-8")
    messaging = (WEB / "src/pages/Messaging.tsx").read_text(encoding="utf-8")

    assert '| { path: "/messages/compose" }' not in router
    assert '| { path: "/messages/:id"; id: string }' not in router
    assert 'path: "/activity"' in router

    assert '<Messaging mode="hub" />' not in app
    assert '<Messaging mode="compose" />' not in app
    assert '<Messaging mode="thread" threadId={route.id} />' not in app

    assert 'nav("/messages/compose")' not in messaging
    assert "PRIVATE_MESSAGING_UNSUPPORTED" in messaging
    assert "Open activity" in messaging


def test_report_detail_does_not_submit_review_assignment_tx() -> None:
    detail = (WEB / "src/pages/DisputeDetail.tsx").read_text(encoding="utf-8")
    assert 'submitDisputeTx("DISPUTE_JUROR_ACCEPT"' not in detail
    assert 'submitDisputeTx("DISPUTE_JUROR_DECLINE"' not in detail
    assert 'dedicated review workspace owns assignment acceptance' in detail
    assert 'nav(`/reviews/${encodeURIComponent(String(dispute?.id || id))}`)' in detail


def test_assigned_report_reviewer_requires_active_juror_role() -> None:
    from weall.runtime.gate_expr import eval_gate

    assigned_only_state = {
        "chain_id": "weall-demo",
        "accounts": {"@demo_tester": {"poh_tier": 2}},
        "roles": {"jurors": {"by_id": {}, "active_set": []}},
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "id": "dispute:SYSTEM:0",
                "jurors": {"@demo_tester": {"status": "assigned"}},
                "assigned_jurors": ["@demo_tester"],
            }
        },
        "params": {},
    }
    ok, _meta = eval_gate("Juror", signer="@demo_tester", state=assigned_only_state, payload={"dispute_id": "dispute:SYSTEM:0"})
    assert ok is False

    active_role_state = dict(assigned_only_state)
    active_role_state["roles"] = {
        "jurors": {
            "by_id": {"@demo_tester": {"active": True, "status": "active"}},
            "active_set": ["@demo_tester"],
        }
    }
    ok, meta = eval_gate("Juror", signer="@demo_tester", state=active_role_state, payload={"dispute_id": "dispute:SYSTEM:0"})
    assert ok is True, meta
