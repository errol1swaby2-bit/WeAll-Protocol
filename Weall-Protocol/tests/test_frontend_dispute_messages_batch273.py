from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"

sys.path.insert(0, str(BACKEND / "src"))


def test_messages_compose_appears_before_conversations() -> None:
    text = (WEB / "src/pages/Messaging.tsx").read_text(encoding="utf-8")
    compose = text.index('<div className="eyebrow">Compose</div>')
    inbox = text.index('<div className="eyebrow">Inbox</div>')
    assert compose < inbox
    assert 'Send a direct message' in text
    assert 'Conversations' in text


def test_dispute_review_choice_semantics_match_backend_resolution() -> None:
    text = (WEB / "src/pages/DisputeReview.tsx").read_text(encoding="utf-8")
    assert '"Keep Post"' in text
    assert '"Remove Post"' in text
    assert 'vote: "no", resolution: { summary: "Reviewer chose to keep the post visible.", actions: [] }' in text
    assert 'vote: "yes", resolution: { summary: "Reviewer upheld the report and chose to remove the post." }' in text
    assert '"Accept assignment", "Review assignment accepted."' in text
    assert '"Accept report", "Report accepted."' not in text


def test_seeded_demo_allows_case_scoped_report_review_without_leaking_to_prod() -> None:
    from weall.api.routes_public_parts.demo_seed import seed_demo_state
    from weall.runtime.gate_expr import eval_gate

    state = {
        "chain_id": "weall-demo",
        "accounts": {"@demo_tester": {"poh_tier": 2, "nonce": 5}},
        "content": {"posts": {"post:@demo_tester:5": {"body": "demo body"}}},
        "roles": {},
        "disputes_by_id": {},
        "gov_proposals_by_id": {},
        "params": {},
    }
    seeded = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")
    dispute_id = seeded["dispute"]["dispute_id"]

    assert state["params"]["allow_case_scoped_juror_without_role"] is True
    # Prove the demo fallback is case-scoped, not dependent on a globally visible
    # role card. Production/devnet never get this flag because demo_seed is fenced.
    state["roles"]["jurors"] = {"by_id": {}, "active_set": []}
    ok, meta = eval_gate("Juror", signer="@demo_tester", state=state, payload={"dispute_id": dispute_id})
    assert ok, meta
