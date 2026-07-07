from __future__ import annotations

from pathlib import Path

from weall.api.routes_public_parts.demo_seed import seed_demo_state
from weall.runtime.gate_expr import eval_gate

REPO_ROOT = Path(__file__).resolve().parents[1]


def _state() -> dict:
    return {
        "height": 0,
        "chain_id": "weall-demo",
        "accounts": {
            "@demo_tester": {
                "nonce": 5,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
                "keys": [],
            },
            "SYSTEM": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
                "keys": [],
            },
        },
        "roles": {},
        "content": {
            "posts": {
                "post:@demo_tester:5": {
                    "post_id": "post:@demo_tester:5",
                    "author": "@demo_tester",
                    "body": "seed me",
                    "media": [],
                    "created_nonce": 5,
                    "visibility": "public",
                    "locked": False,
                    "tags": [],
                    "group_id": None,
                }
            }
        },
        "system_queue": [],
        "params": {"system_signer": "SYSTEM", "gov_action_allowlist": []},
    }


def test_juror_gate_does_not_have_case_assignment_bypass() -> None:
    gate_text = (REPO_ROOT / "src/weall/runtime/gate_expr.py").read_text(encoding="utf-8")
    demo_seed_text = (REPO_ROOT / "src/weall/api/routes_public_parts/demo_seed.py").read_text(encoding="utf-8")

    assert "allow_case_scoped_juror_without_role" not in gate_text
    assert "poh_allow_case_scoped_juror_without_role" not in gate_text
    assert "bootstrap_allow_case_scoped_juror_without_role" not in gate_text
    assert "allow_case_scoped_juror_without_role" not in demo_seed_text


def test_assigned_tier2_account_still_fails_juror_gate_without_active_role() -> None:
    state = _state()
    state["disputes_by_id"] = {
        "dispute:SYSTEM:0": {
            "dispute_id": "dispute:SYSTEM:0",
            "stage": "juror_review",
            "jurors": {"@demo_tester": {"status": "assigned"}},
        }
    }
    state["params"]["allow_case_scoped_juror_without_role"] = True

    ok, meta = eval_gate(
        "Juror",
        signer="@demo_tester",
        ledger=state,
        payload={"dispute_id": "dispute:SYSTEM:0"},
    )

    assert ok is False
    assert meta == {"expr": "Juror"}


def test_seeded_demo_grants_real_juror_role_so_assigned_reviews_pass_gate() -> None:
    state = _state()

    result = seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")
    dispute_id = result["dispute"]["dispute_id"]

    jurors = state["roles"]["jurors"]
    rec = jurors["by_id"]["@demo-tester-reviewer"]
    assert rec["enrolled"] is True
    assert rec["active"] is True
    assert rec["status"] == "active"
    assert "@demo-tester-reviewer" in jurors["active_set"]
    assert result["juror"] == {
        "juror_id": "@demo-tester-reviewer",
        "active": True,
        "authority_source": "seeded_demo_role",
    }

    ok, _ = eval_gate(
        "Juror",
        signer="@demo-tester-reviewer",
        ledger=state,
        payload={"dispute_id": dispute_id},
    )

    assert ok is True
