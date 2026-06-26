from __future__ import annotations

from pathlib import Path

from weall.api.routes_public_parts.demo_seed import seed_demo_state
from weall.runtime.apply.content import apply_content
from weall.runtime.gate_expr import eval_gate
from weall.runtime.tx_admission import TxEnvelope

REPO_ROOT = Path(__file__).resolve().parents[1]
MONOREPO_ROOT = REPO_ROOT.parent


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


def _apply_first_queued_escalation(state: dict) -> str:
    for item in list(state.get("system_queue") or []):
        if item.get("tx_type") != "CONTENT_ESCALATE_TO_DISPUTE":
            continue
        meta = apply_content(
            state,
            TxEnvelope(
                tx_type="CONTENT_ESCALATE_TO_DISPUTE",
                signer=str(item.get("signer") or "SYSTEM"),
                nonce=0,
                payload=dict(item.get("payload") or {}),
                system=True,
                parent=str(item.get("parent") or "CONTENT_FLAG"),
            ),
        )
        return str((meta or {}).get("dispute_id") or "")
    raise AssertionError("CONTENT_ESCALATE_TO_DISPUTE was not queued")


def test_seeded_demo_juror_role_survives_dynamic_flag_review_gate() -> None:
    state = _state()
    seed_demo_state(state, account="@demo_tester", post_id="post:@demo_tester:5")

    apply_content(
        state,
        TxEnvelope(
            tx_type="CONTENT_FLAG",
            signer="@demo_tester",
            nonce=6,
            payload={"target_id": "post:@demo_tester:5", "reason": "test"},
            system=False,
            parent=None,
        ),
    )
    dispute_id = _apply_first_queued_escalation(state)

    assert dispute_id == "dispute:SYSTEM:0"
    assert state["roles"]["jurors"]["by_id"]["@demo-tester-reviewer"]["active"] is True
    assert "@demo-tester-reviewer" in state["roles"]["jurors"]["active_set"]
    assert state["disputes_by_id"][dispute_id]["jurors"]["@demo-tester-reviewer"]["status"] == "assigned"

    ok, meta = eval_gate(
        "Juror",
        signer="@demo-tester-reviewer",
        state=state,
        payload={"dispute_id": dispute_id},
    )

    assert ok is True, meta


def test_dev_boot_restarts_backend_after_demo_seed_so_producer_reloads_roles() -> None:
    script = (MONOREPO_ROOT / "scripts/dev_boot_full_stack.sh").read_text(encoding="utf-8")

    assert "restart_backend_after_demo_bootstrap()" in script
    assert "docker compose restart weall_api weall_producer" in script
    assert "seeded demo reviewer role did not survive backend reload" in script
    assert "restart_backend_after_demo_bootstrap\n\n  log \"writing frontend dev bootstrap manifest" in script
