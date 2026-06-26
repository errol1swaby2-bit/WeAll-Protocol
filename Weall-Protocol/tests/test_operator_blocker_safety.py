from __future__ import annotations

from pathlib import Path

from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_operator_responsibilities import (
    duplicate_node_keys_for_account,
    evaluate_baseline_node_operator,
    evaluate_node_operator_responsibilities,
)
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_PAGE = ROOT.parent / "web" / "src" / "pages" / "Account.tsx"
WEB_API = ROOT.parent / "web" / "src" / "api" / "weall.ts"
ACCOUNTS_ROUTE = ROOT / "src" / "weall" / "api" / "routes_public_parts" / "accounts.py"


def _account(*, pubkey: str, tier: int = 2, rep: int = 6000, banned: bool = False, locked: bool = False) -> dict:
    return {
        "nonce": 0,
        "poh_tier": tier,
        "reputation_milli": rep,
        "banned": banned,
        "locked": locked,
        "devices": {
            "by_id": {
                "node:primary": {
                    "device_type": "node",
                    "pubkey": pubkey,
                    "revoked": False,
                }
            }
        },
    }


def _state(*, duplicate: bool = False, active: bool = False) -> dict:
    pub_a = "node-pub-shared" if duplicate else "node-pub-a"
    pub_b = "node-pub-shared" if duplicate else "node-pub-b"
    return {
        "accounts": {
            "@a": _account(pubkey=pub_a),
            "@b": _account(pubkey=pub_b),
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "@a": {"account_id": "@a", "enrolled": True, "active": active},
                    "@b": {"account_id": "@b", "enrolled": True, "active": active},
                },
                "active_set": ["@a", "@b"] if active else [],
            }
        },
    }


def _preflight(state: dict, *, account: str, pubkey: str):
    import os

    old_account = os.environ.get("WEALL_BOUND_ACCOUNT")
    old_pubkey = os.environ.get("WEALL_NODE_PUBKEY")
    try:
        os.environ["WEALL_BOUND_ACCOUNT"] = account
        os.environ["WEALL_NODE_PUBKEY"] = pubkey
        return evaluate_production_preflight(
            state=state,
            node_id="node-1",
            chain_id="weall-prod",
            schema_version="1",
            tx_index_hash="txhash",
            runtime_profile_hash="profilehash",
            requested_roles=("node_operator",),
            helper_requested=False,
            bft_requested=False,
            sigverify_required=True,
            trusted_anchor_required=True,
        )
    finally:
        if old_account is None:
            os.environ.pop("WEALL_BOUND_ACCOUNT", None)
        else:
            os.environ["WEALL_BOUND_ACCOUNT"] = old_account
        if old_pubkey is None:
            os.environ.pop("WEALL_NODE_PUBKEY", None)
        else:
            os.environ["WEALL_NODE_PUBKEY"] = old_pubkey


def test_duplicate_node_key_blocks_all_matching_accounts_batch300() -> None:
    st = _state(duplicate=True, active=False)

    assert duplicate_node_keys_for_account(st, "@a") == ("node-pub-shared",)
    assert duplicate_node_keys_for_account(st, "@b") == ("node-pub-shared",)

    eval_a = evaluate_baseline_node_operator(st, "@a")
    eval_b = evaluate_baseline_node_operator(st, "@b")
    assert eval_a.eligible is False
    assert eval_b.eligible is False
    assert "node_key_not_unique" in eval_a.reasons
    assert "node_key_not_unique" in eval_b.reasons

    assert schedule_node_operator_system_txs(st, next_height=11) == 0
    assert st["roles"]["node_operators"]["by_id"]["@a"]["activation_check"] == "node_key_not_unique"
    assert st["roles"]["node_operators"]["by_id"]["@b"]["activation_check"] == "node_key_not_unique"


def test_duplicate_node_key_blocks_production_preflight_even_if_legacy_active_batch300() -> None:
    st = _state(duplicate=True, active=True)
    summary = evaluate_node_operator_responsibilities(st, "@a")
    assert summary["baseline"]["active"] is True
    assert summary["baseline"]["eligible"] is False
    assert "node_key_not_unique" in summary["baseline"]["reasons"]

    preflight = _preflight(st, account="@a", pubkey="node-pub-shared")
    assert not preflight.passed
    assert "ROLE_NOT_ACTIVE" in preflight.maintenance_reasons
    assert "node_operator" not in preflight.effective_roles


def test_operator_status_api_exposes_centralized_responsibility_truth_batch300() -> None:
    accounts_route = ACCOUNTS_ROUTE.read_text(encoding="utf-8")
    assert '@router.get("/accounts/{account}/operator-status")' in accounts_route
    assert "evaluate_node_operator_responsibilities" in accounts_route

    st = _state(duplicate=False, active=True)
    rec = st["roles"]["node_operators"]["by_id"]["@a"]
    rec["responsibilities"] = {
        "validator": {
            "opted_in": True,
            "active": False,
            "readiness_status": "pending",
            "reputation_required_milli": 5000,
        },
        "storage": {
            "opted_in": True,
            "active": True,
            "declared_capacity_bytes": 500_000_000,
            "proven_capacity_bytes": 0,
            "allocated_capacity_bytes": 0,
            "proof_status": "pending",
        },
    }
    node_operator = evaluate_node_operator_responsibilities(st, "@a")
    assert node_operator["baseline"]["status"] == "active"
    assert node_operator["baseline"]["active"] is True
    assert node_operator["validator"]["status"] == "readiness_pending"
    assert "validator_readiness_pending" in node_operator["validator"]["reasons"]
    assert node_operator["storage"]["status"] == "proof_pending"
    assert "capacity_proof_pending" in node_operator["storage"]["reasons"]
    assert node_operator["storage"]["details"]["declared_capacity_bytes"] == 500_000_000
    assert node_operator["storage"]["details"]["proven_capacity_bytes"] == 0


def test_frontend_uses_operator_status_api_instead_of_only_raw_role_inference_batch300() -> None:
    api = WEB_API.read_text(encoding="utf-8")
    account_page = ACCOUNT_PAGE.read_text(encoding="utf-8")

    assert "accountOperatorStatus" in api
    assert "/operator-status" in api
    assert "weall.accountOperatorStatus" in account_page
    assert "operatorStatus" in account_page
    assert "Backend readiness reasons" in account_page
