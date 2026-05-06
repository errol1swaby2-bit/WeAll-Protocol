from __future__ import annotations

from pathlib import Path

from weall.runtime.node_operator_responsibilities import (
    evaluate_baseline_node_operator,
    evaluate_node_operator_responsibilities,
    evaluate_storage_responsibility,
    evaluate_validator_responsibility,
)
from weall.runtime.node_lifecycle_preflight import evaluate_production_preflight
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs

ROOT = Path(__file__).resolve().parents[1]


def _state(*, tier: int = 2, rep: int = 6000, active: bool = True, banned: bool = False, locked: bool = False) -> dict:
    return {
        "accounts": {
            "@op": {
                "nonce": 0,
                "poh_tier": int(tier),
                "reputation_milli": int(rep),
                "banned": bool(banned),
                "locked": bool(locked),
                "devices": {
                    "by_id": {
                        "node:primary": {
                            "device_type": "node",
                            "pubkey": "node-pub",
                            "revoked": False,
                        }
                    }
                },
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {
                    "@op": {
                        "account_id": "@op",
                        "enrolled": True,
                        "active": bool(active),
                        "responsibilities": {
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
                        },
                    }
                },
                "active_set": ["@op"] if active else [],
            }
        },
    }


def _preflight(state: dict, *, roles: tuple[str, ...], bft: bool = False):
    return evaluate_production_preflight(
        state=state,
        node_id="node-1",
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="txhash",
        runtime_profile_hash="profilehash",
        requested_roles=roles,
        helper_requested=False,
        bft_requested=bft,
        sigverify_required=True,
        trusted_anchor_required=True,
    )


def test_responsibility_evaluator_reports_baseline_validator_and_storage_status_batch298() -> None:
    st = _state(active=True)
    summary = evaluate_node_operator_responsibilities(st, "@op")

    assert summary["baseline"]["status"] == "active"
    assert summary["baseline"]["active"] is True
    assert summary["validator"]["status"] == "readiness_pending"
    assert summary["validator"]["active"] is False
    assert "validator_readiness_pending" in summary["validator"]["reasons"]
    assert summary["storage"]["status"] == "proof_pending"
    assert summary["storage"]["active"] is False
    assert "capacity_proof_pending" in summary["storage"]["reasons"]


def test_responsibility_evaluator_is_the_shared_scheduler_and_preflight_source_batch298() -> None:
    scheduler = (ROOT / "src" / "weall" / "runtime" / "node_operator_scheduler.py").read_text(encoding="utf-8")
    preflight = (ROOT / "src" / "weall" / "runtime" / "node_lifecycle_preflight.py").read_text(encoding="utf-8")
    roles = (ROOT / "src" / "weall" / "runtime" / "apply" / "roles.py").read_text(encoding="utf-8")

    assert "evaluate_baseline_node_operator" in scheduler
    assert "first_blocking_reason" in scheduler
    assert "evaluate_node_operator_responsibilities" in preflight
    assert "responsibility_active_node_pubkeys_for_account" in roles
    assert "is_node_operator_active" in roles


def test_scheduler_uses_central_baseline_reasons_batch298() -> None:
    tier1 = _state(tier=1, active=False)
    assert evaluate_baseline_node_operator(tier1, "@op").reasons == ("poh_tier_insufficient",)
    assert schedule_node_operator_system_txs(tier1, next_height=10) == 0
    assert tier1["roles"]["node_operators"]["by_id"]["@op"]["activation_check"] == "poh_tier_insufficient"

    missing_key = _state(tier=2, active=False)
    missing_key["accounts"]["@op"]["devices"] = {"by_id": {}}
    assert evaluate_baseline_node_operator(missing_key, "@op").reasons == ("node_key_missing",)
    assert schedule_node_operator_system_txs(missing_key, next_height=10) == 0
    assert missing_key["roles"]["node_operators"]["by_id"]["@op"]["activation_check"] == "node_key_missing"


def test_central_evaluator_and_preflight_keep_opt_in_separate_from_authority_batch298(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@op")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "node-pub")
    monkeypatch.delenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", raising=False)
    st = _state(active=True)

    validator_eval = evaluate_validator_responsibility(st, "@op")
    storage_eval = evaluate_storage_responsibility(st, "@op")
    assert validator_eval.status == "readiness_pending"
    assert validator_eval.active is False
    assert storage_eval.status == "proof_pending"
    assert storage_eval.active is False

    validator_preflight = _preflight(st, roles=("validator",), bft=True)
    assert not validator_preflight.passed
    assert "ROLE_NOT_ACTIVE" in validator_preflight.maintenance_reasons

    storage_preflight = _preflight(st, roles=("storage_operator",))
    assert not storage_preflight.passed
    assert "ROLE_NOT_ACTIVE" in storage_preflight.maintenance_reasons


def test_central_evaluator_blocks_restricted_accounts_across_responsibilities_batch298() -> None:
    banned = _state(active=True, banned=True)
    baseline = evaluate_baseline_node_operator(banned, "@op")
    validator = evaluate_validator_responsibility(banned, "@op")
    storage = evaluate_storage_responsibility(banned, "@op")

    assert baseline.eligible is False
    assert "account_banned" in baseline.reasons
    assert validator.active is False
    assert "baseline_node_operator_inactive" not in validator.reasons or validator.active is False
    assert storage.active is False

    locked = _state(active=False, locked=True)
    assert "account_locked" in evaluate_baseline_node_operator(locked, "@op").reasons
