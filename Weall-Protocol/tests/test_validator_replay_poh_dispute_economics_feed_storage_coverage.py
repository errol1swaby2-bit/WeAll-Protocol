from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from weall.api.routes_public_parts.content import _feed_rank_score, _sort_feed_items
from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.storage import apply_storage
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
CID_A = "bafkreigh2akiscaildc3qj6k2ol6qmk7p2xk3w5t2c5a7xqz7xqz7i"


def _env(tx_type: str, *, signer: str = "alice", nonce: int = 1, payload: dict | None = None, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="", system=system, parent=parent)


def _run_json(script: str) -> dict:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--json"], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(proc.stdout)


def test_real_validator_network_rehearsal() -> None:
    out = _run_json("rehearse_real_validator_network_v1_5.py")
    assert out["ok"] is True
    assert out["public_validator_enabled"] is False
    assert out["minority_partition_result"] == "finality_threshold_not_met"
    assert out["rejoin_root_matches_reference"] is True
    assert out["observer_attempt"]["can_vote"] is False


def test_fresh_node_replay_sync_rehearsal() -> None:
    out = _run_json("rehearse_fresh_node_replay_sync_v1_5.py")
    assert out["ok"] is True
    assert out["snapshot_used"] is False
    assert out["verified_block_count"] == 5
    assert out["source_state_root"] == out["fresh_state_root"] == out["interrupted_resume_root"]


def test_poh_upheld_challenge_flags_prior_approving_reviewers() -> None:
    state = {
        "height": 15,
        "accounts": {"alice": {"poh_tier": 1}, "juror-a": {}, "juror-b": {}},
        "poh": {
            "async_cases": {
                "case-1": {
                    "case_id": "case-1",
                    "account_id": "alice",
                    "reviews": {
                        "juror-a": {"verdict": "approve"},
                        "juror-b": {"verdict": "reject"},
                    },
                }
            }
        },
    }
    apply_poh(state, _env("POH_CHALLENGE_OPEN", signer="bob", nonce=1, payload={"account_id": "alice", "case_id": "case-1", "reason": "duplicate"}))
    out = apply_poh(state, _env("POH_CHALLENGE_RESOLVE", signer="SYSTEM", system=True, nonce=2, payload={"challenge_id": "pohc:alice:1", "resolution": "upheld"}))
    accountability = out["consequence"]["reviewer_accountability"]
    assert accountability["applied"] is True
    assert accountability["reviewers"] == ["juror-a"]
    rec = state["poh"]["reviewer_accountability"]["by_reviewer"]["juror-a"]
    assert rec["status"] == "reviewer_accountability_flagged"
    assert rec["challenge_upheld_review_count"] == 1


def test_dispute_target_registry_and_unsupported_action_rejection() -> None:
    state = {"height": 1, "accounts": {"alice": {}, "bob": {}}, "disputes_by_id": {}}
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, _env("DISPUTE_OPEN", signer="alice", nonce=1, payload={"dispute_id": "bad", "target_type": "weather", "target_id": "x", "reason": "unsupported"}))
    assert exc.value.reason == "unsupported_dispute_target_type"

    apply_dispute(state, _env("DISPUTE_OPEN", signer="alice", nonce=2, payload={"dispute_id": "d-account", "target_type": "account", "target_id": "bob", "reason": "abuse"}))
    out = apply_dispute(state, _env("DISPUTE_FINAL_RECEIPT", signer="SYSTEM", system=True, nonce=3, payload={"dispute_id": "d-account", "appeal_resolution": {"decision": "modify", "actions": [{"tx_type": "UNKNOWN_ACTION", "payload": {}}, {"tx_type": "ACCOUNT_RESTRICTION_SET", "payload": {"account_id": "bob", "restriction": "posting_limited"}}]}}))
    assert out["enforcement_applied"][0]["tx_type"] == "ACCOUNT_RESTRICTION_SET"
    assert state["accounts"]["bob"]["restricted"] is True
    assert state["dispute_enforcement_rejections"][0]["reason"] == "unsupported_enforcement_action"


def test_economics_activation_preconditions_are_enforceable_but_opt_in() -> None:
    state = {"height": 10, "time": 2_000_000_000, "params": {"economic_unlock_time": 1, "economics_enabled": False}, "accounts": {"SYSTEM": {}}}
    with pytest.raises(EconomicsApplyError) as exc:
        apply_economics(state, _env("ECONOMICS_ACTIVATION", signer="SYSTEM", system=True, nonce=1, payload={"enable": True, "enforce_preconditions": True}))
    assert exc.value.reason == "economics_activation_preconditions_not_satisfied"

    state["tokenomics_simulation"] = {"cap": 21_000_000}
    state["treasury_wallets"] = {"treasury": {"balance": 0}}
    state["economics"] = {"reward_policy": {"eligible_roles": ["validator", "juror"]}, "wallet_policy": {"initialization": "explicit"}, "fee_policy": {"post_fee_int": 0}}
    out = apply_economics(state, _env("ECONOMICS_ACTIVATION", signer="SYSTEM", system=True, nonce=2, payload={"enable": True, "enforce_preconditions": True}))
    assert out == {"applied": "ECONOMICS_ACTIVATION", "enabled": True}
    assert state["economics"]["activation_preconditions"]["ready"] is True


def test_storage_pin_confirm_can_record_retrieval_availability() -> None:
    state = {"height": 7, "params": {"ipfs_replication_factor": 1}, "storage": {"operators": {"opA": {"enabled": True, "capacity_bytes": 1000}}, "pins": {"pin-1": {"pin_id": "pin-1", "cid": CID_A, "targets": ["opA"], "size_bytes": 10, "replication_factor": 1}}, "pin_confirms": []}, "accounts": {"opA": {}}}
    out = apply_storage(state, _env("IPFS_PIN_CONFIRM", signer="SYSTEM", system=True, nonce=1, payload={"pin_id": "pin-1", "cid": CID_A, "operator_id": "opA", "ok": True, "retrieval_ok": True}))
    assert out["applied"] == "IPFS_PIN_CONFIRM"
    pin = state["storage"]["pins"]["pin-1"]
    assert pin["durability_status"] == "retrieval_confirmed"
    assert pin["availability_status"] == "available"
    assert pin["retrieval_proofs"][0]["status"] == "retrievable"


def test_full_lifecycle_and_feed_ranking_completion_artifact() -> None:
    out = _run_json("rehearse_v15_full_lifecycle.py")
    assert out["ok"] is True
    assert out["locked_boundaries"] == {"public_validators": False, "live_economics": False, "automatic_upgrades": False, "production_helpers": False}

    generator = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_b517_b521_completion_proof_v1_5.py")], cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    artifact = ROOT / "generated" / "b517_b521_completion_proof_v1_5.json"
    data = json.loads(artifact.read_text())
    assert data["ok"] is True
    assert data["feed_ranking_review"]["current_default"] == "created_at_nonce_desc"
    assert data["feed_ranking_review"]["complete_ranking"] is False
    assert str(artifact) in generator.stdout


def test_feed_ranking_is_deterministic_and_default_compatible() -> None:
    items = [
        {"post_id": "old-popular", "created_at_nonce": 10, "reaction_total": 5, "comment_total": 2},
        {"post_id": "new-quiet", "created_at_nonce": 20, "reaction_total": 0, "comment_total": 0},
    ]
    recency = _sort_feed_items([dict(x, feed_rank_score=_feed_rank_score(x, mode="recency")) for x in items], mode="recency")
    assert [x["post_id"] for x in recency] == ["new-quiet", "old-popular"]

    ranked_items = []
    for item in items:
        obj = dict(item)
        obj["feed_rank_score"] = _feed_rank_score(obj, mode="engagement")
        ranked_items.append(obj)
    engagement = _sort_feed_items(ranked_items, mode="engagement")
    assert [x["post_id"] for x in engagement] == ["old-popular", "new-quiet"]
    assert all(isinstance(x["feed_rank_score"], int) for x in engagement)
