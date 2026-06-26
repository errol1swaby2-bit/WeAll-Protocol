from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.apply.governance import apply_governance
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "generated" / "governance_execution_vectors_v1_5.json"


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def test_governance_execution_vectors_are_fresh_and_cover_every_allowed_action() -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert data["schema"] == "weall.v1_5.governance_execution_vectors"
    assert data["action_vector_count"] == len(data["allowed_action_types"])
    assert data["action_vector_count"] >= 12
    assert set(data["allowed_action_types"]) == {
        "ECONOMICS_ACTIVATION",
        "FEE_POLICY_SET",
        "RATE_LIMIT_POLICY_SET",
        "GOV_QUORUM_SET",
        "GOV_RULES_SET",
        "TREASURY_POLICY_SET",
        "TREASURY_SPEND_EXECUTE",
        "GROUP_TREASURY_SPEND_EXECUTE",
        "VALIDATOR_SET_UPDATE",
        "VALIDATOR_CANDIDATE_APPROVE",
        "VALIDATOR_SUSPEND",
        "VALIDATOR_REMOVE",
    }
    economic_locked = {
        "ECONOMICS_ACTIVATION",
        "FEE_POLICY_SET",
        "TREASURY_POLICY_SET",
        "TREASURY_SPEND_EXECUTE",
        "GROUP_TREASURY_SPEND_EXECUTE",
    }
    by_type = {row["action_type"]: row for row in data["allowed_action_vectors"]}
    for action_type in economic_locked:
        row = by_type[action_type]
        assert row["expected_locked_by_genesis_economics"] is True
        assert row["proposal_create"]["ok"] is False
        assert row["proposal_create"]["error"]["reason"] == "economic_actions_locked"
    for action_type in set(by_type) - economic_locked:
        row = by_type[action_type]
        assert row["proposal_create"]["ok"] is True
        assert row["execution_result"]["ok"] is True
        assert row["execution_audit_hash"]
        emitted_types = [item["tx_type"] for item in row["emitted_actions"]]
        assert action_type in emitted_types
        assert "GOV_EXECUTION_RECEIPT" in emitted_types

    proc = subprocess.run(
        [sys.executable, "scripts/gen_governance_execution_vectors_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_governance_failure_vectors_capture_deterministic_rejections() -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    expected = {
        "failure::unsupported_action": "governance_action_not_allowed",
        "failure::invalid_action_payload": "governance_action_payload_invalid",
        "failure::executable_governance_requires_explicit_electorate": "executable_governance_requires_explicit_electorate",
        "failure::execute_before_tally": "proposal_not_executable",
        "failure::proposal_did_not_pass": "proposal_did_not_pass",
    }
    by_id = {row["id"]: row for row in data["failure_vectors"]}
    assert set(by_id) == set(expected)
    for vector_id, reason in expected.items():
        row = by_id[vector_id]
        assert row["result"]["ok"] is False
        assert row["result"]["error"]["reason"] == reason
        assert row["state_hash_after"]


def test_governance_conflicting_quorum_vector_is_ordered_and_last_write_wins() -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    [row] = data["conflict_vectors"]
    assert row["id"] == "conflict::quorum_last_write_order"
    assert row["proposal_create"]["ok"] is True
    assert row["execution_result"]["ok"] is True
    assert row["emitted_order"][:2] == ["GOV_QUORUM_SET", "GOV_QUORUM_SET"]
    assert row["final_quorum"]["quorum_bps"] == row["expected_final_quorum_bps"] == 7_500
    assert row["post_apply_hash"]


def test_queue_bound_gov_quorum_and_rules_actions_ignore_replay_metadata() -> None:
    state = {
        "height": 5,
        "accounts": {"@alice": {"nonce": 0, "poh_tier": 2}},
        "roles": {"validators": {"active_set": ["@alice"], "by_id": {"@alice": {"active": True}}}},
        "system_queue": [],
        "params": {"gov_action_allowlist": ["GOV_QUORUM_SET", "GOV_RULES_SET"]},
        "gov_config": {},
    }
    canon = load_tx_index_json(ROOT / "generated" / "tx_index.json")
    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "meta-strip",
                "title": "metadata strip",
                "rules": {"start_stage": "voting", "auto_progress_enabled": False},
                "actions": [
                    {"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 5_100}},
                    {"tx_type": "GOV_RULES_SET", "payload": {"params": {"poh": {"tier2_n_jurors": 7}}}},
                ],
            },
        ),
    )
    proposal = state["gov_proposals_by_id"]["meta-strip"]
    proposal["stage"] = "tallied"
    proposal["tallies"] = [{"height": 6, "payload": {"passed": True}}]
    apply_governance(state, _env("GOV_EXECUTE", "SYSTEM", 2, {"proposal_id": "meta-strip"}, system=True, parent="tx:meta-strip"))

    emitted = system_tx_emitter(state, canon=canon, next_height=7, phase="post")
    payload_keys = {env.tx_type: set(env.payload.keys()) for env in emitted if env.tx_type in {"GOV_QUORUM_SET", "GOV_RULES_SET"}}
    assert "_due_height" in payload_keys["GOV_QUORUM_SET"]
    assert "_system_queue_id" in payload_keys["GOV_RULES_SET"]

    for env in emitted:
        if env.tx_type in {"GOV_QUORUM_SET", "GOV_RULES_SET"}:
            out = apply_governance(state, env)
            assert out and out["applied"] is True

    assert state["gov_config"]["quorum"]["quorum_bps"] == 5_100
    assert state["gov_config"]["rules"]["params"]["poh"]["tier2_n_jurors"] == 7
    assert all("_system_queue_id" not in rec for rec in state["gov_quorum_set_receipts"])
    assert all("_due_height" not in rec for rec in state["gov_rules_set_receipts"])
