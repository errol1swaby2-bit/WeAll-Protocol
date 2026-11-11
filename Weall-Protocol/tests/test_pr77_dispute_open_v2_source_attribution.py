"""DISPUTE_OPEN V2 reviews must be scoped to the real transaction handler.

A green scanner regression does not accept an updated semantic-review digest
or prove the constitutional correctness of the actual dispute mechanism.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
compiler = importlib.import_module("compile_v2_spec")
validation = importlib.import_module("v2_spec_validation")


def test_dispute_open_maps_to_actual_handler_not_catchall_dispatcher() -> None:
    registry = json.loads((ROOT / "specs/v2/source/tx_appliers.json").read_text(encoding="utf-8"))
    rows = [row for row in registry["rows"] if row.get("tx_type") == "DISPUTE_OPEN"]
    assert len(rows) == 1
    row = rows[0]
    assert row["dispatch_function"] == "dispute_open"
    tree, functions = compiler._module_cached(ROOT / row["path"])
    assert "dispute_open" in functions
    assert "apply_dispute" in functions


def test_dispute_open_standalone_analysis_does_not_capture_other_transactions() -> None:
    path = ROOT / "src/weall/runtime/apply/dispute.py"
    txs = {"DISPUTE_OPEN", "DISPUTE_RESOLVE", "DISPUTE_APPEAL", "ACCOUNT_BAN"}
    analysis = compiler._tx_function_analysis(
        "DISPUTE_OPEN",
        path,
        "dispute_open",
        txs,
        {"DISPUTE_RESOLVE"},
        ["disputes_by_id"],
    )
    assert analysis["function"] == "dispute_open"
    forbidden = {
        "severe_sanction_initial_twenty_votes_unverified",
        "severe_sanction_initial_outcome_mismatch",
        "automatic_severe_appeal_already_assigned",
        "severe_appeal_fresh_panel_unverified",
    }
    reasons = {row["reason"] for row in analysis["failure_codes"]}
    assert reasons.isdisjoint(forbidden)
    assert analysis["semantic_precision"] == "function_static"


def test_dispute_open_includes_transitive_target_allowlist_rejection() -> None:
    """The dedicated DISPUTE_OPEN contract must see its live target validator."""
    path = ROOT / "src/weall/runtime/apply/dispute.py"
    required = {"code": "forbidden", "reason": "unsupported_dispute_target_type"}
    for dispatch in ("dispute_open", "apply_dispute"):
        analysis = compiler._tx_function_analysis(
            "DISPUTE_OPEN",
            path,
            dispatch,
            {"DISPUTE_OPEN", "DISPUTE_RESOLVE", "DISPUTE_APPEAL"},
            set(),
            ["disputes_by_id"],
        )
        assert required in analysis["failure_codes"]
        assert analysis["function"] == "dispute_open"
        assert analysis["return_keys"] == ["applied", "dispute_id"]


def test_review_material_does_not_bind_line_number_or_fabricate_authority() -> None:
    path = ROOT / "src/weall/runtime/apply/dispute.py"
    analysis = compiler._tx_function_analysis(
        "DISPUTE_OPEN",
        path,
        "dispute_open",
        {"DISPUTE_OPEN"},
        set(),
        ["disputes_by_id"],
    )
    material = validation.tx_review_material(
        {
            "tx_type": "DISPUTE_OPEN",
            "implementation_source": {
                "path": "src/weall/runtime/apply/dispute.py",
                "function": analysis["function"],
                "line": analysis["line"],
            },
        }
    )
    assert material["implementation_source"]["function"] == "dispute_open"
    assert "line" not in material["implementation_source"]
    assert material.get("authority") is None


def test_all_newly_observed_state_tokens_have_stable_append_only_ids() -> None:
    import audit_v2_semantic_review_drift as audit

    rows, ids, sources = audit._current_rows()
    assert audit._missing_state_ids(rows, ids, sources) == []
    names = {
        "Dispute:assignment_blocked_reason",
        "Dispute:automatic_appeal_record",
        "Dispute:disputes_by_id",
        "Reputation:account_id",
        "Reputation:auto",
        "Roles:actual_milli",
        "Roles:required_milli",
    }
    names.update(
        {
            "Groups:electorate_source",
            "Groups:eligible_voter_count",
            "Groups:n_ballots",
            "Groups:no_decision_reason",
            "Groups:quorum_activation_height",
            "Groups:quorum_met",
            "Groups:quorum_policy_version",
            "Groups:required_votes",
        }
    )
    for name in sorted(names):
        expected = "STATE-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:16].upper()
        assert ids.resolve("state", name) == expected


def test_compiler_reports_all_stale_transactions_without_mutating_rows() -> None:
    rows = [
        {"tx_type": "DISPUTE_OPEN", "stable_id": "TX-0200"},
        {"tx_type": "ACCOUNT_BAN", "stable_id": "TX-0904"},
    ]
    reviews = {
        "transactions": [{"stable_id": row["stable_id"], "review_digest": "stale"} for row in rows],
        "routes": [],
    }
    original = copy.deepcopy(rows)
    with pytest.raises(ValueError) as exc:
        validation.apply_semantic_reviews(rows, [], reviews)
    message = str(exc.value)
    assert message.startswith("transaction semantic-review digest is stale:")
    assert "DISPUTE_OPEN" in message and "ACCOUNT_BAN" in message
    assert rows == original


def test_compiler_preserves_independent_route_stale_gate() -> None:
    route = {"stable_id": "ROUTE-TEST", "route_key": "GET /v2/review"}
    review = {
        "transactions": [],
        "routes": [{"stable_id": "ROUTE-TEST", "review_digest": "stale"}],
    }
    with pytest.raises(ValueError) as exc:
        validation.apply_semantic_reviews([], [route], review)
    assert "route semantic-review digest is stale: GET /v2/review" in str(exc.value)
