"""Fail-closed review metadata checks; no confidential ballot cryptography."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from runpy import run_path

# The checked-in scripts/ directory is not installed with the backend wheel.
# Load this research-only validator by exact repository path, not sys.path hacks.
_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
_REVIEW = run_path(str(_SCRIPT_DIR / "validate_group_emissary_architecture_review.py"))
MANIFEST = _REVIEW["MANIFEST"]
REQUIRED_GATES = _REVIEW["REQUIRED_GATES"]
validate_review_matrix = _REVIEW["validate_review_matrix"]


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_review_manifest_stays_research_only_and_no_go() -> None:
    value = _manifest()
    assert validate_review_matrix(value) == []
    assert value["release_decision"] == "NO_GO"
    assert value["selected_production_primitive_suite"] is None
    assert value["authorized_new_consensus_tx_types"] == []
    assert value["baseline"]["signer_visible"] is True
    assert value["baseline"]["ranking_visible_in_signed_envelope"] is True


def test_positive_activation_and_false_security_claims_fail_closed() -> None:
    fields = {
        "document_status": "APPROVED",
        "release_decision": "GO",
        "selected_production_primitive_suite": "invented_mix_v1",
        "claimed_post_quantum_security": True,
        "enabled_ballot_submission": True,
        "authorized_new_consensus_tx_types": ["GROUP_EMISSARY_PRIVATE_BALLOT_V1"],
        "historical_plaintext_tx_unchanged": False,
    }
    for key, value in fields.items():
        mutated = deepcopy(_manifest())
        mutated[key] = value
        assert validate_review_matrix(mutated), key


def test_dropped_cryptographic_release_gates_fail_closed() -> None:
    original = _manifest()
    for gate in sorted(REQUIRED_GATES):
        mutated = deepcopy(original)
        mutated["hard_release_gates"].remove(gate)
        assert "required_release_gates_missing" in validate_review_matrix(mutated)


def test_unsafe_shortcuts_or_fake_hardware_evidence_fail_closed() -> None:
    mutated = _manifest()
    mutated["candidates"][3]["disposition"] = "APPROVED"
    mutated["benchmark_plan"]["real_measurements_collected"] = True
    errors = validate_review_matrix(mutated)
    assert "missing_rejection_additive_homomorphic_first_choice_totals" in errors
    assert "no_measured_benchmark_evidence" in errors


def test_incorrect_privacy_baseline_and_pq_suite_claim_fail_closed() -> None:
    mutated = _manifest()
    mutated["baseline"]["ranking_visible_in_signed_envelope"] = False
    mutated["baseline"]["transport_confidentiality_verified"] = True
    mutated["claimed_post_quantum_security"] = True
    errors = validate_review_matrix(mutated)
    assert "invalid_baseline_ranking_visible_in_signed_envelope" in errors
    assert "invalid_baseline_transport_confidentiality_verified" in errors
    assert "invalid_claimed_post_quantum_security" in errors
