"""Validate research-only group ballot architecture decisions.

This checks claim truth and fail-closed research metadata; it neither validates
cryptography nor grants chain or frontend ballot authority.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "specs/research/group_emissary_ballot_architecture_v0_1.json"
ADR = ROOT / "docs/production_readiness/GROUP_EMISSARY_CRYPTO_ARCHITECTURE_ADR_V0_2.md"

REQUIRED_GATES = frozenset(
    {
        "independent_crypto_review",
        "anonymous_snapshot_membership_soundness",
        "nullifier_uniqueness_without_public_roster_enumeration",
        "full_transport_observer_and_archive_privacy_scan",
        "proof_verified_deterministic_stv",
        "trustee_ceremony_dropout_and_recovery",
        "post_quantum_end_to_end_security_or_explicitly_rejected_deployment",
        "fixed_resource_caps_and_low_end_hardware_benchmark",
        "replay_restart_two_node_equality_and_observer_catchup",
        "constitutionally_recorded_activation",
        "exact_head_release_ci_green",
    }
)


def validate_review_matrix(value: Any) -> list[str]:
    """Return deterministic reasons when research decisions misstate readiness."""
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["review_manifest_must_be_object"]
    for field, expected in (
        ("schema_version", "weall.group-emissary-confidential-ballot.research.v0.1"),
        ("document_status", "RESEARCH_ONLY_NO_ACTIVATION"),
        ("release_decision", "NO_GO"),
        ("selected_production_primitive_suite", None),
        ("claimed_post_quantum_security", False),
        ("enabled_ballot_submission", False),
        ("authorized_new_consensus_tx_types", []),
        ("historical_plaintext_tx_unchanged", True),
    ):
        if value.get(field, object()) != expected:
            errors.append(f"invalid_{field}")
    baseline = value.get("baseline")
    if not isinstance(baseline, dict):
        errors.append("missing_baseline")
    else:
        for field, expected in (
            ("tx_type", "GROUP_EMISSARY_BALLOT_CAST"),
            ("signer_visible", True),
            ("ranking_visible_in_signed_envelope", True),
            ("transport_confidentiality_verified", False),
            ("anonymous_eligibility_verified", False),
            ("verifiable_private_stv_verified", False),
        ):
            if baseline.get(field) != expected:
                errors.append(f"invalid_baseline_{field}")
    candidates = value.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 5:
        errors.append("candidate_matrix_must_have_five_options")
    else:
        seen: set[str] = set()
        for row in candidates:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                errors.append("invalid_candidate_row")
                continue
            name = row["id"]
            if name in seen:
                errors.append("duplicate_candidate")
            seen.add(name)
            if row.get("implementation_ready") is not False:
                errors.append(f"premature_implementation_claim_{name}")
            if not isinstance(row.get("primary_blocker"), str) or not row["primary_blocker"]:
                errors.append(f"missing_blocker_{name}")
        if value.get("preferred_feasibility_track") not in seen:
            errors.append("unlisted_feasibility_track")
        rejected = {
            row.get("id"): row.get("disposition") for row in candidates if isinstance(row, dict)
        }
        for rejected_id, decision in (
            ("additive_homomorphic_first_choice_totals", "REJECT_AS_STV_REPLACEMENT"),
            ("ml_kem_only_encryption", "REJECT_AS_COMPLETE_VOTING_SCHEME"),
        ):
            if rejected.get(rejected_id) != decision:
                errors.append(f"missing_rejection_{rejected_id}")
    gates = value.get("hard_release_gates")
    if not isinstance(gates, list) or not REQUIRED_GATES.issubset(set(map(str, gates))):
        errors.append("required_release_gates_missing")
    benchmark = value.get("benchmark_plan")
    if not isinstance(benchmark, dict):
        errors.append("missing_benchmark_plan")
    else:
        if benchmark.get("real_measurements_collected") is not False:
            errors.append("no_measured_benchmark_evidence")
        if benchmark.get("limits_reviewed_and_committed") is not False:
            errors.append("no_approved_resource_limits")
        hardware = benchmark.get("hardware_profiles")
        if not isinstance(hardware, list) or "baseline_4_gb_ram_laptop" not in hardware:
            errors.append("missing_low_end_laptop_target")
    bindings = value.get("required_election_bindings")
    if not isinstance(bindings, list) or not {
        "chain_id",
        "group_id",
        "election_id",
        "election_version",
        "snapshot_commitment",
        "candidate_order_commitment",
        "election_start_height",
        "election_end_height",
        "ballot_profile_version",
    }.issubset(set(map(str, bindings))):
        errors.append("missing_election_context_bindings")
    return errors


def main() -> int:
    matrix = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures = validate_review_matrix(matrix)
    adr = ADR.read_text(encoding="utf-8")
    for required in (
        "NO-GO",
        "research",
        "post-quantum",
        "4 GB RAM",
        "Verificatum",
        "ElectionGuard",
        "no new",
        "STV",
    ):
        if required.lower() not in adr.lower():
            failures.append(f"adr_missing_{required.replace(' ', '_').lower()}")
    if failures:
        for failure in sorted(set(failures)):
            print(f"FAIL: {failure}")
        return 1
    print("PASS: research-only architecture; no PQ security, ballot or consensus activation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
