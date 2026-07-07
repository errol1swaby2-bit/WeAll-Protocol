from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEGAL_DOCS = [
    "LEGAL_TRUTH_BOUNDARY.md",
    "TOKEN_MARKETING_GUARDRAILS.md",
    "AML_MONEY_TRANSMISSION_BOUNDARY.md",
    "SANCTIONS_AND_BLOCKED_PARTY_POLICY.md",
    "PRIVACY_DATA_PROTECTION_POSTURE.md",
    "MINORS_AND_AGE_POLICY.md",
    "SEVERE_HARM_AND_NCIM_POLICY.md",
    "PUBLIC_CLAIMS_CHECKLIST.md",
    "COUNSEL_REVIEW_EVIDENCE_PACK.md",
]


def test_v15_gap_register_marks_recent_batches_resolved_and_remaining_gaps() -> None:
    payload = json.loads((ROOT / "generated/v15_implementation_gap_register.json").read_text(encoding="utf-8"))
    resolved = {item["id"]: item for item in payload["resolved_since_prior_evidence_map"]}
    remaining = {item["id"]: item for item in payload["remaining_p0_p1_gaps"]}

    assert resolved["V15-TOKENOMICS-EPOCH-ISSUANCE"]["status"] == "resolved_locked_implementation"
    assert resolved["V15-RUNTIME-BLOCK-TIMING-CONFIG"]["status"] == "resolved_config_alignment"
    assert remaining["P0-PROTOCOL-UPGRADE-DELIVERY"]["status"] == "record_only_hardened_not_automatic"
    assert remaining["P0-LEGAL-COMPLIANCE-PACK"]["status"] == "draft_pending_counsel_review"
    assert remaining["P0-PUBLIC-VALIDATOR-BFT-PROOF"]["status"] == "proof_plan_defined_not_passed"


def test_legal_compliance_pack_exists_and_is_counsel_pending() -> None:
    for name in LEGAL_DOCS:
        text = (ROOT / "docs/legal" / name).read_text(encoding="utf-8")
        assert "pending counsel review" in text.lower()
        assert "non-lawyer" in text.lower()


def test_public_validator_bft_plan_preserves_truth_boundary() -> None:
    text = (ROOT / "docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md").read_text(encoding="utf-8")
    required = [
        "equivocation",
        "partition/rejoin",
        "restart/replay",
        "cold node state sync",
        "observer",
        "public multi-validator readiness is not claimed",
    ]
    for phrase in required:
        assert phrase.lower() in text.lower()


def test_evidence_map_references_new_public_readiness_artifacts() -> None:
    text = (ROOT / "docs/V15_IMPLEMENTATION_EVIDENCE_MAP.md").read_text(encoding="utf-8")
    for rel in [
        "generated/api_contract_map_v1_5.json",
        "generated/launch_disabled_matrix_v1_5.json",
        "docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md",
        "docs/legal/*",
        "docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md",
    ]:
        assert rel in text
