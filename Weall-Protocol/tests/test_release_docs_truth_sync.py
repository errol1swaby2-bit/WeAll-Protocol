from __future__ import annotations

import importlib.util
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = REPO_ROOT.parent


def _load_tx_canon_artifact_constants() -> tuple[int, str]:
    script_path = REPO_ROOT / "scripts" / "check_tx_canon_artifacts.py"
    spec = importlib.util.spec_from_file_location(
        "_weall_check_tx_canon_artifacts_for_docs_test",
        script_path,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return int(module.EXPECTED_CANON_COUNT), str(module.EXPECTED_CANON_VERSION)


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected documentation file: {path}"
    return path.read_text(encoding="utf-8")


def test_release_docs_match_current_tx_canon_checkpoint() -> None:
    expected_count, expected_version = _load_tx_canon_artifact_constants()

    docs = [
        OUTER_ROOT / "README.md",
        OUTER_ROOT / "RELEASE_CHECKLIST.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
        REPO_ROOT / "docs" / "PROTOCOL_VERSIONING_STRATEGY.md",
        REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md",
    ]

    for path in docs:
        text = _read(path)
        assert str(expected_count) in text, f"{path} does not mention current tx count"
        assert expected_version in text, f"{path} does not mention current tx canon version"


def test_release_docs_state_two_tier_native_poh_without_external_identity_authority() -> None:
    text = "\n\n".join(
        _read(path)
        for path in [
            OUTER_ROOT / "README.md",
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
            REPO_ROOT / "docs" / "NODE_OPERATOR_ONBOARDING.md",
        ]
    ).lower()

    assert "tier 1 = native async" in text or "tier 1: native async" in text
    assert "tier 2 = native live" in text or "tier 2: native live" in text
    assert "no required email" in text
    assert "named hosting provider" in text
    assert "no required smtp" in text or "smtp" in text and "not required" in text
    assert "no required dns" in text or "dns" in text and "not required" in text


def test_release_docs_include_current_production_safety_gates() -> None:
    text = "\n\n".join(
        _read(path)
        for path in [
            OUTER_ROOT / "RELEASE_CHECKLIST.md",
            REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
            REPO_ROOT / "docs" / "PRODUCTION_RUNBOOK_VALIDATORS.md",
            REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md",
        ]
    ).lower()

    required_phrases = [
        "bft",
        "fail closed",
        "profile-pinned",
        "payload",
        "public api redaction",
        "secret guard",
        "release tree",
    ]

    for phrase in required_phrases:
        assert phrase in text, f"missing release safety phrase: {phrase}"

    snapshot = _read(REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md")
    assert "2026.03-prod.6" in snapshot
    assert re.search(r"\b[a-f0-9]{64}\b", snapshot), "snapshot should include a 64-char profile hash"


ALLOWED_REHEARSAL_CLAIM = (
    "WeAll is a pre-public-testnet protocol implementation under active hardening, "
    "with local/devnet/public-observer-oriented evidence present and public beta readiness "
    "still blocked by explicit external observer, replay, validator/operator, storage, "
    "legal, upgrade-execution, and helper-topology gates."
)


def test_readmes_and_reviewer_docs_preserve_current_allowed_claim() -> None:
    docs = [
        OUTER_ROOT / "README.md",
        OUTER_ROOT / "RELEASE_CHECKLIST.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "reviewer" / "CURRENT_READINESS_STATEMENT.md",
        REPO_ROOT / "docs" / "reviewer" / "EVIDENCE_INDEX.md",
        REPO_ROOT / "docs" / "reviewer" / "PUBLIC_BETA_BLOCKER_STATUS.md",
        REPO_ROOT / "docs" / "testnet" / "FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
        REPO_ROOT / "docs" / "testnet" / "PUBLIC_OBSERVER_QUICKSTART.md",
        REPO_ROOT / "docs" / "testnet" / "TESTNET_LAUNCH_CHECKLIST.md",
        REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
        REPO_ROOT / "docs" / "PROTOCOL_VERSIONING_STRATEGY.md",
    ]

    for path in docs:
        assert ALLOWED_REHEARSAL_CLAIM in _read(path), f"missing allowed claim: {path}"


def test_top_level_readme_has_reviewer_verification_and_evidence_map() -> None:
    text = _read(OUTER_ROOT / "README.md")
    for heading in (
        "## Public-only civic protocol direction",
        "## Current status",
        "## Reviewer verification path",
        "## Evidence package map",
        "## Headline claim to evidence map",
        "## Major protocol surfaces",
        "## What is intentionally disabled",
    ):
        assert heading in text

    for required_link in (
        "Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md",
        "Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md",
        "Weall-Protocol/generated/public_beta_blocker_report_v1_5.json",
        "Weall-Protocol/generated/release_evidence_manifest_v1_5.json",
        "Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md",
        "tests/test_direct_message_transaction_quarantine.py",
        "tests/prod/test_helper_production_safety_checklist.py",
        "test:reviewer-critical-source",
    ):
        assert required_link in text

    assert "236 tx types, version 1.25.0" in text
    assert "public_beta_ready=false" in text or "public_beta_ready` | `false`" in text or "`public_beta_ready=false`" in text
    assert "private, direct, encrypted" in text.lower()
    assert "membership must not gate read visibility" in text.lower()
    assert "first external observer readiness requires a fresh remote/signed observer run" in text.lower()


def test_readme_forbidden_claim_boundaries_are_explicit() -> None:
    text = _read(OUTER_ROOT / "README.md").lower()
    for phrase in (
        "not a public beta",
        "public mainnet",
        "public validator",
        "public multi-validator bft",
        "live-economics",
        "automatic-upgrade",
        "production-helper",
        "legal-approval",
        "public storage-market",
        "frontend state is not protocol authority",
        "local scripts are not public-readiness authority",
    ):
        assert phrase in text


def test_reviewer_docs_preserve_public_beta_blocker_counts() -> None:
    docs = [
        REPO_ROOT / "docs" / "reviewer" / "CURRENT_READINESS_STATEMENT.md",
        REPO_ROOT / "docs" / "reviewer" / "PUBLIC_BETA_BLOCKER_STATUS.md",
        REPO_ROOT / "docs" / "testnet" / "FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
    ]
    for path in docs:
        text = _read(path)
        assert "14" in text
        assert "7" in text
        assert "public_beta_ready" in text
        assert "false" in text.lower()
        assert "p0_open_count" in text
        assert "p1_open_count" in text


def test_pass29_pre_two_node_flow_audit_is_present_and_bounded() -> None:
    path = REPO_ROOT / "docs" / "audits" / "comprehensive_protocol_flow_audit_before_two_node_v1_5.md"
    text = _read(path)

    assert ALLOWED_REHEARSAL_CLAIM in text
    assert "## Flow classification table" in text
    for flow in (
        "First-run tester onboarding",
        "Public observer boot",
        "Node connection and switching",
        "Account creation/login/recovery",
        "Public posting/feed",
        "Group governance",
        "Multi-option voting",
        "Protocol/constitution upgrade record-only surfaces",
        "Dispute review/vote flow",
        "Transaction lifecycle status",
        "Operator command wizard",
        "Public observer open-download transcript docs",
        "Storage/IPFS operator transcript docs",
        "Legal/compliance evidence pack",
        "Production helper topology hardening plan",
        "Final go-gate package",
    ):
        assert flow in text

    for boundary in (
        "public_beta_ready` | `false`",
        "Blocker catalog entries | `14`",
        "Closed in repository | `7`",
        "Still open | `7`",
        "does not close external blockers",
        "frontend state",
        "local scripts",
    ):
        assert boundary in text


def test_first_15_minutes_guide_is_ordered_and_clean_clone_copy_pasteable() -> None:
    text = _read(REPO_ROOT / "docs" / "testnet" / "FIRST_15_MINUTES.md")

    assert "pip install -r requirements.lock" in text
    assert "pip install -e ." in text
    assert text.index("## Flow inspection checklist") < text.index("## Evidence to capture")
    assert text.index("## Evidence to capture") < text.index("## External evidence boundaries")
    assert text.index("## Stop conditions") < text.index("## Allowed readiness statement after this journey")

    stale_numbered_headings = [
        "## 4. Try one public social action",
        "## 6. Inspect the governance rendered journey",
        "## 7. Inspect the dispute and review rendered journey",
    ]
    for heading in stale_numbered_headings:
        assert heading not in text


def test_pass30_documentation_evidence_audit_is_present_and_bounded() -> None:
    path = REPO_ROOT / "docs" / "audits" / "documentation_evidence_package_audit_before_two_node_v1_5.md"
    text = _read(path)

    assert ALLOWED_REHEARSAL_CLAIM in text
    assert "## Documentation classification table" in text
    assert "Generated artifact" in text
    assert "Template-only proof slot" in text
    assert "not completed external evidence" in text
    assert "public_beta_ready` | `false`" in text
    assert "Blocker catalog entries | `14`" in text
    assert "Closed in repository | `7`" in text
    assert "Still open | `7`" in text

    for area in (
        "Root `README.md`",
        "Current reviewer docs",
        "Public observer quickstarts",
        "Legal/compliance proof template",
        "Upgrade execution proof slot",
        "Production helper topology proof slot",
        "Generated artifacts",
    ):
        assert area in text

    for forbidden in (
        "does not claim public beta readiness",
        "frontend state are not protocol authority",
        "Local scripts",
    ):
        assert forbidden.lower() in text.lower()


def test_readme_links_to_final_go_gate_and_current_evidence_artifacts() -> None:
    text = _read(OUTER_ROOT / "README.md")
    for required_link in (
        "Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md",
        "Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md",
        "Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
        "Weall-Protocol/generated/final_public_observer_controlled_testnet_go_gate_v1_5.json",
        "Weall-Protocol/generated/public_beta_blocker_report_v1_5.json",
        "Weall-Protocol/generated/release_evidence_manifest_v1_5.json",
        "Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md",
        "tests/test_direct_message_transaction_quarantine.py",
        "tests/prod/test_helper_production_safety_checklist.py",
        "test:reviewer-critical-source",
    ):
        assert required_link in text


def test_evidence_index_separates_generated_local_template_completed_and_external_evidence() -> None:
    text = _read(REPO_ROOT / "docs" / "reviewer" / "EVIDENCE_INDEX.md")
    for phrase in (
        "## Evidence status legend",
        "Generated artifact",
        "Local repository evidence",
        "Template-only proof slot",
        "Completed limited proof",
        "External blocker-closing evidence",
        "## Proof package distinctions",
        "docs/proofs/controlled-devnet-observer-live-gate/",
        "docs/proofs/public-observer-open-download/2026-07-05/",
        "docs/audits/documentation_evidence_package_audit_before_two_node_v1_5.md",
        "not completed external evidence",
    ):
        assert phrase in text


def test_proof_templates_are_clearly_labeled_and_do_not_close_blockers() -> None:
    template_readmes = sorted((REPO_ROOT / "docs" / "proofs").glob("*/2026-07-05/README.md"))
    assert template_readmes, "expected dated proof-template README files"

    for path in template_readmes:
        text = _read(path).lower()
        normalized = " ".join(text.split())
        assert "template only" in text, f"{path} must be explicitly template-only"
        assert "not completed external evidence" in text, f"{path} must say it is not completed external evidence"
        assert "does not close" in normalized or "do not close" in normalized, f"{path} must not close blockers by itself"
        assert "public beta" in text, f"{path} must preserve public beta claim boundary"

    completed = _read(REPO_ROOT / "docs" / "proofs" / "controlled-devnet-observer-live-gate" / "README.md").lower()
    assert "result: pass" in completed
    assert "controlled-devnet" in completed
    assert "public beta" not in completed or "does not" in completed


def test_public_observer_quickstarts_have_canonical_current_path_and_expected_outputs() -> None:
    current = _read(REPO_ROOT / "docs" / "testnet" / "PUBLIC_OBSERVER_QUICKSTART.md")
    pointer = _read(REPO_ROOT / "docs" / "testnet" / "PUBLIC_OBSERVER_TESTNET_QUICKSTART.md")
    supplement = _read(REPO_ROOT / "docs" / "PUBLIC_OBSERVER_TESTNET_QUICKSTART.md")

    assert "npm ci" in current
    assert "Expected backend status output" in current
    assert "Expected frontend check output" in current
    assert "WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh" in current
    assert "docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md" in pointer
    assert "canonical current runbook" in pointer.lower()
    assert "does not close `AUD-628-P1-001`" in pointer
    assert "Current-status note (Pass 30)" in supplement
    assert "detailed provider-independent discovery" in supplement
    assert "does not replace the current runbook" in supplement


def test_legacy_reviewer_evidence_index_defers_to_current_evidence_index() -> None:
    text = _read(REPO_ROOT / "docs" / "REVIEWER_EVIDENCE_INDEX.md")
    assert "Current-status note (Pass 30)" in text
    assert "docs/reviewer/EVIDENCE_INDEX.md" in text
    assert "public_beta_ready=false" in text
    assert "14 catalog entries" in text
    assert "7 closed in repository" in text
    assert "7 still open" in text
    assert "Do not use this historical checklist" in text
