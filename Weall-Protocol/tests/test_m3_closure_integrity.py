from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "Weall-Protocol"


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_traceability_rejects_missing_referenced_paths() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/check_m3_requirement_traceability.py"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "repository paths" in proc.stdout


def test_canonical_m3_runners_and_contract_exist() -> None:
    required = [
        "scripts/m3_common.sh",
        "scripts/m3_evidence_contract.py",
        "scripts/run_m3_civic_real_stack_e2e.sh",
        "scripts/run_m3_restart_replay_gate.sh",
        "scripts/run_m3_two_node_state_root_gate.sh",
        "scripts/run_m3_observer_catchup_gate.sh",
        "scripts/capture_m3_observer_authority.py",
        "scripts/run_m3_clean_checkout_reproduction.sh",
        "scripts/run_m3_privacy_scan.sh",
        "scripts/check_m3_live_ballot_profile.py",
        "scripts/build_m3_evidence_manifest.py",
        "scripts/gen_m3_actor_contract_templates.py",
        "scripts/gen_m3_closure_manifest.py",
        "scripts/check_m3_evidence_only_commit.py",
    ]
    for rel in required:
        path = ROOT / rel
        assert path.is_file(), rel
        assert not path.is_symlink(), rel



def test_generated_actor_template_uses_canonical_account_ids(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/gen_m3_actor_contract_templates.py",
            "--out-dir",
            str(tmp_path),
            "--implementation-freeze",
            "HEAD",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    actors = json.loads((tmp_path / "m3-actors.template.json").read_text(encoding="utf-8"))
    assert len(actors) == 21
    for actor in actors:
        account = actor["account"]
        assert account.startswith("@")
        assert 1 <= len(account[1:]) <= 32
        assert all(char.islower() or char.isdigit() or char == "_" for char in account[1:])
        assert "signer_state" in actor

    role_to_account = {actor["role"]: actor["account"] for actor in actors}
    transcript = json.loads(
        (tmp_path / "m3-transaction-transcript.template.json").read_text(encoding="utf-8")
    )
    for item in [*transcript["actions"], *transcript["negative_attempts"]]:
        role = item["role"]
        account = item["account"]
        if role == "system_scheduler":
            assert account == "SYSTEM"
        else:
            assert role_to_account[role] == account

def test_closure_runner_requires_observer_privacy_and_freshness_gates() -> None:
    source = _read("scripts/run_m3_complete_closure.sh")
    for marker in (
        "v1.5 readiness artifacts current",
        "v2 specification derivatives current",
        "clean checkout reproduction",
        "frontend group flow source",
        "frontend public-only protocol source",
        "frontend contract check",
        "frontend production safety check",
        "M3 strict live ballot profile",
        "M3 signed real-stack actor journey",
        "M3 restart replay equality",
        "M3 two-node equality",
        "M3 observer catch-up without authority",
        "M3 artifact privacy scan",
        "run_m3_observer_catchup_gate.sh",
        "run_m3_privacy_scan.sh",
    ):
        assert marker in source
    assert "HEAD equals the implementation freeze" in source
    assert "direct child" not in source.split("while [[ $#", 1)[1].split("rm -rf", 1)[0]


def test_evidence_contract_requires_all_evidence_families() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    assert "M3 observer catch-up without authority" in contract.REQUIRED_GATES
    assert "M3 artifact privacy scan" in contract.REQUIRED_GATES
    assert "M3 strict live ballot profile" in contract.REQUIRED_GATES
    for required in (
        "artifacts/m3-closure/browser/civic/transaction-transcript.json",
        "artifacts/m3-closure/restart-replay/final-state.json",
        "artifacts/m3-closure/two-node/final-state.json",
        "artifacts/m3-closure/observer/final-state.json",
        "artifacts/m3-closure/observer/authority.json",
        "artifacts/m3-closure/privacy/private-material-scan.json",
        "artifacts/m3-closure/backend/live-ballot-profile.json",
    ):
        assert required in contract.REQUIRED_EXACT_PATHS
    assert len(contract.REQUIRED_ACTION_LABELS) >= 20
    assert len(contract.REQUIRED_NEGATIVE_LABELS) >= 10


def test_real_stack_spec_executes_negative_signed_attempts_and_requires_eighteen_reviewers() -> None:
    source = _read("web/tests/e2e/m3_civic_governance_real_stack.spec.ts")
    for marker in (
        "schema_version).toBe(3)",
        "transaction_transcript",
        "reviewer_original_",
        "reviewer_appeal_",
        "toBeGreaterThanOrEqual(9)",
        "submitSignedTx",
        "signer_state",
        "context.addInitScript",
        "weall_secret::",
        "negative signed attempts fail closed",
        "/v1/tx/status/",
        "expected_error_code",
        "precondition_tx_id",
        "negative fixture subjects remain active",
        "/v1/gov/ballot-profile",
        "active_controlled_testnet_profile",
    ):
        assert marker in source
    for forbidden in ("test.skip", "test.fixme", "recovery_file?:"):
        assert forbidden not in source


def test_manifest_and_commit_checker_share_schema_three_contract() -> None:
    builder = _read("scripts/gen_m3_closure_manifest.py")
    checker = _read("scripts/check_m3_evidence_only_commit.py")
    contract = _read("scripts/m3_evidence_contract.py")
    for marker in (
        "REQUIRED_EXACT_PATHS",
        "STATE_SUMMARY_PATHS",
        "REQUIRED_ACTION_LABELS",
        "REQUIRED_NEGATIVE_LABELS",
    ):
        assert marker in builder
        assert marker in checker
        assert marker in contract
    assert '"schema_version": 3' in builder
    assert 'manifest.get("schema_version") != 3' in checker
    assert "observer_authority" in builder
    assert "observer_authority" in checker
    assert "live_ballot_profile" in builder
    assert "live_ballot_profile" in checker
    assert "m3_evidence_inherited_from_freeze" in checker
    assert "m3_evidence_commit_not_direct_child" in checker


def test_scope_crosswalk_references_only_existing_implementation_paths() -> None:
    crosswalk = json.loads((BACKEND / "docs/production_readiness/M3_SCOPE_CROSSWALK.json").read_text())
    for deliverable in crosswalk["deliverables"]:
        for value in deliverable["implementation"]:
            text = str(value)
            path = (BACKEND / text).resolve() if text.startswith("../") else (ROOT / text if text.startswith(("scripts/", "web/", "Weall-Protocol/")) else BACKEND / text)
            assert path.exists(), f"{deliverable['id']}: {value}"


def test_transaction_contract_binds_labels_roles_subjects_and_preconditions() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    freeze = "f" * 40
    actors = [
        {"role": "author_proposer", "account": "@author"},
        {"role": "member_reporter_voter", "account": "@member"},
        {"role": "nonmember_ineligible", "account": "@outsider"},
    ]
    actors.extend(
        {"role": f"reviewer_original_{index:02d}", "account": f"@original{index:02d}"}
        for index in range(1, 10)
    )
    actors.extend(
        {"role": f"reviewer_appeal_{index:02d}", "account": f"@appeal{index:02d}"}
        for index in range(1, 10)
    )
    journey = {
        "post_id": "post:main",
        "group_id": "group:main",
        "group_post_id": "post:group:main",
        "dispute_id": "dispute:main",
        "proposal_id": "proposal:main",
        "negative_post_id": "post:negative",
        "negative_group_id": "group:negative",
        "negative_dispute_id": "dispute:negative",
        "negative_proposal_id": "proposal:negative",
    }
    manifest = {
        "schema_version": 3,
        "implementation_freeze_commit": freeze,
        "actors": actors,
        "reviewer_count": 18,
        "journey": journey,
    }
    role_accounts = {item["role"]: item["account"] for item in actors}

    def actor_for(label: str, index: int = 1) -> tuple[str, str]:
        if label in contract.SYSTEM_ACTION_LABELS:
            return "system_scheduler", "SYSTEM"
        if label.startswith("original_panel_"):
            if index == 1:
                return (
                    contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ROLE,
                    contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ACCOUNT,
                )
            if index in {2, 3}:
                role = f"reviewer_appeal_{index:02d}"
                return role, role_accounts[role]
            role = f"reviewer_original_{index:02d}"
            return role, role_accounts[role]
        if label.startswith("appeal_panel_"):
            if index == 1:
                return (
                    contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ROLE,
                    contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ACCOUNT,
                )
            if index in {2, 3}:
                role = f"reviewer_original_{index:02d}"
                return role, role_accounts[role]
            role = f"reviewer_appeal_{index:02d}"
            return role, role_accounts[role]
        if label in {"membership_request", "group_post_create", "content_report", "appeal_open", "proposal_comment"}:
            return "member_reporter_voter", "@member"
        if label == "eligible_ballots" and index == 2:
            return "member_reporter_voter", "@member"
        return "author_proposer", "@author"

    actions: list[dict] = []
    counter = 0
    for label in sorted(contract.REQUIRED_ACTION_LABELS):
        for index in range(1, contract.ACTION_MIN_COUNTS[label] + 1):
            counter += 1
            role, account = actor_for(label, index)
            actions.append(
                {
                    "label": label,
                    "role": role,
                    "account": account,
                    "tx_type": sorted(contract.ACTION_TX_TYPES[label])[0],
                    "tx_id": f"tx-main-{counter}",
                    "subject_id": journey[contract.MAIN_ACTION_SUBJECT_FIELD[label]],
                    "status": "confirmed",
                }
            )
    for attendance in actions:
        attendance_label = str(attendance.get("label") or "")
        if attendance_label not in contract.EMBEDDED_ATTENDANCE_LABELS:
            continue
        acceptance_label = contract.ATTENDANCE_ACCEPTANCE_LABEL[attendance_label]
        matches = [
            item
            for item in actions
            if item.get("label") == acceptance_label
            and item.get("role") == attendance.get("role")
            and item.get("account") == attendance.get("account")
            and item.get("subject_id") == attendance.get("subject_id")
        ]
        assert len(matches) == 1
        attendance["tx_type"] = "DISPUTE_JUROR_ACCEPT"
        attendance["tx_id"] = matches[0]["tx_id"]
        attendance["evidence_kind"] = contract.EMBEDDED_ATTENDANCE_EVIDENCE_KIND

    actions.extend(
        [
            {
                "label": "eligible_ballots",
                "role": "member_reporter_voter",
                "account": "@member",
                "tx_type": "GOV_VOTE_CAST",
                "tx_id": "tx-negative-governance-vote",
                "subject_id": journey["negative_proposal_id"],
                "status": "confirmed",
            },
            {
                "label": "original_panel_ballots",
                "role": "reviewer_original_01",
                "account": "@original01",
                "tx_type": "DISPUTE_VOTE_SUBMIT",
                "tx_id": "tx-negative-dispute-vote",
                "subject_id": journey["negative_dispute_id"],
                "status": "confirmed",
            },
        ]
    )

    def negative(label: str, role: str, account: str, subject: str, payload: dict, *, prior: str = "") -> dict:
        item = {
            "label": label,
            "role": role,
            "account": account,
            "tx_type": sorted(contract.NEGATIVE_TX_TYPES[label])[0],
            "payload": payload,
            "subject_id": subject,
            "expected_error_code": contract.EXPECTED_NEGATIVE_ERROR_CODES[label],
        }
        if prior:
            item["precondition_tx_id"] = prior
        return item

    negatives = [
        negative(
            "nonmember_group_write_rejected",
            "nonmember_ineligible",
            "@outsider",
            journey["negative_group_id"],
            {"post_id": "post:forbidden", "body": "no", "group_id": journey["negative_group_id"]},
        ),
        negative(
            "nonselected_reviewer_vote_rejected",
            "reviewer_appeal_01",
            "@appeal01",
            journey["negative_dispute_id"],
            {"dispute_id": journey["negative_dispute_id"], "vote": "yes"},
        ),
        negative(
            "conflicted_reviewer_vote_rejected",
            "author_proposer",
            "@author",
            journey["negative_dispute_id"],
            {"dispute_id": journey["negative_dispute_id"], "vote": "yes"},
        ),
        negative(
            "ineligible_governance_vote_rejected",
            "nonmember_ineligible",
            "@outsider",
            journey["negative_proposal_id"],
            {"proposal_id": journey["negative_proposal_id"], "vote": "yes"},
        ),
    ]
    for label in (
        "duplicate_governance_vote_rejected",
        "replacement_governance_vote_rejected",
        "governance_revoke_rejected",
    ):
        negatives.append(
            negative(
                label,
                "member_reporter_voter",
                "@member",
                journey["negative_proposal_id"],
                {"proposal_id": journey["negative_proposal_id"], **({} if "revoke" in label else {"vote": "no"})},
                prior="tx-negative-governance-vote",
            )
        )
    for label in (
        "duplicate_dispute_ballot_rejected",
        "replacement_dispute_ballot_rejected",
        "dispute_revoke_rejected",
    ):
        negatives.append(
            negative(
                label,
                "reviewer_original_01",
                "@original01",
                journey["negative_dispute_id"],
                {"dispute_id": journey["negative_dispute_id"], **({} if "revoke" in label else {"vote": "no"})},
                prior="tx-negative-dispute-vote",
            )
        )

    transcript = {
        "schema_version": 1,
        "implementation_freeze_commit": freeze,
        "chain_id": "weall-m3-test",
        "actions": actions,
        "negative_attempts": negatives,
    }
    summary = contract.validate_public_actor_transcript(manifest, transcript, freeze=freeze)
    assert summary["reviewer_count"] == 18
    assert summary["original_reviewer_pool"] == 9
    assert summary["appeal_reviewer_pool"] == 9

    assert contract.role_allowed_for_action(
        "original_panel_ballots",
        "reviewer_appeal_01",
        "@appeal01",
    )
    assert contract.role_allowed_for_action(
        "appeal_panel_ballots",
        "reviewer_original_01",
        "@original01",
    )
    assert contract.role_allowed_for_action(
        "original_panel_ballots",
        contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ROLE,
        contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ACCOUNT,
    )
    assert not contract.role_allowed_for_action(
        "original_panel_ballots",
        contract.CONTROLLED_DEVNET_BOOTSTRAP_REVIEWER_ROLE,
        "@not-devnet-genesis",
    )

    original_acceptance = next(
        item
        for item in transcript["actions"]
        if item["label"] == "original_panel_acceptance"
        and item["subject_id"] == journey["dispute_id"]
    )
    original_attendance = next(
        item
        for item in transcript["actions"]
        if item["label"] == "original_panel_attendance"
        and item["role"] == original_acceptance["role"]
        and item["subject_id"] == journey["dispute_id"]
    )
    assert original_attendance["tx_id"] == original_acceptance["tx_id"]
    assert original_attendance["tx_type"] == "DISPUTE_JUROR_ACCEPT"
    assert (
        original_attendance["evidence_kind"]
        == contract.EMBEDDED_ATTENDANCE_EVIDENCE_KIND
    )

    broken_attendance = json.loads(json.dumps(transcript))
    target = next(
        item
        for item in broken_attendance["actions"]
        if item["label"] == "original_panel_attendance"
        and item["subject_id"] == journey["dispute_id"]
    )
    target["tx_id"] = "tx-impossible-separate-attendance"
    import pytest
    with pytest.raises(ValueError, match="attendance_acceptance_pair_missing"):
        contract.validate_public_actor_transcript(
            manifest,
            broken_attendance,
            freeze=freeze,
        )

    broken = json.loads(json.dumps(transcript))
    broken["actions"][0]["tx_type"] = "PROFILE_UPDATE"
    with pytest.raises(ValueError, match="tx_type_invalid"):
        contract.validate_public_actor_transcript(manifest, broken, freeze=freeze)


def test_state_summary_extractor_requires_equal_complete_nodes(tmp_path: Path) -> None:
    state = {
        "chain_id": "weall-m3",
        "height": 42,
        "tip_hash": "a" * 64,
        "state_root": "b" * 64,
        "schema_version": "1",
        "tx_index_hash": "c" * 64,
        "protocol_profile_hash": "d" * 64,
    }
    source = tmp_path / "compare.log"
    source.write_text(
        "==> Node 1\n"
        + json.dumps(state, indent=2)
        + "\n==> Node 2\n"
        + json.dumps(state, indent=2)
        + "\nOK: node identities, tips, and state roots match\n",
        encoding="utf-8",
    )
    out = tmp_path / "summary.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/extract_m3_state_root_summary.py"),
            "--input",
            str(source),
            "--out",
            str(out),
            "--gate",
            "observer",
            "--implementation-freeze",
            "f" * 40,
            "--implementation-tree",
            "e" * 40,
            "--node1-id",
            "producer",
            "--node2-id",
            "observer",
            "--observer",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    summary = json.loads(out.read_text())
    assert summary["equal"] is True
    assert summary["nodes"][0]["node_id"] != summary["nodes"][1]["node_id"]
    assert summary["observer_authority"] == {
        "observer_mode": True,
        "validator_signing_enabled": False,
        "bft_signing_authority": False,
        "helper_authority": False,
        "treasury_or_governance_authority": False,
    }


def test_private_material_contract_detects_tokens_without_rejecting_public_metadata() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    assert contract.private_material_findings(b'{"authorization_required": true, "cookie_policy": "none"}') == []
    assert contract.private_material_findings(b'{"authorization": "Bearer secret-token-123456"}')
    assert contract.private_material_findings(b'-----BEGIN PRIVATE KEY-----')


def test_final_closure_runbook_preserves_freeze_then_direct_child_sequence() -> None:
    source = _read("Weall-Protocol/docs/production_readiness/M3_FINAL_CLOSURE_RUNBOOK_WSL.md")
    for marker in (
        "21 independent browser actors",
        "nine original reviewers",
        "nine fresh appeal reviewers",
        "negative-post-id",
        "scripts/run_m3_complete_closure.sh",
        "WEALL_M3_CIVIC_GOVERNANCE_STRICT=1",
        "controlled-testnet-aggregate-v1",
        "check_m3_evidence_only_commit.sh --cached",
        "direct child of the implementation freeze",
    ):
        assert marker in source
    assert "git add artifacts/m3-closure" in source
    assert "recovery files, private keys, mnemonics" in source


def test_observer_authority_contract_is_runtime_bound() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    freeze = "f" * 40
    tree = "e" * 40
    value = {
        "schema_version": 1,
        "implementation_freeze_commit": freeze,
        "implementation_tree": tree,
        "mode": "observer",
        "chain_id": "weall-m3",
        "height": 7,
        "node_id": "observer-1",
        "authority_absent": True,
        "authority_checks": {
            "local_is_active_validator": True,
            "local_is_expected_leader": True,
            "validator_active": True,
            "bft_enabled_effective": True,
            "validator_signing_enabled": True,
            "validator_effective": True,
            "helper_effective": True,
        },
    }
    summary = contract.validate_observer_authority(value, freeze=freeze, tree=tree)
    assert summary["authority_absent"] is True
    broken = json.loads(json.dumps(value))
    broken["authority_checks"]["validator_effective"] = False
    import pytest
    with pytest.raises(ValueError, match="observer_authority_checks_invalid"):
        contract.validate_observer_authority(broken, freeze=freeze, tree=tree)


def test_live_ballot_profile_contract_requires_strict_controlled_testnet() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    freeze = "f" * 40
    tree = "a" * 40
    value = {
        "schema_version": 1,
        "implementation_freeze_commit": freeze,
        "implementation_tree": tree,
        "ok": True,
        "ballot_profile": {
            "profile_id": "controlled-testnet-aggregate-v1",
            "active": True,
            "strict": True,
            "mode": "controlled-testnet",
            "reason": "active_controlled_testnet_profile",
        },
    }
    assert contract.validate_live_ballot_profile(value, freeze=freeze, tree=tree)["active"] is True
    value["ballot_profile"]["strict"] = False
    import pytest
    with pytest.raises(ValueError, match="live_ballot_profile_not_strict_active"):
        contract.validate_live_ballot_profile(value, freeze=freeze, tree=tree)


def test_transaction_contract_rejects_uncompleted_templates() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import m3_evidence_contract as contract

    freeze = "f" * 40
    actors = [
        {"role": "author_proposer", "account": "@author"},
        {"role": "member_reporter_voter", "account": "@member"},
        {"role": "nonmember_ineligible", "account": "@outsider"},
    ]
    actors.extend(
        {"role": f"reviewer_original_{index:02d}", "account": f"@original{index:02d}"}
        for index in range(1, 10)
    )
    actors.extend(
        {"role": f"reviewer_appeal_{index:02d}", "account": f"@appeal{index:02d}"}
        for index in range(1, 10)
    )
    manifest = {
        "schema_version": 3,
        "implementation_freeze_commit": freeze,
        "actors": actors,
        "reviewer_count": 18,
        "journey": {
            "post_id": "post:main",
            "group_id": "group:main",
            "group_post_id": "post:group",
            "dispute_id": "dispute:main",
            "proposal_id": "proposal:main",
            "negative_post_id": "post:negative",
            "negative_group_id": "group:negative",
            "negative_dispute_id": "dispute:negative",
            "negative_proposal_id": "proposal:negative",
        },
    }
    transcript = {
        "schema_version": 1,
        "implementation_freeze_commit": freeze,
        "chain_id": "REPLACE_WITH_LIVE_CHAIN_ID",
        "actions": [],
        "negative_attempts": [],
        "template_notice": "not complete",
    }
    import pytest
    with pytest.raises(ValueError, match="transaction_transcript_template_not_completed"):
        contract.validate_public_actor_transcript(manifest, transcript, freeze=freeze)
