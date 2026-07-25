from __future__ import annotations

import re

ARTIFACT_ROOT = "artifacts/m3-closure"
MILESTONE = "R-M3 controlled-testnet civic closure"
TRUTH_BOUNDARY = (
    "Controlled-testnet signed content, public-group, dispute/review/appeal, and "
    "no-action civic-governance finalization only; no public-beta, Mainnet, "
    "executable-governance, emergency-governance, economics, or validator-launch claim."
)

REQUIRED_GATES = (
    "dependency preflight",
    "M3 requirement traceability",
    "v1.5 readiness artifacts current",
    "v2 specification derivatives current",
    "governance execution vectors current",
    "clean checkout reproduction",
    "M3 runtime regression suite",
    "M3 persistence replay and convergence",
    "helper serial equivalence and fallback",
    "full backend suite",
    "frontend public social source",
    "frontend group flow source",
    "frontend public-only protocol source",
    "frontend account profile source",
    "frontend first-run source",
    "frontend governance source",
    "frontend dispute source",
    "frontend contract check",
    "frontend production safety check",
    "frontend typecheck",
    "frontend production build",
    "M3 strict live ballot profile",
    "M3 signed real-stack actor journey",
    "M3 restart replay equality",
    "M3 two-node equality",
    "M3 observer catch-up without authority",
    "M3 artifact privacy scan",
)

REQUIRED_PREFIXES = (
    f"{ARTIFACT_ROOT}/backend/",
    f"{ARTIFACT_ROOT}/frontend/",
    f"{ARTIFACT_ROOT}/browser/civic/",
    f"{ARTIFACT_ROOT}/restart-replay/",
    f"{ARTIFACT_ROOT}/two-node/",
    f"{ARTIFACT_ROOT}/observer/",
    f"{ARTIFACT_ROOT}/privacy/",
)

REQUIRED_EXACT_PATHS = (
    f"{ARTIFACT_ROOT}/gate-results.tsv",
    f"{ARTIFACT_ROOT}/backend/live-ballot-profile.json",
    f"{ARTIFACT_ROOT}/M3_ACTOR_MANIFEST.json",
    f"{ARTIFACT_ROOT}/browser/civic/transaction-transcript.json",
    f"{ARTIFACT_ROOT}/restart-replay/final-state.json",
    f"{ARTIFACT_ROOT}/two-node/final-state.json",
    f"{ARTIFACT_ROOT}/observer/final-state.json",
    f"{ARTIFACT_ROOT}/observer/authority.json",
    f"{ARTIFACT_ROOT}/privacy/private-material-scan.json",
)

STATE_SUMMARY_PATHS = {
    "restart_replay": f"{ARTIFACT_ROOT}/restart-replay/final-state.json",
    "two_node": f"{ARTIFACT_ROOT}/two-node/final-state.json",
    "observer": f"{ARTIFACT_ROOT}/observer/final-state.json",
}

ACTOR_MANIFEST_PATH = f"{ARTIFACT_ROOT}/M3_ACTOR_MANIFEST.json"
TRANSACTION_TRANSCRIPT_PATH = f"{ARTIFACT_ROOT}/browser/civic/transaction-transcript.json"
PRIVACY_REPORT_PATH = f"{ARTIFACT_ROOT}/privacy/private-material-scan.json"
OBSERVER_AUTHORITY_PATH = f"{ARTIFACT_ROOT}/observer/authority.json"
LIVE_BALLOT_PROFILE_PATH = f"{ARTIFACT_ROOT}/backend/live-ballot-profile.json"

# Markers are deliberately written as byte fragments so both the builder and
# the committed-evidence checker use the same fail-closed vocabulary.
PRIVATE_MARKERS = (
    b"-----begin private key-----",
    b"-----begin openssh private key-----",
    b"-----begin rsa private key-----",
    b"-----begin ec private key-----",
    b'"private_key"',
    b'"private_key_hex"',
    b'"secret_key"',
    b'"secretkey"',
    b'"secretkeyb64"',
    b'"recovery_phrase"',
    b'"seed_phrase"',
    b'"mnemonic"',
    b'"recovery_file"',
    b'"sessionkey"',
    b'"session_key"',
    b"weall_kp_v1::",
    b"weall_recovery_key",
)

SENSITIVE_PATTERNS = (
    re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----", re.I),
    re.compile(rb'"(?:private[_-]?key(?:_hex)?|secret[_-]?key(?:b64)?|seed[_-]?phrase|mnemonic|session[_-]?key|recovery[_-]?file)"\s*:\s*"?[^"\s,}]{8,}', re.I),
    re.compile(rb'"(?:authorization|cookie)"\s*:\s*"[^"\r\n]{8,}"', re.I),
    re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+", re.I),
    re.compile(rb"(?:session|api|access|bearer)[_-]?token\s*[=:]\s*[A-Za-z0-9._~+/=-]{16,}", re.I),
    re.compile(rb"weall_kp_v1::", re.I),
)


def private_material_findings(data: bytes) -> list[str]:
    lower = data.lower()
    findings: list[str] = []
    for marker in PRIVATE_MARKERS:
        if marker.lower() in lower:
            findings.append(f"marker:{marker.decode('utf-8', errors='replace')}")
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(data):
            findings.append(f"pattern:{pattern.pattern.decode('utf-8', errors='replace')}")
    return sorted(set(findings))


def validate_live_ballot_profile(
    value: dict,
    *,
    freeze: str,
    tree: str,
) -> dict:
    if value.get("schema_version") != 1 or value.get("ok") is not True:
        raise ValueError("live_ballot_profile_schema_or_status_invalid")
    if value.get("implementation_freeze_commit") != freeze:
        raise ValueError("live_ballot_profile_freeze_mismatch")
    if value.get("implementation_tree") != tree:
        raise ValueError("live_ballot_profile_tree_mismatch")
    profile = value.get("ballot_profile")
    if not isinstance(profile, dict):
        raise ValueError("live_ballot_profile_missing")
    expected = {
        "profile_id": "controlled-testnet-aggregate-v1",
        "active": True,
        "strict": True,
        "mode": "controlled-testnet",
        "reason": "active_controlled_testnet_profile",
    }
    actual = {key: profile.get(key) for key in expected}
    if actual != expected:
        raise ValueError("live_ballot_profile_not_strict_active")
    return actual

REQUIRED_ACTION_LABELS = {
    "post_create",
    "group_create",
    "membership_request",
    "membership_accept",
    "group_post_create",
    "content_report",
    "original_panel_acceptance",
    "original_panel_attendance",
    "original_panel_ballots",
    "dispute_resolution",
    "appeal_open",
    "appeal_panel_acceptance",
    "appeal_panel_attendance",
    "appeal_panel_ballots",
    "appeal_final_receipt",
    "proposal_create",
    "proposal_comment",
    "eligible_ballots",
    "voting_close",
    "tally_publish",
    "proposal_finalization",
}

REQUIRED_NEGATIVE_LABELS = {
    "nonmember_group_write_rejected",
    "nonselected_reviewer_vote_rejected",
    "conflicted_reviewer_vote_rejected",
    "ineligible_governance_vote_rejected",
    "duplicate_governance_vote_rejected",
    "replacement_governance_vote_rejected",
    "governance_revoke_rejected",
    "duplicate_dispute_ballot_rejected",
    "replacement_dispute_ballot_rejected",
    "dispute_revoke_rejected",
}


ACTION_TX_TYPES = {
    "post_create": {"CONTENT_POST_CREATE"},
    "group_create": {"GROUP_CREATE"},
    "membership_request": {"GROUP_MEMBERSHIP_REQUEST"},
    "membership_accept": {"GROUP_MEMBERSHIP_DECIDE"},
    "group_post_create": {"CONTENT_POST_CREATE"},
    "content_report": {"CONTENT_FLAG"},
    "original_panel_acceptance": {"DISPUTE_JUROR_ACCEPT"},
    "original_panel_attendance": {"DISPUTE_JUROR_ATTENDANCE"},
    "original_panel_ballots": {"DISPUTE_VOTE_SUBMIT"},
    "dispute_resolution": {"DISPUTE_RESOLVE"},
    "appeal_open": {"DISPUTE_APPEAL"},
    "appeal_panel_acceptance": {"DISPUTE_JUROR_ACCEPT"},
    "appeal_panel_attendance": {"DISPUTE_JUROR_ATTENDANCE"},
    "appeal_panel_ballots": {"DISPUTE_VOTE_SUBMIT"},
    "appeal_final_receipt": {"DISPUTE_FINAL_RECEIPT"},
    "proposal_create": {"GOV_PROPOSAL_CREATE"},
    "proposal_comment": {"GOV_PROPOSAL_COMMENT"},
    "eligible_ballots": {"GOV_VOTE_CAST"},
    "voting_close": {"GOV_VOTING_CLOSE"},
    "tally_publish": {"GOV_TALLY_PUBLISH"},
    "proposal_finalization": {"GOV_PROPOSAL_FINALIZE"},
}

ACTION_MIN_COUNTS = {
    **{label: 1 for label in REQUIRED_ACTION_LABELS},
    "original_panel_acceptance": 7,
    "original_panel_attendance": 7,
    "original_panel_ballots": 7,
    "appeal_panel_acceptance": 7,
    "appeal_panel_attendance": 7,
    "appeal_panel_ballots": 7,
    "eligible_ballots": 2,
}

SYSTEM_ACTION_LABELS = {
    "dispute_resolution",
    "appeal_final_receipt",
    "voting_close",
    "tally_publish",
    "proposal_finalization",
}

NEGATIVE_TX_TYPES = {
    "nonmember_group_write_rejected": {"CONTENT_POST_CREATE"},
    "nonselected_reviewer_vote_rejected": {"DISPUTE_VOTE_SUBMIT"},
    "conflicted_reviewer_vote_rejected": {"DISPUTE_VOTE_SUBMIT"},
    "ineligible_governance_vote_rejected": {"GOV_VOTE_CAST"},
    "duplicate_governance_vote_rejected": {"GOV_VOTE_CAST"},
    "replacement_governance_vote_rejected": {"GOV_VOTE_CAST"},
    "governance_revoke_rejected": {"GOV_VOTE_REVOKE"},
    "duplicate_dispute_ballot_rejected": {"DISPUTE_VOTE_SUBMIT"},
    "replacement_dispute_ballot_rejected": {"DISPUTE_VOTE_SUBMIT"},
    "dispute_revoke_rejected": {"DISPUTE_VOTE_REVOKE"},
}

EXPECTED_NEGATIVE_ERROR_CODES = {
    "nonmember_group_write_rejected": "group_post_authority_required",
    "nonselected_reviewer_vote_rejected": "juror_not_assigned",
    "conflicted_reviewer_vote_rejected": "juror_conflict_target_owner",
    "ineligible_governance_vote_rejected": "governance_vote_requires_active_round_member",
    "duplicate_governance_vote_rejected": "ballot_already_final",
    "replacement_governance_vote_rejected": "ballot_already_final",
    "governance_revoke_rejected": "ballot_revocation_forbidden",
    "duplicate_dispute_ballot_rejected": "dispute_ballot_already_final",
    "replacement_dispute_ballot_rejected": "dispute_ballot_already_final",
    "dispute_revoke_rejected": "unknown_tx_type",
}

REQUIRED_HUMAN_ROLES = {
    "author_proposer",
    "member_reporter_voter",
    "nonmember_ineligible",
}

ORIGINAL_REVIEWER_ROLE_PREFIX = "reviewer_original_"
APPEAL_REVIEWER_ROLE_PREFIX = "reviewer_appeal_"
MIN_REVIEWERS_PER_PANEL_POOL = 9


def role_allowed_for_action(label: str, role: str, account: str) -> bool:
    if label in SYSTEM_ACTION_LABELS:
        return role == "system_scheduler" and account == "SYSTEM"
    if label in {"post_create", "group_create", "membership_accept", "proposal_create"}:
        return role == "author_proposer"
    if label in {"membership_request", "group_post_create", "content_report", "appeal_open", "proposal_comment"}:
        return role == "member_reporter_voter"
    if label == "eligible_ballots":
        return role in {"author_proposer", "member_reporter_voter"}
    if label.startswith("original_panel_"):
        return role.startswith(ORIGINAL_REVIEWER_ROLE_PREFIX)
    if label.startswith("appeal_panel_"):
        return role.startswith(APPEAL_REVIEWER_ROLE_PREFIX)
    return False


def role_allowed_for_negative(label: str, role: str) -> bool:
    if label == "nonmember_group_write_rejected":
        return role == "nonmember_ineligible"
    if label == "conflicted_reviewer_vote_rejected":
        return role in {"author_proposer", "member_reporter_voter"}
    if label == "ineligible_governance_vote_rejected":
        return role == "nonmember_ineligible"
    if label in {
        "duplicate_governance_vote_rejected",
        "replacement_governance_vote_rejected",
        "governance_revoke_rejected",
    }:
        return role in {"author_proposer", "member_reporter_voter"}
    if label == "nonselected_reviewer_vote_rejected":
        return role.startswith(APPEAL_REVIEWER_ROLE_PREFIX) or role.startswith(ORIGINAL_REVIEWER_ROLE_PREFIX)
    if label in {
        "duplicate_dispute_ballot_rejected",
        "replacement_dispute_ballot_rejected",
        "dispute_revoke_rejected",
    }:
        return role.startswith(ORIGINAL_REVIEWER_ROLE_PREFIX) or role.startswith(APPEAL_REVIEWER_ROLE_PREFIX)
    return False


def validate_public_actor_transcript(actor_manifest: dict, transcript: dict, *, freeze: str) -> dict:
    if actor_manifest.get("schema_version") != 3:
        raise ValueError("actor_manifest_schema_mismatch")
    if str(actor_manifest.get("implementation_freeze_commit") or "") != freeze:
        raise ValueError("actor_manifest_freeze_mismatch")
    actors = actor_manifest.get("actors")
    if not isinstance(actors, list) or not actors:
        raise ValueError("actor_manifest_actors_missing")
    role_to_account: dict[str, str] = {}
    accounts: set[str] = set()
    for item in actors:
        if not isinstance(item, dict):
            raise ValueError("actor_manifest_actor_invalid")
        role = str(item.get("role") or "").strip()
        account = str(item.get("account") or "").strip()
        if not role or not account or role in role_to_account or account in accounts:
            raise ValueError("actor_manifest_identity_set_invalid")
        role_to_account[role] = account
        accounts.add(account)
    if not REQUIRED_HUMAN_ROLES.issubset(role_to_account):
        raise ValueError("actor_manifest_required_roles_missing")
    original_reviewers = sum(role.startswith(ORIGINAL_REVIEWER_ROLE_PREFIX) for role in role_to_account)
    appeal_reviewers = sum(role.startswith(APPEAL_REVIEWER_ROLE_PREFIX) for role in role_to_account)
    if original_reviewers < MIN_REVIEWERS_PER_PANEL_POOL or appeal_reviewers < MIN_REVIEWERS_PER_PANEL_POOL:
        raise ValueError("actor_manifest_reviewer_partition_invalid")
    if int(actor_manifest.get("reviewer_count") or 0) != original_reviewers + appeal_reviewers:
        raise ValueError("actor_manifest_reviewer_count_mismatch")

    if transcript.get("schema_version") != 1:
        raise ValueError("transaction_transcript_schema_mismatch")
    if str(transcript.get("implementation_freeze_commit") or "") != freeze:
        raise ValueError("transaction_transcript_freeze_mismatch")
    chain_id = str(transcript.get("chain_id") or "").strip()
    if not chain_id:
        raise ValueError("transaction_transcript_chain_id_missing")
    if chain_id.startswith("REPLACE_") or "template_notice" in transcript:
        raise ValueError("transaction_transcript_template_not_completed")

    journey = actor_manifest.get("journey")
    if not isinstance(journey, dict):
        raise ValueError("actor_manifest_journey_missing")
    for field in (set(MAIN_ACTION_SUBJECT_FIELD.values()) | set(NEGATIVE_SUBJECT_FIELD.values()) | {"negative_post_id"}):
        if not str(journey.get(field) or "").strip():
            raise ValueError(f"actor_manifest_journey_field_missing:{field}")
    if str(journey["negative_dispute_id"]) == str(journey["dispute_id"]):
        raise ValueError("negative_dispute_fixture_not_distinct")
    if str(journey["negative_proposal_id"]) == str(journey["proposal_id"]):
        raise ValueError("negative_proposal_fixture_not_distinct")

    actions = transcript.get("actions")
    negatives = transcript.get("negative_attempts")
    if not isinstance(actions, list) or not isinstance(negatives, list):
        raise ValueError("transaction_transcript_lists_missing")

    action_counts: dict[str, int] = {}
    main_action_counts: dict[str, int] = {}
    tx_ids: set[str] = set()
    action_by_tx_id: dict[str, dict] = {}
    for raw in actions:
        if not isinstance(raw, dict):
            raise ValueError("transaction_action_invalid")
        label = str(raw.get("label") or "").strip()
        tx_id = str(raw.get("tx_id") or "").strip()
        tx_type = str(raw.get("tx_type") or "").strip()
        role = str(raw.get("role") or "").strip()
        account = str(raw.get("account") or "").strip()
        subject_id = str(raw.get("subject_id") or "").strip()
        if label not in REQUIRED_ACTION_LABELS:
            raise ValueError(f"transaction_action_label_unknown:{label}")
        if not tx_id or tx_id.startswith("REPLACE_") or tx_id in tx_ids or not subject_id:
            raise ValueError(f"transaction_action_tx_id_or_subject_invalid:{tx_id}:{subject_id}")
        tx_ids.add(tx_id)
        action_by_tx_id[tx_id] = raw
        if tx_type not in ACTION_TX_TYPES[label]:
            raise ValueError(f"transaction_action_tx_type_invalid:{label}:{tx_type}")
        if raw.get("status") != "confirmed":
            raise ValueError(f"transaction_action_not_confirmed:{label}")
        if label in SYSTEM_ACTION_LABELS:
            if role != "system_scheduler" or account != "SYSTEM":
                raise ValueError(f"transaction_system_identity_invalid:{label}")
        else:
            if role_to_account.get(role) != account:
                raise ValueError(f"transaction_action_actor_binding_invalid:{label}:{role}")
            if not role_allowed_for_action(label, role, account):
                raise ValueError(f"transaction_action_role_invalid:{label}:{role}")
        action_counts[label] = action_counts.get(label, 0) + 1
        expected_main_subject = str(journey.get(MAIN_ACTION_SUBJECT_FIELD[label]) or "")
        if subject_id == expected_main_subject:
            main_action_counts[label] = main_action_counts.get(label, 0) + 1
    for label, minimum in ACTION_MIN_COUNTS.items():
        if main_action_counts.get(label, 0) < minimum:
            raise ValueError(
                f"transaction_main_action_count_low:{label}:"
                f"{main_action_counts.get(label, 0)}:{minimum}"
            )

    negative_labels: set[str] = set()
    for raw in negatives:
        if not isinstance(raw, dict):
            raise ValueError("transaction_negative_invalid")
        label = str(raw.get("label") or "").strip()
        tx_type = str(raw.get("tx_type") or "").strip()
        role = str(raw.get("role") or "").strip()
        account = str(raw.get("account") or "").strip()
        error_code = str(raw.get("expected_error_code") or "").strip()
        subject_id = str(raw.get("subject_id") or "").strip()
        if label not in REQUIRED_NEGATIVE_LABELS or label in negative_labels:
            raise ValueError(f"transaction_negative_label_invalid:{label}")
        negative_labels.add(label)
        expected_subject = str(journey.get(NEGATIVE_SUBJECT_FIELD[label]) or "")
        if not subject_id or subject_id != expected_subject:
            raise ValueError(f"transaction_negative_subject_invalid:{label}:{subject_id}:{expected_subject}")
        if tx_type not in NEGATIVE_TX_TYPES[label]:
            raise ValueError(f"transaction_negative_tx_type_invalid:{label}:{tx_type}")
        if error_code != EXPECTED_NEGATIVE_ERROR_CODES[label]:
            raise ValueError(f"transaction_negative_error_invalid:{label}:{error_code}")
        if role_to_account.get(role) != account:
            raise ValueError(f"transaction_negative_actor_binding_invalid:{label}:{role}")
        if not role_allowed_for_negative(label, role):
            raise ValueError(f"transaction_negative_role_invalid:{label}:{role}")
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            raise ValueError(f"transaction_negative_payload_invalid:{label}")
        if label == "nonmember_group_write_rejected":
            payload_group = str(payload.get("group_id") or "")
            tags = payload.get("tags") if isinstance(payload.get("tags"), list) else []
            if payload_group != subject_id and f"group:{subject_id}" not in {str(item) for item in tags}:
                raise ValueError(f"transaction_negative_group_payload_unbound:{label}")
        elif "governance" in label:
            if str(payload.get("proposal_id") or "") != subject_id:
                raise ValueError(f"transaction_negative_proposal_payload_unbound:{label}")
        else:
            if str(payload.get("dispute_id") or "") != subject_id:
                raise ValueError(f"transaction_negative_dispute_payload_unbound:{label}")
        required_type = PRECONDITION_REQUIRED_NEGATIVES.get(label)
        if required_type:
            prior_id = str(raw.get("precondition_tx_id") or "").strip()
            prior = action_by_tx_id.get(prior_id)
            if not prior:
                raise ValueError(f"transaction_negative_precondition_missing:{label}:{prior_id}")
            if (
                str(prior.get("tx_type") or "") != required_type
                or str(prior.get("account") or "") != account
                or str(prior.get("subject_id") or "") != subject_id
            ):
                raise ValueError(f"transaction_negative_precondition_invalid:{label}:{prior_id}")
    if negative_labels != REQUIRED_NEGATIVE_LABELS:
        raise ValueError("transaction_negative_set_mismatch")

    return {
        "actor_count": len(actors),
        "reviewer_count": original_reviewers + appeal_reviewers,
        "original_reviewer_pool": original_reviewers,
        "appeal_reviewer_pool": appeal_reviewers,
        "action_count": len(actions),
        "negative_attempt_count": len(negatives),
        "chain_id": chain_id,
        "journey": actor_manifest.get("journey"),
    }

MAIN_ACTION_SUBJECT_FIELD = {
    "post_create": "post_id",
    "group_create": "group_id",
    "membership_request": "group_id",
    "membership_accept": "group_id",
    "group_post_create": "group_post_id",
    "content_report": "post_id",
    "original_panel_acceptance": "dispute_id",
    "original_panel_attendance": "dispute_id",
    "original_panel_ballots": "dispute_id",
    "dispute_resolution": "dispute_id",
    "appeal_open": "dispute_id",
    "appeal_panel_acceptance": "dispute_id",
    "appeal_panel_attendance": "dispute_id",
    "appeal_panel_ballots": "dispute_id",
    "appeal_final_receipt": "dispute_id",
    "proposal_create": "proposal_id",
    "proposal_comment": "proposal_id",
    "eligible_ballots": "proposal_id",
    "voting_close": "proposal_id",
    "tally_publish": "proposal_id",
    "proposal_finalization": "proposal_id",
}

NEGATIVE_SUBJECT_FIELD = {
    "nonmember_group_write_rejected": "negative_group_id",
    "nonselected_reviewer_vote_rejected": "negative_dispute_id",
    "conflicted_reviewer_vote_rejected": "negative_dispute_id",
    "ineligible_governance_vote_rejected": "negative_proposal_id",
    "duplicate_governance_vote_rejected": "negative_proposal_id",
    "replacement_governance_vote_rejected": "negative_proposal_id",
    "governance_revoke_rejected": "negative_proposal_id",
    "duplicate_dispute_ballot_rejected": "negative_dispute_id",
    "replacement_dispute_ballot_rejected": "negative_dispute_id",
    "dispute_revoke_rejected": "negative_dispute_id",
}

PRECONDITION_REQUIRED_NEGATIVES = {
    "duplicate_governance_vote_rejected": "GOV_VOTE_CAST",
    "replacement_governance_vote_rejected": "GOV_VOTE_CAST",
    "governance_revoke_rejected": "GOV_VOTE_CAST",
    "duplicate_dispute_ballot_rejected": "DISPUTE_VOTE_SUBMIT",
    "replacement_dispute_ballot_rejected": "DISPUTE_VOTE_SUBMIT",
    "dispute_revoke_rejected": "DISPUTE_VOTE_SUBMIT",
}


def validate_observer_authority(value: dict, *, freeze: str, tree: str) -> dict:
    if value.get("schema_version") != 1:
        raise ValueError("observer_authority_schema_invalid")
    if value.get("implementation_freeze_commit") != freeze or value.get("implementation_tree") != tree:
        raise ValueError("observer_authority_freeze_mismatch")
    if value.get("mode") != "observer" or value.get("authority_absent") is not True:
        raise ValueError("observer_authority_posture_invalid")
    checks = value.get("authority_checks")
    required = {
        "local_is_active_validator",
        "local_is_expected_leader",
        "validator_active",
        "bft_enabled_effective",
        "validator_signing_enabled",
        "validator_effective",
        "helper_effective",
    }
    if not isinstance(checks, dict) or set(checks) != required or any(checks.get(name) is not True for name in required):
        raise ValueError("observer_authority_checks_invalid")
    if not str(value.get("chain_id") or "").strip():
        raise ValueError("observer_authority_chain_id_missing")
    return {
        "mode": "observer",
        "chain_id": str(value.get("chain_id")),
        "height": int(value.get("height") or 0),
        "node_id": str(value.get("node_id") or ""),
        "authority_absent": True,
        "authority_checks": {name: True for name in sorted(required)},
    }
