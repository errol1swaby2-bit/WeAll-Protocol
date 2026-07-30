#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from m3_evidence_contract import (
    ACTION_MIN_COUNTS,
    ACTION_TX_TYPES,
    EMBEDDED_ATTENDANCE_EVIDENCE_KIND,
    EMBEDDED_ATTENDANCE_LABELS,
    APPEAL_REVIEWER_ROLE_PREFIX,
    action_requires_manifest_actor_binding,
    EXPECTED_NEGATIVE_ERROR_CODES,
    MIN_REVIEWERS_PER_PANEL_POOL,
    NEGATIVE_TX_TYPES,
    ORIGINAL_REVIEWER_ROLE_PREFIX,
    REQUIRED_ACTION_LABELS,
    REQUIRED_HUMAN_ROLES,
    REQUIRED_NEGATIVE_LABELS,
    SYSTEM_ACTION_LABELS,
    role_allowed_for_action,
    role_allowed_for_negative,
    validate_embedded_attendance_pairs,
    validate_public_actor_transcript,
)

ROOT = Path(__file__).resolve().parents[1]
ROLE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
ACCOUNT_RE = re.compile(r"^@[a-z0-9_]{1,32}$")


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"m3_actor_invalid_json:{label}:{path}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"m3_actor_not_object:{label}:{path}")
    return value


def _required_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise SystemExit(f"m3_actor_required_text_missing:{label}")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--implementation-freeze", required=True)
    parser.add_argument("--out-public-manifest", required=True)
    parser.add_argument("--out-transcript", required=True)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = _load(manifest_path, "manifest")
    if manifest.get("schema_version") != 3:
        raise SystemExit("m3_actor_manifest_schema_mismatch")
    if any(key in manifest for key in ("recovery_file", "private_key", "secret_key", "mnemonic")):
        raise SystemExit("m3_actor_manifest_private_field_forbidden")

    freeze = _required_text(args.implementation_freeze, "implementation_freeze")
    if _required_text(manifest.get("implementation_freeze_commit"), "manifest.implementation_freeze_commit") != freeze:
        raise SystemExit("m3_actor_manifest_freeze_mismatch")
    backend = _required_text(manifest.get("backend_base_url"), "manifest.backend_base_url")
    if not re.fullmatch(r"http://127\.0\.0\.1:\d+", backend.rstrip("/")):
        raise SystemExit("m3_actor_backend_must_be_loopback_http")

    actors_raw = manifest.get("actors")
    if not isinstance(actors_raw, list):
        raise SystemExit("m3_actor_manifest_actors_not_list")
    actors: list[dict[str, str]] = []
    accounts: set[str] = set()
    roles: set[str] = set()
    reviewers = 0
    for index, raw in enumerate(actors_raw):
        if not isinstance(raw, dict):
            raise SystemExit(f"m3_actor_invalid_actor:{index}")
        if any(key in raw for key in ("recovery_file", "recovery", "private_key", "secret_key", "mnemonic")):
            raise SystemExit(f"m3_actor_private_field_forbidden:{index}")
        role = _required_text(raw.get("role"), f"actors[{index}].role")
        account = _required_text(raw.get("account"), f"actors[{index}].account")
        storage = Path(_required_text(raw.get("storage_state"), f"actors[{index}].storage_state")).expanduser().resolve()
        signer = Path(_required_text(raw.get("signer_state"), f"actors[{index}].signer_state")).expanduser().resolve()
        if not ROLE_RE.fullmatch(role):
            raise SystemExit(f"m3_actor_invalid_role:{role}")
        if not ACCOUNT_RE.fullmatch(account):
            raise SystemExit(f"m3_actor_invalid_account:{account}")
        if role in roles or account in accounts:
            raise SystemExit(f"m3_actor_duplicate_identity:{role}:{account}")
        if not storage.is_file() or storage.is_symlink():
            raise SystemExit(f"m3_actor_storage_state_missing_or_symlink:{storage}")
        if not signer.is_file() or signer.is_symlink():
            raise SystemExit(f"m3_actor_signer_state_missing_or_symlink:{signer}")
        try:
            signer_payload = json.loads(signer.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"m3_actor_signer_state_invalid_json:{signer}") from exc
        if not isinstance(signer_payload, dict) or signer_payload.get("schema_version") != 1:
            raise SystemExit(f"m3_actor_signer_state_schema_invalid:{signer}")
        if _required_text(signer_payload.get("account"), f"actors[{index}].signer_state.account") != account:
            raise SystemExit(f"m3_actor_signer_state_account_mismatch:{signer}")
        _required_text(signer_payload.get("secretKeyB64"), f"actors[{index}].signer_state.secretKeyB64")
        roles.add(role)
        accounts.add(account)
        if role.startswith("reviewer"):
            reviewers += 1
        actors.append({"role": role, "account": account})

    missing_roles = REQUIRED_HUMAN_ROLES - roles
    if missing_roles:
        raise SystemExit(f"m3_actor_roles_missing:{sorted(missing_roles)}")
    original_reviewers = sum(role.startswith(ORIGINAL_REVIEWER_ROLE_PREFIX) for role in roles)
    appeal_reviewers = sum(role.startswith(APPEAL_REVIEWER_ROLE_PREFIX) for role in roles)
    if original_reviewers < MIN_REVIEWERS_PER_PANEL_POOL or appeal_reviewers < MIN_REVIEWERS_PER_PANEL_POOL:
        raise SystemExit(
            "m3_actor_reviewer_pool_partition_invalid:"
            f"original={original_reviewers}:appeal={appeal_reviewers}:"
            f"required_each={MIN_REVIEWERS_PER_PANEL_POOL}"
        )
    reviewers = original_reviewers + appeal_reviewers

    journey = manifest.get("journey")
    if not isinstance(journey, dict):
        raise SystemExit("m3_actor_journey_not_object")
    journey_public: dict[str, Any] = {}
    for field in (
        "post_id",
        "group_id",
        "group_post_id",
        "dispute_id",
        "proposal_id",
        "negative_post_id",
        "negative_group_id",
        "negative_dispute_id",
        "negative_proposal_id",
    ):
        journey_public[field] = _required_text(journey.get(field), f"journey.{field}")

    transcript_path = Path(_required_text(journey.get("transaction_transcript"), "journey.transaction_transcript")).expanduser().resolve()
    if not transcript_path.is_file() or transcript_path.is_symlink():
        raise SystemExit(f"m3_actor_transcript_missing_or_symlink:{transcript_path}")
    transcript = _load(transcript_path, "transcript")
    if transcript.get("schema_version") != 1:
        raise SystemExit("m3_actor_transcript_schema_mismatch")
    if _required_text(transcript.get("implementation_freeze_commit"), "transcript.implementation_freeze_commit") != freeze:
        raise SystemExit("m3_actor_transcript_freeze_mismatch")
    _required_text(transcript.get("chain_id"), "transcript.chain_id")

    actions = transcript.get("actions")
    if not isinstance(actions, list) or not actions:
        raise SystemExit("m3_actor_transcript_actions_missing")
    action_counts: dict[str, int] = {}
    for index, raw in enumerate(actions):
        if not isinstance(raw, dict):
            raise SystemExit(f"m3_actor_transcript_action_invalid:{index}")
        label = _required_text(raw.get("label"), f"actions[{index}].label")
        if label not in REQUIRED_ACTION_LABELS:
            raise SystemExit(f"m3_actor_transcript_action_label_unknown:{label}")
        tx_id = _required_text(raw.get("tx_id"), f"actions[{index}].tx_id")
        tx_type = _required_text(raw.get("tx_type"), f"actions[{index}].tx_type")
        account = _required_text(raw.get("account"), f"actions[{index}].account")
        role = _required_text(raw.get("role"), f"actions[{index}].role")
        if (
            label in EMBEDDED_ATTENDANCE_LABELS
            and raw.get("evidence_kind") != EMBEDDED_ATTENDANCE_EVIDENCE_KIND
        ):
            raise SystemExit(f"m3_actor_transcript_attendance_evidence_kind_invalid:{tx_id}")
        if tx_type not in ACTION_TX_TYPES[label]:
            raise SystemExit(f"m3_actor_transcript_action_tx_type_invalid:{label}:{tx_type}")
        if raw.get("status") != "confirmed":
            raise SystemExit(f"m3_actor_transcript_action_not_confirmed:{label}")
        if label in SYSTEM_ACTION_LABELS:
            if role != "system_scheduler" or account != "SYSTEM":
                raise SystemExit(f"m3_actor_transcript_system_action_identity_invalid:{label}:{role}:{account}")
        else:
            if not role_allowed_for_action(label, role, account):
                raise SystemExit(f"m3_actor_transcript_action_role_invalid:{label}:{role}")
            if (
                action_requires_manifest_actor_binding(label, role, account)
                and (account not in accounts or role not in roles)
            ):
                raise SystemExit(f"m3_actor_transcript_action_actor_unknown:{label}")
        action_counts[label] = action_counts.get(label, 0) + 1
    try:
        validate_embedded_attendance_pairs(actions)
    except ValueError as exc:
        raise SystemExit(f"m3_actor_transcript_{exc}") from exc
    for label, minimum in ACTION_MIN_COUNTS.items():
        if action_counts.get(label, 0) < minimum:
            raise SystemExit(f"m3_actor_transcript_action_count_low:{label}:{action_counts.get(label, 0)}:required={minimum}")

    negatives = transcript.get("negative_attempts")
    if not isinstance(negatives, list) or not negatives:
        raise SystemExit("m3_actor_transcript_negative_attempts_missing")
    negative_labels: set[str] = set()
    for index, raw in enumerate(negatives):
        if not isinstance(raw, dict):
            raise SystemExit(f"m3_actor_negative_invalid:{index}")
        label = _required_text(raw.get("label"), f"negative_attempts[{index}].label")
        if label not in REQUIRED_NEGATIVE_LABELS or label in negative_labels:
            raise SystemExit(f"m3_actor_negative_label_invalid_or_duplicate:{label}")
        negative_labels.add(label)
        tx_type = _required_text(raw.get("tx_type"), f"negative_attempts[{index}].tx_type")
        account = _required_text(raw.get("account"), f"negative_attempts[{index}].account")
        role = _required_text(raw.get("role"), f"negative_attempts[{index}].role")
        error_code = _required_text(raw.get("expected_error_code"), f"negative_attempts[{index}].expected_error_code")
        if tx_type not in NEGATIVE_TX_TYPES[label]:
            raise SystemExit(f"m3_actor_negative_tx_type_invalid:{label}:{tx_type}")
        if error_code != EXPECTED_NEGATIVE_ERROR_CODES[label]:
            raise SystemExit(f"m3_actor_negative_error_code_invalid:{label}:{error_code}")
        if not isinstance(raw.get("payload"), dict):
            raise SystemExit(f"m3_actor_negative_payload_invalid:{label}")
        if account not in accounts or role not in roles:
            raise SystemExit(f"m3_actor_negative_actor_unknown:{label}")
        if not role_allowed_for_negative(label, role):
            raise SystemExit(f"m3_actor_negative_role_invalid:{label}:{role}")
    if negative_labels != REQUIRED_NEGATIVE_LABELS:
        raise SystemExit(f"m3_actor_negative_attempts_set_mismatch:{sorted(REQUIRED_NEGATIVE_LABELS - negative_labels)}")

    public_manifest = {
        "schema_version": 3,
        "implementation_freeze_commit": freeze,
        "backend_base_url": backend,
        "actors": sorted(actors, key=lambda item: item["role"]),
        "journey": journey_public,
        "reviewer_count": reviewers,
        "truth_boundary": (
            "Public actor identities and journey identifiers only. Private custody, recovery, "
            "session, and storage-state material are intentionally excluded."
        ),
    }
    try:
        validate_public_actor_transcript(public_manifest, transcript, freeze=freeze)
    except ValueError as exc:
        raise SystemExit(f"m3_actor_transcript_contract_invalid:{exc}") from exc
    out_manifest = Path(args.out_public_manifest).expanduser().resolve()
    out_transcript = Path(args.out_transcript).expanduser().resolve()
    out_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_transcript.parent.mkdir(parents=True, exist_ok=True)
    out_manifest.write_text(json.dumps(public_manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    out_transcript.write_text(json.dumps(transcript, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"OK: M3 actor manifest validated with {len(actors)} actors and {reviewers} reviewers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
