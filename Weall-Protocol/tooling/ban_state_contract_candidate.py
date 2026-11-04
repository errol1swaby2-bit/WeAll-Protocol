"""Read-only PR77 ban-state consistency inventory; no consensus authority.

This module is NOT imported by the runtime dispatcher, SYSTEM queue, or block
validator. It never updates an account or ban record, and cannot approve a
sanction, reinstatement, activation, or historical replay migration.

Draft Constitution 2: Article II sections 4/7, VI section 3, VII section 4.
V2 first-draft §32, DSP-210, SAN-005, SAN-006 need separate formal review.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

STATUS = "REVIEW_ONLY_BAN_STATE_CONTRACT_UNAUTHORIZED"
REQUIRED_GATES = (
    "authorized_constitutional_sanction_and_appeal_not_established",
    "authenticated_final_receipt_and_parent_not_established",
    "effective_status_and_history_model_not_approved",
    "chain_committed_version_activation_not_approved",
    "authentic_old_height_replay_compatibility_not_proven",
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _bool_field(mapping: Mapping[str, Any], field: str) -> bool | None:
    value = mapping.get(field)
    # Missing, string-typed and numerical booleans are NOT affirmative state.
    return value if type(value) is bool else None


def review_ban_state_candidate(state: Mapping[str, Any], *, account_id: str) -> dict[str, Any]:
    """Inspect the account flag and mutable ban index, without changing either.

    The flag is presently consulted by transaction admission; the separate
    reputation.bans entry is overwritten by the canonical reputation appliers.
    Neither field alone proves a valid constitutional decision.  A missing
    index does not imply that old state needs to be migrated or re-banned.
    """
    root = _mapping(state)
    account_key = account_id if isinstance(account_id, str) else ""
    accounts = _mapping(root.get("accounts"))
    raw_account = accounts.get(account_key)
    account_present = isinstance(raw_account, Mapping)
    account = _mapping(raw_account)
    rep = _mapping(root.get("reputation"))
    raw_index = _mapping(rep.get("bans")).get(account_key)
    index_present = isinstance(raw_index, Mapping)
    index = _mapping(raw_index)
    flag = _bool_field(account, "banned") if account_present else None
    index_flag = _bool_field(index, "banned") if index_present else None

    if not account_present:
        classification = "ACCOUNT_NOT_FOUND"
    elif flag is None:
        classification = "ACCOUNT_BAN_FLAG_MISSING_OR_INVALID"
    elif raw_index is not None and not index_present:
        classification = "BAN_INDEX_RECORD_INVALID"
    elif index_present and index_flag is None:
        classification = "BAN_INDEX_FLAG_MISSING_OR_INVALID"
    elif not index_present:
        classification = "INDEX_ABSENT_ACCOUNT_ACTIVE" if flag else "INDEX_ABSENT_ACCOUNT_CLEAR"
    elif flag != index_flag:
        classification = (
            "DIVERGENT_ACCOUNT_CLEAR_INDEX_ACTIVE"
            if not flag
            else "DIVERGENT_ACCOUNT_ACTIVE_INDEX_CLEAR"
        )
    else:
        classification = "CONSISTENT_ACTIVE" if flag else "CONSISTENT_CLEAR"

    return {
        "schema": "weall.pr77.ban-state-contract-candidate.v0",
        "status": STATUS,
        "account_id": account_key,
        "classification": classification,
        "observed": {
            "account_present": account_present,
            "account_banned": flag,
            "ban_index_present": index_present,
            "ban_index_banned": index_flag,
            "ban_index_auto": _bool_field(index, "auto") if index_present else None,
            "ban_index_set_at_nonce": index.get("set_at_nonce") if index_present else None,
        },
        "implementation_observation": {
            "admission_checks_account_banned": True,
            "ban_index_overwritten_by_canonical_receipts": True,
            "ban_index_is_not_append_only_event_history": True,
            "full_authoritative_sanction_model_established": False,
        },
        "blocking_reasons": list(REQUIRED_GATES),
        "constitutional_authorization": "NOT_ESTABLISHED",
        "may_apply_transition": False,
        "may_enqueue_system_tx": False,
        "may_activate_new_policy": False,
        "mutates_state": False,
    }
