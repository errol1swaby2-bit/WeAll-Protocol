from __future__ import annotations

"""Central protocol eligibility rules for PoH-gated actions.

This is the single intended source of truth for tier-only action gates. More
specific role checks (Juror, Validator, Signer, GovExecutor, etc.) remain scoped
role checks, but any tier prerequisite should resolve through this module.

Two-tier PoH rule:
    Tier 0 = account / unverified
    Tier 1 = native async verified human
    Tier 2 = native live verified human

There is no legacy third-tier compatibility gate in the rebuilt model. Any
transaction name or gate expression containing the removed tier terminology must
fail closed instead of being interpreted as an alias.
"""

from typing import Any

from weall.runtime.errors import ApplyError
from weall.runtime.poh.state import effective_poh_tier

Json = dict[str, Any]

# Tier-only requirements for user-origin actions. SYSTEM/block-only txs are not
# listed here because their authority is enforced by system/role execution logic.
UNKNOWN_ACTION_REQUIRED_POH_TIER = 99


ACTION_REQUIRED_POH_TIER: dict[str, int] = {
    # Explicit canon coverage for Tier-gated user-origin txs that are
    # authority-checked elsewhere but still must not default-open here.
    "POH_CHALLENGE_OPEN": 1,
    "POH_TIER2_REQUEST_OPEN": 1,

    # Onboarding / identity-safe actions.
    "ACCOUNT_REGISTER": 0,
    "ACCOUNT_KEY_ADD": 0,
    "ACCOUNT_KEY_REVOKE": 0,
    "ACCOUNT_DEVICE_REGISTER": 0,
    "ACCOUNT_DEVICE_REVOKE": 0,
    "ACCOUNT_SESSION_KEY_ISSUE": 0,
    "ACCOUNT_SESSION_KEY_REVOKE": 0,
    "ACCOUNT_GUARDIAN_ADD": 0,
    "ACCOUNT_GUARDIAN_REMOVE": 0,
    "ACCOUNT_SECURITY_POLICY_SET": 0,
    "ACCOUNT_RECOVERY_CONFIG_SET": 0,
    "ACCOUNT_RECOVERY_REQUEST": 0,
    "ACCOUNT_RECOVERY_APPROVE": 0,
    "ACCOUNT_RECOVERY_CANCEL": 0,
    "POH_APPLICATION_SUBMIT": 0,
    "POH_EVIDENCE_DECLARE": 0,
    "POH_EVIDENCE_BIND": 0,
    "POH_ASYNC_REQUEST_OPEN": 0,
    "POH_ASYNC_EVIDENCE_DECLARE": 0,
    "POH_ASYNC_EVIDENCE_BIND": 0,
    "PROFILE_UPDATE": 0,
    "PEER_ADVERTISE": 0,
    "PEER_REQUEST_CONNECT": 0,
    "PEER_RENDEZVOUS_TICKET_CREATE": 0,
    "PEER_RENDEZVOUS_TICKET_REVOKE": 0,
    "NOTIFICATION_SUBSCRIBE": 0,
    "NOTIFICATION_UNSUBSCRIBE": 0,
    "FEE_PAY": 0,

    # Tier 1: basic verified-human participation after native async review.
    "BALANCE_TRANSFER": 1,
    "DIRECT_MESSAGE_SEND": 1,
    "DIRECT_MESSAGE_REDACT": 1,
    "FOLLOW_SET": 1,
    "BLOCK_SET": 1,
    "MUTE_SET": 1,
    "CONTENT_SHARE_CREATE": 1,
    "IPFS_PIN_REQUEST": 1,
    "GROUP_EMISSARY_BALLOT_CAST": 1,

    # Tier 2: live verified human / high-trust participation.
    "CONTENT_COMMENT_CREATE": 2,
    "CONTENT_COMMENT_DELETE": 2,
    "CONTENT_REACTION_SET": 2,
    "CONTENT_FLAG": 2,
    "CONTENT_MEDIA_BIND": 2,
    "CONTENT_MEDIA_REPLACE": 2,
    "CONTENT_MEDIA_UNBIND": 2,
    "DISPUTE_OPEN": 2,
    "DISPUTE_APPEAL": 2,
    "DISPUTE_EVIDENCE_DECLARE": 2,
    "DISPUTE_EVIDENCE_BIND": 2,
    # Assigned report-review actions are not open to every account; the
    # dispute apply layer remains authoritative for assignment, attendance,
    # and target-owner neutrality.  The tier gate must still recognize these
    # canonical user-origin tx types so a Tier 2 assigned reviewer is not
    # rejected as an unknown/legacy action before the dispute-specific checks
    # run.
    "DISPUTE_JUROR_ACCEPT": 2,
    "DISPUTE_JUROR_DECLINE": 2,
    "DISPUTE_JUROR_ATTENDANCE": 2,
    "DISPUTE_VOTE_SUBMIT": 2,
    "GROUP_MEMBERSHIP_REQUEST": 1,
    "POH_LIVE_REQUEST_OPEN": 1,
    "ROLE_NODE_OPERATOR_ENROLL": 2,
    "NODE_OPERATOR_RESPONSIBILITY_UPDATE": 2,
    "NODE_OPERATOR_VALIDATOR_OPT_IN": 2,
    "NODE_OPERATOR_STORAGE_OPT_IN": 2,
    "REWARD_POOL_OPT_IN_SET": 2,
    "STORAGE_LEASE_CREATE": 2,
    "STORAGE_LEASE_RENEW": 2,
    "CREATOR_PERFORMANCE_REPORT": 2,

    # High-trust actions require Tier2+ live verification.
    "CONTENT_POST_CREATE": 2,
    "CONTENT_POST_EDIT": 2,
    "CONTENT_POST_DELETE": 2,
    "CONTENT_MEDIA_DECLARE": 2,
    "GOV_DELEGATION_SET": 2,
    "GOV_PROPOSAL_CREATE": 2,
    "GOV_PROPOSAL_COMMENT": 2,
    "GOV_PROPOSAL_EDIT": 2,
    "GOV_PROPOSAL_WITHDRAW": 2,
    "GOV_VOTE_CAST": 2,
    "GOV_VOTE_REVOKE": 2,
    "GROUP_CREATE": 2,
    "ROLE_EMISSARY_NOMINATE": 2,
    "ROLE_EMISSARY_VOTE": 2,
    "ROLE_JUROR_ENROLL": 2,
    "SLASH_PROPOSE": 2,
    "VALIDATOR_CANDIDATE_REGISTER": 2,
    "TREASURY_CREATE": 2,
}


def normalize_action_name(action_name: str) -> str:
    return str(action_name or "").strip().upper()


def is_removed_legacy_poh_tier_action(action_name: str) -> bool:
    name = normalize_action_name(action_name)
    return ("TIER" + "3") in name or name.startswith("POH_" + "TIER" + "3" + "_")


def get_required_poh_tier(action_name: str) -> int:
    if is_removed_legacy_poh_tier_action(action_name):
        return UNKNOWN_ACTION_REQUIRED_POH_TIER
    name = normalize_action_name(action_name)
    if name not in ACTION_REQUIRED_POH_TIER:
        return UNKNOWN_ACTION_REQUIRED_POH_TIER
    return int(ACTION_REQUIRED_POH_TIER[name])


def can_account_perform_action(state: Json, account_id: str, action_name: str) -> bool:
    if is_removed_legacy_poh_tier_action(action_name):
        return False
    name = normalize_action_name(action_name)
    if name not in ACTION_REQUIRED_POH_TIER:
        return False
    required = get_required_poh_tier(name)
    return effective_poh_tier(state, account_id) >= required


def require_poh_tier(state: Json, account_id: str, action_name: str) -> None:
    if is_removed_legacy_poh_tier_action(action_name):
        raise ApplyError(
            "forbidden",
            "removed_legacy_poh_tier_action",
            {
                "account_id": str(account_id or "").strip(),
                "tx_type": normalize_action_name(action_name),
                "max_tier": 2,
            },
        )
    name = normalize_action_name(action_name)
    if name not in ACTION_REQUIRED_POH_TIER:
        raise ApplyError(
            "forbidden",
            "unknown_poh_eligibility_action",
            {
                "account_id": str(account_id or "").strip(),
                "tx_type": name,
                "max_tier": 2,
            },
        )
    required = get_required_poh_tier(name)
    actual = effective_poh_tier(state, account_id)
    if actual < required:
        raise ApplyError(
            "forbidden",
            "poh_tier_required",
            {
                "account_id": str(account_id or "").strip(),
                "tx_type": normalize_action_name(action_name),
                "required_tier": int(required),
                "actual_tier": int(actual),
            },
        )
