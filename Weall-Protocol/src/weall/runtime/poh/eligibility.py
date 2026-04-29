from __future__ import annotations

"""Central protocol eligibility rules for PoH-gated actions.

This is the single intended source of truth for tier-only action gates. More
specific role checks (Juror, Validator, Signer, GovExecutor, etc.) remain scoped
role checks, but any tier prerequisite should resolve through this module.
"""

from typing import Any

from weall.runtime.errors import ApplyError
from weall.runtime.poh.state import effective_poh_tier

Json = dict[str, Any]

# Tier-only requirements for user-origin actions. SYSTEM/block-only txs are not
# listed here because their authority is enforced by system/role execution logic.
ACTION_REQUIRED_POH_TIER: dict[str, int] = {
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
    "POH_EMAIL_ATTESTATION_SUBMIT": 0,
    "PROFILE_UPDATE": 0,
    "PEER_ADVERTISE": 0,
    "PEER_REQUEST_CONNECT": 0,
    "PEER_RENDEZVOUS_TICKET_CREATE": 0,
    "PEER_RENDEZVOUS_TICKET_REVOKE": 0,
    "NOTIFICATION_SUBSCRIBE": 0,
    "NOTIFICATION_UNSUBSCRIBE": 0,
    "FEE_PAY": 0,

    # Tier 1: limited social/economic convenience after email-control proof.
    "BALANCE_TRANSFER": 1,
    "DIRECT_MESSAGE_SEND": 1,
    "DIRECT_MESSAGE_REDACT": 1,
    "FOLLOW_SET": 1,
    "BLOCK_SET": 1,
    "MUTE_SET": 1,
    "CONTENT_SHARE_CREATE": 1,
    "IPFS_PIN_REQUEST": 1,
    "GROUP_EMISSARY_BALLOT_CAST": 1,

    # Tier 2: async-human-verified participation.
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
    "GROUP_MEMBERSHIP_REQUEST": 2,
    "POH_TIER3_REQUEST_OPEN": 2,
    "ROLE_NODE_OPERATOR_ENROLL": 2,
    "REWARD_POOL_OPT_IN_SET": 2,
    "STORAGE_LEASE_CREATE": 2,
    "STORAGE_LEASE_RENEW": 2,
    "CREATOR_PERFORMANCE_REPORT": 2,

    # Tier 3: live-human-verified creation/governance/high-authority actions.
    "CONTENT_POST_CREATE": 3,
    "CONTENT_POST_EDIT": 3,
    "CONTENT_POST_DELETE": 3,
    "CONTENT_MEDIA_DECLARE": 3,
    "GOV_DELEGATION_SET": 3,
    "GOV_PROPOSAL_CREATE": 3,
    "GOV_PROPOSAL_EDIT": 3,
    "GOV_PROPOSAL_WITHDRAW": 3,
    "GOV_VOTE_CAST": 3,
    "GOV_VOTE_REVOKE": 3,
    "GROUP_CREATE": 3,
    "ROLE_EMISSARY_NOMINATE": 3,
    "ROLE_EMISSARY_VOTE": 3,
    "ROLE_JUROR_ENROLL": 3,
    "SLASH_PROPOSE": 3,
    "VALIDATOR_CANDIDATE_REGISTER": 3,
    "VALIDATOR_REGISTER": 3,
    "TREASURY_CREATE": 3,
    "ORACLE_REGISTER": 3,
    "ORACLE_ROTATE_KEY": 3,
    "ORACLE_UPDATE_METADATA": 3,
}


def normalize_action_name(action_name: str) -> str:
    return str(action_name or "").strip().upper()


def get_required_poh_tier(action_name: str) -> int:
    return int(ACTION_REQUIRED_POH_TIER.get(normalize_action_name(action_name), 0))


def can_account_perform_action(state: Json, account_id: str, action_name: str) -> bool:
    required = get_required_poh_tier(action_name)
    return effective_poh_tier(state, account_id) >= required


def require_poh_tier(state: Json, account_id: str, action_name: str) -> None:
    required = get_required_poh_tier(action_name)
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
