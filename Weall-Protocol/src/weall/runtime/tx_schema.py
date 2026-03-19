# File: src/weall/runtime/tx_schema.py

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

Json = dict[str, Any]


class _StrictModel(BaseModel):
    # IMPORTANT:
    # Keep this strict to surface backend/frontend contract drift early.
    model_config = {"extra": "forbid"}


# ============================================================
# Identity domain
# ============================================================


class AccountRegisterPayload(_StrictModel):
    pubkey: str = Field(..., min_length=1)


class AccountKeyAddPayload(_StrictModel):
    pubkey: str = Field(..., min_length=1)
    key_id: str | None = None
    key_type: str | None = None


class AccountKeyRevokePayload(_StrictModel):
    key_id: str = Field(..., min_length=1)


class AccountDeviceRegisterPayload(_StrictModel):
    device_id: str = Field(..., min_length=1)
    device_type: str | None = Field(default=None, min_length=1)
    label: str | None = Field(default=None, min_length=1)
    pubkey: str | None = Field(default=None, min_length=1)


class AccountDeviceRevokePayload(_StrictModel):
    device_id: str = Field(..., min_length=1)


class AccountSessionKeyIssuePayload(_StrictModel):
    session_pubkey: str | None = Field(default=None, min_length=1)
    expires_ts_ms: int | None = Field(default=None, ge=0)

    session_key: str | None = Field(default=None, min_length=1)
    ttl_s: int | None = Field(default=None, ge=0)


class AccountSessionKeyRevokePayload(_StrictModel):
    session_key: str | None = Field(default=None, min_length=1)
    session_pubkey: str | None = Field(default=None, min_length=1)


class AccountGuardianAddPayload(_StrictModel):
    guardian_id: str = Field(..., min_length=1)


class AccountGuardianRemovePayload(_StrictModel):
    guardian_id: str = Field(..., min_length=1)


class AccountLockPayload(_StrictModel):
    target: str | None = None


class AccountUnlockPayload(_StrictModel):
    target: str | None = None


class AccountRecoveryConfigSetPayload(_StrictModel):
    guardians: list[str] | None = None
    threshold: int | None = Field(default=None, ge=0)
    delay_blocks: int | None = Field(default=None, ge=0)


class AccountRecoveryRequestPayload(_StrictModel):
    request_id: str | None = None
    target: str | None = None


class AccountRecoveryApprovePayload(_StrictModel):
    request_id: str = Field(..., min_length=1)


class AccountRecoveryCancelPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)


class AccountRecoveryFinalizePayload(_StrictModel):
    request_id: str = Field(..., min_length=1)


# ============================================================
# PoH domain (aligned to runtime/apply/poh.py)
# ============================================================


class PohTierSetPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    tier: int = Field(..., ge=0)


class PohApplicationSubmitPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    target_tier: int = Field(..., ge=0)
    video_cid: str | None = None
    video_commitment: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohEvidenceDeclarePayload(_StrictModel):
    evidence_id: str | None = None
    cid: str | None = None
    kind: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohEvidenceBindPayload(_StrictModel):
    evidence_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


class PohChallengeOpenPayload(_StrictModel):
    challenge_id: str | None = None
    account_id: str = Field(..., min_length=1)
    reason: str | None = None
    evidence_id: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohChallengeResolvePayload(_StrictModel):
    challenge_id: str = Field(..., min_length=1)
    resolution: str = Field(..., min_length=1)
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier2RequestOpenPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    target_tier: int = Field(..., ge=0)
    video_cid: str | None = None
    video_commitment: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier2JurorAssignPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1)


class PohTier2JurorAcceptPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier2JurorDeclinePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier2ReviewSubmitPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier2FinalizePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier2ReceiptPayload(_StrictModel):
    receipt_id: str | None = None
    case_id: str = Field(..., min_length=1)
    outcome: str | None = None
    tier_awarded: int | None = Field(default=None, ge=0)
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier3InitPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    session_commitment: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier3JurorAssignPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1)


class PohTier3JurorAcceptPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier3JurorDeclinePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier3JurorReplacePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    old_juror_id: str = Field(..., min_length=1)
    new_juror_id: str = Field(..., min_length=1)


class PohTier3AttendanceMarkPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str | None = None
    attended: bool = Field(...)
    # REQUIRED by runtime/apply/poh.py (bad_session_commitment) and by API skeletons.
    session_commitment: str | None = None
    # API skeletons default to 0; client should set Date.now().
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier3VerdictSubmitPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)
    note: str | None = None
    # REQUIRED by runtime/apply/poh.py (bad_session_commitment) and by API skeletons.
    session_commitment: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohTier3FinalizePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohTier3ReceiptPayload(_StrictModel):
    receipt_id: str | None = None
    case_id: str = Field(..., min_length=1)
    outcome: str | None = None
    tier_awarded: int | None = Field(default=None, ge=0)
    ts_ms: int | None = Field(default=None, ge=0)


class PohBootstrapTier3GrantPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    accepted: bool | None = None
    note: str | None = None


class PohEmailReceiptSubmitPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    receipt: Json


# ============================================================
# Content domain (aligned to runtime/apply/content.py)
# ============================================================


class ContentPostCreatePayload(_StrictModel):
    post_id: str | None = Field(default=None, min_length=1)
    body: str | None = Field(default=None, min_length=1)
    media: list[str] | None = None
    visibility: str | None = Field(default=None, min_length=1)
    tags: list[str] | None = None
    group_id: str | None = None


class ContentPostEditPayload(_StrictModel):
    post_id: str = Field(..., min_length=1)
    body: str | None = Field(default=None, min_length=1)
    media: list[str] | None = None
    tags: list[str] | None = None
    group_id: str | None = None


class ContentPostDeletePayload(_StrictModel):
    post_id: str = Field(..., min_length=1)


class ContentCommentCreatePayload(_StrictModel):
    comment_id: str | None = Field(default=None, min_length=1)
    post_id: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)


class ContentCommentDeletePayload(_StrictModel):
    comment_id: str = Field(..., min_length=1)


class ContentReactionSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    reaction: str = Field(..., min_length=1)


class ContentFlagPayload(_StrictModel):
    flag_id: str | None = Field(default=None, min_length=1)
    target_id: str = Field(..., min_length=1)
    reason: str | None = None


class ContentMediaDeclarePayload(_StrictModel):
    media_id: str | None = Field(default=None, min_length=1)
    id: str | None = Field(default=None, min_length=1)

    cid: str | None = None
    ipfs_cid: str | None = None
    content_cid: str | None = None
    upload_ref: str | None = None
    ref: str | None = None

    kind: str | None = None
    mime: str | None = None
    bytes: int | None = Field(default=None, ge=0)
    name: str | None = None


class ContentMediaBindPayload(_StrictModel):
    binding_id: str | None = Field(default=None, min_length=1)
    media_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


# ============================================================
# Governance domain
# ============================================================


class GovProposalCreatePayload(_StrictModel):
    # NOTE: runtime/apply/governance.py requires proposal_id on create.
    proposal_id: str = Field(..., min_length=1)

    # Optional human-friendly metadata (used by web UI / API responses)
    title: str | None = None
    body: str | None = None

    # Governance engine fields
    rules: Json | None = None
    actions: list[Json] | None = None

    # Deterministic height hint (used in tests / internal scheduling)
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")


class GovVoteCastPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)

    # Backward/forward compatibility: some clients use 'choice'.
    vote: str | None = None
    choice: str | None = None


class GovDelegationSetPayload(_StrictModel):
    # Empty / missing clears delegation.
    delegatee: str | None = None


# ============================================================
# Dispute domain
# ============================================================


class DisputeOpenPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


class DisputeJurorAssignPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1)


class DisputeJurorAcceptPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeJurorDeclinePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeEvidenceDeclarePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    cid: str | None = None


class DisputeEvidenceBindPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


class DisputeVoteSubmitPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)


# ============================================================
# Envelope + dispatcher
# ============================================================


class TxEnvelopeModel(_StrictModel):
    tx_type: str = Field(..., min_length=1)
    signer: str = Field(..., min_length=1)
    nonce: int = Field(..., ge=0)
    payload: Json = Field(default_factory=dict)
    sig: str = Field(default="")
    parent: str | None = None
    system: bool = False

    # IMPORTANT: frontend includes this in the signed envelope; we must accept it.
    chain_id: str | None = None


TxPayloadModel = (
    # Identity
    AccountRegisterPayload,
    AccountKeyAddPayload,
    AccountKeyRevokePayload,
    AccountDeviceRegisterPayload,
    AccountDeviceRevokePayload,
    AccountSessionKeyIssuePayload,
    AccountSessionKeyRevokePayload,
    AccountGuardianAddPayload,
    AccountGuardianRemovePayload,
    AccountLockPayload,
    AccountUnlockPayload,
    AccountRecoveryConfigSetPayload,
    AccountRecoveryRequestPayload,
    AccountRecoveryApprovePayload,
    AccountRecoveryCancelPayload,
    AccountRecoveryFinalizePayload,
    # PoH
    PohTierSetPayload,
    PohApplicationSubmitPayload,
    PohEvidenceDeclarePayload,
    PohEvidenceBindPayload,
    PohChallengeOpenPayload,
    PohChallengeResolvePayload,
    PohTier2RequestOpenPayload,
    PohTier2JurorAssignPayload,
    PohTier2JurorAcceptPayload,
    PohTier2JurorDeclinePayload,
    PohTier2ReviewSubmitPayload,
    PohTier2FinalizePayload,
    PohTier2ReceiptPayload,
    PohTier3InitPayload,
    PohTier3JurorAssignPayload,
    PohTier3JurorAcceptPayload,
    PohTier3JurorDeclinePayload,
    PohTier3JurorReplacePayload,
    PohTier3AttendanceMarkPayload,
    PohTier3VerdictSubmitPayload,
    PohTier3FinalizePayload,
    PohTier3ReceiptPayload,
    PohBootstrapTier3GrantPayload,
    # Content
    ContentPostCreatePayload,
    ContentPostEditPayload,
    ContentPostDeletePayload,
    ContentCommentCreatePayload,
    ContentCommentDeletePayload,
    ContentReactionSetPayload,
    ContentFlagPayload,
    ContentMediaDeclarePayload,
    ContentMediaBindPayload,
    # Governance
    GovProposalCreatePayload,
    GovVoteCastPayload,
    GovDelegationSetPayload,
    # Dispute
    DisputeOpenPayload,
    DisputeJurorAssignPayload,
    DisputeJurorAcceptPayload,
    DisputeJurorDeclinePayload,
    DisputeEvidenceDeclarePayload,
    DisputeEvidenceBindPayload,
    DisputeVoteSubmitPayload,
)

TX_PAYLOADS: dict[str, Any] = {
    # Identity
    "ACCOUNT_REGISTER": AccountRegisterPayload,
    "ACCOUNT_KEY_ADD": AccountKeyAddPayload,
    "ACCOUNT_KEY_REVOKE": AccountKeyRevokePayload,
    "ACCOUNT_DEVICE_REGISTER": AccountDeviceRegisterPayload,
    "ACCOUNT_DEVICE_REVOKE": AccountDeviceRevokePayload,
    "ACCOUNT_SESSION_KEY_ISSUE": AccountSessionKeyIssuePayload,
    "ACCOUNT_SESSION_KEY_REVOKE": AccountSessionKeyRevokePayload,
    "ACCOUNT_GUARDIAN_ADD": AccountGuardianAddPayload,
    "ACCOUNT_GUARDIAN_REMOVE": AccountGuardianRemovePayload,
    "ACCOUNT_LOCK": AccountLockPayload,
    "ACCOUNT_UNLOCK": AccountUnlockPayload,
    "ACCOUNT_RECOVERY_CONFIG_SET": AccountRecoveryConfigSetPayload,
    "ACCOUNT_RECOVERY_REQUEST": AccountRecoveryRequestPayload,
    "ACCOUNT_RECOVERY_APPROVE": AccountRecoveryApprovePayload,
    "ACCOUNT_RECOVERY_CANCEL": AccountRecoveryCancelPayload,
    "ACCOUNT_RECOVERY_FINALIZE": AccountRecoveryFinalizePayload,
    # PoH
    "POH_TIER_SET": PohTierSetPayload,
    "POH_APPLICATION_SUBMIT": PohApplicationSubmitPayload,
    "POH_EVIDENCE_DECLARE": PohEvidenceDeclarePayload,
    "POH_EVIDENCE_BIND": PohEvidenceBindPayload,
    "POH_CHALLENGE_OPEN": PohChallengeOpenPayload,
    "POH_CHALLENGE_RESOLVE": PohChallengeResolvePayload,
    "POH_TIER2_REQUEST_OPEN": PohTier2RequestOpenPayload,
    "POH_TIER2_JUROR_ASSIGN": PohTier2JurorAssignPayload,
    "POH_TIER2_JUROR_ACCEPT": PohTier2JurorAcceptPayload,
    "POH_TIER2_JUROR_DECLINE": PohTier2JurorDeclinePayload,
    "POH_TIER2_REVIEW_SUBMIT": PohTier2ReviewSubmitPayload,
    "POH_TIER2_FINALIZE": PohTier2FinalizePayload,
    "POH_TIER2_RECEIPT": PohTier2ReceiptPayload,
    "POH_TIER3_INIT": PohTier3InitPayload,
    "POH_TIER3_JUROR_ASSIGN": PohTier3JurorAssignPayload,
    "POH_TIER3_JUROR_ACCEPT": PohTier3JurorAcceptPayload,
    "POH_TIER3_JUROR_DECLINE": PohTier3JurorDeclinePayload,
    "POH_TIER3_JUROR_REPLACE": PohTier3JurorReplacePayload,
    "POH_TIER3_ATTENDANCE_MARK": PohTier3AttendanceMarkPayload,
    "POH_TIER3_VERDICT_SUBMIT": PohTier3VerdictSubmitPayload,
    "POH_TIER3_FINALIZE": PohTier3FinalizePayload,
    "POH_TIER3_RECEIPT": PohTier3ReceiptPayload,
    "POH_BOOTSTRAP_TIER3_GRANT": PohBootstrapTier3GrantPayload,
    "POH_EMAIL_RECEIPT_SUBMIT": PohEmailReceiptSubmitPayload,
    # Content (canon)
    "CONTENT_POST_CREATE": ContentPostCreatePayload,
    "CONTENT_POST_EDIT": ContentPostEditPayload,
    "CONTENT_POST_DELETE": ContentPostDeletePayload,
    # Content (back-compat aliases)
    "POST_CREATE": ContentPostCreatePayload,
    "POST_EDIT": ContentPostEditPayload,
    "POST_DELETE": ContentPostDeletePayload,
    "CONTENT_COMMENT_CREATE": ContentCommentCreatePayload,
    "CONTENT_COMMENT_DELETE": ContentCommentDeletePayload,
    "CONTENT_REACTION_SET": ContentReactionSetPayload,
    "CONTENT_FLAG": ContentFlagPayload,
    "CONTENT_MEDIA_DECLARE": ContentMediaDeclarePayload,
    "CONTENT_MEDIA_BIND": ContentMediaBindPayload,
    # Governance
    "GOV_PROPOSAL_CREATE": GovProposalCreatePayload,
    "GOV_VOTE_CAST": GovVoteCastPayload,
    "GOV_DELEGATION_SET": GovDelegationSetPayload,
    # Dispute
    "DISPUTE_OPEN": DisputeOpenPayload,
    "DISPUTE_JUROR_ASSIGN": DisputeJurorAssignPayload,
    "DISPUTE_JUROR_ACCEPT": DisputeJurorAcceptPayload,
    "DISPUTE_JUROR_DECLINE": DisputeJurorDeclinePayload,
    "DISPUTE_EVIDENCE_DECLARE": DisputeEvidenceDeclarePayload,
    "DISPUTE_EVIDENCE_BIND": DisputeEvidenceBindPayload,
    "DISPUTE_VOTE_SUBMIT": DisputeVoteSubmitPayload,
}


def model_for_tx_type(tx_type: str) -> Any | None:
    return TX_PAYLOADS.get((tx_type or "").upper())


def validate_tx_envelope(env: Json) -> tuple[TxEnvelopeModel, BaseModel | None]:
    """Validate envelope + payload shape (strict)."""
    e = TxEnvelopeModel(**env)
    payload_model = model_for_tx_type(e.tx_type)
    if payload_model is None:
        return e, None
    p = payload_model(**(e.payload or {}))
    return e, p
