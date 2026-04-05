# File: src/weall/runtime/tx_schema.py

from __future__ import annotations

from typing import Any

from pydantic import AliasChoices, BaseModel, Field, model_validator

from weall.util.ipfs_cid import validate_ipfs_cid

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


class AccountSecurityPolicySetPayload(_StrictModel):
    policy: Json | None = None
    lock_on_recovery_request: bool | None = None
    session_ttl_s: int | None = Field(default=None, ge=0)
    require_guardian_threshold_for_unlock: bool | None = None


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


class AccountRecoveryReceiptPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)
    status: str | None = None


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
# Social / Messaging / Notifications batch 1
# ============================================================


class ProfileUpdatePayload(_StrictModel):
    display_name: str | None = Field(default=None, min_length=1)
    bio: str | None = None
    avatar_cid: str | None = Field(default=None, min_length=1)
    banner_cid: str | None = Field(default=None, min_length=1)
    website: str | None = Field(default=None, min_length=1)
    location: str | None = Field(default=None, min_length=1)
    tags: list[str] | None = None


class _EdgeTargetPayload(_StrictModel):
    target: str = Field(..., min_length=1, validation_alias=AliasChoices("target", "account_id"))
    active: bool | None = None


class FollowSetPayload(_EdgeTargetPayload):
    pass


class BlockSetPayload(_EdgeTargetPayload):
    pass


class MuteSetPayload(_EdgeTargetPayload):
    pass


class ContentShareCreatePayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    share_id: str | None = Field(default=None, min_length=1)
    comment: str | None = None


class DirectMessageSendPayload(_StrictModel):
    to: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("to", "recipient", "to_account", "account_id"),
    )
    body: str | None = None
    cid: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("cid", "content_cid", "ipfs_cid"),
    )
    thread_id: str | None = Field(default=None, min_length=1)
    message_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("message_id", "id"),
    )

    @model_validator(mode="after")
    def _require_body_or_cid(self) -> "DirectMessageSendPayload":
        if not (self.body or self.cid):
            raise ValueError("body or cid is required")
        return self


class DirectMessageRedactPayload(_StrictModel):
    message_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("message_id", "id"),
    )
    reason: str | None = None


class _TopicPayloadBase(_StrictModel):
    topic: str | list[str] = Field(..., validation_alias=AliasChoices("topic", "topics"))

    @model_validator(mode="after")
    def _normalize_topic_presence(self) -> "_TopicPayloadBase":
        raw = self.topic
        if isinstance(raw, str):
            if not raw.strip():
                raise ValueError("topic must not be empty")
            return self
        if not isinstance(raw, list):
            raise ValueError("topic/topics must be a string or list[str]")
        cleaned = [str(item).strip() for item in raw if str(item).strip()]
        if not cleaned:
            raise ValueError("topics must contain at least one non-empty topic")
        return self


class NotificationSubscribePayload(_TopicPayloadBase):
    pass


class NotificationUnsubscribePayload(_TopicPayloadBase):
    pass




# ============================================================
# Networking / Storage batch 2
# ============================================================


class _OptionalCidPayload(_StrictModel):
    @staticmethod
    def _validate_cid_value(value: str | None, field_name: str) -> str | None:
        if value is None:
            return None
        v = validate_ipfs_cid(value)
        if not v.ok:
            raise ValueError(f"{field_name}: {v.reason}")
        return value


class PeerAdvertisePayload(_StrictModel):
    endpoint: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("endpoint", "url"),
    )
    peer_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("peer_id", "peer", "id"),
    )


class PeerRendezvousTicketCreatePayload(_StrictModel):
    target_peer: str = Field(..., min_length=1)
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("ticket_id", "id"),
    )


class PeerRendezvousTicketRevokePayload(_StrictModel):
    ticket_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("ticket_id", "id"),
    )


class PeerRequestConnectPayload(_StrictModel):
    peer_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("peer_id", "to_peer_id", "target_peer_id"),
    )
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("ticket_id", "id"),
    )
    endpoint: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("endpoint", "url"),
    )

    @model_validator(mode="after")
    def _require_peer_ticket_or_endpoint(self) -> "PeerRequestConnectPayload":
        if not (self.peer_id or self.ticket_id or self.endpoint):
            raise ValueError("peer_id, ticket_id, or endpoint is required")
        return self


class PeerBanSetPayload(_StrictModel):
    peer_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("peer_id", "peer", "id"),
    )
    banned: bool | None = None
    reason: str | None = None


class PeerReputationSignalPayload(_StrictModel):
    peer_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("peer_id", "peer", "id"),
    )
    score: int | None = None
    reason: str | None = None


class StorageOfferCreatePayload(_OptionalCidPayload):
    offer_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("offer_id", "id"),
    )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("operator_id", "operator"),
    )
    cid: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("cid", "content_cid", "ipfs_cid"),
    )
    capacity_bytes: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("capacity_bytes", "capacity"),
    )
    price: Json | int | str | None = None

    @model_validator(mode="after")
    def _validate_cid(self) -> "StorageOfferCreatePayload":
        self._validate_cid_value(self.cid, "cid")
        return self


class StorageOfferWithdrawPayload(_StrictModel):
    offer_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("offer_id", "id"),
    )


class StorageLeaseCreatePayload(_StrictModel):
    offer_id: str = Field(..., min_length=1)
    lease_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("lease_id", "id"),
    )
    duration_blocks: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("duration_blocks", "blocks"),
    )


class StorageLeaseRenewPayload(_StrictModel):
    lease_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("lease_id", "id"),
    )
    add_blocks: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("add_blocks", "duration_blocks"),
    )


class StorageLeaseRevokePayload(_StrictModel):
    lease_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("lease_id", "id"),
    )


class StorageProofSubmitPayload(_OptionalCidPayload):
    lease_id: str = Field(..., min_length=1)
    proof_cid: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("proof_cid", "cid"),
    )

    @model_validator(mode="after")
    def _validate_proof_cid(self) -> "StorageProofSubmitPayload":
        self._validate_cid_value(self.proof_cid, "proof_cid")
        return self


class StorageChallengeIssuePayload(_StrictModel):
    lease_id: str = Field(..., min_length=1)
    challenge_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("challenge_id", "id"),
    )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("operator_id", "operator"),
    )
    account_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("account_id", "lessee"),
    )


class StorageChallengeRespondPayload(_StrictModel):
    challenge_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("challenge_id", "id"),
    )


class StoragePayoutExecutePayload(_StrictModel):
    payout_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("payout_id", "id"),
    )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("operator_id", "operator"),
    )
    amount: int | float | str | None = None


class StorageReportAnchorPayload(_OptionalCidPayload):
    report_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("report_id", "id", "key"),
    )
    report_cid: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("report_cid", "cid"),
    )

    @model_validator(mode="after")
    def _validate_report_cid(self) -> "StorageReportAnchorPayload":
        self._validate_cid_value(self.report_cid, "report_cid")
        return self


class IpfsPinRequestPayload(_OptionalCidPayload):
    cid: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("cid", "ipfs_cid", "content_cid"),
    )
    pin_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("pin_id", "id"),
    )
    size_bytes: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("size_bytes", "bytes", "size"),
    )

    @model_validator(mode="after")
    def _validate_required_cid(self) -> "IpfsPinRequestPayload":
        self._validate_cid_value(self.cid, "cid")
        return self


class IpfsPinConfirmPayload(_OptionalCidPayload):
    pin_id: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("pin_id", "id"),
    )
    cid: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("cid", "ipfs_cid", "content_cid"),
    )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        validation_alias=AliasChoices("operator_id", "operator"),
    )
    ok: bool | int | None = None

    @model_validator(mode="after")
    def _validate_optional_cid(self) -> "IpfsPinConfirmPayload":
        self._validate_cid_value(self.cid, "cid")
        return self


# ============================================================
# Treasury + Groups domains
# ============================================================


class TreasuryCreatePayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, validation_alias=AliasChoices("treasury_id", "id"))


class TreasurySignersSetPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, validation_alias=AliasChoices("treasury_id", "id"))
    signers: list[str] = Field(..., min_length=1)
    threshold: int | None = Field(default=None, ge=1)


class TreasuryWalletCreatePayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, validation_alias=AliasChoices("wallet_id", "treasury_id", "id"))
    meta: Json | None = None


class TreasurySignerAddPayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, validation_alias=AliasChoices("wallet_id", "treasury_id", "id"))
    signer: str = Field(..., min_length=1, validation_alias=AliasChoices("signer", "account", "account_id"))


class TreasurySignerRemovePayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, validation_alias=AliasChoices("wallet_id", "treasury_id", "id"))
    signer: str = Field(..., min_length=1, validation_alias=AliasChoices("signer", "account", "account_id"))


class TreasuryPolicySetPayload(_StrictModel):
    policy: Json = Field(...)


class TreasurySpendProposePayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, validation_alias=AliasChoices("treasury_id", "wallet_id", "id"))
    spend_id: str = Field(..., min_length=1)
    to: str = Field(..., min_length=1)
    amount: int = Field(..., ge=0)
    memo: str | None = None


class TreasurySpendSignPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, validation_alias=AliasChoices("treasury_id", "wallet_id", "id"))
    spend_id: str = Field(..., min_length=1)


class TreasurySpendCancelPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, validation_alias=AliasChoices("treasury_id", "wallet_id", "id"))
    spend_id: str = Field(..., min_length=1)


class TreasurySpendExpirePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class TreasurySpendExecutePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class TreasuryProgramCreatePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, validation_alias=AliasChoices("program_id", "id"))
    config: Json | None = None


class TreasuryProgramUpdatePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, validation_alias=AliasChoices("program_id", "id"))
    patch: Json | None = None
    config: Json | None = None


class TreasuryProgramClosePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, validation_alias=AliasChoices("program_id", "id"))


class TreasuryAuditAnchorSetPayload(_StrictModel):
    anchor: Json = Field(...)


class GroupCreatePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    charter: str | None = None


class GroupUpdatePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    charter: str | None = None


class GroupRoleGrantPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    account: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


class GroupRoleRevokePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    account: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


class GroupMembershipRequestPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    note: str | None = None


class GroupMembershipDecidePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    account: str = Field(..., min_length=1)
    decision: str = Field(..., min_length=1)


class GroupMembershipRemovePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    account: str = Field(..., min_length=1)


class GroupSignersSetPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    signers: list[str] = Field(..., min_length=1)
    threshold: int | None = Field(default=None, ge=1)


class GroupModeratorsSetPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    moderators: list[str]


class GroupTreasuryCreatePayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1)


class GroupTreasuryPolicySetPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    policy: Json = Field(...)


class GroupTreasurySpendProposePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)
    group_id: str = Field(..., min_length=1)
    to: str = Field(..., min_length=1)
    amount: int = Field(..., ge=0)
    memo: str | None = None


class GroupTreasurySpendSignPayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class GroupTreasurySpendCancelPayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class GroupTreasurySpendExpirePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    spend_id: str = Field(..., min_length=1)


class GroupTreasurySpendExecutePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class GroupTreasuryAuditAnchorSetPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    anchor: Json | None = None


class GroupEmissaryElectionCreatePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    election_id: str = Field(..., min_length=1)
    seats: int = Field(..., ge=1)
    candidates: list[str] = Field(..., min_length=1)
    start_height: int | None = Field(default=None, ge=0)
    end_height: int | None = Field(default=None, ge=0)


class GroupEmissaryBallotCastPayload(_StrictModel):
    election_id: str = Field(..., min_length=1)
    ranking: list[str] = Field(..., min_length=1)


class GroupEmissaryElectionFinalizePayload(_StrictModel):
    election_id: str = Field(..., min_length=1)


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



class GovProposalEditPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    title: str | None = None
    body: str | None = None
    rules: Json | None = None
    actions: list[Json] | None = None
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")


class GovProposalWithdrawPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")


class GovStageSetPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    stage: str = Field(..., min_length=1)
    poll_tally: Json | None = None
    poll_total_votes: int | None = Field(default=None, ge=0)
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")


class GovQuorumSetPayload(_StrictModel):
    quorum_percent: int | None = Field(default=None, ge=1, le=100)
    quorum_bps: int | None = Field(default=None, ge=1, le=10_000)


class GovRulesSetPayload(_StrictModel):
    params: Json | None = None
    treasury: Json | None = None


class GovExecutePayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    actions: list[Json] | None = None
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class GovExecutionReceiptPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    ok: bool | int | None = None
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class ProtocolUpgradeDeclarePayload(_StrictModel):
    upgrade_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("upgrade_id", "id", "proposal_id"))
    version: str | None = None
    target_version: str | None = None
    hash: str | None = None
    commit: str | None = None


class ProtocolUpgradeActivatePayload(_StrictModel):
    upgrade_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("upgrade_id", "id", "proposal_id"))
    version: str | None = None
    hash: str | None = None


class GovVoteRevokePayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)


class GovVotingClosePayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)


class GovTallyPublishPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    tally: Json | None = None
    total_votes: int | None = Field(default=None, ge=0)


class GovProposalFinalizePayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class GovProposalReceiptPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    finalized: bool | int | None = None
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


# ============================================================
# Dispute + cases + moderation domains
# ============================================================



class DisputeOpenPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    target_type: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    reason: str | None = None


class DisputeStageSetPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    stage: str = Field(..., min_length=1)


class DisputeJurorAssignPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1, validation_alias=AliasChoices("juror_id", "juror"))


class DisputeJurorAcceptPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeJurorDeclinePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeJurorAttendancePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    present: bool | int | None = None


class DisputeEvidenceDeclarePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    kind: str | None = None
    cid: str | None = None
    meta: Json | None = None


class DisputeEvidenceBindPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    target_id: str | None = None


class DisputeVoteSubmitPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    vote: str | None = None
    verdict: str | None = None
    resolution: Json | None = None

    @model_validator(mode="after")
    def _validate_vote_or_verdict(self) -> "DisputeVoteSubmitPayload":
        if not (self.vote or self.verdict):
            raise ValueError("either vote or verdict is required")
        return self


class DisputeResolvePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    resolution: Json | None = None
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")
    system_queue_id: str | None = Field(default=None, alias="_system_queue_id")
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class DisputeAppealPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    reason: str | None = None
    note: str | None = None
    basis: Json | None = None


class DisputeFinalReceiptPayload(_StrictModel):
    receipt_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("receipt_id", "id"))
    dispute_id: str | None = None
    resolution: Json | None = None
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class CaseTypeRegisterPayload(_StrictModel):
    case_type: str = Field(..., min_length=1, validation_alias=AliasChoices("case_type", "type", "name"))


class CaseBindToDisputePayload(_StrictModel):
    case_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("case_id", "id"))
    dispute_id: str = Field(..., min_length=1)


class CaseOutcomeReceiptPayload(_StrictModel):
    case_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("case_id", "id"))
    outcome: Json | str | None = None


class ModActionReceiptPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, validation_alias=AliasChoices("target_id", "id"))
    action: str | None = None
    visibility: str | None = None
    locked: bool | int | None = None
    labels: list[str] | None = None


class FlagEscalationReceiptPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    dispute_id: str = Field(..., min_length=1)




# ============================================================
# Batch 5 remaining canon coverage
# ============================================================


class AccountBanPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    reason: str | None = None


class AccountReinstatePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    reason: str | None = None


class BalanceTransferPayload(_StrictModel):
    to_account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("to_account_id", "to", "target", "account"))
    amount: int = Field(..., ge=1)
    from_account_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("from_account_id", "from_account", "from"))
    memo: str | None = None


class FeePayPayload(_StrictModel):
    tx_id: str | None = Field(default=None, min_length=1)
    tx_type: str | None = Field(default=None, min_length=1)
    amount: int | None = Field(default=None, ge=0)
    from_account_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("from_account_id", "from_account", "from"))
    to_account_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("to_account_id", "to", "target", "account"))
    note: str | None = None


class EconomicsActivationPayload(_StrictModel):
    enable: bool | None = None
    enabled: bool | None = None


class FeePolicySetPayload(_StrictModel):
    transfer_fee_int: int | None = Field(default=None, ge=0)
    policy: Json | None = None


class RateLimitPolicySetPayload(_StrictModel):
    window_ms: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, ge=0)
    scope: str | None = None
    policy: Json | None = None


class RateLimitStrikeApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account"))
    reason: str | None = None


class MempoolRejectReceiptPayload(_StrictModel):
    tx_id: str | None = Field(default=None, min_length=1)
    tx_type: str | None = Field(default=None, min_length=1)
    code: str | None = None
    reason: str | None = None


class RewardPoolOptInSetPayload(_StrictModel):
    enabled: bool | None = None


class BlockRewardMintPayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    amount: int | None = Field(default=None, ge=0)


class BlockRewardDistributePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class CreatorRewardAllocatePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    alloc_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("alloc_id", "id"))
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class TreasuryRewardAllocatePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    alloc_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("alloc_id", "id"))
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class ForfeitureApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    amount: int | None = Field(default=None, ge=0)
    forfeit_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("forfeit_id", "id"))


class SubjectPerformanceReportPayload(_StrictModel):
    subject: str = Field(..., min_length=1, validation_alias=AliasChoices("subject", "account_id", "account", "target"))
    report_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("report_id", "id"))
    metrics: Json | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PerformanceReceiptPayload(_StrictModel):
    subject: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("subject", "account_id", "account", "target"))
    report_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("report_id", "id"))
    metrics: Json | None = None
    score: int | float | None = None


class ContentLabelSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, validation_alias=AliasChoices("target_id", "id"))
    labels: list[str] = Field(..., min_length=1)


class ContentVisibilitySetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, validation_alias=AliasChoices("target_id", "id"))
    visibility: str = Field(..., min_length=1)


class ContentThreadLockSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, validation_alias=AliasChoices("target_id", "post_id", "id"))
    locked: bool = Field(...)


class ContentMediaReplacePayload(_StrictModel):
    media_id: str = Field(..., min_length=1)
    new_cid: str = Field(..., min_length=1, validation_alias=AliasChoices("new_cid", "cid"))

    @model_validator(mode="after")
    def _validate_cid(self) -> "ContentMediaReplacePayload":
        validate_ipfs_cid(self.new_cid)
        return self


class ContentMediaUnbindPayload(_StrictModel):
    binding_id: str = Field(..., min_length=1)
    content_id: str | None = Field(default=None, min_length=1)
    media_id: str | None = Field(default=None, min_length=1)


class ContentEscalateToDisputePayload(_StrictModel):
    target_type: str | None = None
    target_id: str = Field(..., min_length=1)
    reason: str | None = None
    dispute_id: str | None = Field(default=None, min_length=1)


class NotificationEmitReceiptPayload(_StrictModel):
    topic: str | None = None
    account_id: str | None = Field(default=None, min_length=1)
    receipt_id: str | None = Field(default=None, min_length=1)


class IndexAnchorSetPayload(_StrictModel):
    anchor_id: str = Field(..., min_length=1, validation_alias=AliasChoices("anchor_id", "id", "cid"))


class StateSnapshotDeclarePayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1, validation_alias=AliasChoices("snapshot_id", "id", "cid"))
    hash: str | None = None
    meta: Json | None = None


class StateSnapshotAcceptPayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1, validation_alias=AliasChoices("snapshot_id", "id", "cid"))


class ColdSyncRequestPayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1)
    request_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("request_id", "id"))


class ColdSyncCompletePayload(_StrictModel):
    request_id: str = Field(..., min_length=1, validation_alias=AliasChoices("request_id", "id"))


class IndexTopicRegisterPayload(_StrictModel):
    topic: str = Field(..., min_length=1, validation_alias=AliasChoices("topic", "name"))
    config: Json | None = None


class IndexTopicAnchorSetPayload(_StrictModel):
    topic: str = Field(..., min_length=1)
    anchor_id: str = Field(..., min_length=1, validation_alias=AliasChoices("anchor_id", "id", "cid"))


class TxReceiptEmitPayload(_StrictModel):
    receipt_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("receipt_id", "id"))
    tx_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("tx_id", "txhash", "tx_hash"))
    tx_type: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_receipt_or_tx(self) -> "TxReceiptEmitPayload":
        if not self.receipt_id and not (self.tx_id and self.tx_type):
            raise ValueError("either receipt_id or tx_id+tx_type is required")
        return self


class RoleEligibilitySetPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    role: str = Field(..., min_length=1)


class RoleEligibilityRevokePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    role: str = Field(..., min_length=1)


class RoleEmissaryNominatePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "emissary", "target", "account"))


class RoleEmissaryVotePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "emissary", "target", "account"))


class RoleEmissarySeatPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "emissary", "target", "account"))


class RoleEmissaryRemovePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "emissary", "target", "account"))
    reason: str | None = None


class RoleGovExecutorSetPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "executor", "target", "account", "gov_executor"))
    note: str | None = None


class AccountScopedRolePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "juror", "operator", "node_operator", "validator", "target", "account"))


class ReputationDeltaApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    delta: int | float | None = None
    delta_milli: int | None = None
    delta_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("delta_id", "id"))
    reason: str | None = None

    @model_validator(mode="after")
    def _validate_delta(self) -> "ReputationDeltaApplyPayload":
        if self.delta is None and self.delta_milli is None:
            raise ValueError("either delta or delta_milli is required")
        return self


class ReputationThresholdCrossPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, validation_alias=AliasChoices("account_id", "target", "account", "user"))
    threshold: str = Field(..., min_length=1, validation_alias=AliasChoices("threshold", "threshold_id"))
    direction: str | None = None
    cross_id: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("cross_id", "id"))


class ValidatorRegisterPayload(_StrictModel):
    endpoint: str = Field(..., min_length=1)
    pubkey: str | None = Field(default=None, min_length=1)
    node_id: str | None = Field(default=None, min_length=1)
    metadata_hash: str | None = None


class ValidatorCandidateRegisterPayload(_StrictModel):
    node_id: str = Field(..., min_length=1)
    pubkey: str = Field(..., min_length=1)
    endpoints: list[str] | None = None
    endpoint: str | None = Field(default=None, min_length=1)
    metadata_hash: str | None = None

    @model_validator(mode="after")
    def _validate_endpoint_source(self) -> "ValidatorCandidateRegisterPayload":
        if not self.endpoint and not self.endpoints:
            raise ValueError("either endpoint or endpoints is required")
        return self


class ValidatorCandidateApprovePayload(_StrictModel):
    account: str = Field(..., min_length=1)
    activate_at_epoch: int = Field(..., ge=1)


class ValidatorSuspendPayload(_StrictModel):
    account: str = Field(..., min_length=1)
    effective_epoch: int = Field(..., ge=1)
    reason: str | None = None


class ValidatorRemovePayload(_StrictModel):
    account: str = Field(..., min_length=1)
    effective_epoch: int = Field(..., ge=1)
    reason: str | None = None


class ValidatorDeregisterPayload(_StrictModel):
    account: str = Field(..., min_length=1)


class ValidatorSetUpdatePayload(_StrictModel):
    active_set: list[str] = Field(..., min_length=1)
    activate_at_epoch: int | None = Field(default=None, ge=0)
    activate_bft_at_epoch: int | None = Field(default=None, ge=0)


class ValidatorHeartbeatPayload(_StrictModel):
    node_id: str = Field(..., min_length=1)
    account: str | None = Field(default=None, min_length=1)
    ts_ms: int = Field(..., ge=1)


class ValidatorPerformanceReportPayload(_StrictModel):
    account: str | None = Field(default=None, min_length=1)
    validator: str | None = Field(default=None, min_length=1)
    ts_ms: int | None = Field(default=None, ge=0)
    report: Json | None = None


class BlockProposePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    height: int = Field(..., ge=1)


class BlockAttestPayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    validator: str | None = None
    attestation: str | None = None
    vote: str | None = None
    height: int | None = Field(default=None, ge=0)
    round: int | None = Field(default=None, ge=0)


class BlockFinalizePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, validation_alias=AliasChoices("block_id", "id"))
    height: int = Field(..., ge=1)


class EpochTransitionPayload(_StrictModel):
    epoch: int = Field(..., ge=1)


class SlashProposePayload(_StrictModel):
    slash_id: str = Field(..., min_length=1, validation_alias=AliasChoices("slash_id", "id"))
    subject: str | None = Field(default=None, min_length=1, validation_alias=AliasChoices("subject", "account_id", "account", "target"))
    reason: str | None = None
    evidence: Json | None = None


class SlashVotePayload(_StrictModel):
    slash_id: str = Field(..., min_length=1)
    vote: str = Field(..., min_length=1)


class SlashExecutePayload(_StrictModel):
    slash_id: str = Field(..., min_length=1)
    outcome: str | None = None
    amount: int | None = Field(default=None, ge=0)


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
    AccountSecurityPolicySetPayload,
    AccountLockPayload,
    AccountUnlockPayload,
    AccountRecoveryConfigSetPayload,
    AccountRecoveryRequestPayload,
    AccountRecoveryApprovePayload,
    AccountRecoveryCancelPayload,
    AccountRecoveryFinalizePayload,
    AccountRecoveryReceiptPayload,
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
    # Social / Messaging / Notifications
    ProfileUpdatePayload,
    FollowSetPayload,
    BlockSetPayload,
    MuteSetPayload,
    ContentShareCreatePayload,
    DirectMessageSendPayload,
    DirectMessageRedactPayload,
    NotificationSubscribePayload,
    NotificationUnsubscribePayload,
    # Networking / Storage
    PeerAdvertisePayload,
    PeerRendezvousTicketCreatePayload,
    PeerRendezvousTicketRevokePayload,
    PeerRequestConnectPayload,
    PeerBanSetPayload,
    PeerReputationSignalPayload,
    StorageOfferCreatePayload,
    StorageOfferWithdrawPayload,
    StorageLeaseCreatePayload,
    StorageLeaseRenewPayload,
    StorageLeaseRevokePayload,
    StorageProofSubmitPayload,
    StorageChallengeIssuePayload,
    StorageChallengeRespondPayload,
    StoragePayoutExecutePayload,
    StorageReportAnchorPayload,
    IpfsPinRequestPayload,
    IpfsPinConfirmPayload,
    # Governance
    GovProposalCreatePayload,
    GovVoteCastPayload,
    GovDelegationSetPayload,
    GovProposalEditPayload,
    GovProposalWithdrawPayload,
    GovStageSetPayload,
    GovQuorumSetPayload,
    GovRulesSetPayload,
    GovExecutePayload,
    GovExecutionReceiptPayload,
    ProtocolUpgradeDeclarePayload,
    ProtocolUpgradeActivatePayload,
    GovVoteRevokePayload,
    GovVotingClosePayload,
    GovTallyPublishPayload,
    GovProposalFinalizePayload,
    GovProposalReceiptPayload,
    # Dispute / Cases / Moderation
    DisputeOpenPayload,
    DisputeStageSetPayload,
    DisputeJurorAssignPayload,
    DisputeJurorAcceptPayload,
    DisputeJurorDeclinePayload,
    DisputeJurorAttendancePayload,
    DisputeEvidenceDeclarePayload,
    DisputeEvidenceBindPayload,
    DisputeVoteSubmitPayload,
    DisputeResolvePayload,
    DisputeAppealPayload,
    DisputeFinalReceiptPayload,
    CaseTypeRegisterPayload,
    CaseBindToDisputePayload,
    CaseOutcomeReceiptPayload,
    ModActionReceiptPayload,
    FlagEscalationReceiptPayload,
    # Remaining canon cleanup
    AccountBanPayload,
    AccountReinstatePayload,
    BalanceTransferPayload,
    FeePayPayload,
    EconomicsActivationPayload,
    FeePolicySetPayload,
    RateLimitPolicySetPayload,
    RateLimitStrikeApplyPayload,
    MempoolRejectReceiptPayload,
    RewardPoolOptInSetPayload,
    BlockRewardMintPayload,
    BlockRewardDistributePayload,
    CreatorRewardAllocatePayload,
    TreasuryRewardAllocatePayload,
    ForfeitureApplyPayload,
    SubjectPerformanceReportPayload,
    PerformanceReceiptPayload,
    ContentLabelSetPayload,
    ContentVisibilitySetPayload,
    ContentThreadLockSetPayload,
    ContentMediaReplacePayload,
    ContentMediaUnbindPayload,
    ContentEscalateToDisputePayload,
    NotificationEmitReceiptPayload,
    IndexAnchorSetPayload,
    StateSnapshotDeclarePayload,
    StateSnapshotAcceptPayload,
    ColdSyncRequestPayload,
    ColdSyncCompletePayload,
    IndexTopicRegisterPayload,
    IndexTopicAnchorSetPayload,
    TxReceiptEmitPayload,
    RoleEligibilitySetPayload,
    RoleEligibilityRevokePayload,
    RoleEmissaryNominatePayload,
    RoleEmissaryVotePayload,
    RoleEmissarySeatPayload,
    RoleEmissaryRemovePayload,
    RoleGovExecutorSetPayload,
    AccountScopedRolePayload,
    ReputationDeltaApplyPayload,
    ReputationThresholdCrossPayload,
    ValidatorRegisterPayload,
    ValidatorCandidateRegisterPayload,
    ValidatorCandidateApprovePayload,
    ValidatorSuspendPayload,
    ValidatorRemovePayload,
    ValidatorDeregisterPayload,
    ValidatorSetUpdatePayload,
    ValidatorHeartbeatPayload,
    ValidatorPerformanceReportPayload,
    BlockProposePayload,
    BlockAttestPayload,
    BlockFinalizePayload,
    EpochTransitionPayload,
    SlashProposePayload,
    SlashVotePayload,
    SlashExecutePayload,
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
    "ACCOUNT_SECURITY_POLICY_SET": AccountSecurityPolicySetPayload,
    "ACCOUNT_LOCK": AccountLockPayload,
    "ACCOUNT_UNLOCK": AccountUnlockPayload,
    "ACCOUNT_RECOVERY_CONFIG_SET": AccountRecoveryConfigSetPayload,
    "ACCOUNT_RECOVERY_REQUEST": AccountRecoveryRequestPayload,
    "ACCOUNT_RECOVERY_APPROVE": AccountRecoveryApprovePayload,
    "ACCOUNT_RECOVERY_CANCEL": AccountRecoveryCancelPayload,
    "ACCOUNT_RECOVERY_FINALIZE": AccountRecoveryFinalizePayload,
    "ACCOUNT_RECOVERY_RECEIPT": AccountRecoveryReceiptPayload,
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
    # Social
    "PROFILE_UPDATE": ProfileUpdatePayload,
    "FOLLOW_SET": FollowSetPayload,
    "BLOCK_SET": BlockSetPayload,
    "MUTE_SET": MuteSetPayload,
    "CONTENT_SHARE_CREATE": ContentShareCreatePayload,
    # Messaging
    "DIRECT_MESSAGE_SEND": DirectMessageSendPayload,
    "DIRECT_MESSAGE_REDACT": DirectMessageRedactPayload,
    # Notifications
    "NOTIFICATION_SUBSCRIBE": NotificationSubscribePayload,
    "NOTIFICATION_UNSUBSCRIBE": NotificationUnsubscribePayload,
    # Networking
    "PEER_ADVERTISE": PeerAdvertisePayload,
    "PEER_RENDEZVOUS_TICKET_CREATE": PeerRendezvousTicketCreatePayload,
    "PEER_RENDEZVOUS_TICKET_REVOKE": PeerRendezvousTicketRevokePayload,
    "PEER_REQUEST_CONNECT": PeerRequestConnectPayload,
    "PEER_BAN_SET": PeerBanSetPayload,
    "PEER_REPUTATION_SIGNAL": PeerReputationSignalPayload,
    # Storage
    "STORAGE_OFFER_CREATE": StorageOfferCreatePayload,
    "STORAGE_OFFER_WITHDRAW": StorageOfferWithdrawPayload,
    "STORAGE_LEASE_CREATE": StorageLeaseCreatePayload,
    "STORAGE_LEASE_RENEW": StorageLeaseRenewPayload,
    "STORAGE_LEASE_REVOKE": StorageLeaseRevokePayload,
    "STORAGE_PROOF_SUBMIT": StorageProofSubmitPayload,
    "STORAGE_CHALLENGE_ISSUE": StorageChallengeIssuePayload,
    "STORAGE_CHALLENGE_RESPOND": StorageChallengeRespondPayload,
    "STORAGE_PAYOUT_EXECUTE": StoragePayoutExecutePayload,
    "STORAGE_REPORT_ANCHOR": StorageReportAnchorPayload,
    "IPFS_PIN_REQUEST": IpfsPinRequestPayload,
    "IPFS_PIN_CONFIRM": IpfsPinConfirmPayload,
    # Treasury
    "TREASURY_CREATE": TreasuryCreatePayload,
    "TREASURY_SIGNERS_SET": TreasurySignersSetPayload,
    "TREASURY_WALLET_CREATE": TreasuryWalletCreatePayload,
    "TREASURY_SIGNER_ADD": TreasurySignerAddPayload,
    "TREASURY_SIGNER_REMOVE": TreasurySignerRemovePayload,
    "TREASURY_POLICY_SET": TreasuryPolicySetPayload,
    "TREASURY_SPEND_PROPOSE": TreasurySpendProposePayload,
    "TREASURY_SPEND_SIGN": TreasurySpendSignPayload,
    "TREASURY_SPEND_CANCEL": TreasurySpendCancelPayload,
    "TREASURY_SPEND_EXPIRE": TreasurySpendExpirePayload,
    "TREASURY_SPEND_EXECUTE": TreasurySpendExecutePayload,
    "TREASURY_PROGRAM_CREATE": TreasuryProgramCreatePayload,
    "TREASURY_PROGRAM_UPDATE": TreasuryProgramUpdatePayload,
    "TREASURY_PROGRAM_CLOSE": TreasuryProgramClosePayload,
    "TREASURY_AUDIT_ANCHOR_SET": TreasuryAuditAnchorSetPayload,
    # Groups
    "GROUP_CREATE": GroupCreatePayload,
    "GROUP_UPDATE": GroupUpdatePayload,
    "GROUP_ROLE_GRANT": GroupRoleGrantPayload,
    "GROUP_ROLE_REVOKE": GroupRoleRevokePayload,
    "GROUP_MEMBERSHIP_REQUEST": GroupMembershipRequestPayload,
    "GROUP_MEMBERSHIP_DECIDE": GroupMembershipDecidePayload,
    "GROUP_MEMBERSHIP_REMOVE": GroupMembershipRemovePayload,
    "GROUP_SIGNERS_SET": GroupSignersSetPayload,
    "GROUP_MODERATORS_SET": GroupModeratorsSetPayload,
    "GROUP_TREASURY_CREATE": GroupTreasuryCreatePayload,
    "GROUP_TREASURY_POLICY_SET": GroupTreasuryPolicySetPayload,
    "GROUP_TREASURY_SPEND_PROPOSE": GroupTreasurySpendProposePayload,
    "GROUP_TREASURY_SPEND_SIGN": GroupTreasurySpendSignPayload,
    "GROUP_TREASURY_SPEND_CANCEL": GroupTreasurySpendCancelPayload,
    "GROUP_TREASURY_SPEND_EXPIRE": GroupTreasurySpendExpirePayload,
    "GROUP_TREASURY_SPEND_EXECUTE": GroupTreasurySpendExecutePayload,
    "GROUP_TREASURY_AUDIT_ANCHOR_SET": GroupTreasuryAuditAnchorSetPayload,
    "GROUP_EMISSARY_ELECTION_CREATE": GroupEmissaryElectionCreatePayload,
    "GROUP_EMISSARY_BALLOT_CAST": GroupEmissaryBallotCastPayload,
    "GROUP_EMISSARY_ELECTION_FINALIZE": GroupEmissaryElectionFinalizePayload,
    # Governance
    "GOV_PROPOSAL_CREATE": GovProposalCreatePayload,
    "GOV_VOTE_CAST": GovVoteCastPayload,
    "GOV_DELEGATION_SET": GovDelegationSetPayload,
    "GOV_PROPOSAL_EDIT": GovProposalEditPayload,
    "GOV_PROPOSAL_WITHDRAW": GovProposalWithdrawPayload,
    "GOV_STAGE_SET": GovStageSetPayload,
    "GOV_QUORUM_SET": GovQuorumSetPayload,
    "GOV_RULES_SET": GovRulesSetPayload,
    "GOV_EXECUTE": GovExecutePayload,
    "GOV_EXECUTION_RECEIPT": GovExecutionReceiptPayload,
    "PROTOCOL_UPGRADE_DECLARE": ProtocolUpgradeDeclarePayload,
    "PROTOCOL_UPGRADE_ACTIVATE": ProtocolUpgradeActivatePayload,
    "GOV_VOTE_REVOKE": GovVoteRevokePayload,
    "GOV_VOTING_CLOSE": GovVotingClosePayload,
    "GOV_TALLY_PUBLISH": GovTallyPublishPayload,
    "GOV_PROPOSAL_FINALIZE": GovProposalFinalizePayload,
    "GOV_PROPOSAL_RECEIPT": GovProposalReceiptPayload,
    # Dispute / Cases / Moderation
    "DISPUTE_OPEN": DisputeOpenPayload,
    "DISPUTE_STAGE_SET": DisputeStageSetPayload,
    "DISPUTE_JUROR_ASSIGN": DisputeJurorAssignPayload,
    "DISPUTE_JUROR_ACCEPT": DisputeJurorAcceptPayload,
    "DISPUTE_JUROR_DECLINE": DisputeJurorDeclinePayload,
    "DISPUTE_JUROR_ATTENDANCE": DisputeJurorAttendancePayload,
    "DISPUTE_EVIDENCE_DECLARE": DisputeEvidenceDeclarePayload,
    "DISPUTE_EVIDENCE_BIND": DisputeEvidenceBindPayload,
    "DISPUTE_VOTE_SUBMIT": DisputeVoteSubmitPayload,
    "DISPUTE_RESOLVE": DisputeResolvePayload,
    "DISPUTE_APPEAL": DisputeAppealPayload,
    "DISPUTE_FINAL_RECEIPT": DisputeFinalReceiptPayload,
    "CASE_TYPE_REGISTER": CaseTypeRegisterPayload,
    "CASE_BIND_TO_DISPUTE": CaseBindToDisputePayload,
    "CASE_OUTCOME_RECEIPT": CaseOutcomeReceiptPayload,
    "MOD_ACTION_RECEIPT": ModActionReceiptPayload,
    "FLAG_ESCALATION_RECEIPT": FlagEscalationReceiptPayload,
    # Remaining canon cleanup
    "ACCOUNT_BAN": AccountBanPayload,
    "ACCOUNT_REINSTATE": AccountReinstatePayload,
    "BALANCE_TRANSFER": BalanceTransferPayload,
    "FEE_PAY": FeePayPayload,
    "ECONOMICS_ACTIVATION": EconomicsActivationPayload,
    "FEE_POLICY_SET": FeePolicySetPayload,
    "RATE_LIMIT_POLICY_SET": RateLimitPolicySetPayload,
    "RATE_LIMIT_STRIKE_APPLY": RateLimitStrikeApplyPayload,
    "MEMPOOL_REJECT_RECEIPT": MempoolRejectReceiptPayload,
    "REWARD_POOL_OPT_IN_SET": RewardPoolOptInSetPayload,
    "BLOCK_REWARD_MINT": BlockRewardMintPayload,
    "BLOCK_REWARD_DISTRIBUTE": BlockRewardDistributePayload,
    "CREATOR_REWARD_ALLOCATE": CreatorRewardAllocatePayload,
    "TREASURY_REWARD_ALLOCATE": TreasuryRewardAllocatePayload,
    "FORFEITURE_APPLY": ForfeitureApplyPayload,
    "CREATOR_PERFORMANCE_REPORT": SubjectPerformanceReportPayload,
    "NODE_OPERATOR_PERFORMANCE_REPORT": SubjectPerformanceReportPayload,
    "PERFORMANCE_EVALUATE": PerformanceReceiptPayload,
    "PERFORMANCE_SCORE_APPLY": PerformanceReceiptPayload,
    "CONTENT_LABEL_SET": ContentLabelSetPayload,
    "CONTENT_VISIBILITY_SET": ContentVisibilitySetPayload,
    "CONTENT_THREAD_LOCK_SET": ContentThreadLockSetPayload,
    "CONTENT_MEDIA_REPLACE": ContentMediaReplacePayload,
    "CONTENT_MEDIA_UNBIND": ContentMediaUnbindPayload,
    "CONTENT_ESCALATE_TO_DISPUTE": ContentEscalateToDisputePayload,
    "NOTIFICATION_EMIT_RECEIPT": NotificationEmitReceiptPayload,
    "INDEX_ANCHOR_SET": IndexAnchorSetPayload,
    "STATE_SNAPSHOT_DECLARE": StateSnapshotDeclarePayload,
    "STATE_SNAPSHOT_ACCEPT": StateSnapshotAcceptPayload,
    "COLD_SYNC_REQUEST": ColdSyncRequestPayload,
    "COLD_SYNC_COMPLETE": ColdSyncCompletePayload,
    "INDEX_TOPIC_REGISTER": IndexTopicRegisterPayload,
    "INDEX_TOPIC_ANCHOR_SET": IndexTopicAnchorSetPayload,
    "TX_RECEIPT_EMIT": TxReceiptEmitPayload,
    "ROLE_ELIGIBILITY_SET": RoleEligibilitySetPayload,
    "ROLE_ELIGIBILITY_REVOKE": RoleEligibilityRevokePayload,
    "ROLE_EMISSARY_NOMINATE": RoleEmissaryNominatePayload,
    "ROLE_EMISSARY_VOTE": RoleEmissaryVotePayload,
    "ROLE_EMISSARY_SEAT": RoleEmissarySeatPayload,
    "ROLE_EMISSARY_REMOVE": RoleEmissaryRemovePayload,
    "ROLE_GOV_EXECUTOR_SET": RoleGovExecutorSetPayload,
    "ROLE_JUROR_ENROLL": AccountScopedRolePayload,
    "ROLE_JUROR_ACTIVATE": AccountScopedRolePayload,
    "ROLE_JUROR_REINSTATE": AccountScopedRolePayload,
    "ROLE_JUROR_SUSPEND": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_ENROLL": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_ACTIVATE": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_SUSPEND": AccountScopedRolePayload,
    "ROLE_VALIDATOR_ACTIVATE": AccountScopedRolePayload,
    "ROLE_VALIDATOR_SUSPEND": AccountScopedRolePayload,
    "REPUTATION_DELTA_APPLY": ReputationDeltaApplyPayload,
    "REPUTATION_THRESHOLD_CROSS": ReputationThresholdCrossPayload,
    "VALIDATOR_REGISTER": ValidatorRegisterPayload,
    "VALIDATOR_CANDIDATE_REGISTER": ValidatorCandidateRegisterPayload,
    "VALIDATOR_CANDIDATE_APPROVE": ValidatorCandidateApprovePayload,
    "VALIDATOR_SUSPEND": ValidatorSuspendPayload,
    "VALIDATOR_REMOVE": ValidatorRemovePayload,
    "VALIDATOR_DEREGISTER": ValidatorDeregisterPayload,
    "VALIDATOR_SET_UPDATE": ValidatorSetUpdatePayload,
    "VALIDATOR_HEARTBEAT": ValidatorHeartbeatPayload,
    "VALIDATOR_PERFORMANCE_REPORT": ValidatorPerformanceReportPayload,
    "BLOCK_PROPOSE": BlockProposePayload,
    "BLOCK_ATTEST": BlockAttestPayload,
    "BLOCK_FINALIZE": BlockFinalizePayload,
    "EPOCH_OPEN": EpochTransitionPayload,
    "EPOCH_CLOSE": EpochTransitionPayload,
    "SLASH_PROPOSE": SlashProposePayload,
    "SLASH_VOTE": SlashVotePayload,
    "SLASH_EXECUTE": SlashExecutePayload,
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
