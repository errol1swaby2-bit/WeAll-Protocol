# File: src/weall/runtime/tx_schema.py

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from weall.util.ipfs_cid import validate_ipfs_cid

Json = dict[str, Any]

def _validate_public_cid_value(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    v = validate_ipfs_cid(value)
    if not v.ok:
        raise ValueError(f"{field_name}: {v.reason}")
    return value


def _normalized_public_cid_values(*pairs: tuple[str, str | None]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for field_name, value in pairs:
        if value is None:
            continue
        s = str(value or "").strip()
        if not s:
            continue
        _validate_public_cid_value(s, field_name)
        out.append((field_name, s))
    return out


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
    tier: int = Field(..., ge=0, le=2)


class PohApplicationSubmitPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    target_tier: int = Field(..., ge=0, le=2)
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
    case_id: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohChallengeResolvePayload(_StrictModel):
    challenge_id: str = Field(..., min_length=1)
    resolution: str = Field(..., min_length=1)
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)




class PohAsyncRequestOpenPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    case_id: str | None = None
    challenge_id: str | None = None
    challenge_commitment: str | None = None
    response_commitment: str | None = None
    expires_height: int | None = Field(default=None, ge=0)
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohAsyncEvidenceDeclarePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    evidence_id: str | None = None
    evidence_commitment: str | None = None
    response_commitment: str | None = None
    public_evidence_id: str | None = None
    evidence_cid: str | None = Field(default=None, min_length=1)
    uri: str | None = Field(default=None, min_length=1)
    mime: str | None = Field(default=None, min_length=1)
    name: str | None = Field(default=None, min_length=1)
    filename: str | None = Field(default=None, min_length=1)
    size: int | None = Field(default=None, ge=0)
    video_commitment: str | None = Field(default=None, min_length=1)
    kind: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohAsyncEvidenceBindPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    target_id: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohAsyncJurorAssignPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    jurors: list[str] = Field(..., min_length=1)
    min_reviews: int | None = Field(default=None, ge=0)
    approval_threshold: int | None = Field(default=None, ge=0)
    rejection_threshold: int | None = Field(default=None, ge=0)
    min_rep_milli: int | None = Field(default=None, ge=0)
    bootstrap_adaptive_quorum: dict[str, Any] | None = None


class PohAsyncJurorAcceptPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohAsyncJurorDeclinePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohAsyncReviewSubmitPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)
    reason_code: str | None = None
    review_commitment: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohAsyncFinalizePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    ts_ms: int | None = Field(default=None, ge=0)


class PohAsyncReceiptPayload(_StrictModel):
    receipt_id: str | None = None
    case_id: str = Field(..., min_length=1)
    outcome: str | None = None
    tier_awarded: int | None = Field(default=None, ge=0, le=2)
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
    ts_ms: int | None = Field(default=None, ge=0)
    min_total_reviews: int | None = Field(default=None, ge=0)
    pass_threshold: int | None = Field(default=None, ge=0)
    fail_max: int | None = Field(default=None, ge=0)


class PohTier2ReceiptPayload(_StrictModel):
    receipt_id: str | None = None
    case_id: str = Field(..., min_length=1)
    outcome: str | None = None
    tier_awarded: int | None = Field(default=None, ge=0, le=2)
    ts_ms: int | None = Field(default=None, ge=0)


class PohLiveRequestOpenPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    session_commitment: str | None = Field(default=None, min_length=1)
    room_commitment: str | None = Field(default=None, min_length=1)
    prompt_commitment: str | None = Field(default=None, min_length=1)
    device_pairing_commitment: str | None = Field(default=None, min_length=1)
    relay_commitment: str | None = Field(default=None, min_length=1)
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohLiveSessionInitPayload(_StrictModel):
    # Runtime/apply/poh.py requires case binding plus the same session
    # commitment opened by POH_LIVE_REQUEST_OPEN.  Optional transport
    # commitments are commitment-only; raw live-room authority stays off-chain.
    case_id: str = Field(..., min_length=1)
    account_id: str = Field(..., min_length=1)
    session_commitment: str = Field(..., min_length=1)
    room_commitment: str | None = None
    prompt_commitment: str | None = None
    device_pairing_commitment: str | None = None
    relay_commitment: str | None = None
    note: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohLiveJurorAssignPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    jurors: list[str]
    min_rep_milli: int | None = Field(default=None, ge=0)
    pass_threshold_num: int | None = Field(default=None, ge=1)
    pass_threshold_den: int | None = Field(default=None, ge=1)
    live_quorum: Any | None = None

    @model_validator(mode="after")
    def _check_jurors(self) -> "PohLiveJurorAssignPayload":
        if not (1 <= len(self.jurors) <= 10):
            raise ValueError("jurors must contain 1..10 entries")
        if len(set(self.jurors)) != len(self.jurors):
            raise ValueError("jurors must be unique")
        return self


class PohLiveJurorAcceptPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohLiveJurorDeclinePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohLiveJurorReplacePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    old_juror_id: str = Field(..., min_length=1)
    new_juror_id: str = Field(..., min_length=1)


class PohLiveAttendanceMarkPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str | None = None
    attended: bool = Field(...)
    # REQUIRED by runtime/apply/poh.py (bad_session_commitment) and by API skeletons.
    session_commitment: str | None = None
    # API skeletons default to 0; client should set Date.now().
    ts_ms: int | None = Field(default=None, ge=0)


class PohLiveVerdictSubmitPayload(_StrictModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)
    note: str | None = None
    # REQUIRED by runtime/apply/poh.py (bad_session_commitment) and by API skeletons.
    session_commitment: str | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PohLiveFinalizePayload(_StrictModel):
    case_id: str = Field(..., min_length=1)


class PohLiveReceiptPayload(_StrictModel):
    receipt_id: str | None = None
    case_id: str = Field(..., min_length=1)
    outcome: str | None = None
    tier_awarded: int | None = Field(default=None, ge=0, le=2)
    ts_ms: int | None = Field(default=None, ge=0)


class PohBootstrapTier2GrantPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    accepted: bool | None = None
    note: str | None = None




class PohTierRevokePayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    reason: str | None = None




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
    sha256: str | None = None
    content_sha256: str | None = None
    bytes_sha256: str | None = None
    digest_sha256: str | None = None

    @model_validator(mode="after")
    def _validate_public_cid_aliases(self) -> "ContentMediaDeclarePayload":
        values = _normalized_public_cid_values(
            ("cid", self.cid),
            ("ipfs_cid", self.ipfs_cid),
            ("content_cid", self.content_cid),
            ("upload_ref", self.upload_ref),
            ("ref", self.ref),
        )
        distinct = {cid for _, cid in values}
        if len(distinct) > 1:
            raise ValueError("content media CID aliases must refer to the same public content-addressed object")
        return self


class ContentMediaBindPayload(_StrictModel):
    binding_id: str | None = Field(default=None, min_length=1)
    media_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


# ============================================================
# Social / Notifications batch 1
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
    target: str = Field(..., min_length=1, )
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


class _TopicPayloadBase(_StrictModel):
    topic: str | list[str] = Field(..., )

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
        return _validate_public_cid_value(value, field_name)


class PeerAdvertisePayload(_StrictModel):
    endpoint: str = Field(
        ...,
        min_length=1,
        )
    peer_id: str | None = Field(
        default=None,
        min_length=1,
        )
    device_id: str | None = Field(default=None, min_length=1)
    node_pubkey: str | None = Field(
        default=None,
        min_length=1,
        )


class PeerRendezvousTicketCreatePayload(_StrictModel):
    target_peer: str = Field(..., min_length=1)
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        )


class PeerRendezvousTicketRevokePayload(_StrictModel):
    ticket_id: str = Field(
        ...,
        min_length=1,
        )


class PeerRequestConnectPayload(_StrictModel):
    peer_id: str | None = Field(
        default=None,
        min_length=1,
        )
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        )
    endpoint: str | None = Field(
        default=None,
        min_length=1,
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
        )
    banned: bool | None = None
    reason: str | None = None


class PeerReputationSignalPayload(_StrictModel):
    peer_id: str = Field(
        ...,
        min_length=1,
        )
    score: int | None = None
    reason: str | None = None


class StorageOfferCreatePayload(_OptionalCidPayload):
    offer_id: str | None = Field(
        default=None,
        min_length=1,
        )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        )
    cid: str | None = Field(
        default=None,
        min_length=1,
        )
    capacity_bytes: int | None = Field(
        default=None,
        ge=0,
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
        )


class StorageLeaseCreatePayload(_StrictModel):
    offer_id: str = Field(..., min_length=1)
    lease_id: str | None = Field(
        default=None,
        min_length=1,
        )
    duration_blocks: int | None = Field(
        default=None,
        ge=0,
        )


class StorageLeaseRenewPayload(_StrictModel):
    lease_id: str = Field(
        ...,
        min_length=1,
        )
    add_blocks: int | None = Field(
        default=None,
        ge=0,
        )


class StorageLeaseRevokePayload(_StrictModel):
    lease_id: str = Field(
        ...,
        min_length=1,
        )


class StorageProofSubmitPayload(_OptionalCidPayload):
    lease_id: str = Field(..., min_length=1)
    proof_cid: str | None = Field(
        default=None,
        min_length=1,
        )

    @model_validator(mode="after")
    def _validate_proof_cid(self) -> "StorageProofSubmitPayload":
        self._validate_cid_value(self.proof_cid, "proof_cid")
        return self


class StorageChallengeIssuePayload(_StrictModel):
    lease_id: str | None = Field(default=None, min_length=1)
    challenge_id: str | None = Field(
        default=None,
        min_length=1,
        )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        )
    account_id: str | None = Field(
        default=None,
        min_length=1,
        )
    proof_scope: str | None = Field(default=None, min_length=1, )
    node_pubkey: str | None = Field(default=None, min_length=1, )
    challenge_seed_commitment: str | None = Field(default=None, min_length=1, )
    challenge_count: int | None = Field(default=None, ge=0, )
    sample_size_bytes: int | None = Field(default=None, ge=0, )
    challenged_capacity_bytes: int | None = Field(default=None, ge=0, )
    expires_height: int | None = Field(default=None, ge=0, )
    reserved_capacity_bytes: int | None = Field(default=None, ge=0, )
    probe_offsets: list[int] | None = None
    challenge_seed: str | None = Field(default=None, min_length=1, )

    @model_validator(mode="after")
    def _validate_scope_fields(self) -> "StorageChallengeIssuePayload":
        scope = str(self.proof_scope or "lease").strip().lower()
        if scope in ("capacity", "storage_capacity", "capacity_probe", "storage_capacity_probe"):
            if not self.account_id and not self.operator_id:
                raise ValueError("account_id or operator_id is required for capacity probe challenges")
            if not self.challenge_count or int(self.challenge_count) <= 0:
                raise ValueError("challenge_count is required for capacity probe challenges")
            if not self.sample_size_bytes or int(self.sample_size_bytes) <= 0:
                raise ValueError("sample_size_bytes is required for capacity probe challenges")
            if not self.expires_height or int(self.expires_height) <= 0:
                raise ValueError("expires_height is required for capacity probe challenges")
            return self
        if not self.lease_id:
            raise ValueError("lease_id is required")
        return self


class StorageChallengeRespondPayload(_StrictModel):
    challenge_id: str = Field(
        ...,
        min_length=1,
        )
    proof_scope: str | None = Field(default=None, min_length=1, )
    response_commitment: str | None = Field(default=None, min_length=1, )
    sample_response_commitments: list[str] | None = Field(default=None, )
    measured_capacity_bytes: int | None = Field(default=None, ge=0, )
    verification_status: str | None = Field(default=None, min_length=1, )
    verified_capacity_bytes: int | None = Field(default=None, ge=0, )
    response_cid: str | None = Field(default=None, min_length=1)
    probe_responses: list[Json] | None = None
    verifier_id: str | None = Field(default=None, min_length=1, )
    verification_method: str | None = None
    verification_receipt_hash: str | None = Field(default=None, min_length=1, )
    proof_ttl_blocks: int | None = Field(default=None, ge=0, )


class StoragePayoutExecutePayload(_StrictModel):
    payout_id: str | None = Field(
        default=None,
        min_length=1,
        )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
        )
    amount: int | float | str | None = None


class StorageReportAnchorPayload(_OptionalCidPayload):
    report_id: str | None = Field(
        default=None,
        min_length=1,
        )
    report_cid: str | None = Field(
        default=None,
        min_length=1,
        )

    @model_validator(mode="after")
    def _validate_report_cid(self) -> "StorageReportAnchorPayload":
        self._validate_cid_value(self.report_cid, "report_cid")
        return self


class IpfsPinRequestPayload(_OptionalCidPayload):
    cid: str = Field(
        ...,
        min_length=1,
        )
    pin_id: str | None = Field(
        default=None,
        min_length=1,
        )
    size_bytes: int | None = Field(
        default=None,
        ge=0,
        )

    @model_validator(mode="after")
    def _validate_required_cid(self) -> "IpfsPinRequestPayload":
        self._validate_cid_value(self.cid, "cid")
        return self


class IpfsPinConfirmPayload(_OptionalCidPayload):
    pin_id: str = Field(
        ...,
        min_length=1,
        )
    cid: str | None = Field(
        default=None,
        min_length=1,
        )
    operator_id: str | None = Field(
        default=None,
        min_length=1,
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
    treasury_id: str = Field(..., min_length=1, )


class TreasurySignersSetPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, )
    signers: list[str] = Field(..., min_length=1)
    threshold: int | None = Field(default=None, ge=1)


class TreasuryWalletCreatePayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, )
    meta: Json | None = None


class TreasurySignerAddPayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, )
    signer: str = Field(..., min_length=1, )


class TreasurySignerRemovePayload(_StrictModel):
    wallet_id: str = Field(..., min_length=1, )
    signer: str = Field(..., min_length=1, )


class TreasuryPolicySetPayload(_StrictModel):
    policy: Json = Field(...)


class TreasurySpendProposePayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, )
    spend_id: str = Field(..., min_length=1)
    to: str = Field(..., min_length=1)
    amount: int = Field(..., ge=0)
    memo: str | None = None


class TreasurySpendSignPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, )
    spend_id: str = Field(..., min_length=1)


class TreasurySpendCancelPayload(_StrictModel):
    treasury_id: str = Field(..., min_length=1, )
    spend_id: str = Field(..., min_length=1)


class TreasurySpendExpirePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class TreasurySpendExecutePayload(_StrictModel):
    spend_id: str = Field(..., min_length=1)


class TreasuryProgramCreatePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, )
    config: Json | None = None


class TreasuryProgramUpdatePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, )
    patch: Json | None = None
    config: Json | None = None


class TreasuryProgramClosePayload(_StrictModel):
    program_id: str = Field(..., min_length=1, )


class TreasuryAuditAnchorSetPayload(_StrictModel):
    anchor: Json = Field(...)


class _PublicGroupPermissionsPayload(_StrictModel):
    posting_permission: str | None = None
    commenting_permission: str | None = None
    voting_permission: str | None = None
    moderation_permission: str | None = None
    administration_permission: str | None = None
    read_visibility: str | None = "public"

    @model_validator(mode="after")
    def _read_visibility_must_be_public(self):
        if str(self.read_visibility or "public").strip().lower() != "public":
            raise ValueError("PUBLIC_READ_VISIBILITY_REQUIRED")
        return self


class GroupCreatePayload(_PublicGroupPermissionsPayload):
    group_id: str = Field(..., min_length=1)
    charter: str | None = None


class GroupUpdatePayload(_PublicGroupPermissionsPayload):
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


class GovProposalEditPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    title: str | None = None
    body: str | None = None
    rules: Json | None = None
    actions: list[Json] | None = None
    reason: str | None = None
    revision_reason: str | None = None
    due_height: int | None = Field(default=None, ge=0, alias="_due_height")


class GovProposalCommentPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    body: str | None = None
    comment: str | None = None
    comment_id: str | None = None


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
    upgrade_id: str | None = Field(default=None, min_length=1, )
    version: str | None = None
    target_version: str | None = None
    hash: str | None = None
    commit: str | None = None


class ProtocolUpgradeActivatePayload(_StrictModel):
    upgrade_id: str | None = Field(default=None, min_length=1, )
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
    juror_id: str = Field(..., min_length=1, )


class DisputeJurorAcceptPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeJurorDeclinePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)


class DisputeJurorWithdrawPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    reason: str | None = None


class DisputeJurorTimeoutPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1, )
    deadline_height: int | None = Field(default=None, ge=0)


class DisputeJurorAttendancePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    present: bool | int | None = None


class DisputeEvidenceDeclarePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_id: str = Field(..., min_length=1)
    kind: str | None = None
    cid: str | None = None
    meta: Json | None = None

    @model_validator(mode="after")
    def _validate_public_evidence_cid(self) -> "DisputeEvidenceDeclarePayload":
        _validate_public_cid_value(self.cid, "cid")
        return self


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
    receipt_id: str | None = Field(default=None, min_length=1, )
    dispute_id: str | None = None
    resolution: Json | None = None
    parent_ref: str | None = Field(default=None, alias="_parent_ref")


class CaseTypeRegisterPayload(_StrictModel):
    case_type: str = Field(..., min_length=1, )


class CaseBindToDisputePayload(_StrictModel):
    case_id: str | None = Field(default=None, min_length=1, )
    dispute_id: str = Field(..., min_length=1)


class CaseOutcomeReceiptPayload(_StrictModel):
    case_id: str | None = Field(default=None, min_length=1, )
    outcome: Json | str | None = None


class ModActionReceiptPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, )
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
    account_id: str = Field(..., min_length=1, )
    reason: str | None = None


class AccountReinstatePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    reason: str | None = None


class BalanceTransferPayload(_StrictModel):
    to_account_id: str = Field(..., min_length=1, )
    amount: int = Field(..., ge=1)
    from_account_id: str | None = Field(default=None, min_length=1, )
    memo: str | None = None


class FeePayPayload(_StrictModel):
    tx_id: str | None = Field(default=None, min_length=1)
    tx_type: str | None = Field(default=None, min_length=1)
    amount: int | None = Field(default=None, ge=0)
    from_account_id: str | None = Field(default=None, min_length=1, )
    to_account_id: str | None = Field(default=None, min_length=1, )
    note: str | None = None


class EconomicsActivationPayload(_StrictModel):
    enable: bool | None = None
    enabled: bool | None = None


class FeePolicySetPayload(_StrictModel):
    transfer_fee_int: int | None = Field(default=None, ge=0)
    policy: Json | None = None


class RateLimitPolicySetPayload(_StrictModel):
    window_ms: int | None = Field(default=None, ge=1000, le=86_400_000)
    limit: int | None = Field(default=None, ge=1, le=1_000_000)
    scope: str | None = None
    policy: Json | None = None


class RateLimitStrikeApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    reason: str | None = None


class MempoolRejectReceiptPayload(_StrictModel):
    tx_id: str | None = Field(default=None, min_length=1)
    tx_type: str | None = Field(default=None, min_length=1)
    code: str | None = None
    reason: str | None = None


class RewardPoolOptInSetPayload(_StrictModel):
    enabled: bool | None = None


class BlockRewardMintPayload(_StrictModel):
    # Legacy tx name retained for compatibility; payload now represents one
    # v1.5 issuance epoch, not a per-block mint.
    block_id: str = Field(..., min_length=1, )
    amount: int | None = Field(default=None, ge=0)
    height: int | None = Field(default=None, ge=0)
    issuance_epoch: int | None = Field(default=None, ge=0)
    epoch_id: str | None = Field(default=None, min_length=1)
    fees: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)
    proposer: str | None = None


class BlockRewardDistributePayload(_StrictModel):
    # Legacy tx name retained for compatibility; payload now distributes one
    # v1.5 issuance epoch, not a per-block reward.
    block_id: str = Field(..., min_length=1, )
    height: int | None = Field(default=None, ge=0)
    issuance_epoch: int | None = Field(default=None, ge=0)
    epoch_id: str | None = Field(default=None, min_length=1)
    subsidy: int | None = Field(default=None, ge=0)
    fees: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)
    proposer: str | None = None
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class CreatorRewardAllocatePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, )
    alloc_id: str | None = Field(default=None, min_length=1, )
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class TreasuryRewardAllocatePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, )
    alloc_id: str | None = Field(default=None, min_length=1, )
    transfers: list[Json] | None = None
    debits: list[Json] | None = None


class ForfeitureApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    amount: int | None = Field(default=None, ge=0)
    forfeit_id: str | None = Field(default=None, min_length=1, )


class SubjectPerformanceReportPayload(_StrictModel):
    subject: str = Field(..., min_length=1, )
    report_id: str | None = Field(default=None, min_length=1, )
    metrics: Json | None = None
    ts_ms: int | None = Field(default=None, ge=0)


class PerformanceReceiptPayload(_StrictModel):
    subject: str | None = Field(default=None, min_length=1, )
    report_id: str | None = Field(default=None, min_length=1, )
    metrics: Json | None = None
    score: int | float | None = None


class ContentLabelSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, )
    labels: list[str] = Field(..., min_length=1)


class ContentVisibilitySetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, )
    visibility: str = Field(..., min_length=1)


class ContentThreadLockSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1, )
    locked: bool = Field(...)


class ContentMediaReplacePayload(_StrictModel):
    media_id: str = Field(..., min_length=1)
    new_cid: str = Field(..., min_length=1, )

    @model_validator(mode="after")
    def _validate_cid(self) -> "ContentMediaReplacePayload":
        _validate_public_cid_value(self.new_cid, "new_cid")
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
    anchor_id: str = Field(..., min_length=1, )


class StateSnapshotDeclarePayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1, )
    hash: str | None = None
    meta: Json | None = None


class StateSnapshotAcceptPayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1, )


class ColdSyncRequestPayload(_StrictModel):
    snapshot_id: str = Field(..., min_length=1)
    request_id: str | None = Field(default=None, min_length=1, )


class ColdSyncCompletePayload(_StrictModel):
    request_id: str = Field(..., min_length=1, )


class IndexTopicRegisterPayload(_StrictModel):
    topic: str = Field(..., min_length=1, )
    config: Json | None = None


class IndexTopicAnchorSetPayload(_StrictModel):
    topic: str = Field(..., min_length=1)
    anchor_id: str = Field(..., min_length=1, )


class TxReceiptEmitPayload(_StrictModel):
    receipt_id: str | None = Field(default=None, min_length=1, )
    tx_id: str | None = Field(default=None, min_length=1, )
    tx_type: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_receipt_or_tx(self) -> "TxReceiptEmitPayload":
        if not self.receipt_id and not (self.tx_id and self.tx_type):
            raise ValueError("either receipt_id or tx_id+tx_type is required")
        return self


class RoleEligibilitySetPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    role: str = Field(..., min_length=1)


class RoleEligibilityRevokePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    role: str = Field(..., min_length=1)


class RoleEmissaryNominatePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )


class RoleEmissaryVotePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )


class RoleEmissarySeatPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )


class RoleEmissaryRemovePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    reason: str | None = None


class RoleGovExecutorSetPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    note: str | None = None


class AccountScopedRolePayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    # Optional responsibility scaffold fields. These are currently used by
    # explicit NODE_OPERATOR_* responsibility transaction types to let an already-active baseline Node Operator
    # opt into validator/storage responsibility with clear production semantics.
    validator_opt_in: bool | None = None
    validator_readiness_commitment: str | None = None
    validator_endpoint_commitment: str | None = None
    validator_readiness_receipt_hash: str | None = None
    manifest_hash: str | None = None
    tx_index_hash: str | None = None
    runtime_profile_hash: str | None = None
    chain_id: str | None = None
    schema_version: str | None = None
    protocol_version: str | None = None
    bft_pubkey: str | None = Field(default=None, )
    readiness_checks: Json | None = None
    readiness_expires_height: int | None = Field(default=None, ge=0)
    verification_status: str | None = None
    reputation_required_milli: int | None = Field(default=None, ge=0)
    storage_opt_in: bool | None = None
    declared_capacity_bytes: int | None = Field(default=None, ge=0, )
    storage_endpoint_commitment: str | None = None
    node_pubkey: str | None = Field(default=None, )
    responsibilities: Json | None = None
    lane: str | None = Field(default=None, )
    reviewer_lanes: list[str] | None = None


class ReputationDeltaApplyPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    delta: int | float | None = None
    delta_milli: int | None = None
    delta_id: str | None = Field(default=None, min_length=1, )
    reason: str | None = None

    @model_validator(mode="after")
    def _validate_delta(self) -> "ReputationDeltaApplyPayload":
        if self.delta is None and self.delta_milli is None:
            raise ValueError("either delta or delta_milli is required")
        return self


class ReputationThresholdCrossPayload(_StrictModel):
    account_id: str = Field(..., min_length=1, )
    threshold: str = Field(..., min_length=1, )
    direction: str | None = None
    cross_id: str | None = Field(default=None, min_length=1, )


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
    block_id: str = Field(..., min_length=1, )
    height: int = Field(..., ge=1)


class BlockAttestPayload(_StrictModel):
    block_id: str = Field(..., min_length=1, )
    validator: str | None = None
    attestation: str | None = None
    vote: str | None = None
    height: int | None = Field(default=None, ge=0)
    round: int | None = Field(default=None, ge=0)


class BlockFinalizePayload(_StrictModel):
    block_id: str = Field(..., min_length=1, )
    height: int = Field(..., ge=1)


class EpochTransitionPayload(_StrictModel):
    epoch: int = Field(..., ge=1)


class SlashProposePayload(_StrictModel):
    slash_id: str = Field(..., min_length=1, )
    subject: str | None = Field(default=None, min_length=1, )
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
    PohAsyncRequestOpenPayload,
    PohAsyncEvidenceDeclarePayload,
    PohAsyncEvidenceBindPayload,
    PohAsyncJurorAssignPayload,
    PohAsyncJurorAcceptPayload,
    PohAsyncJurorDeclinePayload,
    PohAsyncReviewSubmitPayload,
    PohAsyncFinalizePayload,
    PohAsyncReceiptPayload,
    PohTier2RequestOpenPayload,
    PohTier2JurorAssignPayload,
    PohTier2JurorAcceptPayload,
    PohTier2JurorDeclinePayload,
    PohTier2ReviewSubmitPayload,
    PohTier2FinalizePayload,
    PohTier2ReceiptPayload,
    PohLiveSessionInitPayload,
    PohLiveJurorAssignPayload,
    PohLiveJurorAcceptPayload,
    PohLiveJurorDeclinePayload,
    PohLiveJurorReplacePayload,
    PohLiveAttendanceMarkPayload,
    PohLiveVerdictSubmitPayload,
    PohLiveFinalizePayload,
    PohLiveReceiptPayload,
    PohBootstrapTier2GrantPayload,
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
    # Social / Notifications
    ProfileUpdatePayload,
    FollowSetPayload,
    BlockSetPayload,
    MuteSetPayload,
    ContentShareCreatePayload,
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
    "POH_ASYNC_REQUEST_OPEN": PohAsyncRequestOpenPayload,
    "POH_ASYNC_EVIDENCE_DECLARE": PohAsyncEvidenceDeclarePayload,
    "POH_ASYNC_EVIDENCE_BIND": PohAsyncEvidenceBindPayload,
    "POH_ASYNC_JUROR_ASSIGN": PohAsyncJurorAssignPayload,
    "POH_ASYNC_JUROR_ACCEPT": PohAsyncJurorAcceptPayload,
    "POH_ASYNC_JUROR_DECLINE": PohAsyncJurorDeclinePayload,
    "POH_ASYNC_REVIEW_SUBMIT": PohAsyncReviewSubmitPayload,
    "POH_ASYNC_FINALIZE": PohAsyncFinalizePayload,
    "POH_ASYNC_RECEIPT": PohAsyncReceiptPayload,
    "POH_TIER2_REQUEST_OPEN": PohTier2RequestOpenPayload,
    "POH_TIER2_JUROR_ASSIGN": PohTier2JurorAssignPayload,
    "POH_TIER2_JUROR_ACCEPT": PohTier2JurorAcceptPayload,
    "POH_TIER2_JUROR_DECLINE": PohTier2JurorDeclinePayload,
    "POH_TIER2_REVIEW_SUBMIT": PohTier2ReviewSubmitPayload,
    "POH_TIER2_FINALIZE": PohTier2FinalizePayload,
    "POH_TIER2_RECEIPT": PohTier2ReceiptPayload,
    "POH_LIVE_REQUEST_OPEN": PohLiveRequestOpenPayload,
    "POH_LIVE_SESSION_INIT": PohLiveSessionInitPayload,
    "POH_LIVE_JUROR_ASSIGN": PohLiveJurorAssignPayload,
    "POH_LIVE_JUROR_ACCEPT": PohLiveJurorAcceptPayload,
    "POH_LIVE_JUROR_DECLINE": PohLiveJurorDeclinePayload,
    "POH_LIVE_JUROR_REPLACE": PohLiveJurorReplacePayload,
    "POH_LIVE_ATTENDANCE_MARK": PohLiveAttendanceMarkPayload,
    "POH_LIVE_VERDICT_SUBMIT": PohLiveVerdictSubmitPayload,
    "POH_LIVE_FINALIZE": PohLiveFinalizePayload,
    "POH_LIVE_RECEIPT": PohLiveReceiptPayload,
    "POH_BOOTSTRAP_TIER2_GRANT": PohBootstrapTier2GrantPayload,
    "POH_TIER_REVOKE": PohTierRevokePayload,
    # Content (canon)
    "CONTENT_POST_CREATE": ContentPostCreatePayload,
    "CONTENT_POST_EDIT": ContentPostEditPayload,
    "CONTENT_POST_DELETE": ContentPostDeletePayload,
    # Content (back-compat aliases)
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
    "STORAGE_CAPACITY_PROOF_VERIFY": StorageChallengeRespondPayload,
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
    "GOV_PROPOSAL_EDIT": GovProposalEditPayload,
    "GOV_PROPOSAL_COMMENT": GovProposalCommentPayload,
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
    "DISPUTE_JUROR_WITHDRAW": DisputeJurorWithdrawPayload,
    "DISPUTE_JUROR_TIMEOUT": DisputeJurorTimeoutPayload,
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
    "REVIEWER_LANE_OPT_IN": AccountScopedRolePayload,
    "REVIEWER_LANE_OPT_OUT": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_ENROLL": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_ACTIVATE": AccountScopedRolePayload,
    "ROLE_NODE_OPERATOR_SUSPEND": AccountScopedRolePayload,
    "NODE_OPERATOR_STORAGE_OPT_IN": AccountScopedRolePayload,
    "NODE_OPERATOR_VALIDATOR_OPT_IN": AccountScopedRolePayload,
    "NODE_OPERATOR_HELPER_OPT_IN": AccountScopedRolePayload,
    "NODE_OPERATOR_RESPONSIBILITY_UPDATE": AccountScopedRolePayload,
    "VALIDATOR_READINESS_VERIFY": AccountScopedRolePayload,
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


# Backwards-compatible alias used by tests and audit tooling.
PAYLOAD_MODELS = TX_PAYLOADS

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
