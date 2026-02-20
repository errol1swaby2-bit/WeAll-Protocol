from __future__ import annotations

"""Transaction payload schemas.

This module provides optional (but recommended) payload shape validation for canon TxTypes
(see generated/tx_index.json). Validation is invoked by tx_admission when:

    WEALL_ENFORCE_TX_SCHEMA=true

HARDENING POLICY (production):
- USER mempool txs: strict schemas where feasible (reject unknown keys).
- VALIDATOR mempool txs: strict schemas (liveness/consensus signals).
- SYSTEM receipt/block txs: at minimum require payload is a JSON object (dict) or None.
  For consensus-critical SYSTEM receipts we additionally provide strict schemas.

Apply-layer code still enforces semantics. These schemas are early, consensus-safe
shape checks (types/required keys) to prevent malformed payloads from causing divergent
state transitions across nodes.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, Union

from pydantic import BaseModel, Field, ValidationError

# Pydantic v1/v2 compatibility:
# - v2 provides ConfigDict + model_validator
# - v1 uses inner Config + root_validator
try:  # pragma: no cover
    from pydantic import ConfigDict, model_validator  # type: ignore

    _PYDANTIC_V2 = True
except Exception:  # pragma: no cover
    from pydantic import root_validator  # type: ignore

    ConfigDict = dict  # type: ignore
    _PYDANTIC_V2 = False

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Base Models
# ---------------------------------------------------------------------------


class _StrictModel(BaseModel):
    """Strict model: reject unknown keys."""

    if _PYDANTIC_V2:  # pragma: no cover
        model_config = ConfigDict(extra="forbid")
    else:  # pragma: no cover
        class Config:
            extra = "forbid"


class _ObjectOnlyModel(BaseModel):
    """Object-only model: payload must be a JSON object; keys may evolve."""

    if _PYDANTIC_V2:  # pragma: no cover
        model_config = ConfigDict(extra="allow")
    else:  # pragma: no cover
        class Config:
            extra = "allow"


@dataclass(frozen=True)
class TxMeta:
    origin: str
    context: str
    receipt_only: bool


def _load_tx_meta() -> Dict[str, TxMeta]:
    """Best-effort load of canon meta from generated/tx_index.json.

    This file exists in repo/runtime deployments. In unit-test contexts it should
    also exist. If missing, we fall back to schema-only validation.
    """

    try:
        # src/weall/runtime/tx_schema.py -> src/weall/runtime -> src/weall -> src -> repo_root
        repo_root = Path(__file__).resolve().parents[3]
        idx_path = repo_root / "generated" / "tx_index.json"
        if not idx_path.exists():
            return {}
        import json

        idx = json.loads(idx_path.read_text())
        by_id = idx.get("by_id")
        if not isinstance(by_id, dict):
            return {}
        out: Dict[str, TxMeta] = {}
        for _id, spec in by_id.items():
            if not isinstance(spec, dict):
                continue
            name = str(spec.get("name") or "").strip().upper()
            if not name:
                continue
            out[name] = TxMeta(
                origin=str(spec.get("origin") or "").strip().upper(),
                context=str(spec.get("context") or "").strip().lower(),
                receipt_only=bool(spec.get("receipt_only", False)),
            )
        return out
    except Exception:
        return {}


_TX_META: Dict[str, TxMeta] = _load_tx_meta()


def _meta(tx_type: str) -> Optional[TxMeta]:
    return _TX_META.get(str(tx_type or "").strip().upper())


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _AccountPickerModel(_StrictModel):
    """Common pattern: many txs accept multiple alias keys for an account.

    We allow the keys but require at least one non-empty.
    """

    account_id: Optional[str] = None
    target: Optional[str] = None
    account: Optional[str] = None
    user: Optional[str] = None
    juror: Optional[str] = None
    operator: Optional[str] = None

    if _PYDANTIC_V2:  # pragma: no cover
        @model_validator(mode="after")
        def _at_least_one(self) -> "_AccountPickerModel":
            vals = [self.account_id, self.target, self.account, self.user, self.juror, self.operator]
            if not any(str(v or "").strip() for v in vals):
                raise ValueError("missing_account_id")
            return self
    else:  # pragma: no cover
        @root_validator
        def _at_least_one(cls, values: Dict[str, Any]) -> Dict[str, Any]:
            vals = [
                values.get("account_id"),
                values.get("target"),
                values.get("account"),
                values.get("user"),
                values.get("juror"),
                values.get("operator"),
            ]
            if not any(str(v or "").strip() for v in vals):
                raise ValueError("missing_account_id")
            return values


# ---------------------------------------------------------------------------
# USER mempool: Identity
# ---------------------------------------------------------------------------


class AccountRegisterPayload(_StrictModel):
    account_id: Optional[str] = Field(default=None, min_length=1)
    pubkey: Optional[str] = Field(default=None, min_length=1)
    email_hash: Optional[str] = Field(default=None, min_length=1)


class AccountKeyAddPayload(_StrictModel):
    pubkey: str = Field(..., min_length=1)


class AccountKeyRevokePayload(_StrictModel):
    pubkey: str = Field(..., min_length=1)


class AccountDeviceRegisterPayload(_StrictModel):
    device_id: str = Field(..., min_length=1)


class AccountDeviceRevokePayload(_StrictModel):
    device_id: str = Field(..., min_length=1)


class AccountSessionKeyIssuePayload(_StrictModel):
    session_pubkey: str = Field(..., min_length=1)
    expires_ts_ms: int = Field(..., ge=0)


class AccountSessionKeyRevokePayload(_StrictModel):
    session_key: str = Field(..., min_length=1)


class AccountGuardianAddPayload(_StrictModel):
    guardian: str = Field(..., min_length=1)


class AccountGuardianRemovePayload(_StrictModel):
    guardian: str = Field(..., min_length=1)


class AccountRecoveryConfigSetPayload(_StrictModel):
    enabled: Optional[bool] = None
    threshold: Optional[int] = Field(default=None, ge=0)


class AccountRecoveryRequestPayload(_StrictModel):
    target: str = Field(..., min_length=1)
    request_id: Optional[str] = None
    new_pubkey: Optional[str] = None


class AccountRecoveryCancelPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)


class AccountRecoveryApprovePayload(_StrictModel):
    request_id: str = Field(..., min_length=1)


class AccountSecurityPolicySetPayload(_ObjectOnlyModel):
    """Forward-compatible policy blob."""


# ---------------------------------------------------------------------------
# USER mempool: Economics
# ---------------------------------------------------------------------------


class BalanceTransferPayload(_StrictModel):
    to: str = Field(..., min_length=1)
    amount: int = Field(..., ge=0)


class FeePayPayload(_ObjectOnlyModel):
    """Forward-compatible fee payment blob."""


# ---------------------------------------------------------------------------
# USER mempool: Social / Content
# ---------------------------------------------------------------------------


class ProfileUpdatePayload(_StrictModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_cid: Optional[str] = None
    banner_cid: Optional[str] = None
    website: Optional[str] = None
    location: Optional[str] = None
    tags: Optional[List[str]] = None


class EdgeSetPayload(_StrictModel):
    # Used for FOLLOW_SET / BLOCK_SET / MUTE_SET
    target: Optional[str] = None
    account_id: Optional[str] = None
    active: Optional[bool] = True


class ContentPostCreatePayload(_StrictModel):
    post_id: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)


class ContentPostEditPayload(_StrictModel):
    post_id: str = Field(..., min_length=1)
    body: Optional[str] = None
    cid: Optional[str] = None


class ContentPostDeletePayload(_StrictModel):
    post_id: str = Field(..., min_length=1)


class ContentCommentCreatePayload(_StrictModel):
    comment_id: str = Field(..., min_length=1)
    post_id: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)


class ContentCommentDeletePayload(_StrictModel):
    comment_id: str = Field(..., min_length=1)


class ContentReactionSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    reaction: str = Field(..., min_length=1)


class ContentFlagPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    flag_id: Optional[str] = None
    reason: Optional[str] = None


class ContentShareCreatePayload(_StrictModel):
    share_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)


class ContentShareDeletePayload(_StrictModel):
    share_id: str = Field(..., min_length=1)


class ContentMediaAttachPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    cid: str = Field(..., min_length=1)
    mime: Optional[str] = None
    bytes: Optional[int] = Field(default=None, ge=0)


class ContentMediaDetachPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    cid: str = Field(..., min_length=1)


class ContentTagSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    tags: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# USER mempool: Groups / Communities
# ---------------------------------------------------------------------------


class GroupCreatePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    private: Optional[bool] = False


class GroupUpdatePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    name: Optional[str] = None
    private: Optional[bool] = None
    rules: Optional[Dict[str, Any]] = None


class GroupDeletePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)


class GroupJoinRequestPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    request_id: Optional[str] = None
    message: Optional[str] = None


class GroupJoinApprovePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)


class GroupJoinRejectPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)


class GroupLeavePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)


class GroupRoleGrantPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


class GroupRoleRevokePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# USER mempool: Disputes / Moderation
# ---------------------------------------------------------------------------


class DisputeOpenPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    reason: Optional[str] = None


class DisputeEvidenceAddPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    evidence_cid: str = Field(..., min_length=1)


class DisputeVoteCastPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    vote: str = Field(..., min_length=1)


class DisputeResolvePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    outcome: Optional[str] = None


# ---------------------------------------------------------------------------
# USER mempool: PoH user actions
# ---------------------------------------------------------------------------


class PoHTier2RequestPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)
    email: Optional[str] = None
    email_hash: Optional[str] = None


class PoHTier3VideoSubmitPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)
    cid: str = Field(..., min_length=1)
    bytes: Optional[int] = Field(default=None, ge=0)


# ---------------------------------------------------------------------------
# VALIDATOR mempool: liveness + consensus signals
# ---------------------------------------------------------------------------


class ValidatorHeartbeatPayload(_StrictModel):
    node_id: str = Field(..., min_length=1)
    ts_ms: int = Field(..., ge=0)


class ValidatorPerfReportPayload(_StrictModel):
    node_id: str = Field(..., min_length=1)
    epoch: int = Field(..., ge=0)
    blocks_produced: Optional[int] = Field(default=None, ge=0)
    attestations_signed: Optional[int] = Field(default=None, ge=0)


class BlockAttestPayload(_StrictModel):
    block_id: str = Field(..., min_length=1)
    block_hash: str = Field(..., min_length=1)
    height: int = Field(..., ge=0)
    signer: Optional[str] = None
    sig: Optional[str] = None


# ---------------------------------------------------------------------------
# SYSTEM receipts: minimum object-only
# ---------------------------------------------------------------------------


class ReceiptOkPayload(_ObjectOnlyModel):
    ok: Optional[bool] = True
    code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# SYSTEM receipts: strict for consensus-critical txs
# ---------------------------------------------------------------------------


class EconomicsActivationPayload(_StrictModel):
    enable: Optional[bool] = None
    enabled: Optional[bool] = None


class FeePolicySetPayload(_ObjectOnlyModel):
    """Policy blob; ints are normalized in apply layer."""


class RateLimitPolicySetPayload(_ObjectOnlyModel):
    """Anti-spam policy; forward-compatible."""


class AccountLockPayload(_StrictModel):
    target: str = Field(..., min_length=1)


class AccountRecoveryReceiptPayload(_StrictModel):
    request_id: str = Field(..., min_length=1)
    ok: bool = True
    code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ReputationDeltaApplyPayload(_AccountPickerModel):
    delta: Union[int, float, str]
    delta_id: Optional[str] = None
    id: Optional[str] = None
    reason: Optional[str] = None


class ReputationThresholdCrossPayload(_AccountPickerModel):
    threshold: Optional[str] = None
    threshold_id: Optional[str] = None
    direction: Optional[str] = None
    cross_id: Optional[str] = None
    id: Optional[str] = None

    if _PYDANTIC_V2:  # pragma: no cover
        @model_validator(mode="after")
        def _need_threshold(self) -> "ReputationThresholdCrossPayload":
            th = str(self.threshold or self.threshold_id or "").strip()
            if not th:
                raise ValueError("missing_threshold")
            if self.direction is not None:
                d = str(self.direction).strip().lower()
                if d and d not in {"up", "down", "above", "below", "cross"}:
                    raise ValueError("bad_direction")
            return self
    else:  # pragma: no cover
        @root_validator
        def _need_threshold(cls, values: Dict[str, Any]) -> Dict[str, Any]:
            th = str(values.get("threshold") or values.get("threshold_id") or "").strip()
            if not th:
                raise ValueError("missing_threshold")
            direction = values.get("direction")
            if direction is not None:
                d = str(direction).strip().lower()
                if d and d not in {"up", "down", "above", "below", "cross"}:
                    raise ValueError("bad_direction")
            return values


class AccountBanPayload(_AccountPickerModel):
    reason: Optional[str] = None


class GovProposalIdPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    _parent_ref: Optional[str] = None


class GovStageSetPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    stage: Optional[str] = None
    _parent_ref: Optional[str] = None


class GovQuorumSetPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    quorum: Optional[Union[int, float, str]] = None
    _parent_ref: Optional[str] = None


class GovRulesSetPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    rules: Optional[Dict[str, Any]] = None
    _parent_ref: Optional[str] = None


class GovExecutionReceiptPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    ok: bool = True
    code: Optional[str] = None
    _parent_ref: Optional[str] = None


class GovVoteCastPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    vote: str = Field(..., min_length=1)
    _parent_ref: Optional[str] = None


class GovFinalizeReceiptPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    ok: bool = True
    code: Optional[str] = None
    _parent_ref: Optional[str] = None


class GovParamChangeReceiptPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)
    ok: bool = True
    code: Optional[str] = None
    _parent_ref: Optional[str] = None


class ConsensusEquivocationSlashReceiptPayload(_StrictModel):
    offender: str = Field(..., min_length=1)
    ok: bool = True
    code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Tx type -> schema mapping
# ---------------------------------------------------------------------------

Schema = Type[BaseModel]

_SCHEMA_BY_TX_TYPE: Dict[str, Schema] = {
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
    "ACCOUNT_RECOVERY_CONFIG_SET": AccountRecoveryConfigSetPayload,
    "ACCOUNT_RECOVERY_REQUEST": AccountRecoveryRequestPayload,
    "ACCOUNT_RECOVERY_CANCEL": AccountRecoveryCancelPayload,
    "ACCOUNT_RECOVERY_APPROVE": AccountRecoveryApprovePayload,
    "ACCOUNT_SECURITY_POLICY_SET": AccountSecurityPolicySetPayload,
    # Economics
    "BALANCE_TRANSFER": BalanceTransferPayload,
    "FEE_PAY": FeePayPayload,
    # Social/content
    "PROFILE_UPDATE": ProfileUpdatePayload,
    "FOLLOW_SET": EdgeSetPayload,
    "BLOCK_SET": EdgeSetPayload,
    "MUTE_SET": EdgeSetPayload,
    "CONTENT_POST_CREATE": ContentPostCreatePayload,
    "CONTENT_POST_EDIT": ContentPostEditPayload,
    "CONTENT_POST_DELETE": ContentPostDeletePayload,
    "CONTENT_COMMENT_CREATE": ContentCommentCreatePayload,
    "CONTENT_COMMENT_DELETE": ContentCommentDeletePayload,
    "CONTENT_REACTION_SET": ContentReactionSetPayload,
    "CONTENT_FLAG": ContentFlagPayload,
    "CONTENT_SHARE_CREATE": ContentShareCreatePayload,
    "CONTENT_SHARE_DELETE": ContentShareDeletePayload,
    "CONTENT_MEDIA_ATTACH": ContentMediaAttachPayload,
    "CONTENT_MEDIA_DETACH": ContentMediaDetachPayload,
    "CONTENT_TAG_SET": ContentTagSetPayload,
    # Groups
    "GROUP_CREATE": GroupCreatePayload,
    "GROUP_UPDATE": GroupUpdatePayload,
    "GROUP_DELETE": GroupDeletePayload,
    "GROUP_JOIN_REQUEST": GroupJoinRequestPayload,
    "GROUP_JOIN_APPROVE": GroupJoinApprovePayload,
    "GROUP_JOIN_REJECT": GroupJoinRejectPayload,
    "GROUP_LEAVE": GroupLeavePayload,
    "GROUP_ROLE_GRANT": GroupRoleGrantPayload,
    "GROUP_ROLE_REVOKE": GroupRoleRevokePayload,
    # Disputes
    "DISPUTE_OPEN": DisputeOpenPayload,
    "DISPUTE_EVIDENCE_ADD": DisputeEvidenceAddPayload,
    "DISPUTE_VOTE_CAST": DisputeVoteCastPayload,
    "DISPUTE_RESOLVE": DisputeResolvePayload,
    # PoH
    "POH_TIER2_REQUEST": PoHTier2RequestPayload,
    "POH_TIER3_VIDEO_SUBMIT": PoHTier3VideoSubmitPayload,
    # Validator
    "VALIDATOR_HEARTBEAT": ValidatorHeartbeatPayload,
    "VALIDATOR_PERF_REPORT": ValidatorPerfReportPayload,
    "BLOCK_ATTEST": BlockAttestPayload,
    # System receipts / consensus critical
    "ECONOMICS_ACTIVATION": EconomicsActivationPayload,
    "FEE_POLICY_SET": FeePolicySetPayload,
    "RATE_LIMIT_POLICY_SET": RateLimitPolicySetPayload,
    "ACCOUNT_LOCK": AccountLockPayload,
    "ACCOUNT_RECOVERY_RECEIPT": AccountRecoveryReceiptPayload,
    "REPUTATION_DELTA_APPLY": ReputationDeltaApplyPayload,
    "REPUTATION_THRESHOLD_CROSS": ReputationThresholdCrossPayload,
    "ACCOUNT_BAN": AccountBanPayload,
    "GOV_PROPOSAL_ID": GovProposalIdPayload,
    "GOV_STAGE_SET": GovStageSetPayload,
    "GOV_QUORUM_SET": GovQuorumSetPayload,
    "GOV_RULES_SET": GovRulesSetPayload,
    "GOV_EXECUTION_RECEIPT": GovExecutionReceiptPayload,
    "GOV_VOTE_CAST": GovVoteCastPayload,
    "GOV_FINALIZE_RECEIPT": GovFinalizeReceiptPayload,
    "GOV_PARAM_CHANGE_RECEIPT": GovParamChangeReceiptPayload,
    "CONSENSUS_EQUIVOCATION_SLASH_RECEIPT": ConsensusEquivocationSlashReceiptPayload,
}

# Many system receipts are intentionally forward-compatible blobs.
_DEFAULT_RECEIPT_SCHEMA: Schema = ReceiptOkPayload


def _schema_for(tx_type: str) -> Optional[Schema]:
    t = str(tx_type or "").strip().upper()
    if not t:
        return None
    sch = _SCHEMA_BY_TX_TYPE.get(t)
    if sch is not None:
        return sch

    m = _meta(t)
    if m is not None and m.receipt_only:
        return _DEFAULT_RECEIPT_SCHEMA

    return None


def validate_payload(
    *,
    tx_type: str,
    payload: Any,
    origin: str,
    context: str,
    system: bool,
) -> Tuple[bool, str, str, Optional[Dict[str, Any]]]:
    """Validate payload against schema (best-effort).

    Returns: (ok, code, reason, details)
    """
    sch = _schema_for(tx_type)
    if sch is None:
        # No schema available: accept object-only for system receipts, otherwise accept as-is.
        if system:
            if payload is None or isinstance(payload, dict):
                return True, "", "", None
            return False, "schema:payload_not_object", "system_payload_must_be_object_or_null", None
        return True, "", "", None

    try:
        if payload is None:
            # Only allow None for object-only models; strict models generally require object anyway.
            if issubclass(sch, _ObjectOnlyModel):
                sch()  # ok
                return True, "", "", None
            return False, "schema:payload_missing", "payload_required", None

        if not isinstance(payload, dict):
            return False, "schema:payload_not_object", "payload_must_be_object", None

        sch(**payload)
        return True, "", "", None

    except ValidationError as ve:
        return False, "schema:validation_error", "payload_schema_mismatch", {"errors": ve.errors()}
    except Exception as e:
        return False, "schema:error", "payload_schema_error", {"err": str(e)}
