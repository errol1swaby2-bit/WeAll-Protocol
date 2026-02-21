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


# ---------------------------------------------------------------------------
# USER mempool: Profile / graph edges
# ---------------------------------------------------------------------------


class ProfileUpdatePayload(_ObjectOnlyModel):
    # Forward compatible; UI evolves.
    pass


class EdgeSetPayload(_StrictModel):
    target: str = Field(..., min_length=1)
    enabled: bool = Field(default=True)


# ---------------------------------------------------------------------------
# USER mempool: Social/content
# ---------------------------------------------------------------------------


class ContentPostCreatePayload(_ObjectOnlyModel):
    # Forward compatible. Common keys:
    # - text, tags, visibility, media_ids, reply_to, group_id, etc.
    pass


class ContentPostEditPayload(_ObjectOnlyModel):
    # Forward compatible edit payload.
    pass


class ContentPostDeletePayload(_StrictModel):
    post_id: str = Field(..., min_length=1)


class ContentCommentCreatePayload(_ObjectOnlyModel):
    pass


class ContentCommentDeletePayload(_StrictModel):
    comment_id: str = Field(..., min_length=1)


class ContentReactionSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    reaction: str = Field(..., min_length=1)
    enabled: bool = Field(default=True)


class ContentFlagPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)


class ContentShareCreatePayload(_StrictModel):
    target_id: str = Field(..., min_length=1)


class ContentShareDeletePayload(_StrictModel):
    share_id: str = Field(..., min_length=1)


class ContentMediaAttachPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    media_id: str = Field(..., min_length=1)


class ContentMediaDetachPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    media_id: str = Field(..., min_length=1)


class ContentTagSetPayload(_StrictModel):
    target_id: str = Field(..., min_length=1)
    tag: str = Field(..., min_length=1)
    enabled: bool = Field(default=True)


# ---------------------------------------------------------------------------
# USER mempool: Groups
# ---------------------------------------------------------------------------


class GroupCreatePayload(_ObjectOnlyModel):
    pass


class GroupUpdatePayload(_ObjectOnlyModel):
    pass


class GroupDeletePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)


class GroupJoinRequestPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    message: Optional[str] = Field(default=None)


class GroupJoinApprovePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)


class GroupJoinRejectPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    reason: Optional[str] = Field(default=None)


class GroupLeavePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)


class GroupRoleGrantPayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


class GroupRoleRevokePayload(_StrictModel):
    group_id: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# USER mempool: Disputes
# ---------------------------------------------------------------------------


class DisputeOpenPayload(_ObjectOnlyModel):
    pass


class DisputeEvidenceAddPayload(_ObjectOnlyModel):
    pass


class DisputeVoteCastPayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    option: str = Field(..., min_length=1)


class DisputeResolvePayload(_StrictModel):
    dispute_id: str = Field(..., min_length=1)
    outcome: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# USER mempool: PoH
# ---------------------------------------------------------------------------


class PoHTier2RequestPayload(_StrictModel):
    # Minimal request; details may evolve.
    account_id: Optional[str] = Field(default=None, min_length=1)
    target: Optional[str] = Field(default=None, min_length=1)

    if _PYDANTIC_V2:  # pragma: no cover
        @model_validator(mode="after")
        def _one_of(self) -> "PoHTier2RequestPayload":
            if not any(str(v or "").strip() for v in [self.account_id, self.target]):
                raise ValueError("missing_account_id")
            return self
    else:  # pragma: no cover
        @root_validator
        def _one_of(cls, values: Dict[str, Any]) -> Dict[str, Any]:
            if not any(str(values.get(k) or "").strip() for k in ["account_id", "target"]):
                raise ValueError("missing_account_id")
            return values


class PoHTier3VideoSubmitPayload(_StrictModel):
    video_cid: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# USER mempool: Economics
# ---------------------------------------------------------------------------


class BalanceTransferPayload(_StrictModel):
    to: str = Field(..., min_length=1)
    amount: int = Field(..., ge=0)


class FeePayPayload(_StrictModel):
    # Internal system charging could evolve; keep strict.
    amount: int = Field(..., ge=0)


# ---------------------------------------------------------------------------
# VALIDATOR mempool
# ---------------------------------------------------------------------------


class ValidatorHeartbeatPayload(_StrictModel):
    height: int = Field(..., ge=0)
    ts_ms: int = Field(..., ge=0)


class ValidatorPerfReportPayload(_ObjectOnlyModel):
    pass


class BlockAttestPayload(_StrictModel):
    block_id: str = Field(..., min_length=1)
    height: int = Field(..., ge=0)


# ---------------------------------------------------------------------------
# SYSTEM receipts (consensus-critical where enforced)
# ---------------------------------------------------------------------------


class ReceiptOkPayload(_ObjectOnlyModel):
    # Default receipt blob; forward compatible.
    pass


class EconomicsActivationPayload(_StrictModel):
    activated: bool = Field(...)


class FeePolicySetPayload(_ObjectOnlyModel):
    pass


class RateLimitPolicySetPayload(_ObjectOnlyModel):
    pass


class AccountLockPayload(_StrictModel):
    account_id: str = Field(..., min_length=1)
    locked: bool = Field(...)


class AccountRecoveryReceiptPayload(_ObjectOnlyModel):
    pass


class ReputationDeltaApplyPayload(_ObjectOnlyModel):
    pass


class ReputationThresholdCrossPayload(_ObjectOnlyModel):
    pass


class AccountBanPayload(_ObjectOnlyModel):
    pass


class GovProposalIdPayload(_StrictModel):
    proposal_id: str = Field(..., min_length=1)


class GovStageSetPayload(_ObjectOnlyModel):
    pass


class GovQuorumSetPayload(_ObjectOnlyModel):
    pass


class GovRulesSetPayload(_ObjectOnlyModel):
    pass


class GovExecutionReceiptPayload(_ObjectOnlyModel):
    pass


class GovVoteCastPayload(_ObjectOnlyModel):
    pass


class GovFinalizeReceiptPayload(_ObjectOnlyModel):
    pass


class GovParamChangeReceiptPayload(_ObjectOnlyModel):
    pass


class ConsensusEquivocationSlashReceiptPayload(_ObjectOnlyModel):
    pass


# ---------------------------------------------------------------------------
# Schema map
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


def has_schema(tx_type: str) -> bool:
    """Return True if this tx_type has a schema.

    Receipt-only canon tx types are treated as having a schema because they are
    validated against the default receipt schema.
    """

    return _schema_for(tx_type) is not None


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
