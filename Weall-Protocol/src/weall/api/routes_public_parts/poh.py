from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, File, Request, UploadFile
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _snapshot
from weall.api.security import require_account_session
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.util.ipfs_cid import validate_ipfs_cid

router = APIRouter()

Json = dict[str, Any]


class PohRouteConfigError(ValueError):
    """Raised when explicit PoH route envs are malformed in prod."""


_ALLOWED_TRUE = {"1", "true", "yes", "y", "on"}
_ALLOWED_FALSE = {"0", "false", "no", "n", "off"}


def _is_prod() -> bool:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return False
    return (str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod") == "prod"


# ---------------------------------------------------------------------------
# PoH native verification only
# ---------------------------------------------------------------------------
# External identity-provider verification routes were removed. Tier 1 is
# native async juror-attested PoH. Tier 2 is native live juror-attested PoH.

# ---------------------------------------------------------------------------
# PoH Tier2: Video intake (IPFS upload helper)
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    v = str(raw).strip().lower()
    if not v:
        return bool(default)
    if v in _ALLOWED_TRUE:
        return True
    if v in _ALLOWED_FALSE:
        return False
    if _is_prod():
        raise PohRouteConfigError(f"invalid_boolean_env:{name}")
    return bool(default)




def _now_ms() -> int:
    return int(time.time() * 1000)

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    v = str(raw).strip()
    if not v:
        return int(default)
    try:
        return int(v)
    except Exception as exc:
        if _is_prod():
            raise PohRouteConfigError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _file_size(up: UploadFile) -> int:
    # best-effort
    try:
        pos = up.file.tell()
        up.file.seek(0, 2)
        end = up.file.tell()
        up.file.seek(pos, 0)
        return int(end)
    except Exception:
        return -1


def _sha256_hex(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


class PohTier2VideoUploadResponse(BaseModel):
    ok: bool
    cid: str
    size: int
    name: str
    mime: str
    uri: str
    gateway_url: str
    video_commitment: str


async def _upload_poh_video_evidence(
    *,
    file: UploadFile,
    enabled_env: str,
    max_bytes_env: str,
    pin_env: str,
    default_name: str,
    default_max_bytes: int = 25 * 1024 * 1024,
) -> PohTier2VideoUploadResponse:
    if not _env_bool(enabled_env, False):
        raise ApiError.not_found("not_found", "endpoint_disabled")

    max_bytes = _env_int(max_bytes_env, default_max_bytes)

    name = (file.filename or default_name).strip() or default_name
    mime = (file.content_type or "").strip() or (
        mimetypes.guess_type(name)[0] or "application/octet-stream"
    )

    if not mime.startswith("video/"):
        raise ApiError.invalid("invalid_payload", "video_file_required")

    size = _file_size(file)
    if size == 0:
        raise ApiError.invalid("invalid_payload", "empty_file")
    if size > 0 and size > max_bytes:
        raise ApiError.invalid("invalid_payload", f"file_too_large (max {max_bytes} bytes)")

    try:
        file.file.seek(0)
    except Exception:
        pass

    pin_on_upload = _env_bool(pin_env, False)

    try:
        cid, ipfs_reported_size = ipfs_add_fileobj(
            name=name, fileobj=file.file, pin=bool(pin_on_upload)
        )
    except RuntimeError as e:
        raise ApiError.bad_request("ipfs_error", str(e))

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.bad_request("ipfs_error", f"invalid_cid_from_ipfs:{v.reason}")

    final_size = size if size >= 0 else int(ipfs_reported_size)
    uri = f"ipfs://{cid}"
    gw = ipfs_gateway_url(cid)
    video_commitment = _sha256_hex(cid.encode("utf-8"))

    return PohTier2VideoUploadResponse(
        ok=True,
        cid=cid,
        size=int(final_size),
        name=name,
        mime=mime,
        uri=uri,
        gateway_url=gw,
        video_commitment=video_commitment,
    )


@router.post(
    "/poh/async/evidence/video/upload",
    response_model=PohTier2VideoUploadResponse,
    name="poh_async_video_upload",
)
async def poh_async_video_upload(
    request: Request, file: UploadFile = File(...)
) -> PohTier2VideoUploadResponse:
    """Upload native async Tier-1 freshly recorded video evidence.

    This endpoint is a node-local evidence intake helper only. It does not grant
    verification, sign transactions, or write consensus state. Clients must still
    submit POH_ASYNC_REQUEST_OPEN, POH_ASYNC_EVIDENCE_DECLARE, and
    POH_ASYNC_EVIDENCE_BIND through normal signed transactions.
    """

    return await _upload_poh_video_evidence(
        file=file,
        enabled_env="WEALL_ENABLE_POH_ASYNC_VIDEO_UPLOAD",
        max_bytes_env="WEALL_POH_ASYNC_VIDEO_MAX_BYTES",
        pin_env="WEALL_POH_ASYNC_VIDEO_PIN_ON_UPLOAD",
        default_name="poh_async_video.webm",
    )


@router.post(
    "/poh/tier2/video/upload",
    response_model=PohTier2VideoUploadResponse,
    name="poh_tier2_video_upload",
)
async def poh_tier2_video_upload(
    request: Request, file: UploadFile = File(...)
) -> PohTier2VideoUploadResponse:
    """Upload Tier-2 video evidence to IPFS and return a CID + commitment.

    Why this exists:
      - /v1/media/upload is Live gated (for public social content).
      - Tier-2 applicants are usually Tier-1 users and need a safe intake path.

    Production posture:
      - Endpoint is OFF by default. Enable explicitly with:
          WEALL_ENABLE_POH_TIER2_VIDEO_UPLOAD=1
      - Strict size limits (default 25MB) to reduce abuse.
      - We do NOT pin on upload by default.
        Durability should come from operator pin workflows.
    """

    if not _env_bool("WEALL_ENABLE_POH_TIER2_VIDEO_UPLOAD", False):
        # fail-closed unless explicitly enabled
        raise ApiError.not_found("not_found", "endpoint_disabled")

    max_bytes = _env_int("WEALL_POH_TIER2_VIDEO_MAX_BYTES", 25 * 1024 * 1024)

    name = (file.filename or "poh_tier2_video").strip() or "poh_tier2_video"
    mime = (file.content_type or "").strip() or (
        mimetypes.guess_type(name)[0] or "application/octet-stream"
    )

    size = _file_size(file)
    if size == 0:
        raise ApiError.invalid("invalid_payload", "empty_file")
    if size > 0 and size > max_bytes:
        raise ApiError.invalid("invalid_payload", f"file_too_large (max {max_bytes} bytes)")

    try:
        file.file.seek(0)
    except Exception:
        pass

    pin_on_upload = _env_bool("WEALL_POH_TIER2_VIDEO_PIN_ON_UPLOAD", False)

    try:
        cid, ipfs_reported_size = ipfs_add_fileobj(
            name=name, fileobj=file.file, pin=bool(pin_on_upload)
        )
    except RuntimeError as e:
        raise ApiError.bad_request("ipfs_error", str(e))

    v = validate_ipfs_cid(cid)
    if not v.ok:
        raise ApiError.bad_request("ipfs_error", f"invalid_cid_from_ipfs:{v.reason}")

    final_size = size if size >= 0 else int(ipfs_reported_size)
    uri = f"ipfs://{cid}"
    gw = ipfs_gateway_url(cid)

    # Commitment used by POH_TIER2_REQUEST_OPEN if client prefers commitments over raw CIDs.
    video_commitment = _sha256_hex(cid.encode("utf-8"))

    return PohTier2VideoUploadResponse(
        ok=True,
        cid=cid,
        size=int(final_size),
        name=name,
        mime=mime,
        uri=uri,
        gateway_url=gw,
        video_commitment=video_commitment,
    )




def _async_cases_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    cases = poh.get("async_cases")
    return cases if isinstance(cases, dict) else {}


def _opt_int_value(v: Any) -> int | None:
    try:
        return int(v) if isinstance(v, (int, float)) else None
    except Exception:
        return None


class PohAsyncCaseModel(BaseModel):
    case_id: str
    account_id: str
    status: str
    opened_height: int | None = None
    expires_height: int | None = None
    finalized_height: int | None = None
    finalized_ts_ms: int | None = None
    outcome: str | None = None
    tier_awarded: int | None = None
    challenge_id: str | None = None
    assigned_jurors: list[object] = Field(default_factory=list)
    accepted_jurors: list[object] = Field(default_factory=list)
    declined_jurors: list[object] = Field(default_factory=list)
    jurors: dict[str, object] = Field(default_factory=dict)
    reviews: dict[str, object] = Field(default_factory=dict)
    evidence_commitments: dict[str, object] = Field(default_factory=dict)
    evidence_binds: dict[str, object] = Field(default_factory=dict)
    public_evidence_ids: list[object] = Field(default_factory=list)
    reviewable_evidence: dict[str, object] = Field(default_factory=dict)
    reviewer_private_evidence: dict[str, object] = Field(default_factory=dict)
    receipt: dict[str, object] = Field(default_factory=dict)
    evidence_declared: bool = False
    evidence_bound: bool = False
    reviewable: bool = False
    assigned: bool = False
    missing_steps: list[str] = Field(default_factory=list)
    reviewer_queue_reason: str | None = None


def _as_async_case(case_id: str, r: dict[str, object], *, include_private_evidence: bool = False) -> PohAsyncCaseModel:
    def _list(v: Any) -> list[object]:
        return list(v) if isinstance(v, list) else []

    def _dict(v: Any) -> dict[str, object]:
        return dict(v) if isinstance(v, dict) else {}

    evidence_commitments = _dict(r.get("evidence_commitments"))
    evidence_binds = _dict(r.get("evidence_binds"))
    public_evidence_ids = _list(r.get("public_evidence_ids"))
    reviewable_evidence_raw = _dict(r.get("reviewable_evidence"))
    reviewer_private_raw = _dict(r.get("reviewer_private_evidence"))
    assigned_jurors = _list(r.get("assigned_jurors"))
    jurors = _dict(r.get("jurors"))
    status = str(r.get("status") or "unknown").strip() or "unknown"
    outcome = str(r.get("outcome") or "").strip()
    final_or_reviewed = bool(
        status.lower() in {"approved", "rejected", "finalized"}
        or outcome
        or _dict(r.get("receipt"))
        or _opt_int_value(r.get("finalized_height")) is not None
    )
    evidence_declared = bool(evidence_commitments or public_evidence_ids or reviewable_evidence_raw or reviewer_private_raw or final_or_reviewed)
    # Batch 422: older rehearsal runs could enqueue POH_ASYNC_JUROR_ASSIGN after
    # evidence declare and before evidence bind, making the bind tx fail while
    # reviewer-private evidence still became visible and the case finalized.
    # Surface that case as effectively complete instead of leaving the observer
    # UI stuck on missing evidence_bind.  New scheduler logic prevents the race.
    evidence_bound = bool(evidence_binds or public_evidence_ids or reviewable_evidence_raw or reviewer_private_raw or final_or_reviewed)
    assigned = bool([j for j in assigned_jurors if str(j or "").strip()] or jurors)
    reviewable = bool(final_or_reviewed or (evidence_declared and evidence_bound))
    missing_steps: list[str] = []
    if not evidence_declared:
        missing_steps.append("evidence_declare")
    if not evidence_bound:
        missing_steps.append("evidence_bind")
    if not assigned and not final_or_reviewed:
        missing_steps.append("juror_assignment")
    if final_or_reviewed:
        reviewer_queue_reason = "finalized"
    elif not evidence_declared or not evidence_bound:
        reviewer_queue_reason = "case_opened_not_reviewable"
    elif not assigned:
        reviewer_queue_reason = "case_reviewable_not_assigned"
    else:
        reviewer_queue_reason = "assigned"

    return PohAsyncCaseModel(
        case_id=str(case_id),
        account_id=str(r.get("account_id") or "").strip(),
        status=status,
        opened_height=_opt_int_value(r.get("opened_height")),
        expires_height=_opt_int_value(r.get("expires_height")),
        finalized_height=_opt_int_value(r.get("finalized_height")),
        finalized_ts_ms=_opt_int_value(r.get("finalized_ts_ms")),
        outcome=str(r.get("outcome") or "").strip() or None,
        tier_awarded=_opt_int_value(r.get("tier_awarded")),
        challenge_id=str(r.get("challenge_id") or "").strip() or None,
        assigned_jurors=assigned_jurors,
        accepted_jurors=_list(r.get("accepted_jurors")),
        declined_jurors=_list(r.get("declined_jurors")),
        jurors=jurors,
        reviews=_dict(r.get("reviews")),
        evidence_commitments=evidence_commitments,
        evidence_binds=evidence_binds,
        public_evidence_ids=public_evidence_ids,
        reviewable_evidence=_dict(r.get("reviewer_private_evidence") if include_private_evidence else r.get("reviewable_evidence")),
        reviewer_private_evidence=_dict(r.get("reviewer_private_evidence") if include_private_evidence else {}),
        receipt=_dict(r.get("receipt")),
        evidence_declared=evidence_declared,
        evidence_bound=evidence_bound,
        reviewable=reviewable,
        assigned=assigned,
        missing_steps=missing_steps,
        reviewer_queue_reason=reviewer_queue_reason,
    )


def _request_account(request: Request) -> str:
    return str(request.headers.get("x-weall-account") or "").strip()


def _allow_header_scoped_private_poh_compat() -> bool:
    """Allow legacy header-only PoH private access only outside production.

    Production private evidence and live-room transport control must be bound to
    an authenticated backend session, not a forgeable account header.  Local
    rehearsal and older tests keep a deliberate opt-out compatibility path.
    """

    return (not _is_prod()) and _env_bool("WEALL_DEV_ALLOW_HEADER_SCOPED_PRIVATE_POH", True)


def _session_principal_for_private_poh(request: Request, st: Json) -> str:
    try:
        return str(require_account_session(request, st) or "").strip()
    except PermissionError:
        if _allow_header_scoped_private_poh_compat():
            return _request_account(request)
        return ""


def _require_session_principal_for_poh_private(request: Request, st: Json, *, purpose: str) -> str:
    try:
        acct = str(require_account_session(request, st) or "").strip()
    except PermissionError as exc:
        if _allow_header_scoped_private_poh_compat():
            acct = _request_account(request)
        else:
            raise ApiError.forbidden(
                "session_required",
                f"authenticated session required for {purpose}",
                {"purpose": purpose},
            ) from exc
    if not acct:
        raise ApiError.forbidden(
            "session_required",
            f"authenticated session required for {purpose}",
            {"purpose": purpose},
        )
    return acct


def _async_case_allows_private_evidence(raw: dict[str, object], *, account: str) -> bool:
    if not account:
        return False
    if str(raw.get("account_id") or "").strip() == account:
        return True
    assigned = raw.get("assigned_jurors")
    if isinstance(assigned, list) and account in [str(x) for x in assigned]:
        return True
    jurors = raw.get("jurors")
    if isinstance(jurors, dict) and account in jurors:
        return True
    return False


class PohAsyncCaseResponse(BaseModel):
    ok: bool
    case: PohAsyncCaseModel


class PohAsyncCaseListResponse(BaseModel):
    ok: bool
    cases: list[PohAsyncCaseModel]
    diagnostics: dict[str, object] = Field(default_factory=dict)


@router.get("/poh/async/case/{case_id}", response_model=PohAsyncCaseResponse, name="poh_async_case")
def poh_async_case(case_id: str, request: Request) -> PohAsyncCaseResponse:
    st = _snapshot(request)
    cases = _async_cases_from_snapshot(st)
    cid = str(case_id or "").strip()
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "async_case_not_found")
    principal = _session_principal_for_private_poh(request, st)
    include_private = _async_case_allows_private_evidence(raw, account=principal)
    return PohAsyncCaseResponse(ok=True, case=_as_async_case(cid, raw, include_private_evidence=include_private))


@router.get(
    "/poh/async/my-cases", response_model=PohAsyncCaseListResponse, name="poh_async_my_cases"
)
def poh_async_my_cases(account: str, request: Request) -> PohAsyncCaseListResponse:
    acct = str(account or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account", {})
    st = _snapshot(request)
    cases = _async_cases_from_snapshot(st)
    out: list[PohAsyncCaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        if str(raw.get("account_id") or "").strip() == acct:
            principal = _session_principal_for_private_poh(request, st)
            include_private = principal == acct
            out.append(_as_async_case(str(cid), raw, include_private_evidence=include_private))
    out.sort(key=lambda c: (c.opened_height or 0, c.case_id))
    return PohAsyncCaseListResponse(
        ok=True,
        cases=out,
        diagnostics={
            "account": acct,
            "total_cases": len(out),
            "reviewable_cases": len([c for c in out if c.reviewable]),
            "assigned_cases": len([c for c in out if c.assigned]),
            "opened_not_reviewable_cases": len([c for c in out if c.reviewer_queue_reason == "case_opened_not_reviewable"]),
        },
    )


@router.get(
    "/poh/async/juror-cases", response_model=PohAsyncCaseListResponse, name="poh_async_juror_cases"
)
def poh_async_juror_cases(juror: str, request: Request) -> PohAsyncCaseListResponse:
    j = str(juror or "").strip()
    if not j:
        raise ApiError.bad_request("bad_request", "missing juror", {})
    st = _snapshot(request)
    cases = _async_cases_from_snapshot(st)
    out: list[PohAsyncCaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        assigned = raw.get("assigned_jurors")
        jurors = raw.get("jurors")
        if (isinstance(assigned, list) and j in assigned) or (isinstance(jurors, dict) and j in jurors):
            principal = _session_principal_for_private_poh(request, st)
            include_private = principal == j
            out.append(_as_async_case(str(cid), raw, include_private_evidence=include_private))
    out.sort(key=lambda c: (c.opened_height or 0, c.case_id))
    roles = st.get("roles") if isinstance(st.get("roles"), dict) else {}
    juror_roles = roles.get("jurors") if isinstance(roles.get("jurors"), dict) else {}
    active_set = juror_roles.get("active_set") if isinstance(juror_roles.get("active_set"), list) else []
    active_juror = j in [str(x) for x in active_set]
    modeled_cases = [_as_async_case(str(cid), raw, include_private_evidence=False) for cid, raw in cases.items() if isinstance(raw, dict)]
    return PohAsyncCaseListResponse(
        ok=True,
        cases=out,
        diagnostics={
            "juror": j,
            "active_juror": active_juror,
            "assigned_cases": len(out),
            "reviewable_unassigned_cases": len([c for c in modeled_cases if c.reviewable and not c.assigned]),
            "opened_not_reviewable_cases": len([c for c in modeled_cases if c.reviewer_queue_reason == "case_opened_not_reviewable"]),
            "empty_queue_reason": None if out else (
                "juror_not_active" if not active_juror else
                "cases_exist_but_not_reviewable" if any(c.reviewer_queue_reason == "case_opened_not_reviewable" for c in modeled_cases) else
                "reviewable_cases_not_assigned" if any(c.reviewable and not c.assigned for c in modeled_cases) else
                "no_async_cases"
            ),
        },
    )

# ---------------------------------------------------------------------------
# PoH Tier2: Read-only views (for product UI / juror dashboards)
# ---------------------------------------------------------------------------


def _tier2_cases_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    cases = poh.get("tier2_cases")
    return cases if isinstance(cases, dict) else {}


def _live_cases_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    cases = poh.get("live_cases")
    return cases if isinstance(cases, dict) else {}


def _live_sessions_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    sess = poh.get("live_sessions")
    return sess if isinstance(sess, dict) else {}


def _live_session_participants_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    sp = poh.get("live_session_participants")
    return sp if isinstance(sp, dict) else {}


class PohTier2CaseModel(BaseModel):
    case_id: str
    account_id: str
    status: str
    requested_by: str | None = None
    created_ts_ms: int | None = None
    finalized_ts_ms: int | None = None
    outcome: str | None = None
    tier_awarded: int | None = None
    jurors: dict[str, object] = Field(default_factory=dict)
    evidence: dict[str, object] = Field(default_factory=dict)


def _as_tier2_case(case_id: str, r: dict[str, object]) -> PohTier2CaseModel:
    acct = str(r.get("account_id") or "").strip()
    status = str(r.get("status") or "").strip() or "unknown"

    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    jurors = r.get("jurors")
    if not isinstance(jurors, dict):
        jurors = {}

    ev = r.get("evidence")
    if not isinstance(ev, dict):
        ev = {}

    return PohTier2CaseModel(
        case_id=str(case_id),
        account_id=acct,
        status=status,
        requested_by=str(r.get("requested_by") or "").strip() or None,
        created_ts_ms=_opt_int(r.get("created_ts_ms")),
        finalized_ts_ms=_opt_int(r.get("finalized_ts_ms")),
        outcome=str(r.get("outcome") or "").strip() or None,
        tier_awarded=_opt_int(r.get("tier_awarded")),
        jurors=dict(jurors),
        evidence=dict(ev),
    )


class PohTier2CaseResponse(BaseModel):
    ok: bool
    case: PohTier2CaseModel


class PohTier2CaseListResponse(BaseModel):
    ok: bool
    cases: list[PohTier2CaseModel]


@router.get("/poh/tier2/case/{case_id}", response_model=PohTier2CaseResponse, name="poh_tier2_case")
def poh_tier2_case(case_id: str, request: Request) -> PohTier2CaseResponse:
    st = _snapshot(request)
    cases = _tier2_cases_from_snapshot(st)
    cid = str(case_id or "").strip()
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "tier2_case_not_found")
    return PohTier2CaseResponse(ok=True, case=_as_tier2_case(cid, raw))


@router.get(
    "/poh/tier2/my-cases", response_model=PohTier2CaseListResponse, name="poh_tier2_my_cases"
)
def poh_tier2_my_cases(account: str, request: Request) -> PohTier2CaseListResponse:
    acct = str(account or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account", {})
    st = _snapshot(request)
    cases = _tier2_cases_from_snapshot(st)

    out: list[PohTier2CaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        if str(raw.get("account_id") or "").strip() == acct:
            out.append(_as_tier2_case(str(cid), raw))

    out.sort(key=lambda c: c.case_id)
    return PohTier2CaseListResponse(ok=True, cases=out)


@router.get(
    "/poh/tier2/juror-cases", response_model=PohTier2CaseListResponse, name="poh_tier2_juror_cases"
)
def poh_tier2_juror_cases(juror: str, request: Request) -> PohTier2CaseListResponse:
    j = str(juror or "").strip()
    if not j:
        raise ApiError.bad_request("bad_request", "missing juror", {})
    st = _snapshot(request)
    cases = _tier2_cases_from_snapshot(st)

    out: list[PohTier2CaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        jm = raw.get("jurors")
        if not isinstance(jm, dict):
            continue
        if j in jm:
            out.append(_as_tier2_case(str(cid), raw))

    out.sort(key=lambda c: c.case_id)
    return PohTier2CaseListResponse(ok=True, cases=out)


# ---------------------------------------------------------------------------
# PoH Live: Read-only views (cases, assigned, sessions)
# ---------------------------------------------------------------------------


class PohLiveJurorModel(BaseModel):
    juror_id: str
    role: str
    accepted: bool
    attended: bool
    attended_ts_ms: int | None = None
    verdict: str | None = None


class PohLiveCaseModel(BaseModel):
    case_id: str
    account_id: str
    status: str
    requested_by: str | None = None
    session_commitment: str | None = None
    room_commitment: str | None = None
    prompt_commitment: str | None = None
    device_pairing_commitment: str | None = None
    relay_commitment: str | None = None
    relay_authority: str | None = None
    init_ts_ms: int | None = None
    finalized_ts_ms: int | None = None
    outcome: str | None = None
    tier_awarded: int | None = None
    poh_nft_token_id: str | None = None
    jurors: list[PohLiveJurorModel] = Field(default_factory=list)


def _as_live_case(case_id: str, r: dict[str, object]) -> PohLiveCaseModel:
    acct = str(r.get("account_id") or "").strip()
    status = str(r.get("status") or "").strip() or "unknown"

    jurors: list[PohLiveJurorModel] = []
    jm = r.get("jurors")
    if isinstance(jm, dict):
        for jid, jrec_any in jm.items():
            jrec = jrec_any if isinstance(jrec_any, dict) else {}
            accepted = bool(jrec.get("accepted", False))
            attended = bool(jrec.get("attended", False))
            verdict = jrec.get("verdict")
            verdict = str(verdict).strip() if isinstance(verdict, str) else None

            ats: int | None
            try:
                ats = None
                if jrec.get("attended_ts_ms") is not None:
                    ats = int(jrec.get("attended_ts_ms"))
            except Exception:
                ats = None

            jurors.append(
                PohLiveJurorModel(
                    juror_id=str(jid),
                    role=str(jrec.get("role") or "").strip() or "unknown",
                    accepted=accepted,
                    attended=attended,
                    attended_ts_ms=ats,
                    verdict=verdict,
                )
            )

    jurors.sort(key=lambda j: (0 if j.role == "interacting" else 1, j.juror_id))

    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohLiveCaseModel(
        case_id=str(case_id),
        account_id=acct,
        status=status,
        requested_by=str(r.get("requested_by") or "").strip() or None,
        session_commitment=str(r.get("session_commitment") or "").strip() or None,
        room_commitment=str(r.get("room_commitment") or "").strip() or None,
        prompt_commitment=str(r.get("prompt_commitment") or "").strip() or None,
        device_pairing_commitment=str(r.get("device_pairing_commitment") or "").strip() or None,
        relay_commitment=str(r.get("relay_commitment") or "").strip() or None,
        relay_authority=str(r.get("relay_authority") or "").strip() or None,
        init_ts_ms=_opt_int(r.get("init_ts_ms")),
        finalized_ts_ms=_opt_int(r.get("finalized_ts_ms")),
        outcome=str(r.get("outcome") or "").strip() or None,
        tier_awarded=_opt_int(r.get("tier_awarded")),
        poh_nft_token_id=str(r.get("poh_nft_token_id") or "").strip() or None,
        jurors=jurors,
    )


class PohLiveCaseResponse(BaseModel):
    ok: bool
    case: PohLiveCaseModel


class PohLiveAssignedResponse(BaseModel):
    ok: bool
    cases: list[PohLiveCaseModel]


@router.get("/poh/live/case/{case_id}", response_model=PohLiveCaseResponse, name="poh_live_case")
def poh_live_case(case_id: str, request: Request) -> PohLiveCaseResponse:
    st = _snapshot(request)
    cases = _live_cases_from_snapshot(st)
    cid = str(case_id or "").strip()
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_case_not_found")
    return PohLiveCaseResponse(ok=True, case=_as_live_case(cid, raw))


@router.get(
    "/poh/live/assigned", response_model=PohLiveAssignedResponse, name="poh_live_assigned"
)
def poh_live_assigned(juror: str, request: Request) -> PohLiveAssignedResponse:
    j = str(juror or "").strip()
    if not j:
        raise ApiError.bad_request("bad_request", "missing juror", {})
    st = _snapshot(request)
    cases = _live_cases_from_snapshot(st)

    out: list[PohLiveCaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        jm = raw.get("jurors")
        if not isinstance(jm, dict):
            continue
        if j in jm:
            out.append(_as_live_case(str(cid), raw))

    out.sort(key=lambda c: c.case_id)
    return PohLiveAssignedResponse(ok=True, cases=out)


@router.get(
    "/poh/live/juror-cases", response_model=PohLiveAssignedResponse, name="poh_live_juror_cases"
)
def poh_live_juror_cases(juror: str, request: Request) -> PohLiveAssignedResponse:
    # Compatibility alias for async juror-cases and operator probes.
    return poh_live_assigned(juror=juror, request=request)


@router.get(
    "/poh/live/my-cases", response_model=PohLiveAssignedResponse, name="poh_live_my_cases"
)
def poh_live_my_cases(account: str, request: Request) -> PohLiveAssignedResponse:
    acct = str(account or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account", {})
    st = _snapshot(request)
    cases = _live_cases_from_snapshot(st)

    out: list[PohLiveCaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        if str(raw.get("account_id") or "").strip() == acct:
            out.append(_as_live_case(str(cid), raw))

    out.sort(key=lambda c: c.case_id)
    return PohLiveAssignedResponse(ok=True, cases=out)


class PohLiveSessionModel(BaseModel):
    session_id: str
    case_id: str
    status: str
    created_ts_ms: int | None = None
    started_ts_ms: int | None = None
    ended_ts_ms: int | None = None
    session_commitment: str | None = None
    room_commitment: str | None = None
    prompt_commitment: str | None = None
    device_pairing_commitment: str | None = None
    relay_commitment: str | None = None
    relay_authority: str | None = None
    # Kept as an always-null compatibility field so older clients do not break.
    # Protocol-native Live state exposes commitments only, never raw relay URLs.
    join_url: str | None = None


class PohLiveSessionResponse(BaseModel):
    ok: bool
    session: PohLiveSessionModel


class PohLiveSessionListResponse(BaseModel):
    ok: bool
    sessions: list[PohLiveSessionModel]


def _as_live_session(session_id: str, r: dict[str, object]) -> PohLiveSessionModel:
    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohLiveSessionModel(
        session_id=str(session_id),
        case_id=str(r.get("case_id") or "").strip(),
        status=str(r.get("status") or "").strip() or "unknown",
        created_ts_ms=_opt_int(r.get("created_ts_ms")),
        started_ts_ms=_opt_int(r.get("started_ts_ms")),
        ended_ts_ms=_opt_int(r.get("ended_ts_ms")),
        session_commitment=str(r.get("session_commitment") or "").strip() or None,
        room_commitment=str(r.get("room_commitment") or "").strip() or None,
        prompt_commitment=str(r.get("prompt_commitment") or "").strip() or None,
        device_pairing_commitment=str(r.get("device_pairing_commitment") or "").strip() or None,
        relay_commitment=str(r.get("relay_commitment") or "").strip() or None,
        relay_authority=str(r.get("relay_authority") or "").strip() or None,
        join_url=None,
    )


@router.get(
    "/poh/live/session/{session_id}",
    response_model=PohLiveSessionResponse,
    name="poh_live_session",
)
def poh_live_session(session_id: str, request: Request) -> PohLiveSessionResponse:
    st = _snapshot(request)
    sess = _live_sessions_from_snapshot(st)
    sid = str(session_id or "").strip()
    raw = sess.get(sid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_session_not_found")
    return PohLiveSessionResponse(ok=True, session=_as_live_session(sid, raw))


@router.get(
    "/poh/live/sessions", response_model=PohLiveSessionListResponse, name="poh_live_sessions"
)
def poh_live_sessions(request: Request) -> PohLiveSessionListResponse:
    st = _snapshot(request)
    sess = _live_sessions_from_snapshot(st)

    out: list[PohLiveSessionModel] = []
    for sid, raw in sess.items():
        if not isinstance(raw, dict):
            continue
        out.append(_as_live_session(str(sid), raw))

    out.sort(key=lambda s: (s.case_id, s.session_id))
    return PohLiveSessionListResponse(ok=True, sessions=out)


class PohLiveSessionParticipantModel(BaseModel):
    session_id: str
    juror_id: str
    role: str | None = None
    status: str
    joined_ts_ms: int | None = None
    left_ts_ms: int | None = None


class PohLiveSessionParticipantsResponse(BaseModel):
    ok: bool
    participants: list[PohLiveSessionParticipantModel]


def _as_participant(
    session_id: str, juror_id: str, r: dict[str, object]
) -> PohLiveSessionParticipantModel:
    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohLiveSessionParticipantModel(
        session_id=str(session_id),
        juror_id=str(juror_id),
        role=str(r.get("role") or "").strip() or None,
        status=str(r.get("status") or "").strip() or "unknown",
        joined_ts_ms=_opt_int(r.get("joined_ts_ms")),
        left_ts_ms=_opt_int(r.get("left_ts_ms")),
    )


@router.get(
    "/poh/live/session/{session_id}/participants",
    response_model=PohLiveSessionParticipantsResponse,
    name="poh_live_session_participants",
)
def poh_live_session_participants(
    session_id: str, request: Request
) -> PohLiveSessionParticipantsResponse:
    st = _snapshot(request)
    sp = _live_session_participants_from_snapshot(st)
    sid = str(session_id or "").strip()
    raw = sp.get(sid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_session_participants_not_found")

    out: list[PohLiveSessionParticipantModel] = []
    for juror_id, jrec_any in raw.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        out.append(_as_participant(sid, str(juror_id), jrec))

    out.sort(key=lambda p: p.juror_id)
    return PohLiveSessionParticipantsResponse(ok=True, participants=out)




# ---------------------------------------------------------------------------
# PoH Live: Node-local room presence (transport only, non-authoritative)
# ---------------------------------------------------------------------------


_ALLOWED_LIVE_PRESENCE_STATUSES = {"joined", "left", "reconnect", "heartbeat"}


def _live_presence_store(request: Request) -> Json:
    """Return the node-local, ephemeral Live Room presence store.

    This store is intentionally outside consensus state. It exists only to help
    the frontend render room presence, camera/mic check-in posture, reconnects,
    and left/joined status. Chain authority still comes only from signed
    POH_LIVE_ATTENDANCE_MARK, POH_LIVE_VERDICT_SUBMIT, and POH_LIVE_FINALIZE.
    """

    store = getattr(request.app.state, "poh_live_room_presence", None)
    if not isinstance(store, dict):
        store = {}
        request.app.state.poh_live_room_presence = store
    return store


def _live_session_case_id(st: Json, session_id: str) -> str:
    sess = _live_sessions_from_snapshot(st)
    raw = sess.get(session_id)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_session_not_found")
    cid = str(raw.get("case_id") or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "live_session_missing_case_id", {"session_id": session_id})
    return cid


def _require_live_room_participant(st: Json, *, session_id: str, account_id: str) -> tuple[str, str]:
    cid = _live_session_case_id(st, session_id)
    cases = _live_cases_from_snapshot(st)
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_case_not_found")

    subject = str(raw.get("account_id") or "").strip()
    if account_id and account_id == subject:
        return cid, "subject"

    jurors = raw.get("jurors")
    if isinstance(jurors, dict) and account_id in jurors:
        jrec = jurors.get(account_id)
        role = "juror"
        if isinstance(jrec, dict):
            role = str(jrec.get("role") or "juror").strip() or "juror"
        return cid, role

    raise ApiError.forbidden(
        "forbidden",
        "live_room_participant_required",
        {"session_id": session_id, "case_id": cid, "account_id": account_id},
    )


class PohLivePresenceUpdateRequest(BaseModel):
    account_id: str = Field(..., min_length=1)
    status: Literal["joined", "left", "reconnect", "heartbeat"] = "heartbeat"
    camera_enabled: bool | None = None
    mic_enabled: bool | None = None
    display_name: str | None = Field(default=None, max_length=80)
    ts_ms: int | None = None


class PohLivePresenceModel(BaseModel):
    session_id: str
    case_id: str
    account_id: str
    role: str
    status: str
    camera_enabled: bool | None = None
    mic_enabled: bool | None = None
    display_name: str | None = None
    joined_ts_ms: int | None = None
    last_seen_ts_ms: int | None = None
    left_ts_ms: int | None = None
    authority: str = "transport_only_ephemeral"


class PohLivePresenceResponse(BaseModel):
    ok: bool
    presence: list[PohLivePresenceModel]
    authority: str = "transport_only_ephemeral"


class PohLivePresenceUpdateResponse(BaseModel):
    ok: bool
    record: PohLivePresenceModel
    authority: str = "transport_only_ephemeral"
    message: str = "Room presence is transport-only. Chain authority requires signed attendance, verdict, and finalization transactions."


def _as_presence(session_id: str, account_id: str, raw: dict[str, object]) -> PohLivePresenceModel:
    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohLivePresenceModel(
        session_id=session_id,
        case_id=str(raw.get("case_id") or "").strip(),
        account_id=account_id,
        role=str(raw.get("role") or "participant").strip() or "participant",
        status=str(raw.get("status") or "unknown").strip() or "unknown",
        camera_enabled=raw.get("camera_enabled") if isinstance(raw.get("camera_enabled"), bool) else None,
        mic_enabled=raw.get("mic_enabled") if isinstance(raw.get("mic_enabled"), bool) else None,
        display_name=str(raw.get("display_name") or "").strip() or None,
        joined_ts_ms=_opt_int(raw.get("joined_ts_ms")),
        last_seen_ts_ms=_opt_int(raw.get("last_seen_ts_ms")),
        left_ts_ms=_opt_int(raw.get("left_ts_ms")),
    )


@router.get(
    "/poh/live/session/{session_id}/presence",
    response_model=PohLivePresenceResponse,
    name="poh_live_session_presence",
)
def poh_live_session_presence(session_id: str, request: Request) -> PohLivePresenceResponse:
    sid = str(session_id or "").strip()
    if not sid:
        raise ApiError.bad_request("bad_request", "missing session_id", {})

    st = _snapshot(request)
    # Require the session to exist in chain-derived state, but keep presence data ephemeral.
    _live_session_case_id(st, sid)

    session_store = _live_presence_store(request).get(sid)
    raw_records = session_store if isinstance(session_store, dict) else {}
    records = [
        _as_presence(sid, str(account_id), rec if isinstance(rec, dict) else {})
        for account_id, rec in raw_records.items()
    ]
    records.sort(key=lambda r: (r.role != "subject", r.account_id))
    return PohLivePresenceResponse(ok=True, presence=records)


@router.post(
    "/poh/live/session/{session_id}/presence",
    response_model=PohLivePresenceUpdateResponse,
    name="poh_live_session_presence_update",
)
def poh_live_session_presence_update(
    session_id: str, req: PohLivePresenceUpdateRequest, request: Request
) -> PohLivePresenceUpdateResponse:
    sid = str(session_id or "").strip()
    if not sid:
        raise ApiError.bad_request("bad_request", "missing session_id", {})

    account_id = str(req.account_id or "").strip()
    if not account_id:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    header_account = _request_account(request)
    if not header_account:
        raise ApiError.forbidden(
            "forbidden",
            "presence_account_header_required",
            {"account_id": account_id},
        )
    if header_account != account_id:
        raise ApiError.forbidden(
            "forbidden",
            "presence_account_header_mismatch",
            {"header_account": header_account, "account_id": account_id},
        )

    st = _snapshot(request)
    principal = _require_session_principal_for_poh_private(
        request, st, purpose="live room presence"
    )
    if principal != account_id:
        raise ApiError.forbidden(
            "forbidden",
            "presence_account_mismatch",
            {"session_account": principal, "account_id": account_id},
        )

    status = str(req.status or "heartbeat").strip().lower()
    if status not in _ALLOWED_LIVE_PRESENCE_STATUSES:
        raise ApiError.bad_request("bad_request", "invalid_presence_status", {"status": status})

    case_id, role = _require_live_room_participant(st, session_id=sid, account_id=account_id)

    try:
        ts_ms = int(req.ts_ms) if req.ts_ms is not None else 0
    except Exception:
        ts_ms = 0

    session_store = _live_presence_store(request).setdefault(sid, {})
    if not isinstance(session_store, dict):
        session_store = {}
        _live_presence_store(request)[sid] = session_store

    prev = session_store.get(account_id)
    rec: Json = dict(prev) if isinstance(prev, dict) else {}
    rec["case_id"] = case_id
    rec["role"] = role
    rec["status"] = "left" if status == "left" else "joined"
    rec["last_seen_ts_ms"] = ts_ms
    if req.camera_enabled is not None:
        rec["camera_enabled"] = bool(req.camera_enabled)
    if req.mic_enabled is not None:
        rec["mic_enabled"] = bool(req.mic_enabled)
    display_name = str(req.display_name or "").strip()
    if display_name:
        rec["display_name"] = display_name
    if status in {"joined", "reconnect"} and not rec.get("joined_ts_ms"):
        rec["joined_ts_ms"] = ts_ms
    if status == "left":
        rec["left_ts_ms"] = ts_ms
    else:
        rec["left_ts_ms"] = None

    session_store[account_id] = rec
    return PohLivePresenceUpdateResponse(ok=True, record=_as_presence(sid, account_id, rec))


# ---------------------------------------------------------------------------
# PoH Live: decentralized WebRTC signaling (transport only)
# ---------------------------------------------------------------------------

_ALLOWED_WEBRTC_SIGNAL_TYPES = {"hello", "offer", "answer", "ice", "leave"}
_MAX_WEBRTC_SDP_BYTES = 64 * 1024
_MAX_WEBRTC_CANDIDATE_BYTES = 8 * 1024


def _webrtc_signal_ttl_ms() -> int:
    return max(10_000, _env_int("WEALL_P2P_SIGNAL_TTL_MS", 10 * 60 * 1000))


def _normalize_webrtc_signal_ts_ms(value: object) -> int:
    """Use receive-time when a browser supplies stale, missing, or future signal time."""
    now_ms = int(time.time() * 1000)
    try:
        ts_ms = int(value or 0)
    except Exception:
        ts_ms = 0
    ttl_ms = _webrtc_signal_ttl_ms()
    if ts_ms <= 0 or ts_ms < now_ms - ttl_ms or ts_ms > now_ms + 60_000:
        return now_ms
    return ts_ms


def _validate_webrtc_bridge_signal_ts_ms(value: object, *, source_node: str) -> int:
    """Reject stale/future bridge imports instead of making replayed signals fresh."""
    now_ms = _now_ms()
    try:
        ts_ms = int(value or 0)
    except Exception as exc:
        _record_webrtc_bridge_rejection("webrtc_bridge_signal_ts_invalid", source_node=source_node)
        raise ApiError.bad_request("bad_request", "webrtc_bridge_signal_ts_invalid", {"source_node": source_node}) from exc
    ttl_ms = _webrtc_signal_ttl_ms()
    if ts_ms <= 0:
        _record_webrtc_bridge_rejection("webrtc_bridge_signal_ts_required", source_node=source_node)
        raise ApiError.bad_request("bad_request", "webrtc_bridge_signal_ts_required", {"source_node": source_node})
    if now_ms - ts_ms > ttl_ms:
        _record_webrtc_bridge_rejection("webrtc_bridge_signal_replay_window_expired", source_node=source_node)
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_bridge_signal_replay_window_expired",
            {"source_node": source_node, "ts_ms": ts_ms, "ttl_ms": ttl_ms},
        )
    future_skew_ms = max(1_000, _env_int("WEALL_WEBRTC_SIGNAL_FUTURE_SKEW_MS", 60_000))
    if ts_ms > now_ms + future_skew_ms:
        _record_webrtc_bridge_rejection("webrtc_bridge_signal_ts_future", source_node=source_node)
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_bridge_signal_ts_future",
            {"source_node": source_node, "ts_ms": ts_ms, "future_skew_ms": future_skew_ms},
        )
    return ts_ms


class PohLiveWebRTCSignalRequest(BaseModel):
    account_id: str = Field(..., min_length=1)
    type: Literal["hello", "offer", "answer", "ice", "leave"]
    to_account: str | None = Field(default=None, max_length=128)
    sdp: str | None = Field(default=None, max_length=_MAX_WEBRTC_SDP_BYTES)
    candidate: dict[str, object] | None = None
    client_signal_id: str | None = Field(default=None, max_length=128)
    ts_ms: int | None = None


class PohLiveWebRTCSignalModel(BaseModel):
    seq: int
    signal_id: str
    session_id: str
    case_id: str
    from_account: str
    to_account: str | None = None
    type: str
    sdp: str | None = None
    candidate: dict[str, object] | None = None
    ts_ms: int
    authority: str = "transport_only_ephemeral"


class PohLiveWebRTCSignalResponse(BaseModel):
    ok: bool
    signal: PohLiveWebRTCSignalModel
    authority: str = "transport_only_ephemeral"
    message: str = "WebRTC signaling is transport-only and may be bridged across operator-configured peers; chain state remains authoritative."


class PohLiveWebRTCSignalListResponse(BaseModel):
    ok: bool
    session_id: str
    case_id: str
    account_id: str
    signals: list[PohLiveWebRTCSignalModel]
    next_seq: int
    authority: str = "transport_only_ephemeral"


class PohLiveWebRTCIceServerModel(BaseModel):
    urls: str | list[str]
    username: str | None = None
    credential: str | None = None
    credential_expires_ms: int | None = None


class PohLiveWebRTCRelayConfigResponse(BaseModel):
    ok: bool
    ice_servers: list[PohLiveWebRTCIceServerModel]
    relay_policy: str = "optional_community_relay_fallback"
    authority: str = "transport_only_non_consensus"


class PohLiveWebRTCSignalBridgeRequest(BaseModel):
    signal: dict[str, object]
    source_node: str | None = Field(default=None, max_length=128)
    source_chain_id: str | None = Field(default=None, max_length=128)
    signature: str | None = Field(default=None, max_length=256)


class PohLiveWebRTCSignalBridgeResponse(BaseModel):
    ok: bool
    imported: bool
    signal: PohLiveWebRTCSignalModel | None = None
    authority: str = "transport_only_bridge"




def _split_csv_env(name: str) -> list[str]:
    raw = str(os.environ.get(name) or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def _valid_ice_url(url: str) -> bool:
    u = str(url or "").strip().lower()
    return u.startswith("stun:") or u.startswith("turn:") or u.startswith("turns:")


def _ice_urls_include_turn(urls: object) -> bool:
    url_list = [str(urls)] if isinstance(urls, str) else [str(u) for u in urls] if isinstance(urls, list) else []
    return any(u.strip().lower().startswith(("turn:", "turns:")) for u in url_list)


def _validate_webrtc_turn_credential_expiry(expires_ms: int, *, has_credential: bool, urls: object) -> None:
    if not (_is_prod() and has_credential and _ice_urls_include_turn(urls)):
        return
    now_ms = _now_ms()
    max_ttl_ms = _env_int("WEALL_WEBRTC_TURN_MAX_CREDENTIAL_TTL_MS", 24 * 60 * 60 * 1000)
    if expires_ms <= now_ms or expires_ms > now_ms + max_ttl_ms:
        raise PohRouteConfigError("prod_webrtc_turn_credentials_must_be_short_lived")


def _webrtc_ice_servers_from_env() -> list[Json]:
    raw_json = str(os.environ.get("WEALL_WEBRTC_ICE_SERVERS_JSON") or os.environ.get("WEALL_P2P_ICE_SERVERS_JSON") or "").strip()
    out: list[Json] = []
    if raw_json:
        try:
            parsed = json.loads(raw_json)
        except Exception as exc:
            if _is_prod():
                raise PohRouteConfigError("invalid_webrtc_ice_servers_json") from exc
            parsed = []
        rows = parsed if isinstance(parsed, list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            urls = row.get("urls")
            url_list = [str(urls)] if isinstance(urls, str) else [str(u) for u in urls] if isinstance(urls, list) else []
            url_list = [u.strip() for u in url_list if _valid_ice_url(u)]
            if not url_list:
                if _is_prod():
                    raise PohRouteConfigError("webrtc_ice_server_invalid_url")
                continue
            rec: Json = {"urls": url_list[0] if len(url_list) == 1 else url_list}
            if row.get("username"):
                rec["username"] = str(row.get("username"))
            credential = str(row.get("credential") or "")
            expires_ms = 0
            try:
                expires_ms = int(row.get("credential_expires_ms") or row.get("expires_ms") or 0)
            except Exception:
                expires_ms = 0
            _validate_webrtc_turn_credential_expiry(expires_ms, has_credential=bool(credential), urls=url_list)
            if credential:
                rec["credential"] = credential
            if expires_ms > 0:
                rec["credential_expires_ms"] = expires_ms
            out.append(rec)
    stun_urls = [u for u in _split_csv_env("WEALL_WEBRTC_STUN_URLS") if _valid_ice_url(u)]
    if stun_urls:
        out.append({"urls": stun_urls if len(stun_urls) > 1 else stun_urls[0]})
    turn_urls = [u for u in _split_csv_env("WEALL_WEBRTC_TURN_URLS") if _valid_ice_url(u)]
    if turn_urls:
        rec = {"urls": turn_urls if len(turn_urls) > 1 else turn_urls[0]}
        username = str(os.environ.get("WEALL_WEBRTC_TURN_USERNAME") or "").strip()
        credential = str(os.environ.get("WEALL_WEBRTC_TURN_CREDENTIAL") or "").strip()
        if username:
            rec["username"] = username
        expires_ms = _env_int("WEALL_WEBRTC_TURN_CREDENTIAL_EXPIRES_MS", 0)
        now_ms = _now_ms()
        if credential:
            _validate_webrtc_turn_credential_expiry(expires_ms, has_credential=True, urls=turn_urls)
            rec["credential"] = credential
        if expires_ms > 0:
            rec["credential_expires_ms"] = expires_ms
        out.append(rec)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    clean: list[Json] = []
    for rec in out:
        key = json.dumps(rec, sort_keys=True)
        if key not in seen:
            clean.append(rec)
            seen.add(key)
    return clean[: max(1, _env_int("WEALL_WEBRTC_MAX_ICE_SERVERS", 8))]

def _live_webrtc_store(request: Request) -> Json:
    store = getattr(request.app.state, "poh_live_webrtc_signals", None)
    if not isinstance(store, dict):
        store = {}
        request.app.state.poh_live_webrtc_signals = store
    return store


def _live_webrtc_next_seq(request: Request) -> int:
    raw = getattr(request.app.state, "poh_live_webrtc_next_seq", 0)
    try:
        seq = int(raw) + 1
    except Exception:
        seq = 1
    request.app.state.poh_live_webrtc_next_seq = seq
    return seq


def _webrtc_chain_id() -> str:
    return str(os.environ.get("WEALL_CHAIN_ID") or os.environ.get("WEALL_CHAIN") or "weall-controlled-devnet").strip()


def _webrtc_bridge_diag() -> Json:
    diag = globals().setdefault("_WEALL_WEBRTC_SIGNAL_BRIDGE_DIAGNOSTICS", {})
    if not isinstance(diag, dict):
        diag = {}
        globals()["_WEALL_WEBRTC_SIGNAL_BRIDGE_DIAGNOSTICS"] = diag
    diag.setdefault("last_drain_result", {})
    diag.setdefault("rejected_peers", {})
    diag.setdefault("stale_signal_pruned", 0)
    diag.setdefault("stale_outbox_pruned", 0)
    diag.setdefault("max_record_pruned", 0)
    return diag


def _record_webrtc_bridge_rejection(reason: str, *, source_node: str = "", peer: str = "") -> None:
    diag = _webrtc_bridge_diag()
    rejected = diag.setdefault("rejected_peers", {})
    if not isinstance(rejected, dict):
        rejected = {}
        diag["rejected_peers"] = rejected
    key = str(source_node or peer or "unknown").strip() or "unknown"
    row = rejected.setdefault(key, {"count": 0, "last_reason": ""})
    if isinstance(row, dict):
        row["count"] = int(row.get("count") or 0) + 1
        row["last_reason"] = str(reason)
        row["updated_ms"] = _now_ms()


def _canonical_webrtc_bridge_signing_payload(*, source_node: str, source_chain_id: str, signal: Json) -> bytes:
    return json.dumps(
        {
            "source_node": str(source_node or ""),
            "source_chain_id": str(source_chain_id or ""),
            "signal": signal,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sign_webrtc_bridge_payload(*, secret: str, source_node: str, source_chain_id: str, signal: Json) -> str:
    payload = _canonical_webrtc_bridge_signing_payload(
        source_node=source_node, source_chain_id=source_chain_id, signal=signal
    )
    return hmac.new(str(secret).encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _webrtc_bridge_token() -> str:
    return str(
        os.environ.get("WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN")
        or os.environ.get("WEALL_STATE_SYNC_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OBSERVER_EDGE_OPERATOR_TOKEN")
        or os.environ.get("WEALL_OPERATOR_TOKEN")
        or ""
    ).strip()


def _request_webrtc_bridge_token(request: Request) -> str:
    for name in (
        "x-weall-webrtc-signal-bridge-token",
        "x-weall-state-sync-operator-token",
        "x-weall-observer-operator-token",
        "x-weall-operator-token",
    ):
        got = str(request.headers.get(name) or "").strip()
        if got:
            return got
    return ""


def _require_webrtc_bridge_operator(request: Request) -> None:
    want = _webrtc_bridge_token()
    if not want:
        _record_webrtc_bridge_rejection("webrtc_signal_bridge_token_required")
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_signal_bridge_token_required",
            {"message": "WebRTC signal bridge import requires WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN or an operator token"},
        )
    if _request_webrtc_bridge_token(request) != want:
        _record_webrtc_bridge_rejection("bad_webrtc_signal_bridge_token")
        raise ApiError.forbidden("forbidden", "bad_webrtc_signal_bridge_token", {})


def _bridge_peer_token(spec: Json) -> str:
    return str(spec.get("bridge_token") or spec.get("token") or "").strip()


def _bridge_peer_secret(spec: Json) -> str:
    return str(spec.get("bridge_secret") or spec.get("secret") or "").strip()


def _require_webrtc_bridge_import_auth(request: Request, req: "PohLiveWebRTCSignalBridgeRequest", raw: Json, spec: Json | None, *, source_node: str, source_chain_id: str) -> None:
    spec = spec if isinstance(spec, dict) else {}
    peer_token = _bridge_peer_token(spec)
    peer_secret = _bridge_peer_secret(spec)
    if peer_token:
        if _request_webrtc_bridge_token(request) != peer_token:
            _record_webrtc_bridge_rejection("bad_webrtc_peer_bridge_token", source_node=source_node)
            raise ApiError.forbidden("forbidden", "bad_webrtc_peer_bridge_token", {"source_node": source_node})
        return
    if peer_secret:
        supplied = str(req.signature or raw.get("signature") or request.headers.get("x-weall-webrtc-signal-bridge-signature") or "").strip()
        expected = _sign_webrtc_bridge_payload(
            secret=peer_secret,
            source_node=source_node,
            source_chain_id=source_chain_id,
            signal=dict(req.signal or {}),
        )
        if not supplied or not hmac.compare_digest(supplied, expected):
            _record_webrtc_bridge_rejection("bad_webrtc_bridge_signature", source_node=source_node)
            raise ApiError.forbidden("forbidden", "bad_webrtc_bridge_signature", {"source_node": source_node})
        return
    if _is_prod() and spec:
        _record_webrtc_bridge_rejection("webrtc_peer_bridge_auth_required", source_node=source_node)
        raise ApiError.forbidden("forbidden", "webrtc_peer_bridge_auth_required", {"source_node": source_node})
    _require_webrtc_bridge_operator(request)


def _webrtc_node_id() -> str:
    return str(os.environ.get("WEALL_NODE_ID") or os.environ.get("WEALL_NODE_ACCOUNT") or "weall-node").strip()


def _safe_webrtc_peer_url(url: str) -> str:
    out = str(url or "").strip().rstrip("/")
    if not (out.startswith("http://") or out.startswith("https://")):
        return ""
    return out


def _webrtc_signal_peer_specs() -> list[Json]:
    """Return operator-pinned WebRTC signal bridge peers.

    Production nodes should use WEALL_WEBRTC_SIGNAL_PEERS_JSON with explicit
    node_id/url entries. Raw URL lists remain available only for controlled dev
    rehearsals or when explicitly allowed.
    """
    limit = max(1, _env_int("WEALL_WEBRTC_SIGNAL_MAX_PEERS", 4))
    raw_json = str(
        os.environ.get("WEALL_WEBRTC_SIGNAL_PEERS_JSON")
        or os.environ.get("WEALL_LIVE_WEBRTC_SIGNAL_PEERS_JSON")
        or ""
    ).strip()
    manifest_path = str(os.environ.get("WEALL_WEBRTC_SIGNAL_PEER_MANIFEST_PATH") or "").strip()
    if not raw_json and manifest_path:
        try:
            raw_json = Path(manifest_path).read_text(encoding="utf-8")
        except Exception as exc:
            if _is_prod():
                raise PohRouteConfigError("invalid_webrtc_signal_peer_manifest_path") from exc
            raw_json = ""
    specs: list[Json] = []
    if raw_json:
        try:
            parsed = json.loads(raw_json)
        except Exception as exc:
            if _is_prod():
                raise PohRouteConfigError("invalid_webrtc_signal_peers_json") from exc
            parsed = []
        if isinstance(parsed, dict) and isinstance(parsed.get("webrtc_signal_peers"), list):
            parsed = parsed.get("webrtc_signal_peers")
        rows = parsed if isinstance(parsed, list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = _safe_webrtc_peer_url(str(row.get("url") or ""))
            node_id = str(row.get("node_id") or row.get("id") or "").strip()
            chain_id = str(row.get("chain_id") or "").strip()
            if not url or not node_id:
                if _is_prod():
                    raise PohRouteConfigError("webrtc_signal_peer_requires_node_id_and_url")
                continue
            rec: Json = {"url": url, "node_id": node_id}
            if chain_id:
                rec["chain_id"] = chain_id
            bridge_token = str(row.get("bridge_token") or row.get("token") or "").strip()
            bridge_secret = str(row.get("bridge_secret") or row.get("secret") or "").strip()
            if bridge_token:
                rec["bridge_token"] = bridge_token
            if bridge_secret:
                rec["bridge_secret"] = bridge_secret
            if _is_prod() and not bridge_token and not bridge_secret:
                raise PohRouteConfigError("webrtc_signal_peer_requires_token_or_signed_envelope")
            if rec not in specs:
                specs.append(rec)
            if len(specs) >= limit:
                break
        return specs

    raw_urls = str(
        os.environ.get("WEALL_WEBRTC_SIGNAL_PEER_URLS")
        or os.environ.get("WEALL_LIVE_WEBRTC_SIGNAL_PEER_URLS")
        or ""
    ).strip()
    if not raw_urls:
        return []
    if _is_prod() and not _env_bool("WEALL_ALLOW_RAW_WEBRTC_SIGNAL_PEER_URLS", False):
        raise PohRouteConfigError("prod_webrtc_signal_peers_must_be_node_pinned")

    node_ids = [p.strip() for p in str(os.environ.get("WEALL_WEBRTC_SIGNAL_PEER_NODE_IDS") or "").replace(";", ",").split(",") if p.strip()]
    for idx, part in enumerate(raw_urls.replace(";", ",").split(",")):
        url = _safe_webrtc_peer_url(part)
        if not url:
            continue
        node_id = node_ids[idx] if idx < len(node_ids) else f"dev-peer-{idx + 1}"
        rec = {"url": url, "node_id": node_id, "raw_url_compat": True}
        chain_id = str(os.environ.get("WEALL_WEBRTC_SIGNAL_PEER_CHAIN_ID") or _webrtc_chain_id()).strip()
        if chain_id:
            rec["chain_id"] = chain_id
        bridge_token = str(os.environ.get("WEALL_WEBRTC_SIGNAL_BRIDGE_TOKEN") or "").strip()
        if bridge_token:
            rec["bridge_token"] = bridge_token
        if rec not in specs:
            specs.append(rec)
        if len(specs) >= limit:
            break
    return specs


def _normalized_webrtc_signal_peer_urls() -> list[str]:
    # Compatibility helper retained for older tests and diagnostics.
    return [str(spec.get("url") or "") for spec in _webrtc_signal_peer_specs() if str(spec.get("url") or "")]


def _allowed_webrtc_bridge_source_nodes() -> set[str]:
    allowed = {str(spec.get("node_id") or "").strip() for spec in _webrtc_signal_peer_specs() if str(spec.get("node_id") or "").strip()}
    extra = str(os.environ.get("WEALL_WEBRTC_SIGNAL_ALLOWED_SOURCE_NODE_IDS") or "").strip()
    for part in extra.replace(";", ",").split(","):
        if part.strip():
            allowed.add(part.strip())
    return allowed


def _webrtc_signal_peer_spec_for_source(source_node: str) -> Json | None:
    node = str(source_node or "").strip()
    if not node:
        return None
    for spec in _webrtc_signal_peer_specs():
        if str(spec.get("node_id") or "").strip() == node:
            return spec
    return None


def _validate_webrtc_bridge_source_chain(*, source_node: str, source_chain_id: str, spec: Json | None) -> None:
    expected_chain = str((spec or {}).get("chain_id") or _webrtc_chain_id()).strip()
    got_chain = str(source_chain_id or "").strip()
    if (_is_prod() or spec) and not got_chain:
        _record_webrtc_bridge_rejection("webrtc_bridge_source_chain_id_required", source_node=source_node)
        raise ApiError.forbidden("forbidden", "webrtc_bridge_source_chain_id_required", {"source_node": source_node})
    if got_chain and expected_chain and got_chain != expected_chain:
        _record_webrtc_bridge_rejection("webrtc_bridge_chain_id_mismatch", source_node=source_node)
        raise ApiError.forbidden("forbidden", "webrtc_bridge_chain_id_mismatch", {"source_node": source_node, "source_chain_id": got_chain, "expected_chain_id": expected_chain})


def _redact_webrtc_peer_url(url: str) -> str:
    if "@" in url:
        scheme, rest = url.split("://", 1) if "://" in url else ("", url)
        rest = rest.split("@", 1)[-1]
        return f"{scheme}://{rest}" if scheme else rest
    return url


def _bridge_payload_for_signal(rec: Json, spec: Json | None = None) -> Json:
    # Bridge records are transport-only and explicitly non-consensus. The peer
    # allocates its own local sequence number on import so browser polling stays
    # monotonic per node.
    signal = {
        "signal_id": str(rec.get("signal_id") or ""),
        "session_id": str(rec.get("session_id") or ""),
        "case_id": str(rec.get("case_id") or ""),
        "from_account": str(rec.get("from_account") or ""),
        "to_account": str(rec.get("to_account") or ""),
        "type": str(rec.get("type") or ""),
        "sdp": str(rec.get("sdp") or ""),
        "candidate": dict(rec.get("candidate")) if isinstance(rec.get("candidate"), dict) else {},
        "ts_ms": int(rec.get("ts_ms") or 0),
        "authority": "transport_only_ephemeral",
    }
    source_node = _webrtc_node_id()
    source_chain_id = _webrtc_chain_id()
    payload: Json = {"signal": signal, "source_node": source_node, "source_chain_id": source_chain_id}
    secret = _bridge_peer_secret(spec or {})
    if secret:
        payload["signature"] = _sign_webrtc_bridge_payload(
            secret=secret, source_node=source_node, source_chain_id=source_chain_id, signal=signal
        )
    return payload


def _webrtc_signal_outbox_path() -> Path:
    raw = str(os.environ.get("WEALL_WEBRTC_SIGNAL_OUTBOX_PATH") or "").strip()
    if raw:
        return Path(raw)
    return Path(os.environ.get("WEALL_RUNTIME_DIR") or "data") / "webrtc_signal_bridge_outbox.json"


def _webrtc_signal_outbox_lock():
    path = _webrtc_signal_outbox_path()
    locks = globals().setdefault("_WEALL_WEBRTC_SIGNAL_OUTBOX_LOCKS", {})
    lock = locks.get(str(path))
    if lock is None:
        lock = threading.Lock()
        locks[str(path)] = lock
    return lock


def _load_webrtc_signal_outbox_unlocked() -> list[Json]:
    path = _webrtc_signal_outbox_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "[]")
    except Exception:
        bad = path.with_suffix(path.suffix + f".corrupt-{int(time.time() * 1000)}")
        try:
            path.replace(bad)
        except Exception:
            pass
        return []
    return data if isinstance(data, list) else []


def _write_webrtc_signal_outbox_unlocked(rows: list[Json]) -> None:
    path = _webrtc_signal_outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    max_rows = max(16, _env_int("WEALL_WEBRTC_SIGNAL_OUTBOX_MAX_ROWS", 1024))
    ttl_ms = max(10_000, _env_int("WEALL_WEBRTC_SIGNAL_OUTBOX_TTL_MS", _webrtc_signal_ttl_ms()))
    now = _now_ms()
    clean: list[Json] = []
    seen: set[str] = set()
    stale_outbox_pruned = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        created = int(row.get("created_ms") or 0)
        if created and now - created > ttl_ms:
            stale_outbox_pruned += 1
            continue
        key = str(row.get("outbox_id") or "").strip() or json.dumps(row, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        clean.append(row)
    if stale_outbox_pruned:
        diag = _webrtc_bridge_diag()
        diag["stale_outbox_pruned"] = int(diag.get("stale_outbox_pruned") or 0) + stale_outbox_pruned
    overflow_pruned = max(0, len(clean) - max_rows)
    if overflow_pruned:
        diag = _webrtc_bridge_diag()
        diag["max_record_pruned"] = int(diag.get("max_record_pruned") or 0) + overflow_pruned
    clean = clean[-max_rows:]
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(clean, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _read_webrtc_signal_outbox() -> list[Json]:
    with _webrtc_signal_outbox_lock():
        rows = _load_webrtc_signal_outbox_unlocked()
        _write_webrtc_signal_outbox_unlocked(rows)
        return _load_webrtc_signal_outbox_unlocked()


def _enqueue_webrtc_signal_bridge(rec: Json) -> Json:
    specs = _webrtc_signal_peer_specs()
    if not specs:
        return {"attempted": False, "queued": 0, "mode": "durable_outbox", "results": []}
    created = _now_ms()
    with _webrtc_signal_outbox_lock():
        rows = _load_webrtc_signal_outbox_unlocked()
        queued = 0
        for spec in specs:
            url = str(spec.get("url") or "").strip()
            node_id = str(spec.get("node_id") or "").strip()
            if not url or not node_id:
                continue
            payload = _bridge_payload_for_signal(rec, spec)
            outbox_id = hashlib.sha256(json.dumps({"peer": node_id, "signal": payload}, sort_keys=True).encode("utf-8")).hexdigest()
            if any(isinstance(r, dict) and r.get("outbox_id") == outbox_id for r in rows):
                continue
            rows.append({
                "outbox_id": outbox_id,
                "peer_url": url,
                "peer_node_id": node_id,
                "peer_chain_id": str(spec.get("chain_id") or _webrtc_chain_id()),
                "payload": payload,
                "session_id": str(rec.get("session_id") or ""),
                "created_ms": created,
                "attempts": 0,
                "last_error": "",
            })
            queued += 1
        _write_webrtc_signal_outbox_unlocked(rows)
    return {"attempted": bool(specs), "queued": queued, "mode": "durable_outbox", "results": []}


def _post_webrtc_signal_outbox_row(row: Json, *, timeout_s: int) -> Json:
    url = str(row.get("peer_url") or "").strip()
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    signal = payload.get("signal") if isinstance(payload.get("signal"), dict) else {}
    sid = str(signal.get("session_id") or row.get("session_id") or "").strip()
    if not url or not sid:
        return {"ok": False, "error": "missing_peer_or_session", "peer": _redact_webrtc_peer_url(url)}
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"content-type": "application/json"}
    peer_node_id = str(row.get("peer_node_id") or "").strip()
    spec = _webrtc_signal_peer_spec_for_source(peer_node_id) if peer_node_id else None
    token = _bridge_peer_token(spec or {}) or _webrtc_bridge_token()
    if token:
        headers["x-weall-webrtc-signal-bridge-token"] = token
    if payload.get("source_node"):
        headers["x-weall-webrtc-signal-bridge-source-node"] = str(payload.get("source_node"))
    if payload.get("source_chain_id"):
        headers["x-weall-webrtc-signal-bridge-chain-id"] = str(payload.get("source_chain_id"))
    if payload.get("signature"):
        headers["x-weall-webrtc-signal-bridge-signature"] = str(payload.get("signature"))
    req = urllib.request.Request(
        f"{url.rstrip('/')}/v1/poh/live/session/{sid}/webrtc/signals/import",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=max(1, int(timeout_s))) as resp:  # noqa: S310 - operator-pinned peer URL
            parsed = json.loads(resp.read().decode("utf-8") or "{}")
            return {"ok": bool(isinstance(parsed, dict) and parsed.get("ok")), "peer": _redact_webrtc_peer_url(url), "peer_node_id": str(row.get("peer_node_id") or ""), "status": int(resp.status)}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": "peer_http_error", "status": int(exc.code), "peer": _redact_webrtc_peer_url(url)}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:160], "peer": _redact_webrtc_peer_url(url)}


def _drain_webrtc_signal_outbox(*, limit: int | None = None) -> Json:
    limit_n = max(1, int(limit or _env_int("WEALL_WEBRTC_SIGNAL_OUTBOX_DRAIN_BATCH", 32)))
    timeout_s = max(1, _env_int("WEALL_WEBRTC_SIGNAL_PEER_TIMEOUT_S", 3))
    results: list[Json] = []
    with _webrtc_signal_outbox_lock():
        rows = _load_webrtc_signal_outbox_unlocked()
        rows = rows[-max(16, _env_int("WEALL_WEBRTC_SIGNAL_OUTBOX_MAX_ROWS", 1024)):]
        keep: list[Json] = []
        selected = 0
        for row in rows:
            if selected >= limit_n:
                keep.append(row)
                continue
            selected += 1
            result = _post_webrtc_signal_outbox_row(row, timeout_s=timeout_s)
            results.append(result)
            if not bool(result.get("ok")):
                row["attempts"] = int(row.get("attempts") or 0) + 1
                row["last_error"] = str(result.get("error") or "peer_rejected")
                if int(row.get("attempts") or 0) < max(1, _env_int("WEALL_WEBRTC_SIGNAL_OUTBOX_MAX_ATTEMPTS", 5)):
                    keep.append(row)
        _write_webrtc_signal_outbox_unlocked(keep)
    summary = {"ok": True, "attempted": bool(results), "accepted": any(bool(r.get("ok")) for r in results), "queued": len(_read_webrtc_signal_outbox()), "results": results}
    diag = _webrtc_bridge_diag()
    diag["last_drain_result"] = summary
    diag["last_drain_ms"] = _now_ms()
    return summary


def _bridge_webrtc_signal_to_peers(rec: Json) -> Json:
    # Request path durability only: the worker/operator drain performs network IO.
    return _enqueue_webrtc_signal_bridge(rec)


def _webrtc_signal_bridge_autodrain_enabled() -> bool:
    return _env_bool("WEALL_WEBRTC_SIGNAL_BRIDGE_AUTODRAIN", False)


def _webrtc_signal_bridge_interval_s() -> float:
    return max(0.25, _env_int("WEALL_WEBRTC_SIGNAL_BRIDGE_INTERVAL_MS", 1000) / 1000.0)


def start_webrtc_signal_bridge_autodrain() -> threading.Thread | None:
    if not _webrtc_signal_bridge_autodrain_enabled():
        return None
    existing = globals().get("_WEALL_WEBRTC_SIGNAL_BRIDGE_THREAD")
    if isinstance(existing, threading.Thread) and existing.is_alive():
        return existing
    stop = threading.Event()
    globals()["_WEALL_WEBRTC_SIGNAL_BRIDGE_STOP"] = stop

    def _loop() -> None:
        while not stop.is_set():
            try:
                _drain_webrtc_signal_outbox()
            except Exception:
                pass
            stop.wait(_webrtc_signal_bridge_interval_s())

    thread = threading.Thread(target=_loop, name="weall-webrtc-signal-bridge-drain", daemon=True)
    thread.start()
    globals()["_WEALL_WEBRTC_SIGNAL_BRIDGE_THREAD"] = thread
    return thread


def stop_webrtc_signal_bridge_autodrain(_thread: threading.Thread | None = None) -> None:
    stop = globals().get("_WEALL_WEBRTC_SIGNAL_BRIDGE_STOP")
    if hasattr(stop, "set"):
        stop.set()
    thread = _thread or globals().get("_WEALL_WEBRTC_SIGNAL_BRIDGE_THREAD")
    if isinstance(thread, threading.Thread) and thread.is_alive():
        thread.join(timeout=2.0)


def _webrtc_signal_dedup_key(raw: Json) -> str:
    origin = str(raw.get("origin_signal_id") or raw.get("source_signal_id") or raw.get("signal_id") or "").strip()
    if origin:
        return origin
    candidate = raw.get("candidate") if isinstance(raw.get("candidate"), dict) else {}
    return json.dumps(
        {
            "session_id": str(raw.get("session_id") or ""),
            "case_id": str(raw.get("case_id") or ""),
            "from_account": str(raw.get("from_account") or ""),
            "to_account": str(raw.get("to_account") or ""),
            "type": str(raw.get("type") or ""),
            "sdp": str(raw.get("sdp") or ""),
            "candidate": candidate,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _store_webrtc_signal_record(request: Request, sid: str, rec: Json) -> tuple[bool, Json]:
    store = _live_webrtc_store(request)
    records = store.get(sid)
    if not isinstance(records, list):
        records = []
    key = _webrtc_signal_dedup_key(rec)
    for existing in records:
        if isinstance(existing, dict) and _webrtc_signal_dedup_key(existing) == key:
            return False, existing
    records.append(rec)
    store[sid] = _prune_webrtc_session_records(records)
    return True, rec


def _live_case_participant_ids(raw: Json) -> set[str]:
    out: set[str] = set()
    subject = str(raw.get("account_id") or "").strip()
    if subject:
        out.add(subject)
    jurors = raw.get("jurors")
    if isinstance(jurors, dict):
        out.update(str(j).strip() for j in jurors.keys() if str(j).strip())
    assigned = raw.get("assigned_jurors")
    if isinstance(assigned, list):
        out.update(str(j).strip() for j in assigned if str(j).strip())
    return out


def _live_case_for_session(st: Json, session_id: str) -> tuple[str, Json]:
    cid = _live_session_case_id(st, session_id)
    raw = _live_cases_from_snapshot(st).get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "live_case_not_found", {"case_id": cid})
    return cid, raw


def _validate_webrtc_target(case: Json, *, from_account: str, to_account: str) -> None:
    if not to_account:
        return
    participants = _live_case_participant_ids(case)
    if to_account not in participants:
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_target_must_be_case_participant",
            {"from_account": from_account, "to_account": to_account},
        )


def _validate_webrtc_signal(req: PohLiveWebRTCSignalRequest) -> tuple[str, str, str, Json | None]:
    signal_type = str(req.type or "").strip().lower()
    if signal_type not in _ALLOWED_WEBRTC_SIGNAL_TYPES:
        raise ApiError.bad_request("bad_request", "invalid_webrtc_signal_type", {"type": signal_type})

    sdp = str(req.sdp or "")
    candidate = req.candidate if isinstance(req.candidate, dict) else None

    if signal_type in {"offer", "answer"}:
        if not sdp.strip():
            raise ApiError.bad_request("bad_request", "webrtc_sdp_required", {"type": signal_type})
        if len(sdp.encode("utf-8")) > _MAX_WEBRTC_SDP_BYTES:
            raise ApiError.bad_request("bad_request", "webrtc_sdp_too_large", {})
        candidate = None
    elif signal_type == "ice":
        if not candidate:
            raise ApiError.bad_request("bad_request", "webrtc_candidate_required", {})
        try:
            encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        except Exception as exc:
            raise ApiError.bad_request("bad_request", "webrtc_candidate_invalid", {}) from exc
        if len(encoded.encode("utf-8")) > _MAX_WEBRTC_CANDIDATE_BYTES:
            raise ApiError.bad_request("bad_request", "webrtc_candidate_too_large", {})
        cand = str(candidate.get("candidate") or "").strip()
        if not cand:
            raise ApiError.bad_request("bad_request", "webrtc_candidate_required", {})
        sdp = ""
    else:
        sdp = ""
        candidate = None

    to_account = str(req.to_account or "").strip()
    if signal_type in {"offer", "answer", "ice"} and not to_account:
        raise ApiError.bad_request("bad_request", "webrtc_target_required", {"type": signal_type})
    return signal_type, to_account, sdp, candidate


def _as_webrtc_signal(raw: Json) -> PohLiveWebRTCSignalModel:
    return PohLiveWebRTCSignalModel(
        seq=int(raw.get("seq") or 0),
        signal_id=str(raw.get("signal_id") or ""),
        session_id=str(raw.get("session_id") or ""),
        case_id=str(raw.get("case_id") or ""),
        from_account=str(raw.get("from_account") or ""),
        to_account=str(raw.get("to_account") or "").strip() or None,
        type=str(raw.get("type") or ""),
        sdp=str(raw.get("sdp") or "").strip() or None,
        candidate=dict(raw.get("candidate")) if isinstance(raw.get("candidate"), dict) else None,
        ts_ms=int(raw.get("ts_ms") or 0),
    )


def _prune_webrtc_session_records(records: list[Json]) -> list[Json]:
    max_records = max(16, _env_int("WEALL_P2P_SIGNAL_MAX_RECORDS_PER_SESSION", 256))
    ttl_ms = _webrtc_signal_ttl_ms()
    now = _now_ms()
    kept: list[Json] = []
    stale_count = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        try:
            ts_ms = int(rec.get("ts_ms") or 0)
        except Exception:
            ts_ms = 0
        if ts_ms and now - ts_ms > ttl_ms:
            stale_count += 1
            continue
        kept.append(rec)
    if stale_count:
        diag = _webrtc_bridge_diag()
        diag["stale_signal_pruned"] = int(diag.get("stale_signal_pruned") or 0) + stale_count
    if len(kept) <= max_records:
        return kept
    dropped = len(kept) - max_records
    diag = _webrtc_bridge_diag()
    diag["max_record_pruned"] = int(diag.get("max_record_pruned") or 0) + dropped
    return kept[-max_records:]




@router.get(
    "/poh/live/webrtc/relay-config",
    response_model=PohLiveWebRTCRelayConfigResponse,
    name="poh_live_webrtc_relay_config",
)
def poh_live_webrtc_relay_config() -> PohLiveWebRTCRelayConfigResponse:
    """Return optional STUN/TURN/community relay settings for browser WebRTC.

    This endpoint is transport-only: the chain remains authoritative for live
    verification acceptance, attendance, verdicts, and finalization.
    """
    return PohLiveWebRTCRelayConfigResponse(
        ok=True,
        ice_servers=[PohLiveWebRTCIceServerModel(**rec) for rec in _webrtc_ice_servers_from_env()],
    )


@router.get("/poh/live/webrtc/signals/diagnostics")
def poh_live_webrtc_signal_diagnostics(request: Request) -> Json:
    _require_webrtc_bridge_operator(request)
    diag = dict(_webrtc_bridge_diag())
    rows = _read_webrtc_signal_outbox()
    diag.update({
        "ok": True,
        "authority": "transport_only_operator_diagnostics",
        "queue_depth": len(rows),
        "peer_count": len(_webrtc_signal_peer_specs()),
        "source_node": _webrtc_node_id(),
        "chain_id": _webrtc_chain_id(),
    })
    return diag


@router.post("/poh/live/webrtc/signals/outbox/drain")
def poh_live_webrtc_signal_outbox_drain(request: Request, limit: int | None = None) -> Json:
    _require_webrtc_bridge_operator(request)
    return _drain_webrtc_signal_outbox(limit=limit)

@router.get(
    "/poh/live/session/{session_id}/webrtc/signals",
    response_model=PohLiveWebRTCSignalListResponse,
    name="poh_live_webrtc_signals",
)
def poh_live_webrtc_signals(
    session_id: str, request: Request, since_seq: int = 0
) -> PohLiveWebRTCSignalListResponse:
    sid = str(session_id or "").strip()
    if not sid:
        raise ApiError.bad_request("bad_request", "missing session_id", {})

    st = _snapshot(request)
    account = _require_session_principal_for_poh_private(
        request, st, purpose="WebRTC live-room signaling"
    )
    case_id, case = _live_case_for_session(st, sid)
    _require_live_room_participant(st, session_id=sid, account_id=account)

    try:
        since = int(since_seq or 0)
    except Exception:
        since = 0

    signal_store = _live_webrtc_store(request)
    raw_records = signal_store.get(sid)
    records = _prune_webrtc_session_records(raw_records if isinstance(raw_records, list) else [])
    signal_store[sid] = records
    visible: list[PohLiveWebRTCSignalModel] = []
    max_seq = since
    for rec in records:
        if not isinstance(rec, dict):
            continue
        seq = int(rec.get("seq") or 0)
        max_seq = max(max_seq, seq)
        if seq <= since:
            continue
        to_account = str(rec.get("to_account") or "").strip()
        from_account = str(rec.get("from_account") or "").strip()
        if to_account and to_account != account and from_account != account:
            continue
        # Only chain-authorized case participants can list signaling records.
        # This assertion keeps stale records from leaking if case membership changes.
        if from_account not in _live_case_participant_ids(case):
            continue
        visible.append(_as_webrtc_signal(rec))

    return PohLiveWebRTCSignalListResponse(
        ok=True,
        session_id=sid,
        case_id=case_id,
        account_id=account,
        signals=visible[:100],
        next_seq=max_seq,
    )


@router.post(
    "/poh/live/session/{session_id}/webrtc/signals/import",
    response_model=PohLiveWebRTCSignalBridgeResponse,
    name="poh_live_webrtc_signal_bridge_import",
)
def poh_live_webrtc_signal_bridge_import(
    session_id: str, req: PohLiveWebRTCSignalBridgeRequest, request: Request
) -> PohLiveWebRTCSignalBridgeResponse:
    sid = str(session_id or "").strip()
    if not sid:
        raise ApiError.bad_request("bad_request", "missing session_id", {})
    raw = dict(req.signal or {})
    raw_sid = str(raw.get("session_id") or sid).strip()
    if raw_sid != sid:
        raise ApiError.bad_request("bad_request", "webrtc_session_mismatch", {"session_id": sid, "signal_session_id": raw_sid})

    st = _snapshot(request)
    case_id, case = _live_case_for_session(st, sid)
    source_node = str(req.source_node or raw.get("source_node") or request.headers.get("x-weall-webrtc-signal-bridge-source-node") or "").strip()
    source_chain_id = str(req.source_chain_id or raw.get("source_chain_id") or request.headers.get("x-weall-webrtc-signal-bridge-chain-id") or "").strip()
    allowed_sources = _allowed_webrtc_bridge_source_nodes()
    source_spec = _webrtc_signal_peer_spec_for_source(source_node)
    if (_is_prod() or allowed_sources) and source_node not in allowed_sources:
        _record_webrtc_bridge_rejection("webrtc_bridge_source_node_not_allowed", source_node=source_node)
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_bridge_source_node_not_allowed",
            {"source_node": source_node, "allowed_source_nodes": sorted(allowed_sources)},
        )
    _validate_webrtc_bridge_source_chain(source_node=source_node, source_chain_id=source_chain_id, spec=source_spec)
    _require_webrtc_bridge_import_auth(request, req, raw, source_spec, source_node=source_node, source_chain_id=source_chain_id)
    signal_type = str(raw.get("type") or "").strip().lower()
    bridge_req = PohLiveWebRTCSignalRequest(
        account_id=str(raw.get("from_account") or ""),
        type=signal_type,  # type: ignore[arg-type]
        to_account=str(raw.get("to_account") or "").strip() or None,
        sdp=str(raw.get("sdp") or "") or None,
        candidate=dict(raw.get("candidate")) if isinstance(raw.get("candidate"), dict) else None,
        ts_ms=int(raw.get("ts_ms") or 0) or None,
    )
    signal_type, to_account, sdp, candidate = _validate_webrtc_signal(bridge_req)
    from_account = str(bridge_req.account_id or "").strip()
    if from_account not in _live_case_participant_ids(case):
        raise ApiError.forbidden("forbidden", "webrtc_source_must_be_case_participant", {"from_account": from_account})
    _validate_webrtc_target(case, from_account=from_account, to_account=to_account)

    ts_ms = _validate_webrtc_bridge_signal_ts_ms(bridge_req.ts_ms or raw.get("ts_ms"), source_node=source_node)
    seq = _live_webrtc_next_seq(request)
    rec: Json = {
        "seq": seq,
        "signal_id": f"webrtc:{sid}:bridge:{seq}",
        "origin_signal_id": str(raw.get("signal_id") or raw.get("origin_signal_id") or ""),
        "source_node": source_node or "peer",
        "source_chain_id": source_chain_id,
        "session_id": sid,
        "case_id": case_id,
        "from_account": from_account,
        "to_account": to_account,
        "type": signal_type,
        "sdp": sdp,
        "candidate": candidate or {},
        "ts_ms": ts_ms,
        "authority": "transport_only_bridge",
    }
    imported, stored = _store_webrtc_signal_record(request, sid, rec)
    return PohLiveWebRTCSignalBridgeResponse(
        ok=True,
        imported=bool(imported),
        signal=_as_webrtc_signal(stored) if isinstance(stored, dict) else None,
    )


@router.post(
    "/poh/live/session/{session_id}/webrtc/signals",
    response_model=PohLiveWebRTCSignalResponse,
    name="poh_live_webrtc_signal_send",
)
def poh_live_webrtc_signal_send(
    session_id: str, req: PohLiveWebRTCSignalRequest, request: Request
) -> PohLiveWebRTCSignalResponse:
    sid = str(session_id or "").strip()
    if not sid:
        raise ApiError.bad_request("bad_request", "missing session_id", {})

    account_id = str(req.account_id or "").strip()
    if not account_id:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    st = _snapshot(request)
    account = _require_session_principal_for_poh_private(
        request, st, purpose="WebRTC live-room signaling"
    )
    if account != account_id:
        raise ApiError.forbidden(
            "forbidden",
            "webrtc_account_mismatch",
            {"session_account": account, "account_id": account_id},
        )

    case_id, case = _live_case_for_session(st, sid)
    _require_live_room_participant(st, session_id=sid, account_id=account_id)
    signal_type, to_account, sdp, candidate = _validate_webrtc_signal(req)
    _validate_webrtc_target(case, from_account=account_id, to_account=to_account)

    seq = _live_webrtc_next_seq(request)
    ts_ms = _normalize_webrtc_signal_ts_ms(req.ts_ms)

    rec: Json = {
        "seq": seq,
        "signal_id": f"webrtc:{sid}:{seq}",
        "session_id": sid,
        "case_id": case_id,
        "from_account": account_id,
        "to_account": to_account,
        "type": signal_type,
        "sdp": sdp,
        "candidate": candidate or {},
        "ts_ms": ts_ms,
        "authority": "transport_only_ephemeral",
    }

    _store_webrtc_signal_record(request, sid, rec)
    bridge_result = _bridge_webrtc_signal_to_peers(rec)
    rec["bridge_propagation"] = bridge_result

    return PohLiveWebRTCSignalResponse(ok=True, signal=_as_webrtc_signal(rec))


# ---------------------------------------------------------------------------
# PoH Operator endpoints (MVP)
# ---------------------------------------------------------------------------


def _require_operator_poh_enabled() -> None:
    if not _env_bool("WEALL_ENABLE_OPERATOR_POH", False):
        raise ApiError.not_found("not_found", "operator_poh_disabled")


def _require_operator_token(request: Request) -> None:
    want = (os.getenv("WEALL_OPERATOR_TOKEN") or "").strip()
    if not want:
        raise ApiError.bad_request(
            "missing_env", "WEALL_OPERATOR_TOKEN must be set when operator endpoints are enabled"
        )

    got = (request.headers.get("X-WeAll-Operator-Token") or "").strip()
    if not got or got != want:
        raise ApiError.forbidden("forbidden", "bad_operator_token", {})


def _operator_live_case(st: Json, case_id: str) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        poh = {}

    cases = poh.get("live_cases")
    if not isinstance(cases, dict):
        cases = {}

    case = cases.get(case_id)
    if not isinstance(case, dict):
        raise ApiError.not_found("not_found", "live_case_not_found")

    return case


def _operator_live_case_required_field(case: Json, field: str, *, case_id: str) -> str:
    value = str(case.get(field) or "").strip()
    if not value:
        raise ApiError.bad_request(
            "bad_request",
            f"live case missing {field}",
            {"case_id": case_id, "field": field},
        )
    return value


class OperatorPohTier2FinalizeRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    outcome: str = Field(..., min_length=1)


class OperatorPohTier2FinalizeResponse(BaseModel):
    ok: bool
    enqueued: bool
    due_height: int


@router.post(
    "/poh/operator/tier2/finalize",
    response_model=OperatorPohTier2FinalizeResponse,
    name="operator_poh_tier2_finalize",
)
def operator_poh_tier2_finalize(
    req: OperatorPohTier2FinalizeRequest, request: Request
) -> OperatorPohTier2FinalizeResponse:
    _require_operator_poh_enabled()
    _require_operator_token(request)

    case_id = str(req.case_id or "").strip()
    outcome = str(req.outcome or "").strip().lower()
    if not case_id:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if outcome not in ("pass", "fail"):
        raise ApiError.bad_request(
            "bad_request", "outcome must be 'pass' or 'fail'", {"outcome": outcome}
        )

    st = _snapshot(request)
    height = int(st.get("height") or 0)

    enqueue_system_tx(
        st,
        tx_type="POH_TIER2_FINALIZE",
        payload={"case_id": case_id, "outcome": outcome, "ts_ms": 0},
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    return OperatorPohTier2FinalizeResponse(ok=True, enqueued=True, due_height=height + 1)


class OperatorPohLiveInitRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    join_url: str = Field(..., min_length=1)


class OperatorPohLiveInitResponse(BaseModel):
    ok: bool
    enqueued: bool
    due_height: int


@router.post(
    "/poh/operator/live/init",
    response_model=OperatorPohLiveInitResponse,
    name="operator_poh_live_init",
)
def operator_poh_live_init(
    req: OperatorPohLiveInitRequest, request: Request
) -> OperatorPohLiveInitResponse:
    _require_operator_poh_enabled()
    _require_operator_token(request)

    case_id = str(req.case_id or "").strip()
    join_url = str(req.join_url or "").strip()
    if not case_id:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if not join_url:
        raise ApiError.bad_request("bad_request", "missing join_url", {})

    st = _snapshot(request)
    height = int(st.get("height") or 0)
    case = _operator_live_case(st, case_id)
    account_id = _operator_live_case_required_field(case, "account_id", case_id=case_id)
    session_commitment = _operator_live_case_required_field(
        case, "session_commitment", case_id=case_id
    )

    enqueue_system_tx(
        st,
        tx_type="POH_LIVE_SESSION_INIT",
        payload={
            "case_id": case_id,
            "account_id": account_id,
            "session_commitment": session_commitment,
            "relay_commitment": _sha256_hex(join_url.encode("utf-8")),
            "ts_ms": 0,
        },
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    return OperatorPohLiveInitResponse(ok=True, enqueued=True, due_height=height + 1)


class OperatorPohLiveFinalizeRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class OperatorPohLiveFinalizeResponse(BaseModel):
    ok: bool
    enqueued: bool
    due_height: int


@router.post(
    "/poh/operator/live/finalize",
    response_model=OperatorPohLiveFinalizeResponse,
    name="operator_poh_live_finalize",
)
def operator_poh_live_finalize(
    req: OperatorPohLiveFinalizeRequest, request: Request
) -> OperatorPohLiveFinalizeResponse:
    _require_operator_poh_enabled()
    _require_operator_token(request)

    case_id = str(req.case_id or "").strip()
    if not case_id:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    st = _snapshot(request)
    height = int(st.get("height") or 0)

    enqueue_system_tx(
        st,
        tx_type="POH_LIVE_FINALIZE",
        payload={"case_id": case_id, "ts_ms": 0},
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    return OperatorPohLiveFinalizeResponse(ok=True, enqueued=True, due_height=height + 1)


# ---------------------------------------------------------------------------
# PoH Tier2: Tx skeleton helpers (client signs + submits via /v1/tx/submit)
# ---------------------------------------------------------------------------


class TxSkeletonTier2(BaseModel):
    tx_type: str
    signer_hint: str
    parent: str | None
    payload: Json


class TxSkeletonResponseTier2(BaseModel):
    ok: bool
    tx: TxSkeletonTier2


class PohTier2RequestSkeletonRequest(BaseModel):
    account_id: str = Field(..., min_length=1)
    # User may supply either a video commitment (sha256) or an uploaded CID.
    video_commitment: str | None = Field(default=None, max_length=128)
    video_cid: str | None = Field(default=None, max_length=256)
    # Optional compatibility: legacy target_tier=2 is rejected in favor of the live request path.
    target_tier: int | None = Field(default=None, ge=2, le=3)


class PohTier2JurorActionSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class PohTier2ReviewSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)




class TxSkeletonAsync(BaseModel):
    tx_type: str
    signer_hint: str
    parent: str | None
    payload: Json


class TxSkeletonResponseAsync(BaseModel):
    ok: bool
    tx: TxSkeletonAsync


class PohAsyncJurorActionSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class PohAsyncReviewSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)
    reason_code: str | None = Field(default=None, max_length=128)


@router.post(
    "/poh/async/tx/juror-accept",
    response_model=TxSkeletonResponseAsync,
    name="poh_async_tx_juror_accept",
)
def poh_async_tx_juror_accept(
    req: PohAsyncJurorActionSkeletonRequest, request: Request
) -> TxSkeletonResponseAsync:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    return TxSkeletonResponseAsync(
        ok=True,
        tx=TxSkeletonAsync(
            tx_type="POH_ASYNC_JUROR_ACCEPT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/async/tx/juror-decline",
    response_model=TxSkeletonResponseAsync,
    name="poh_async_tx_juror_decline",
)
def poh_async_tx_juror_decline(
    req: PohAsyncJurorActionSkeletonRequest, request: Request
) -> TxSkeletonResponseAsync:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    return TxSkeletonResponseAsync(
        ok=True,
        tx=TxSkeletonAsync(
            tx_type="POH_ASYNC_JUROR_DECLINE",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/async/tx/review", response_model=TxSkeletonResponseAsync, name="poh_async_tx_review"
)
def poh_async_tx_review(req: PohAsyncReviewSkeletonRequest, request: Request) -> TxSkeletonResponseAsync:
    cid = str(req.case_id or "").strip()
    verdict = str(req.verdict or "").strip().lower()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if verdict not in ("approve", "reject", "needs_followup", "invalid_evidence", "abstain"):
        raise ApiError.bad_request(
            "bad_request",
            "verdict must be approve, reject, needs_followup, invalid_evidence, or abstain",
            {"verdict": verdict},
        )
    payload: Json = {"case_id": cid, "verdict": verdict, "ts_ms": 0}
    reason_code = str(req.reason_code or "").strip()
    if reason_code:
        payload["reason_code"] = reason_code
    return TxSkeletonResponseAsync(
        ok=True,
        tx=TxSkeletonAsync(
            tx_type="POH_ASYNC_REVIEW_SUBMIT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/tier2/tx/request", response_model=TxSkeletonResponseTier2, name="poh_tier2_tx_request"
)
def poh_tier2_tx_request(
    req: PohTier2RequestSkeletonRequest, request: Request
) -> TxSkeletonResponseTier2:
    """Return a tx skeleton for the legacy Tier-2 async escalation request.

    Client must sign and submit via /v1/tx/submit. target_tier=2 is legacy
    compatibility and should move to the Live Verification request endpoint.
    """

    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    vc = (req.video_commitment or "").strip()
    cid = (req.video_cid or "").strip()

    # Legacy target_tier=2 requests may not have video evidence at case open.
    # The apply path rejects this form and points clients to POH_LIVE_REQUEST_OPEN,
    # which is now treated as the Live Verification compatibility tx.
    target_tier = int(req.target_tier) if req.target_tier is not None else 2

    if target_tier == 2 and not vc and not cid:
        raise ApiError.bad_request("bad_request", "missing video_commitment or video_cid", {})

    payload: Json = {"account_id": acct, "target_tier": int(target_tier)}
    if vc:
        payload["video_commitment"] = vc
    if cid:
        payload["video_cid"] = cid

    return TxSkeletonResponseTier2(
        ok=True,
        tx=TxSkeletonTier2(
            tx_type="POH_TIER2_REQUEST_OPEN",
            signer_hint=acct,
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/tier2/tx/juror-accept",
    response_model=TxSkeletonResponseTier2,
    name="poh_tier2_tx_juror_accept",
)
def poh_tier2_tx_juror_accept(
    req: PohTier2JurorActionSkeletonRequest, request: Request
) -> TxSkeletonResponseTier2:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    return TxSkeletonResponseTier2(
        ok=True,
        tx=TxSkeletonTier2(
            tx_type="POH_TIER2_JUROR_ACCEPT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/tier2/tx/juror-decline",
    response_model=TxSkeletonResponseTier2,
    name="poh_tier2_tx_juror_decline",
)
def poh_tier2_tx_juror_decline(
    req: PohTier2JurorActionSkeletonRequest, request: Request
) -> TxSkeletonResponseTier2:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    return TxSkeletonResponseTier2(
        ok=True,
        tx=TxSkeletonTier2(
            tx_type="POH_TIER2_JUROR_DECLINE",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/tier2/tx/review", response_model=TxSkeletonResponseTier2, name="poh_tier2_tx_review"
)
def poh_tier2_tx_review(
    req: PohTier2ReviewSkeletonRequest, request: Request
) -> TxSkeletonResponseTier2:
    cid = str(req.case_id or "").strip()
    verdict = str(req.verdict or "").strip().lower()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApiError.bad_request(
            "bad_request", "verdict must be 'pass' or 'fail'", {"verdict": verdict}
        )

    return TxSkeletonResponseTier2(
        ok=True,
        tx=TxSkeletonTier2(
            tx_type="POH_TIER2_REVIEW_SUBMIT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid, "verdict": verdict, "ts_ms": 0},
        ),
    )


# PoH Live: Tx skeleton helpers (client signs + submits via /v1/tx/submit)
# ---------------------------------------------------------------------------


class TxSkeleton(BaseModel):
    tx_type: str
    signer_hint: str
    parent: str | None = None
    payload: Json


class TxSkeletonResponse(BaseModel):
    ok: bool
    tx: TxSkeleton


class PohLiveRequestSkeletonRequest(BaseModel):
    account_id: str = Field(..., min_length=1)
    session_commitment: str | None = Field(default=None, max_length=128)
    room_commitment: str | None = Field(default=None, max_length=128)
    prompt_commitment: str | None = Field(default=None, max_length=128)
    device_pairing_commitment: str | None = Field(default=None, max_length=128)


class PohLiveJurorCaseSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class PohLiveAttendanceSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1)
    attended: bool = Field(...)


class PohLiveVerdictSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)


def _case_session_commitment(st: Json, case_id: str) -> str:
    cases = _live_cases_from_snapshot(st)
    raw = cases.get(case_id)
    if not isinstance(raw, dict):
        return ""
    return str(raw.get("session_commitment") or "").strip()


@router.post(
    "/poh/live/tx/request", response_model=TxSkeletonResponse, name="poh_live_tx_request"
)
def poh_live_tx_request(
    req: PohLiveRequestSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    """Return a tx skeleton to request Live Verification.

    IMPORTANT:
    - This endpoint does NOT sign and does NOT submit the tx.
    - Clients must sign with their account key and submit via /v1/tx/submit.
    """

    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    payload: Json = {"account_id": acct}
    missing: list[str] = []
    for key, value in (
        ("session_commitment", req.session_commitment),
        ("room_commitment", req.room_commitment),
        ("prompt_commitment", req.prompt_commitment),
        ("device_pairing_commitment", req.device_pairing_commitment),
    ):
        v = str(value or "").strip()
        if v:
            payload[key] = v
        elif key in {"session_commitment", "room_commitment", "prompt_commitment"}:
            missing.append(key)
    if missing:
        raise ApiError.bad_request(
            "missing_live_session_commitment",
            "Live Verification request requires session_commitment, room_commitment, and prompt_commitment",
            {"missing": missing},
        )

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_LIVE_REQUEST_OPEN",
            signer_hint=acct,
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/live/tx/juror-accept",
    response_model=TxSkeletonResponse,
    name="poh_live_tx_juror_accept",
)
def poh_live_tx_juror_accept(
    req: PohLiveJurorCaseSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    # signer_hint is informational; client must set signer itself.
    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_LIVE_JUROR_ACCEPT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/live/tx/juror-decline",
    response_model=TxSkeletonResponse,
    name="poh_live_tx_juror_decline",
)
def poh_live_tx_juror_decline(
    req: PohLiveJurorCaseSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_LIVE_JUROR_DECLINE",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/live/tx/attendance", response_model=TxSkeletonResponse, name="poh_live_tx_attendance"
)
def poh_live_tx_attendance(
    req: PohLiveAttendanceSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    juror_id = str(req.juror_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if not juror_id:
        raise ApiError.bad_request("bad_request", "missing juror_id", {})

    st = _snapshot(request)
    sc = _case_session_commitment(st, cid)
    if not sc:
        # If INIT hasn't run yet, attendance marks should not be accepted anyway.
        raise ApiError.bad_request(
            "session_not_ready",
            "Live session not initialized yet (missing session_commitment)",
            {"case_id": cid},
        )

    payload: Json = {
        "case_id": cid,
        "juror_id": juror_id,
        "attended": bool(req.attended),
        "session_commitment": sc,
        "ts_ms": 0,  # client SHOULD set Date.now(); 0 is accepted but less useful for UX
    }

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_LIVE_ATTENDANCE_MARK",
            signer_hint=juror_id,
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/live/tx/verdict", response_model=TxSkeletonResponse, name="poh_live_tx_verdict"
)
def poh_live_tx_verdict(
    req: PohLiveVerdictSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    verdict = str(req.verdict or "").strip().lower()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})
    if verdict not in ("pass", "fail"):
        raise ApiError.bad_request(
            "bad_request", "verdict must be 'pass' or 'fail'", {"verdict": verdict}
        )

    st = _snapshot(request)
    sc = _case_session_commitment(st, cid)
    if not sc:
        raise ApiError.bad_request(
            "session_not_ready",
            "Live session not initialized yet (missing session_commitment)",
            {"case_id": cid},
        )

    payload: Json = {
        "case_id": cid,
        "verdict": verdict,
        "session_commitment": sc,
        "ts_ms": 0,  # client SHOULD set Date.now()
    }

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_LIVE_VERDICT_SUBMIT",
            signer_hint="<INTERACTING_JUROR_ACCOUNT_ID>",
            parent=None,
            payload=payload,
        ),
    )


