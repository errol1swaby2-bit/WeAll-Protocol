from __future__ import annotations

import hashlib
import mimetypes
import os
from typing import Any, Literal

from fastapi import APIRouter, File, Request, UploadFile
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _snapshot
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
    receipt: dict[str, object] = Field(default_factory=dict)


def _as_async_case(case_id: str, r: dict[str, object]) -> PohAsyncCaseModel:
    def _list(v: Any) -> list[object]:
        return list(v) if isinstance(v, list) else []

    def _dict(v: Any) -> dict[str, object]:
        return dict(v) if isinstance(v, dict) else {}

    return PohAsyncCaseModel(
        case_id=str(case_id),
        account_id=str(r.get("account_id") or "").strip(),
        status=str(r.get("status") or "unknown").strip() or "unknown",
        opened_height=_opt_int_value(r.get("opened_height")),
        expires_height=_opt_int_value(r.get("expires_height")),
        finalized_height=_opt_int_value(r.get("finalized_height")),
        finalized_ts_ms=_opt_int_value(r.get("finalized_ts_ms")),
        outcome=str(r.get("outcome") or "").strip() or None,
        tier_awarded=_opt_int_value(r.get("tier_awarded")),
        challenge_id=str(r.get("challenge_id") or "").strip() or None,
        assigned_jurors=_list(r.get("assigned_jurors")),
        accepted_jurors=_list(r.get("accepted_jurors")),
        declined_jurors=_list(r.get("declined_jurors")),
        jurors=_dict(r.get("jurors")),
        reviews=_dict(r.get("reviews")),
        evidence_commitments=_dict(r.get("evidence_commitments")),
        evidence_binds=_dict(r.get("evidence_binds")),
        public_evidence_ids=_list(r.get("public_evidence_ids")),
        reviewable_evidence=_dict(r.get("reviewable_evidence")),
        receipt=_dict(r.get("receipt")),
    )


class PohAsyncCaseResponse(BaseModel):
    ok: bool
    case: PohAsyncCaseModel


class PohAsyncCaseListResponse(BaseModel):
    ok: bool
    cases: list[PohAsyncCaseModel]


@router.get("/poh/async/case/{case_id}", response_model=PohAsyncCaseResponse, name="poh_async_case")
def poh_async_case(case_id: str, request: Request) -> PohAsyncCaseResponse:
    st = _snapshot(request)
    cases = _async_cases_from_snapshot(st)
    cid = str(case_id or "").strip()
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "async_case_not_found")
    return PohAsyncCaseResponse(ok=True, case=_as_async_case(cid, raw))


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
            out.append(_as_async_case(str(cid), raw))
    out.sort(key=lambda c: (c.opened_height or 0, c.case_id))
    return PohAsyncCaseListResponse(ok=True, cases=out)


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
            out.append(_as_async_case(str(cid), raw))
    out.sort(key=lambda c: (c.opened_height or 0, c.case_id))
    return PohAsyncCaseListResponse(ok=True, cases=out)

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
    # Kept for response compatibility. New protocol-native Live state should
    # expose commitments, not raw relay URLs.
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
        join_url=str(r.get("join_url") or "").strip() or None,
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

    header_account = str(request.headers.get("x-weall-account") or "").strip()
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

    status = str(req.status or "heartbeat").strip().lower()
    if status not in _ALLOWED_LIVE_PRESENCE_STATUSES:
        raise ApiError.bad_request("bad_request", "invalid_presence_status", {"status": status})

    st = _snapshot(request)
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


