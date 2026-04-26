from __future__ import annotations

import hashlib
import mimetypes
import os
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from nacl.signing import SigningKey
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _snapshot
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity
from weall.poh.operator_email_receipts import (
    RECEIPT_KIND,
    RECEIPT_VERSION,
    canonical_receipt_message,
)
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
# PoH Tier1: Email verification
# ---------------------------------------------------------------------------


class PohEmailBeginRequest(BaseModel):
    account: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=3, max_length=320)
    turnstile_token: str | None = Field(default=None, max_length=4096)


class PohEmailBeginResponse(BaseModel):
    ok: bool
    request_id: str
    expires_ms: int


class PohEmailCompleteRequest(BaseModel):
    account: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=3, max_length=320)
    code: str = Field(..., min_length=1, max_length=128)
    request_id: str = Field(..., min_length=1, max_length=256)
    turnstile_token: str | None = Field(default=None, max_length=4096)


class PohEmailCompleteResponse(BaseModel):
    ok: bool
    request_id: str
    completed: bool
    receipt: Json
    tx: Json


class PohEmailOracleAuthorityResponse(BaseModel):
    ok: bool
    chain_id: str
    height: int
    authority_source: str
    authorized_accounts: list[str]
    authorized_pubkeys: list[str]
    registry: dict[str, dict[str, Any]]


def _consensus_validator_registry(st: Json) -> dict[str, dict[str, Any]]:
    consensus = st.get("consensus")
    consensus = consensus if isinstance(consensus, dict) else {}
    validators = consensus.get("validators")
    validators = validators if isinstance(validators, dict) else {}
    registry = validators.get("registry")
    return registry if isinstance(registry, dict) else {}


def _active_validator_accounts(st: Json) -> list[str]:
    roles = st.get("roles")
    roles = roles if isinstance(roles, dict) else {}
    validators = roles.get("validators")
    validators = validators if isinstance(validators, dict) else {}
    active = validators.get("active_set")
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(active, list):
        for item in active:
            acct = str(item or "").strip()
            if acct and acct not in seen:
                seen.add(acct)
                out.append(acct)
    return out


def _active_node_operator_accounts(st: Json) -> list[str]:
    roles = st.get("roles")
    roles = roles if isinstance(roles, dict) else {}
    node_ops = roles.get("node_operators")
    node_ops = node_ops if isinstance(node_ops, dict) else {}
    active = node_ops.get("active_set")
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(active, list):
        for item in active:
            acct = str(item or "").strip()
            if acct and acct not in seen:
                seen.add(acct)
                out.append(acct)
    return out


def _account_active_pubkeys(st: Json, account: str) -> list[str]:
    acct = ((st.get("accounts") or {}).get(account) if isinstance(st.get("accounts"), dict) else None)
    acct = acct if isinstance(acct, dict) else {}
    keys = acct.get("keys")
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for meta in by_id.values():
                meta = meta if isinstance(meta, dict) else {}
                pk = str(meta.get("pubkey") or "").strip()
                if not pk or pk in seen:
                    continue
                revoked = bool(meta.get("revoked", False))
                active = not revoked and bool(meta.get("active", True))
                if active:
                    seen.add(pk)
                    out.append(pk)
        for pubkey, meta in keys.items():
            if pubkey == "by_id":
                continue
            pk = str(pubkey or "").strip()
            if not pk or pk in seen:
                continue
            active = True
            if isinstance(meta, dict):
                active = bool(meta.get("active", True)) and not bool(meta.get("revoked", False))
            elif isinstance(meta, bool):
                active = meta
            if active:
                seen.add(pk)
                out.append(pk)
    elif isinstance(keys, list):
        for item in keys:
            pk = str(item or "").strip()
            if pk and pk not in seen:
                seen.add(pk)
                out.append(pk)
    return out


def _bootstrap_founder_account(st: Json) -> str:
    params = st.get("params")
    params = params if isinstance(params, dict) else {}
    return str(params.get("bootstrap_founder_account") or "").strip()


def _oracle_authority_registry(st: Json) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    validator_registry = _consensus_validator_registry(st)
    active_validators = set(_active_validator_accounts(st))
    active_node_ops = set(_active_node_operator_accounts(st))

    def _merge_account(account: str, *, reason: str, status: str) -> None:
        rec = validator_registry.get(account) if isinstance(validator_registry, dict) else None
        rec = rec if isinstance(rec, dict) else {}
        pubkeys: list[str] = []
        seen: set[str] = set()

        validator_pubkey = str(rec.get("pubkey") or "").strip()
        if validator_pubkey and validator_pubkey not in seen:
            seen.add(validator_pubkey)
            pubkeys.append(validator_pubkey)

        for pk in _account_active_pubkeys(st, account):
            if pk not in seen:
                seen.add(pk)
                pubkeys.append(pk)

        if not pubkeys:
            return

        base = registry.setdefault(account, {"pubkeys": [], "reasons": [], "status": status})
        for pk in pubkeys:
            if pk not in base["pubkeys"]:
                base["pubkeys"].append(pk)
        if reason not in base["reasons"]:
            base["reasons"].append(reason)
        if reason == "active_validator":
            base["status"] = str(rec.get("status") or base.get("status") or "active").strip() or "active"
        elif not str(base.get("status") or "").strip():
            base["status"] = status

    for account in sorted(active_validators):
        _merge_account(account, reason="active_validator", status="active")

    for account in sorted(active_node_ops):
        _merge_account(account, reason="active_node_operator", status="active")

    founder = _bootstrap_founder_account(st)
    if founder:
        founder_pubkeys: list[str] = []
        seen2: set[str] = set()
        params = st.get("params")
        params = params if isinstance(params, dict) else {}
        allowlist = params.get("bootstrap_allowlist")
        allowlist = allowlist if isinstance(allowlist, dict) else {}
        allow_rec = allowlist.get(founder) if isinstance(allowlist.get(founder), dict) else {}
        allow_pk = str(allow_rec.get("pubkey") or "").strip()
        if allow_pk and allow_pk not in seen2:
            seen2.add(allow_pk)
            founder_pubkeys.append(allow_pk)
        for pk in _account_active_pubkeys(st, founder):
            if pk not in seen2:
                seen2.add(pk)
                founder_pubkeys.append(pk)
        if founder_pubkeys:
            base = registry.setdefault(founder, {"pubkeys": [], "reasons": [], "status": "bootstrap_founder"})
            for pk in founder_pubkeys:
                if pk not in base["pubkeys"]:
                    base["pubkeys"].append(pk)
            if "bootstrap_founder" not in base["reasons"]:
                base["reasons"].append("bootstrap_founder")
            if not str(base.get("status") or "").strip():
                base["status"] = "bootstrap_founder"

    return registry


def _oracle_caller_identity(request: Request, st: Json) -> OracleCallerIdentity | None:
    ex = getattr(request.app.state, "executor", None)
    if ex is not None:
        fn = getattr(ex, "_local_validator_identity", None)
        if callable(fn):
            try:
                account, pubkey, privkey = fn()
                if account and pubkey and privkey:
                    return OracleCallerIdentity(
                        operator_account=str(account).strip(),
                        node_pubkey=str(pubkey).strip(),
                        node_privkey=str(privkey).strip(),
                    )
            except Exception:
                pass

    account = str(os.getenv("WEALL_ORACLE_OPERATOR_ACCOUNT") or os.getenv("WEALL_VALIDATOR_ACCOUNT") or "").strip()
    pubkey = str(os.getenv("WEALL_NODE_PUBKEY") or "").strip()
    privkey = str(os.getenv("WEALL_NODE_PRIVKEY") or "").strip()

    if not account and pubkey:
        for acct, rec in _oracle_authority_registry(st).items():
            pubkeys = rec.get("pubkeys") if isinstance(rec, dict) else []
            if isinstance(pubkeys, list) and pubkey in {str(x).strip() for x in pubkeys}:
                account = acct
                break

    if account and pubkey and privkey:
        auth = _oracle_authority_registry(st)
        rec = auth.get(account) if isinstance(auth.get(account), dict) else {}
        pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), list) else []
        if pubkey in {str(x).strip() for x in pubkeys}:
            return OracleCallerIdentity(operator_account=account, node_pubkey=pubkey, node_privkey=privkey)

    return None


def _svc(request: Request) -> EmailVerificationService:
    """Construct the off-chain email verification service.

    Notes:
    - We intentionally keep all plaintext email handling inside the verifier module.
    - This API route layer should not introduce new plaintext-email key literals.
    """

    secret = os.getenv("WEALL_POH_EMAIL_SECRET", "").strip()
    if not secret:
        raise ApiError.bad_request(
            "missing_email_secret",
            "WEALL_POH_EMAIL_SECRET must be set in prod",
        )

    ttl_ms_raw = os.getenv("WEALL_POH_EMAIL_TTL_MS", "").strip()
    ttl_ms = 15 * 60 * 1000  # default 15 minutes
    if ttl_ms_raw:
        try:
            ttl_ms = int(ttl_ms_raw)
        except ValueError:
            raise ApiError.bad_request("invalid_ttl_ms", "WEALL_POH_EMAIL_TTL_MS must be an int")

    st = _snapshot(request)
    caller_identity = _oracle_caller_identity(request, st)
    if caller_identity is None:
        raise ApiError.bad_request(
            "missing_oracle_caller_identity",
            "authorized local node identity required for email verification oracle calls",
        )

    return EmailVerificationService(secret=secret, ttl_ms=ttl_ms, caller_identity=caller_identity)


def _sign_local_operator_receipt(*, svc: EmailVerificationService, chain_id: str, account: str, relay_token: Json) -> Json:
    if not isinstance(relay_token, dict):
        raise ApiError.bad_request("missing_relay_token", "email oracle did not return a relay token", {})

    relay_payload = relay_token.get("payload")
    if not isinstance(relay_payload, dict):
        raise ApiError.bad_request("missing_relay_payload", "email relay token payload is missing", {})

    caller = svc.caller_identity
    worker_account = str(caller.operator_account or "").strip()
    worker_pubkey = str(caller.node_pubkey or "").strip().lower()
    worker_privkey = str(caller.node_privkey or "").strip().lower()
    chain_id_norm = str(chain_id or "").strip()

    if not worker_account or not worker_pubkey or not worker_privkey:
        raise ApiError.bad_request(
            "missing_oracle_signing_identity",
            "authorized local node signing identity is incomplete",
            {},
        )

    receipt: Json = {
        "version": RECEIPT_VERSION,
        "kind": RECEIPT_KIND,
        "chain_id": chain_id_norm,
        "worker_account_id": worker_account,
        "worker_pubkey": worker_pubkey,
        "subject_account_id": str(account or "").strip(),
        "email_commitment": str(relay_payload.get("email_commitment") or "").strip(),
        "request_id": str(relay_payload.get("challenge_id") or "").strip(),
        "nonce": str(relay_token.get("signature") or "").strip(),
        "issued_at_ms": int(relay_payload.get("issued_at_ms") or 0),
        "expires_at_ms": int(relay_payload.get("expires_at_ms") or 0),
        "relay_token": relay_token,
    }

    relay_chain_id = str(relay_payload.get("chain_id") or "").strip()
    if not relay_chain_id:
        raise ApiError.bad_request(
            "missing_relay_chain_id",
            "email relay token must be bound to this chain",
            {"expected_chain_id": chain_id_norm},
        )
    if relay_chain_id != chain_id_norm:
        raise ApiError.bad_request(
            "relay_chain_id_mismatch",
            "email relay token is bound to a different chain",
            {"expected_chain_id": chain_id_norm, "relay_chain_id": relay_chain_id},
        )
    if not receipt["email_commitment"]:
        raise ApiError.bad_request("missing_email_commitment", "email relay token is missing email commitment", {})
    if not receipt["request_id"]:
        raise ApiError.bad_request("missing_request_id", "email relay token is missing challenge id", {})
    if not receipt["nonce"]:
        raise ApiError.bad_request("missing_relay_signature", "email relay token is missing signature", {})

    try:
        signing_key = SigningKey(bytes.fromhex(worker_privkey))
    except Exception as exc:
        raise ApiError.bad_request("invalid_oracle_node_privkey", "oracle node private key is invalid", {}) from exc

    receipt["signature"] = signing_key.sign(canonical_receipt_message(receipt)).signature.hex()
    return receipt


@router.get("/poh/email/oracle-authority", response_model=PohEmailOracleAuthorityResponse, name="poh_email_oracle_authority")
def poh_email_oracle_authority(request: Request) -> PohEmailOracleAuthorityResponse:
    st = _snapshot(request)
    registry = _oracle_authority_registry(st)
    authorized_accounts = sorted(registry.keys())
    authorized_pubkeys = sorted(
        {str(pk).strip() for rec in registry.values() if isinstance(rec, dict) for pk in (rec.get("pubkeys") or []) if str(pk).strip()}
    )
    return PohEmailOracleAuthorityResponse(
        ok=True,
        chain_id=str(st.get("chain_id") or "").strip(),
        height=int(st.get("height") or 0),
        authority_source="on_chain",
        authorized_accounts=authorized_accounts,
        authorized_pubkeys=authorized_pubkeys,
        registry=registry,
    )


@router.post("/poh/email/begin", response_model=PohEmailBeginResponse, name="poh_email_begin")
def poh_email_begin(req: PohEmailBeginRequest, request: Request) -> PohEmailBeginResponse:
    account = str(req.account or "").strip()
    email = str(req.email or "").strip()

    if not account:
        raise ApiError.bad_request("invalid_account", "account is required")
    if not email:
        raise ApiError.bad_request("invalid_email", "email is required")

    # In a fully booted node, bind the email challenge request to the local
    # chain. In route-shape tests and lightweight app construction
    # (boot_runtime=False), app.state.executor is intentionally absent; keep the
    # begin route backward-compatible so test doubles can still validate the
    # response contract without requiring a live executor.
    chain_id = ""
    try:
        st = _snapshot(request)
        chain_id = str(st.get("chain_id") or "").strip()
    except ApiError as exc:
        if exc.code != "not_ready":
            raise

    svc = _svc(request)
    try:
        result = svc.begin(account=account, email=email, turnstile_token=req.turnstile_token, chain_id=chain_id)
    except TypeError as exc:
        # Test doubles and older in-process dev adapters may not yet accept the
        # chain_id keyword. Keep the public route backward-compatible while the
        # real EmailVerificationService remains chain-bound whenever a real
        # executor/chain identity is available.
        if "chain_id" not in str(exc):
            raise
        result = svc.begin(account=account, email=email, turnstile_token=req.turnstile_token)

    request_id = str(result.get("request_id") or result.get("challenge_id") or "").strip()
    expires_ms_raw = result.get("expires_ms")
    if expires_ms_raw is None:
        expires_ms_raw = result.get("expires_at_ms")
    try:
        expires_ms = int(expires_ms_raw or 0)
    except (TypeError, ValueError):
        expires_ms = 0

    if not request_id:
        raise ApiError.internal("poh_email_begin_invalid_response", "missing request_id")
    if expires_ms <= 0:
        raise ApiError.internal("poh_email_begin_invalid_response", "missing expires_ms")

    return PohEmailBeginResponse(ok=True, request_id=request_id, expires_ms=expires_ms)


@router.post("/poh/email/complete", response_model=PohEmailCompleteResponse, name="poh_email_complete")
def poh_email_complete(req: PohEmailCompleteRequest, request: Request) -> PohEmailCompleteResponse:
    account = str(req.account or "").strip()
    email = str(req.email or "").strip()
    code = str(req.code or "").strip()
    request_id = str(req.request_id or "").strip()

    if not account:
        raise ApiError.bad_request("invalid_account", "account is required")
    if not email:
        raise ApiError.bad_request("invalid_email", "email is required")
    if not code:
        raise ApiError.bad_request("invalid_code", "code is required")
    if not request_id:
        raise ApiError.bad_request("invalid_request_id", "request_id is required")

    st = _snapshot(request)
    chain_id = str(st.get("chain_id") or "").strip()
    svc = _svc(request)
    try:
        result = svc.complete(
            account=account,
            email=email,
            code=code,
            request_id=request_id,
            turnstile_token=req.turnstile_token,
            chain_id=chain_id,
        )
    except TypeError as exc:
        if "chain_id" not in str(exc):
            raise
        result = svc.complete(
            account=account,
            email=email,
            code=code,
            request_id=request_id,
            turnstile_token=req.turnstile_token,
        )
    relay_token = result.get("relay_token") if isinstance(result, dict) else None
    receipt = _sign_local_operator_receipt(
        svc=svc,
        chain_id=chain_id,
        account=account,
        relay_token=relay_token if isinstance(relay_token, dict) else {},
    )

    return PohEmailCompleteResponse(
        ok=True,
        request_id=request_id,
        completed=bool(result.get("completed", True)) if isinstance(result, dict) else True,
        receipt=receipt,
        tx={
            "tx_type": "POH_EMAIL_RECEIPT_SUBMIT",
            "signer_hint": account,
            "parent": None,
            "payload": {"account_id": account, "receipt": receipt},
        },
    )




class PohEmailReceiptSubmitRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    receipt: Json


@router.post("/poh/email/tx/receipt-submit", name="poh_email_tx_receipt_submit")
def poh_email_tx_receipt_submit(req: PohEmailReceiptSubmitRequest, request: Request) -> Json:
    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})
    if not isinstance(req.receipt, dict):
        raise ApiError.bad_request("bad_request", "receipt must be an object", {})

    return {
        "ok": True,
        "tx": {
            "tx_type": "POH_EMAIL_RECEIPT_SUBMIT",
            "signer_hint": acct,
            "parent": None,
            "payload": {"account_id": acct, "receipt": req.receipt},
        },
    }


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
      - /v1/media/upload is Tier-3 gated (for public social content).
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


# ---------------------------------------------------------------------------
# PoH Tier2: Read-only views (for product UI / juror dashboards)
# ---------------------------------------------------------------------------


def _tier2_cases_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    cases = poh.get("tier2_cases")
    return cases if isinstance(cases, dict) else {}


def _tier3_cases_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    cases = poh.get("tier3_cases")
    return cases if isinstance(cases, dict) else {}


def _tier3_sessions_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    sess = poh.get("tier3_sessions")
    return sess if isinstance(sess, dict) else {}


def _tier3_session_participants_from_snapshot(st: Json) -> Json:
    poh = st.get("poh")
    if not isinstance(poh, dict):
        return {}
    sp = poh.get("tier3_session_participants")
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
# PoH Tier3: Read-only views (cases, assigned, sessions)
# ---------------------------------------------------------------------------


class PohTier3JurorModel(BaseModel):
    juror_id: str
    role: str
    accepted: bool
    attended: bool
    attended_ts_ms: int | None = None
    verdict: str | None = None


class PohTier3CaseModel(BaseModel):
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
    jurors: list[PohTier3JurorModel] = Field(default_factory=list)


def _as_tier3_case(case_id: str, r: dict[str, object]) -> PohTier3CaseModel:
    acct = str(r.get("account_id") or "").strip()
    status = str(r.get("status") or "").strip() or "unknown"

    jurors: list[PohTier3JurorModel] = []
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
                PohTier3JurorModel(
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

    return PohTier3CaseModel(
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


class PohTier3CaseResponse(BaseModel):
    ok: bool
    case: PohTier3CaseModel


class PohTier3AssignedResponse(BaseModel):
    ok: bool
    cases: list[PohTier3CaseModel]


@router.get("/poh/tier3/case/{case_id}", response_model=PohTier3CaseResponse, name="poh_tier3_case")
def poh_tier3_case(case_id: str, request: Request) -> PohTier3CaseResponse:
    st = _snapshot(request)
    cases = _tier3_cases_from_snapshot(st)
    cid = str(case_id or "").strip()
    raw = cases.get(cid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "tier3_case_not_found")
    return PohTier3CaseResponse(ok=True, case=_as_tier3_case(cid, raw))


@router.get(
    "/poh/tier3/assigned", response_model=PohTier3AssignedResponse, name="poh_tier3_assigned"
)
def poh_tier3_assigned(juror: str, request: Request) -> PohTier3AssignedResponse:
    j = str(juror or "").strip()
    if not j:
        raise ApiError.bad_request("bad_request", "missing juror", {})
    st = _snapshot(request)
    cases = _tier3_cases_from_snapshot(st)

    out: list[PohTier3CaseModel] = []
    for cid, raw in cases.items():
        if not isinstance(raw, dict):
            continue
        jm = raw.get("jurors")
        if not isinstance(jm, dict):
            continue
        if j in jm:
            out.append(_as_tier3_case(str(cid), raw))

    out.sort(key=lambda c: c.case_id)
    return PohTier3AssignedResponse(ok=True, cases=out)


class PohTier3SessionModel(BaseModel):
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
    # Kept for response compatibility. New protocol-native Tier3 state should
    # expose commitments, not raw relay URLs.
    join_url: str | None = None


class PohTier3SessionResponse(BaseModel):
    ok: bool
    session: PohTier3SessionModel


class PohTier3SessionListResponse(BaseModel):
    ok: bool
    sessions: list[PohTier3SessionModel]


def _as_tier3_session(session_id: str, r: dict[str, object]) -> PohTier3SessionModel:
    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohTier3SessionModel(
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
    "/poh/tier3/session/{session_id}",
    response_model=PohTier3SessionResponse,
    name="poh_tier3_session",
)
def poh_tier3_session(session_id: str, request: Request) -> PohTier3SessionResponse:
    st = _snapshot(request)
    sess = _tier3_sessions_from_snapshot(st)
    sid = str(session_id or "").strip()
    raw = sess.get(sid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "tier3_session_not_found")
    return PohTier3SessionResponse(ok=True, session=_as_tier3_session(sid, raw))


@router.get(
    "/poh/tier3/sessions", response_model=PohTier3SessionListResponse, name="poh_tier3_sessions"
)
def poh_tier3_sessions(request: Request) -> PohTier3SessionListResponse:
    st = _snapshot(request)
    sess = _tier3_sessions_from_snapshot(st)

    out: list[PohTier3SessionModel] = []
    for sid, raw in sess.items():
        if not isinstance(raw, dict):
            continue
        out.append(_as_tier3_session(str(sid), raw))

    out.sort(key=lambda s: (s.case_id, s.session_id))
    return PohTier3SessionListResponse(ok=True, sessions=out)


class PohTier3SessionParticipantModel(BaseModel):
    session_id: str
    juror_id: str
    role: str | None = None
    status: str
    joined_ts_ms: int | None = None
    left_ts_ms: int | None = None


class PohTier3SessionParticipantsResponse(BaseModel):
    ok: bool
    participants: list[PohTier3SessionParticipantModel]


def _as_participant(
    session_id: str, juror_id: str, r: dict[str, object]
) -> PohTier3SessionParticipantModel:
    def _opt_int(v: Any) -> int | None:
        try:
            return int(v) if isinstance(v, (int, float)) else None
        except Exception:
            return None

    return PohTier3SessionParticipantModel(
        session_id=str(session_id),
        juror_id=str(juror_id),
        role=str(r.get("role") or "").strip() or None,
        status=str(r.get("status") or "").strip() or "unknown",
        joined_ts_ms=_opt_int(r.get("joined_ts_ms")),
        left_ts_ms=_opt_int(r.get("left_ts_ms")),
    )


@router.get(
    "/poh/tier3/session/{session_id}/participants",
    response_model=PohTier3SessionParticipantsResponse,
    name="poh_tier3_session_participants",
)
def poh_tier3_session_participants(
    session_id: str, request: Request
) -> PohTier3SessionParticipantsResponse:
    st = _snapshot(request)
    sp = _tier3_session_participants_from_snapshot(st)
    sid = str(session_id or "").strip()
    raw = sp.get(sid)
    if not isinstance(raw, dict):
        raise ApiError.not_found("not_found", "tier3_session_participants_not_found")

    out: list[PohTier3SessionParticipantModel] = []
    for juror_id, jrec_any in raw.items():
        jrec = jrec_any if isinstance(jrec_any, dict) else {}
        out.append(_as_participant(sid, str(juror_id), jrec))

    out.sort(key=lambda p: p.juror_id)
    return PohTier3SessionParticipantsResponse(ok=True, participants=out)


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


class OperatorPohTier3InitRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    join_url: str = Field(..., min_length=1)


class OperatorPohTier3InitResponse(BaseModel):
    ok: bool
    enqueued: bool
    due_height: int


@router.post(
    "/poh/operator/tier3/init",
    response_model=OperatorPohTier3InitResponse,
    name="operator_poh_tier3_init",
)
def operator_poh_tier3_init(
    req: OperatorPohTier3InitRequest, request: Request
) -> OperatorPohTier3InitResponse:
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

    enqueue_system_tx(
        st,
        tx_type="POH_TIER3_INIT",
        payload={"case_id": case_id, "relay_commitment": _sha256_hex(join_url.encode("utf-8")), "ts_ms": 0},
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    return OperatorPohTier3InitResponse(ok=True, enqueued=True, due_height=height + 1)


class OperatorPohTier3FinalizeRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class OperatorPohTier3FinalizeResponse(BaseModel):
    ok: bool
    enqueued: bool
    due_height: int


@router.post(
    "/poh/operator/tier3/finalize",
    response_model=OperatorPohTier3FinalizeResponse,
    name="operator_poh_tier3_finalize",
)
def operator_poh_tier3_finalize(
    req: OperatorPohTier3FinalizeRequest, request: Request
) -> OperatorPohTier3FinalizeResponse:
    _require_operator_poh_enabled()
    _require_operator_token(request)

    case_id = str(req.case_id or "").strip()
    if not case_id:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    st = _snapshot(request)
    height = int(st.get("height") or 0)

    enqueue_system_tx(
        st,
        tx_type="POH_TIER3_FINALIZE",
        payload={"case_id": case_id, "ts_ms": 0},
        due_height=height + 1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    return OperatorPohTier3FinalizeResponse(ok=True, enqueued=True, due_height=height + 1)


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
    # Optional: request Tier3 directly via Tier2 request path
    target_tier: int | None = Field(default=None, ge=2, le=3)


class PohTier2JurorActionSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class PohTier2ReviewSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)


@router.post(
    "/poh/tier2/tx/request", response_model=TxSkeletonResponseTier2, name="poh_tier2_tx_request"
)
def poh_tier2_tx_request(
    req: PohTier2RequestSkeletonRequest, request: Request
) -> TxSkeletonResponseTier2:
    """Return a tx skeleton to request Tier-2 (or Tier-3 via target_tier=3).

    Client must sign and submit via /v1/tx/submit.
    """

    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    vc = (req.video_commitment or "").strip()
    cid = (req.video_cid or "").strip()

    # For Tier3 requests, you may not have video evidence at the time of opening the case.
    # We allow it to be absent when target_tier==3. The canonical tx schema requires
    # target_tier, so Tier-2 request skeletons must default it explicitly to 2.
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


# PoH Tier3: Tx skeleton helpers (client signs + submits via /v1/tx/submit)
# ---------------------------------------------------------------------------


class TxSkeleton(BaseModel):
    tx_type: str
    signer_hint: str
    parent: str | None = None
    payload: Json


class TxSkeletonResponse(BaseModel):
    ok: bool
    tx: TxSkeleton


class PohTier3RequestSkeletonRequest(BaseModel):
    account_id: str = Field(..., min_length=1)
    session_commitment: str | None = Field(default=None, max_length=128)
    room_commitment: str | None = Field(default=None, max_length=128)
    prompt_commitment: str | None = Field(default=None, max_length=128)
    device_pairing_commitment: str | None = Field(default=None, max_length=128)


class PohTier3JurorCaseSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)


class PohTier3AttendanceSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    juror_id: str = Field(..., min_length=1)
    attended: bool = Field(...)


class PohTier3VerdictSkeletonRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    verdict: str = Field(..., min_length=1)


def _case_session_commitment(st: Json, case_id: str) -> str:
    cases = _tier3_cases_from_snapshot(st)
    raw = cases.get(case_id)
    if not isinstance(raw, dict):
        return ""
    return str(raw.get("session_commitment") or "").strip()


@router.post(
    "/poh/tier3/tx/request", response_model=TxSkeletonResponse, name="poh_tier3_tx_request"
)
def poh_tier3_tx_request(
    req: PohTier3RequestSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    """Return a tx skeleton to request Tier-3.

    IMPORTANT:
    - This endpoint does NOT sign and does NOT submit the tx.
    - Clients must sign with their account key and submit via /v1/tx/submit.
    """

    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})

    payload: Json = {"account_id": acct}
    for key, value in (
        ("session_commitment", req.session_commitment),
        ("room_commitment", req.room_commitment),
        ("prompt_commitment", req.prompt_commitment),
        ("device_pairing_commitment", req.device_pairing_commitment),
    ):
        v = str(value or "").strip()
        if v:
            payload[key] = v

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_TIER3_REQUEST_OPEN",
            signer_hint=acct,
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/tier3/tx/juror-accept",
    response_model=TxSkeletonResponse,
    name="poh_tier3_tx_juror_accept",
)
def poh_tier3_tx_juror_accept(
    req: PohTier3JurorCaseSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    # signer_hint is informational; client must set signer itself.
    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_TIER3_JUROR_ACCEPT",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/tier3/tx/juror-decline",
    response_model=TxSkeletonResponse,
    name="poh_tier3_tx_juror_decline",
)
def poh_tier3_tx_juror_decline(
    req: PohTier3JurorCaseSkeletonRequest, request: Request
) -> TxSkeletonResponse:
    cid = str(req.case_id or "").strip()
    if not cid:
        raise ApiError.bad_request("bad_request", "missing case_id", {})

    return TxSkeletonResponse(
        ok=True,
        tx=TxSkeleton(
            tx_type="POH_TIER3_JUROR_DECLINE",
            signer_hint="<JUROR_ACCOUNT_ID>",
            parent=None,
            payload={"case_id": cid},
        ),
    )


@router.post(
    "/poh/tier3/tx/attendance", response_model=TxSkeletonResponse, name="poh_tier3_tx_attendance"
)
def poh_tier3_tx_attendance(
    req: PohTier3AttendanceSkeletonRequest, request: Request
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
            "Tier-3 session not initialized yet (missing session_commitment)",
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
            tx_type="POH_TIER3_ATTENDANCE_MARK",
            signer_hint=juror_id,
            parent=None,
            payload=payload,
        ),
    )


@router.post(
    "/poh/tier3/tx/verdict", response_model=TxSkeletonResponse, name="poh_tier3_tx_verdict"
)
def poh_tier3_tx_verdict(
    req: PohTier3VerdictSkeletonRequest, request: Request
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
            "Tier-3 session not initialized yet (missing session_commitment)",
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
            tx_type="POH_TIER3_VERDICT_SUBMIT",
            signer_hint="<INTERACTING_JUROR_ACCOUNT_ID>",
            parent=None,
            payload=payload,
        ),
    )


