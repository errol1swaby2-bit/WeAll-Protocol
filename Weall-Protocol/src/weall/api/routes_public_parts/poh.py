from __future__ import annotations

import hashlib
import mimetypes
import os
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from pydantic import BaseModel, Field

from weall.api.errors import ApiError
from weall.api.ipfs import ipfs_add_fileobj, ipfs_gateway_url
from weall.api.routes_public_parts.common import _snapshot
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.reputation_units import account_reputation_units
from weall.runtime.state_hash import compute_state_root
from weall.runtime.chain_manifest import load_chain_manifest
from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity
from weall.runtime.poh.email_attestation import (
    build_unsigned_email_control_attestation_v1,
    domain_hash_for_attestation,
    email_hash_for_attestation,
    sign_email_control_attestation_v1,
)
from weall.poh.oracle_authority_snapshot import (
    DEFAULT_SNAPSHOT_TTL_MS,
    SNAPSHOT_TYPE,
    SNAPSHOT_VERSION,
    now_ms as authority_now_ms,
    sign_authority_snapshot,
    snapshot_hash,
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


class PohEmailBeginResponse(BaseModel):
    ok: bool
    request_id: str
    expires_ms: int
    security_phrase: str = ""
    official_sender: str = "verify@poh.weall.org"
    email_masked: str | None = None
    dev_code: str | None = None


class PohEmailCompleteRequest(BaseModel):
    account: str = Field(..., min_length=1, max_length=128)
    email: str = Field(..., min_length=3, max_length=320)
    code: str = Field(..., min_length=1, max_length=128)
    request_id: str = Field(..., min_length=1, max_length=256)


class PohEmailCompleteResponse(BaseModel):
    ok: bool
    request_id: str
    completed: bool
    attestation: Json = Field(default_factory=dict)
    tx: Json
    security_phrase: str = ""


class PohEmailOracleAuthorityResponse(BaseModel):
    ok: bool
    version: int = SNAPSHOT_VERSION
    type: str = SNAPSHOT_TYPE
    chain_id: str
    genesis_hash: str = ""
    height: int
    block_hash: str = ""
    state_root: str = ""
    tx_index_hash: str = ""
    schema_version: str = ""
    validator_epoch: int = 0
    validator_set_hash: str = ""
    authority_source: str
    generated_at_ms: int = 0
    expires_at_ms: int = 0
    authorized_accounts: list[str]
    authorized_pubkeys: list[str]
    registry: dict[str, dict[str, Any]]
    snapshot_hash: str = ""
    signatures: list[dict[str, Any]] = Field(default_factory=list)


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


def _oracle_chain_manifest_identity(st: Json) -> dict[str, str]:
    mode = str(os.environ.get("WEALL_MODE", "") or "").strip().lower()
    manifest = None
    try:
        manifest = load_chain_manifest(required=False, mode=mode)
    except Exception:
        manifest = None
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    out = {
        "genesis_hash": "",
        "genesis_state_root": "",
        "tx_index_hash": str(meta.get("tx_index_hash") or "").strip().lower(),
        "schema_version": str(meta.get("schema_version") or "").strip(),
    }
    if manifest is not None:
        out["genesis_hash"] = str(manifest.genesis_hash or "").strip().lower()
        out["genesis_state_root"] = str(manifest.genesis_state_root or "").strip().lower()
        out["tx_index_hash"] = str(manifest.tx_index_hash or out["tx_index_hash"] or "").strip().lower()
        out["schema_version"] = str(manifest.schema_version or out["schema_version"] or "").strip()
    return out


def _oracle_height(st: Json) -> int:
    chain = st.get("chain") if isinstance(st.get("chain"), dict) else {}
    try:
        return int(st.get("height") or chain.get("height") or 0)
    except Exception:
        return 0


def _oracle_block_hash(st: Json) -> str:
    chain = st.get("chain") if isinstance(st.get("chain"), dict) else {}
    return str(st.get("tip_hash") or st.get("tip") or chain.get("block_hash") or chain.get("block_id") or "").strip()


def _oracle_validator_epoch(st: Json) -> int:
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    epochs = consensus.get("epochs") if isinstance(consensus.get("epochs"), dict) else {}
    try:
        return int(epochs.get("current") or 0)
    except Exception:
        return 0


def _oracle_validator_set_hash(st: Json) -> str:
    consensus = st.get("consensus") if isinstance(st.get("consensus"), dict) else {}
    validator_set = consensus.get("validator_set") if isinstance(consensus.get("validator_set"), dict) else {}
    return str(validator_set.get("set_hash") or "").strip()




def _oracle_account_reputation_units(st: Json, account: str, acct: Json) -> int:
    """Return reputation units for oracle-authority eligibility.

    Account-local reputation is the canonical modern shape. Migration-era and
    harness snapshots may expose reputation under
    state["reputation"]["accounts"][account]; accept that shape for authority
    snapshots so eligible node operators are not incorrectly marked ineligible
    during bootstrap/preflight checks.
    """

    if isinstance(acct, dict) and ("reputation_milli" in acct or "reputation" in acct):
        return int(account_reputation_units(acct, default=0))

    rep_root = st.get("reputation") if isinstance(st.get("reputation"), dict) else {}
    rep_accounts = rep_root.get("accounts") if isinstance(rep_root.get("accounts"), dict) else {}
    rep_rec = rep_accounts.get(account) if isinstance(rep_accounts, dict) else None
    if isinstance(rep_rec, dict):
        for key in ("reputation_milli", "reputation_units", "units"):
            if key in rep_rec:
                try:
                    return int(rep_rec.get(key) or 0)
                except Exception:
                    return 0
        if "reputation" in rep_rec:
            return int(account_reputation_units(rep_rec, default=0))

    return int(account_reputation_units(acct, default=0))

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

    # Legacy email-adapter authorization is narrower than merely being present
    # in a role list. While retained during the v2.1 migration, the adapter
    # should accept only active node operators whose canonical account state
    # satisfies the full authority contract: Tier2+/Live Verified Human,
    # positive reputation, not locked/banned, and at least one active registered
    # key. Keep legacy active-validator/bootstrap records
    # visible for diagnostics, but mark eligibility explicitly on node-operator
    # records so the oracle can fail closed without inferring from frontend state.
    accounts = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    for account in sorted(active_node_ops):
        rec = registry.get(account)
        if not isinstance(rec, dict):
            continue
        acct = accounts.get(account) if isinstance(accounts, dict) else None
        acct = acct if isinstance(acct, dict) else {}
        tier = int(acct.get("poh_tier") or 0)
        reputation_units = _oracle_account_reputation_units(st, account, acct)
        locked = bool(acct.get("locked", False))
        banned = bool(acct.get("banned", False))
        pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), list) else []
        active_key = bool([pk for pk in pubkeys if str(pk or "").strip()])
        reasons = rec.setdefault("reasons", [])
        if not isinstance(reasons, list):
            reasons = []
            rec["reasons"] = reasons

        def add_reason(reason: str) -> None:
            if reason not in reasons:
                reasons.append(reason)

        if tier >= 2:
            add_reason("live_verified_human")
        if reputation_units > 0:
            add_reason("positive_reputation")
        if not locked:
            add_reason("account_unlocked")
        if not banned:
            add_reason("account_not_banned")
        if active_key:
            add_reason("active_account_key")

        rec["eligible"] = bool(tier >= 2 and reputation_units > 0 and not locked and not banned and active_key)
        rec["poh_tier"] = tier
        rec["active_node_operator"] = True
        rec["reputation_units"] = int(reputation_units)
        rec["locked"] = locked
        rec["banned"] = banned

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



def _read_env_or_file(*names: str) -> str:
    for name in names:
        raw = str(os.getenv(name, "") or "").strip()
        if raw:
            return raw
    for name in names:
        path = str(os.getenv(f"{name}_FILE", "") or "").strip()
        if not path:
            continue
        try:
            value = open(path, "r", encoding="utf-8").read().strip()
        except Exception:
            value = ""
        if value:
            return value
    return ""


def _split_csv(value: str) -> set[str]:
    return {str(part or "").strip().lower() for part in str(value or "").split(",") if str(part or "").strip()}


def _configured_trusted_authority_pubkeys() -> set[str]:
    configured = _split_csv(os.getenv("WEALL_ORACLE_AUTHORITY_PUBKEYS", ""))
    configured.update(_split_csv(os.getenv("WEALL_TRUSTED_AUTHORITY_PUBKEYS", "")))
    try:
        manifest = load_chain_manifest(required=False, mode=str(os.getenv("WEALL_MODE", "") or ""))
    except Exception:
        manifest = None
    if manifest is not None:
        configured.update({str(pk or "").strip().lower() for pk in manifest.trusted_authority_pubkeys if str(pk or "").strip()})
    return configured


def _oracle_authority_signer_identity(request: Request, st: Json) -> OracleCallerIdentity | None:
    """Return the key allowed to sign oracle-authority snapshots.

    This is intentionally separate from normal node-operator request signing.
    Node operators may be eligible callers inside the signed snapshot, but they
    should not automatically become trusted snapshot signers.
    """

    account = _read_env_or_file(
        "WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT",
        "WEALL_ORACLE_AUTHORITY_ACCOUNT",
    )
    pubkey = _read_env_or_file(
        "WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY",
        "WEALL_ORACLE_AUTHORITY_PUBKEY",
    ).lower()
    privkey = _read_env_or_file(
        "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
        "WEALL_ORACLE_AUTHORITY_PRIVKEY",
    ).lower()

    dedicated_present = bool(account or pubkey or privkey)
    require_signed = _is_prod() or _env_bool("WEALL_REQUIRE_SIGNED_ORACLE_AUTHORITY", False)

    if dedicated_present:
        missing: list[str] = []
        if not account:
            missing.append("WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT")
        if not pubkey:
            missing.append("WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY")
        if not privkey:
            missing.append("WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY")
        if missing:
            raise ApiError.bad_request(
                "missing_oracle_authority_signer",
                "oracle authority signer identity is incomplete",
                {"missing": missing},
            )
        trusted = _configured_trusted_authority_pubkeys()
        if require_signed and not trusted:
            raise ApiError.bad_request(
                "missing_oracle_authority_trusted_pubkeys",
                "trusted authority snapshot signer pubkeys must be configured",
                {},
            )
        if require_signed and trusted and pubkey not in trusted:
            raise ApiError.bad_request(
                "oracle_authority_signer_not_trusted",
                "oracle authority signer pubkey is not in the trusted authority set",
                {},
            )
        return OracleCallerIdentity(operator_account=account, node_pubkey=pubkey, node_privkey=privkey)

    if require_signed:
        raise ApiError.bad_request(
            "missing_oracle_authority_signer",
            "production oracle-authority snapshots require a dedicated authority signer",
            {},
        )

    # Development/demo fallback: preserve the earlier behavior where a local
    # node identity can sign a diagnostic snapshot. Production never reaches
    # this fallback because require_signed is true in prod.
    return _oracle_caller_identity(request, st)


def _svc(request: Request) -> EmailVerificationService:
    """Construct the off-chain email verification service.

    Notes:
    - We intentionally keep all plaintext email handling inside the verifier module.
    - This API route layer should not introduce new plaintext-email key literals.
    """

    secret = (os.getenv("WEALL_POH_EMAIL_HASH_SALT") or "").strip()
    if not secret and _is_prod():
        raise ApiError.bad_request(
            "missing_email_hash_salt",
            "WEALL_POH_EMAIL_HASH_SALT must be set for the in-process PoH email oracle in prod",
        )
    if not secret:
        secret = "weall-local-dev-email-secret"

    ttl_seconds_raw = os.getenv("WEALL_POH_EMAIL_CHALLENGE_TTL_SECONDS", "").strip()
    ttl_ms = 15 * 60 * 1000  # default 15 minutes
    if ttl_seconds_raw:
        try:
            ttl_seconds = int(ttl_seconds_raw)
        except ValueError:
            raise ApiError.bad_request("invalid_challenge_ttl_seconds", "WEALL_POH_EMAIL_CHALLENGE_TTL_SECONDS must be an int")
        if ttl_seconds <= 0:
            raise ApiError.bad_request("invalid_challenge_ttl_seconds", "WEALL_POH_EMAIL_CHALLENGE_TTL_SECONDS must be positive")
        ttl_ms = ttl_seconds * 1000

    st = _snapshot(request)
    caller_identity = _oracle_caller_identity(request, st)
    if caller_identity is None:
        raise ApiError.bad_request(
            "missing_oracle_caller_identity",
            "authorized local node identity required for email verification oracle calls",
        )

    return EmailVerificationService(secret=secret, ttl_ms=ttl_ms, caller_identity=caller_identity)


def _attestation_ttl_heights() -> int:
    raw = os.getenv("WEALL_POH_EMAIL_TTL_HEIGHTS", "60").strip()
    try:
        value = int(raw)
    except Exception as exc:
        raise ApiError.bad_request("invalid_ttl_heights", "WEALL_POH_EMAIL_TTL_HEIGHTS must be an int", {}) from exc
    if value <= 0:
        raise ApiError.bad_request("invalid_ttl_heights", "WEALL_POH_EMAIL_TTL_HEIGHTS must be positive", {})
    return value


def _sign_email_control_attestation(
    *,
    svc: EmailVerificationService,
    chain_id: str,
    account: str,
    email: str,
    challenge_id: str,
    current_height: int,
) -> Json:
    caller = svc.caller_identity
    oracle_id = (os.getenv("WEALL_EMAIL_ORACLE_ID") or caller.operator_account or "").strip()
    dedicated_oracle_privkey = _read_env_or_file("WEALL_EMAIL_ORACLE_PRIVATE_KEY").strip().lower()
    if _is_prod() and not dedicated_oracle_privkey:
        raise ApiError.bad_request("missing_email_oracle_private_key", "production email oracle signing requires WEALL_EMAIL_ORACLE_PRIVATE_KEY or WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE", {})
    oracle_privkey = (dedicated_oracle_privkey or caller.node_privkey or "").strip().lower()
    salt = (os.getenv("WEALL_POH_EMAIL_HASH_SALT") or "").strip()

    if not oracle_id:
        raise ApiError.bad_request("missing_email_oracle_id", "email oracle id is required", {})
    if not oracle_privkey:
        raise ApiError.bad_request("missing_email_oracle_private_key", "email oracle private key is required", {})
    if not salt and _is_prod():
        raise ApiError.bad_request("missing_email_hash_salt", "WEALL_POH_EMAIL_HASH_SALT must be set in prod", {})
    if not salt:
        salt = "weall-local-dev-email-secret"

    email_hash = email_hash_for_attestation(normalized_email=email, salt=salt, account_id=account)
    domain_hash = domain_hash_for_attestation(normalized_email=email, salt=salt, account_id=account)
    issued_at_height = int(current_height)
    expires_at_height = issued_at_height + _attestation_ttl_heights()
    unsigned = build_unsigned_email_control_attestation_v1(
        account_id=account,
        email_hash=email_hash,
        domain_hash=domain_hash,
        challenge_id=challenge_id,
        issued_at_height=issued_at_height,
        expires_at_height=expires_at_height,
        oracle_id=oracle_id,
        chain_id=chain_id,
    )
    return sign_email_control_attestation_v1(unsigned, oracle_private_key=oracle_privkey)



@router.get("/poh/email/oracle-authority", response_model=PohEmailOracleAuthorityResponse, name="poh_email_oracle_authority")
def poh_email_oracle_authority(request: Request) -> PohEmailOracleAuthorityResponse:
    st = _snapshot(request)
    registry = _oracle_authority_registry(st)
    authorized_accounts = sorted(registry.keys())
    authorized_pubkeys = sorted(
        {str(pk).strip().lower() for rec in registry.values() if isinstance(rec, dict) for pk in (rec.get("pubkeys") or []) if str(pk).strip()}
    )
    manifest_identity = _oracle_chain_manifest_identity(st)
    generated_at_ms = authority_now_ms()
    try:
        ttl_ms = max(5_000, int(os.getenv("WEALL_ORACLE_AUTHORITY_SNAPSHOT_TTL_MS", str(DEFAULT_SNAPSHOT_TTL_MS))))
    except Exception:
        ttl_ms = DEFAULT_SNAPSHOT_TTL_MS
    payload: Json = {
        "ok": True,
        "version": SNAPSHOT_VERSION,
        "type": SNAPSHOT_TYPE,
        "chain_id": str(st.get("chain_id") or "").strip(),
        "genesis_hash": manifest_identity.get("genesis_hash", ""),
        "height": _oracle_height(st),
        "block_hash": _oracle_block_hash(st),
        "state_root": compute_state_root(st if isinstance(st, dict) else {}),
        "tx_index_hash": manifest_identity.get("tx_index_hash", ""),
        "schema_version": manifest_identity.get("schema_version", ""),
        "validator_epoch": _oracle_validator_epoch(st),
        "validator_set_hash": _oracle_validator_set_hash(st),
        "authority_source": "on_chain_signed_snapshot",
        "generated_at_ms": generated_at_ms,
        "expires_at_ms": generated_at_ms + ttl_ms,
        "authorized_accounts": authorized_accounts,
        "authorized_pubkeys": authorized_pubkeys,
        "registry": registry,
    }
    payload["snapshot_hash"] = snapshot_hash(payload)
    payload["signatures"] = []

    signer = _oracle_authority_signer_identity(request, st)
    if signer is not None and signer.node_privkey and signer.node_pubkey:
        try:
            payload = sign_authority_snapshot(
                payload,
                signer=signer.operator_account,
                pubkey=signer.node_pubkey,
                privkey_hex=signer.node_privkey,
            )
        except Exception as exc:
            if _is_prod() or _env_bool("WEALL_REQUIRE_SIGNED_ORACLE_AUTHORITY", False):
                raise ApiError.bad_request(
                    "oracle_authority_snapshot_signing_failed",
                    "oracle authority snapshot signing failed",
                    {},
                ) from exc
            # Keep the diagnostic endpoint available for non-signing local/dev
            # nodes. Production oracle-authority snapshots require a valid signature and fail
            # closed if signatures is empty or invalid.
            payload["signatures"] = []
    return PohEmailOracleAuthorityResponse(**payload)


@router.post(
    "/poh/email/begin",
    response_model=PohEmailBeginResponse,
    response_model_exclude_none=True,
    name="poh_email_begin",
)
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
    genesis_hash = ""
    try:
        st = _snapshot(request)
        chain_id = str(st.get("chain_id") or "").strip()
        genesis_hash = _oracle_chain_manifest_identity(st).get("genesis_hash", "")
    except ApiError as exc:
        if exc.code != "not_ready":
            raise

    svc = _svc(request)
    try:
        result = svc.begin(account=account, email=email, chain_id=chain_id, genesis_hash=genesis_hash)
    except TypeError as exc:
        # Test doubles and older in-process dev adapters may not yet accept the
        # chain_id keyword. Keep the public route backward-compatible while the
        # real EmailVerificationService remains chain-bound whenever a real
        # executor/chain identity is available.
        if "chain_id" not in str(exc) and "genesis_hash" not in str(exc):
            raise
        result = svc.begin(account=account, email=email)

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

    return PohEmailBeginResponse(
        ok=True,
        request_id=request_id,
        expires_ms=expires_ms,
        security_phrase=str(result.get("security_phrase") or ""),
        official_sender=str(result.get("official_sender") or "verify@poh.weall.org"),
        email_masked=result.get("email_masked") if isinstance(result.get("email_masked"), str) else None,
        dev_code=str(result.get("dev_code")) if result.get("dev_code") is not None else None,
    )


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
    genesis_hash = _oracle_chain_manifest_identity(st).get("genesis_hash", "")
    svc = _svc(request)
    try:
        result = svc.complete(
            account=account,
            email=email,
            code=code,
            request_id=request_id,
            chain_id=chain_id,
            genesis_hash=genesis_hash,
        )
    except TypeError as exc:
        if "chain_id" not in str(exc) and "genesis_hash" not in str(exc):
            raise
        result = svc.complete(
            account=account,
            email=email,
            code=code,
            request_id=request_id,
        )
    attestation = _sign_email_control_attestation(
        svc=svc,
        chain_id=chain_id,
        account=account,
        email=email,
        challenge_id=request_id,
        current_height=int(st.get("height") or 0),
    )

    return PohEmailCompleteResponse(
        ok=True,
        request_id=request_id,
        completed=bool(result.get("completed", True)) if isinstance(result, dict) else True,
        attestation=attestation,
        tx={
            "tx_type": "POH_EMAIL_ATTESTATION_SUBMIT",
            "signer_hint": account,
            "parent": None,
            "payload": {"account_id": account, "attestation": attestation},
        },
        security_phrase=str(result.get("security_phrase") or "") if isinstance(result, dict) else "",
    )




class PohEmailAttestationSubmitRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=128)
    attestation: Json


@router.post("/poh/email/tx/attestation-submit", name="poh_email_tx_attestation_submit")
def poh_email_tx_attestation_submit(req: PohEmailAttestationSubmitRequest, request: Request) -> Json:
    acct = str(req.account_id or "").strip()
    if not acct:
        raise ApiError.bad_request("bad_request", "missing account_id", {})
    if not isinstance(req.attestation, dict):
        raise ApiError.bad_request("bad_request", "attestation must be an object", {})

    return {
        "ok": True,
        "tx": {
            "tx_type": "POH_EMAIL_ATTESTATION_SUBMIT",
            "signer_hint": acct,
            "parent": None,
            "payload": {"account_id": acct, "attestation": req.attestation},
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

    enqueue_system_tx(
        st,
        tx_type="POH_LIVE_INIT",
        payload={"case_id": case_id, "relay_commitment": _sha256_hex(join_url.encode("utf-8")), "ts_ms": 0},
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


