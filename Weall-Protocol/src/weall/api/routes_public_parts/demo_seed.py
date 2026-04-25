from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from weall.api.errors import ApiError
from weall.runtime.bft_hotstuff import normalize_validators, quorum_threshold, validator_set_hash
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission import TxEnvelope

router = APIRouter()
Json = dict[str, Any]


class DemoSeedRequest(BaseModel):
    account: str
    post_id: str
    group_id: str | None = None
    proposal_id: str | None = None
    dispute_id: str | None = None


class _LedgerStoreWriter:
    def __init__(self) -> None:
        self.last_written: Json | None = None

    def write(self, state: Json) -> None:
        self.last_written = state


def _env_true(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _runtime_profile() -> str:
    return (
        os.getenv("WEALL_RUNTIME_PROFILE")
        or os.getenv("WEALL_PROTOCOL_PROFILE")
        or os.getenv("WEALL_PROFILE")
        or ""
    ).strip().lower()


def _runtime_mode() -> str:
    return str(os.getenv("WEALL_MODE", "") or "").strip().lower()


def _seeded_demo_profile_enabled() -> bool:
    profile = _runtime_profile()
    mode = _runtime_mode()
    if profile != "seeded_demo":
        return False
    if mode in {"prod", "production", "production_like", "devnet", "multi_node_devnet"}:
        return False
    return True


def _demo_seed_enabled() -> bool:
    # This route directly mutates canonical state and forces demo authority.
    # It is intentionally available only in the explicit seeded_demo profile,
    # never in multi-node devnet or production-like modes.
    return _env_true("WEALL_ENABLE_DEMO_SEED_ROUTE") and _seeded_demo_profile_enabled()


def _dev_bootstrap_secret_enabled() -> bool:
    # Do not inherit the powerful bootstrap-secret route from demo-seed by
    # default. It must be independently enabled and fenced to seeded_demo.
    return _env_true("WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE") and _seeded_demo_profile_enabled()


def _dev_bootstrap_secret_path() -> Path:
    configured = str(os.getenv("WEALL_DEV_BOOTSTRAP_SECRET_PATH", "")).strip()
    if configured:
        return Path(configured).expanduser()

    default_name = "demo_bootstrap_secret.json"
    repo_root = Path(__file__).resolve().parents[4]
    candidates = [
        Path("/app/generated") / default_name,
        repo_root / "generated" / default_name,
        Path.cwd() / "generated" / default_name,
    ]
    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file():
                return candidate
        except Exception:
            continue
    return candidates[0]


def _load_dev_bootstrap_secret(account: str) -> Json:
    path = _dev_bootstrap_secret_path()
    if not path.exists() or not path.is_file():
        raise ApiError.not_found("dev_bootstrap_secret_missing", "Dev bootstrap secret not available")
    try:
        payload = Json(__import__("json").loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ApiError.server_error("dev_bootstrap_secret_invalid", "Dev bootstrap secret file is invalid") from exc
    secret_account = str(payload.get("account") or "").strip()
    if secret_account and secret_account != account:
        raise ApiError.not_found("dev_bootstrap_secret_account_mismatch", "Dev bootstrap secret not available for that account")
    secret_key_b64 = str(payload.get("secret_key_b64") or "").strip()
    if not secret_key_b64:
        raise ApiError.server_error("dev_bootstrap_secret_invalid", "Dev bootstrap secret file is missing the private key")
    return {
        "account": secret_account or account,
        "secretKeyB64": secret_key_b64,
        "secret_key_b64": secret_key_b64,
        "pubkeyB64": str(payload.get("pubkey_b64") or "").strip(),
        "sessionTtlSeconds": int(payload.get("session_ttl_seconds") or 3600),
    }


def _slug(value: str) -> str:
    raw = str(value or "demo").strip().lower()
    raw = raw[1:] if raw.startswith("@") else raw
    raw = re.sub(r"[^a-z0-9]+", "-", raw)
    raw = raw.strip("-") or "demo"
    return raw


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _ensure_account(state: Json, account: str) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        raise ApiError.bad_request("invalid_state", "accounts root missing")
    acct = accounts.get(account)
    if not isinstance(acct, dict):
        raise ApiError.bad_request("account_required", f"Demo account {account} not found")
    return acct


def _current_nonce(state: Json, signer: str) -> int:
    accounts = state.get("accounts")
    acct = accounts.get(signer) if isinstance(accounts, dict) else None
    if not isinstance(acct, dict):
        return 0
    try:
        return int(acct.get("nonce") or 0)
    except Exception:
        return 0


def _apply_user_tx(state: Json, *, signer: str, tx_type: str, payload: Json, parent: str | None = None) -> Json | None:
    nonce = _current_nonce(state, signer) + 1
    env = TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="",
        parent=parent,
        system=False,
    )
    return apply_tx(state, env)


def _apply_system_tx(state: Json, *, tx_type: str, payload: Json, parent: str | None = None) -> Json | None:
    env = TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM",
        nonce=1,
        payload=payload,
        sig="",
        parent=parent,
        system=True,
    )
    return apply_tx(state, env)


def _ensure_single_active_validator(state: Json, account: str) -> dict[str, Any]:
    roles = state.setdefault("roles", {})
    if not isinstance(roles, dict):
        raise ApiError.server_error("invalid_state", "roles root missing")
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {}
        roles["validators"] = validators
    active = normalize_validators([account])
    validators["active_set"] = list(active)
    by_id = validators.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        validators["by_id"] = by_id
    by_id[account] = {
        **_as_dict(by_id.get(account)),
        "account_id": account,
        "status": "active",
    }

    consensus = state.get("consensus")
    if not isinstance(consensus, dict):
        consensus = {}
        state["consensus"] = consensus
    validator_set = consensus.get("validator_set")
    if not isinstance(validator_set, dict):
        validator_set = {}
        consensus["validator_set"] = validator_set
    validator_set["active_set"] = list(active)
    epoch = int(validator_set.get("epoch") or 1)
    if epoch <= 0:
        epoch = 1
    validator_set["epoch"] = epoch
    validator_set["set_hash"] = validator_set_hash(active)

    validators_bucket = consensus.get("validators")
    if not isinstance(validators_bucket, dict):
        validators_bucket = {}
        consensus["validators"] = validators_bucket
    registry = validators_bucket.get("registry")
    if not isinstance(registry, dict):
        registry = {}
        validators_bucket["registry"] = registry
    registry[account] = {
        **_as_dict(registry.get(account)),
        "account_id": account,
        "status": "active",
    }

    return {
        "active_validator_ids": list(active),
        "eligible_validator_count": len(active),
        "required_votes": quorum_threshold(len(active)),
        "validator_epoch": epoch,
        "validator_set_hash": str(validator_set.get("set_hash") or ""),
    }


def seed_demo_state(
    state: Json,
    *,
    account: str,
    post_id: str,
    group_id: str | None = None,
    proposal_id: str | None = None,
    dispute_id: str | None = None,
) -> Json:
    acct = _ensure_account(state, account)
    tier = int(acct.get("poh_tier") or acct.get("tier") or 0)
    if tier < 3:
        raise ApiError.bad_request("insufficient_tier", f"Demo account {account} must be Tier 3+")

    content = _as_dict(state.get("content"))
    posts = _as_dict(content.get("posts"))
    if not isinstance(posts.get(post_id), dict):
        raise ApiError.bad_request("post_required", f"Demo post {post_id} not found")

    validator_summary = _ensure_single_active_validator(state, account)

    slug = _slug(account)
    group_id = str(group_id or f"g:{slug}:demo-public").strip()
    proposal_id = str(proposal_id or f"proposal:{slug}:demo-vote").strip()
    dispute_id = str(dispute_id or f"dispute:{slug}:demo-post").strip()

    groups_root = _as_dict(_as_dict(state.get("roles")).get("groups_by_id"))
    if not isinstance(groups_root.get(group_id), dict):
        _apply_user_tx(
            state,
            signer=account,
            tx_type="GROUP_CREATE",
            payload={
                "group_id": group_id,
                "name": "Demo Public Group",
                "charter": "Conference-safe seeded public group.",
                "visibility": "public",
            },
        )

    group_obj = _as_dict(_as_dict(_as_dict(state.get("roles")).get("groups_by_id")).get(group_id))
    members = _as_dict(group_obj.get("members"))
    if account not in members:
        _apply_user_tx(
            state,
            signer=account,
            tx_type="GROUP_MEMBERSHIP_REQUEST",
            payload={"group_id": group_id, "message": "Deterministic demo membership"},
        )

    gov_root = _as_dict(state.get("gov_proposals_by_id"))
    if not isinstance(gov_root.get(proposal_id), dict):
        _apply_user_tx(
            state,
            signer=account,
            tx_type="GOV_PROPOSAL_CREATE",
            payload={
                "proposal_id": proposal_id,
                "title": "Enable conference-safe demo governance proof",
                "body": "Seeded proposal for deterministic live voting.",
                "rules": {"start_stage": "voting"},
                "actions": [],
            },
        )

    disputes = _as_dict(state.get("disputes_by_id"))
    if not isinstance(disputes.get(dispute_id), dict):
        _apply_user_tx(
            state,
            signer=account,
            tx_type="DISPUTE_OPEN",
            payload={
                "dispute_id": dispute_id,
                "target_type": "content",
                "target_id": post_id,
                "reason": "seeded_demo_review",
            },
        )

    roles = _as_dict(state.get("roles"))
    jurors = _as_dict(roles.get("jurors"))
    juror_by_id = _as_dict(jurors.get("by_id"))
    active_set = jurors.get("active_set") if isinstance(jurors.get("active_set"), list) else []
    if account not in juror_by_id:
        _apply_user_tx(
            state,
            signer=account,
            tx_type="ROLE_JUROR_ENROLL",
            payload={"account_id": account},
        )
    if account not in active_set:
        _apply_system_tx(
            state,
            tx_type="ROLE_JUROR_ACTIVATE",
            payload={"account_id": account},
            parent="demo_seed:juror_activate",
        )

    dispute_obj = _as_dict(_as_dict(state.get("disputes_by_id")).get(dispute_id))
    juror_assignments = _as_dict(dispute_obj.get("jurors"))
    assigned = _as_dict(juror_assignments.get(account))
    if not assigned:
        _apply_system_tx(
            state,
            tx_type="DISPUTE_JUROR_ASSIGN",
            payload={"dispute_id": dispute_id, "juror": account},
            parent="demo_seed:juror_assign",
        )
    if str(dispute_obj.get("stage") or "").strip().lower() not in {"juror_review", "voting"}:
        _apply_system_tx(
            state,
            tx_type="DISPUTE_STAGE_SET",
            payload={"dispute_id": dispute_id, "stage": "juror_review"},
            parent="demo_seed:stage_set",
        )

    final_group = _as_dict(_as_dict(_as_dict(state.get("roles")).get("groups_by_id")).get(group_id))
    final_proposal = _as_dict(_as_dict(state.get("gov_proposals_by_id")).get(proposal_id))
    final_dispute = _as_dict(_as_dict(state.get("disputes_by_id")).get(dispute_id))
    final_juror = _as_dict(_as_dict(final_dispute.get("jurors")).get(account))

    return {
        "validator": validator_summary,
        "group": {
            "group_id": group_id,
            "member_visible": bool(account in _as_dict(final_group.get("members"))),
            "visibility": str(final_group.get("visibility") or _as_dict(final_group.get("meta")).get("visibility") or "public"),
        },
        "proposal": {
            "proposal_id": proposal_id,
            "stage": str(final_proposal.get("stage") or ""),
        },
        "dispute": {
            "dispute_id": dispute_id,
            "stage": str(final_dispute.get("stage") or ""),
            "juror": account,
            "juror_status": str(final_juror.get("status") or ""),
            "target_id": str(final_dispute.get("target_id") or ""),
        },
    }




@router.get("/dev/bootstrap-secret")
def v1_dev_bootstrap_secret(account: str):
    if not _dev_bootstrap_secret_enabled():
        raise HTTPException(status_code=404, detail="Route not found")
    account_norm = str(account).strip()
    if not account_norm:
        raise ApiError.bad_request("account_required", "Account is required")
    return _load_dev_bootstrap_secret(account_norm)


@router.post("/dev/demo-seed")
def v1_demo_seed(request: Request, body: DemoSeedRequest):
    if not _demo_seed_enabled():
        raise HTTPException(status_code=404, detail="Route not found")

    ex = getattr(request.app.state, "executor", None)
    if ex is None or not hasattr(ex, "read_state"):
        raise ApiError.server_error("executor_missing", "Executor not available")

    state = ex.read_state()
    result = seed_demo_state(
        state,
        account=str(body.account).strip(),
        post_id=str(body.post_id).strip(),
        group_id=body.group_id,
        proposal_id=body.proposal_id,
        dispute_id=body.dispute_id,
    )
    ex.state = state
    store = getattr(ex, "_ledger_store", None)
    if store is not None and hasattr(store, "write"):
        store.write(state)

    return {"ok": True, **result}


__all__ = ["router", "seed_demo_state", "DemoSeedRequest", "_LedgerStoreWriter"]
