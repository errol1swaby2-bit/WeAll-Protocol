from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from weall.api.routes_public_parts.common import _snapshot, _str_param
from weall.runtime.econ_phase import econ_allowed_from_state, is_econ_unlocked
from weall.ledger.tokenomics import tokenomics_policy_from_state

Json = dict[str, Any]

router = APIRouter()


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _fee_policy(econ: Json) -> Json:
    policy = _as_dict(econ.get("fee_policy"))
    out: Json = {}
    for k in sorted(policy):
        v = policy.get(k)
        if str(k).endswith("_fee_int"):
            out[str(k)] = _as_int(v, 0)
        else:
            out[str(k)] = v
    return out


def _account_balance(st: Json, account: str) -> int | None:
    acct = _as_dict(_as_dict(st.get("accounts")).get(account))
    if not acct:
        return None
    return _as_int(acct.get("balance"), 0)


def economics_status_from_state(st: Json, *, account: str = "") -> Json:
    """Return the production-facing locked tokenomics status.

    This is deliberately a read model, not authority.  The apply path remains the
    authority for activation, transfers, fees, and treasury mutation.  The goal is
    to give the UI/reviewer a single truthful object instead of scattered status
    text that can drift across pages.
    """

    state = st if isinstance(st, dict) else {}
    params = _as_dict(state.get("params"))
    econ = _as_dict(state.get("economics"))
    treasury = _as_dict(state.get("treasury"))
    tre_wallets = _as_dict(state.get("treasury_wallets"))

    try:
        unlocked = bool(is_econ_unlocked(state))
    except Exception:
        unlocked = False
    try:
        enabled = bool(econ_allowed_from_state(state))
    except Exception:
        enabled = False

    unlock_height = _as_int(params.get("economic_unlock_height"), 0)
    unlock_time = _as_int(params.get("economic_unlock_time"), 0)
    current_height = _as_int(state.get("height"), 0)

    acct = _str_param(account).strip()
    balance = _account_balance(state, acct) if acct else None
    tokenomics = tokenomics_policy_from_state(state)

    civic_fee_free_keys = [
        "post_fee_int",
        "comment_fee_int",
        "like_fee_int",
        "reaction_fee_int",
        "share_fee_int",
        "follow_fee_int",
        "group_fee_int",
        "group_join_fee_int",
        "governance_fee_int",
        "governance_vote_fee_int",
        "proposal_fee_int",
        "vote_fee_int",
        "poh_fee_int",
        "dispute_fee_int",
        "review_fee_int",
    ]
    policy = _fee_policy(econ)
    civic_fee_violations = [k for k in civic_fee_free_keys if _as_int(policy.get(k), 0) > 0]

    return {
        "ok": True,
        "stage": "locked_genesis_model" if not enabled else "activated",
        "unlocked": bool(unlocked),
        "enabled": bool(enabled),
        "locked": not bool(enabled),
        "current_height": current_height,
        "economic_unlock_height": unlock_height,
        "economic_unlock_time": unlock_time,
        "activation_required": not bool(enabled),
        "activation_requirements": [
            "genesis economic lock expired" if not unlocked else "genesis economic lock expired: satisfied",
            "ECONOMICS_ACTIVATION must be emitted through governance/system authority",
            "fee policy may not make civic, social, governance, PoH, or review actions pay-to-participate",
            "treasury spend remains locked until economics activation and treasury governance rules are satisfied",
        ],
        "tokenomics": tokenomics,
        "capabilities": {
            "balance_transfer_enabled": bool(enabled),
            "fee_policy_enabled": bool(enabled),
            "fee_pay_enabled": bool(enabled),
            "treasury_spend_enabled": bool(enabled),
            "rewards_enabled": bool(enabled),
            "civic_social_governance_fee_free": len(civic_fee_violations) == 0,
        },
        "account": {
            "account_id": acct,
            "balance": balance,
            "balance_known": balance is not None,
            "transfer_disabled_reason": "economics_locked" if not enabled else "",
        } if acct else None,
        "fee_policy": policy,
        "civic_fee_violations": civic_fee_violations,
        "treasury": {
            "program_count": len(_as_dict(treasury.get("programs"))),
            "spend_count": len(_as_dict(treasury.get("spends"))),
            "wallet_count": len(tre_wallets),
            "locked": not bool(enabled),
        },
        "truth_label": "Economics are defined but locked" if not enabled else "Economics activated by governance/system rule",
        "claim": "Civic, social, governance, PoH, and review actions remain fee-free; WeCoin transfers, rewards, and treasury spending stay locked until explicit activation rules are satisfied.",
    }


@router.get("/economics/status")
def economics_status(request: Request, account: str | None = Query(default=None)):
    st = _snapshot(request)
    return economics_status_from_state(st if isinstance(st, dict) else {}, account=_str_param(account).strip())


@router.get("/wallet/{account}")
def wallet_status(request: Request, account: str):
    st = _snapshot(request)
    return economics_status_from_state(st if isinstance(st, dict) else {}, account=_str_param(account).strip())

def economics_activation_readiness_from_state(st: Json) -> Json:
    state = st if isinstance(st, dict) else {}
    params = _as_dict(state.get("params"))
    econ = _as_dict(state.get("economics"))
    status = economics_status_from_state(state)
    unlocked = bool(status.get("unlocked"))
    enabled = bool(status.get("enabled"))
    fee_violations = list(status.get("civic_fee_violations") or [])
    requirements: list[Json] = [
        {"key": "genesis_lock_expired", "ok": unlocked, "label": "Genesis economic lock expired"},
        {"key": "economics_not_already_enabled", "ok": not enabled, "label": "Economics not already enabled"},
        {"key": "civic_fee_floor", "ok": len(fee_violations) == 0, "label": "Civic/social/governance actions remain fee-free"},
        {"key": "governance_activation_tx", "ok": False, "label": "ECONOMICS_ACTIVATION still requires governance/system authority"},
    ]
    return {
        "ok": True,
        "ready_for_activation_tx": all(bool(item["ok"]) for item in requirements[:-1]) and not bool(enabled),
        "enabled": enabled,
        "unlocked": unlocked,
        "economic_unlock_height": _as_int(params.get("economic_unlock_height"), 0),
        "economic_unlock_time": _as_int(params.get("economic_unlock_time"), 0),
        "fee_policy": _fee_policy(econ),
        "civic_fee_violations": fee_violations,
        "requirements": requirements,
        "claim": "Readiness only; activation still requires a canonical ECONOMICS_ACTIVATION transaction from governance/system authority.",
    }


def transfer_preview_from_state(st: Json, *, from_account: str, to_account: str, amount: int) -> Json:
    state = st if isinstance(st, dict) else {}
    status = economics_status_from_state(state, account=from_account)
    enabled = bool(status.get("enabled"))
    accounts = _as_dict(state.get("accounts"))
    fa = _as_dict(accounts.get(from_account))
    ta = _as_dict(accounts.get(to_account))
    balance = _as_int(fa.get("balance"), 0) if fa else 0
    issues: list[str] = []
    if not enabled:
        issues.append("economics_locked")
    if not from_account:
        issues.append("missing_from_account")
    if not to_account:
        issues.append("missing_to_account")
    if amount <= 0:
        issues.append("bad_amount")
    if from_account and not fa:
        issues.append("from_account_missing")
    if to_account and not ta:
        issues.append("to_account_missing")
    if enabled and amount > balance:
        issues.append("insufficient_funds")
    return {
        "ok": True,
        "would_submit": bool(enabled and not issues),
        "allowed": bool(enabled and not issues),
        "from": from_account,
        "to": to_account,
        "amount": int(amount),
        "balance": int(balance),
        "issues": issues,
        "disabled_reason": issues[0] if issues else "",
        "tx_type": "BALANCE_TRANSFER",
        "claim": "Preview only; actual transfer still requires a signed canonical BALANCE_TRANSFER and economics activation.",
    }


def treasury_status_from_state(st: Json) -> Json:
    state = st if isinstance(st, dict) else {}
    status = economics_status_from_state(state)
    treasury = _as_dict(state.get("treasury"))
    wallets = _as_dict(state.get("treasury_wallets"))
    return {
        "ok": True,
        "locked": not bool(status.get("enabled")),
        "enabled": bool(status.get("enabled")),
        "wallets": {k: _as_dict(v) for k, v in sorted(wallets.items())},
        "programs": _as_dict(treasury.get("programs")),
        "spends": _as_dict(treasury.get("spends")),
        "policy": _as_dict(state.get("treasury_policy")),
        "spend_disabled_reason": "economics_locked" if not bool(status.get("enabled")) else "",
        "claim": "Treasury read model only; spend execution requires economics activation plus treasury governance/signature rules.",
    }


@router.get("/economics/activation/readiness")
def economics_activation_readiness(request: Request):
    st = _snapshot(request)
    return economics_activation_readiness_from_state(st if isinstance(st, dict) else {})


@router.get("/economics/transfer/preview")
def economics_transfer_preview(
    request: Request,
    from_account: str = Query(default=""),
    to_account: str = Query(default=""),
    amount: int = Query(default=0),
):
    st = _snapshot(request)
    return transfer_preview_from_state(
        st if isinstance(st, dict) else {},
        from_account=_str_param(from_account).strip(),
        to_account=_str_param(to_account).strip(),
        amount=int(amount or 0),
    )


@router.get("/treasury/status")
def treasury_status(request: Request):
    st = _snapshot(request)
    return treasury_status_from_state(st if isinstance(st, dict) else {})

