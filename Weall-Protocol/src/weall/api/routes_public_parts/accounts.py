from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Request

from weall.ledger.state import LedgerView
from weall.api.routes_public_parts.common import _snapshot

router = APIRouter()


def _normalize_keys(acct: Dict[str, Any]) -> List[dict]:
    ks = acct.get("keys")
    out: List[dict] = []

    if isinstance(ks, dict):
        for pubkey, rec in ks.items():
            p = str(pubkey or "").strip()
            if not p:
                continue
            active = bool(rec.get("active", True)) if isinstance(rec, dict) else bool(rec)
            out.append({"pubkey": p, "active": active})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    if isinstance(ks, list):
        for it in ks:
            p = str(it or "").strip()
            if p:
                out.append({"pubkey": p, "active": True})
        out.sort(key=lambda x: x.get("pubkey", ""))
        return out

    return out


@router.get("/v1/accounts/{account}")
def v1_account_get(account: str, request: Request):
    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)
    a = ledger.accounts.get(account)
    return {
        "ok": True,
        "account": account,
        "state": a or {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False, "reputation": 0},
    }


@router.get("/v1/accounts/{account}/registered")
def v1_account_registered(account: str, request: Request):
    """
    Node eligibility rule:
      - Account exists
      - PoH tier >= 3
      - Not banned
    """
    st = _snapshot(request)
    ledger = LedgerView.from_ledger(st)

    acct = ledger.accounts.get(account)
    if not acct:
        return {"ok": True, "account": account, "registered": False}

    tier = int(acct.get("poh_tier", 0) or 0)
    banned = bool(acct.get("banned", False))

    registered = tier >= 3 and not banned

    return {"ok": True, "account": account, "registered": registered}
