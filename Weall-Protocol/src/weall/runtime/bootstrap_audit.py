from __future__ import annotations

"""Deterministic bootstrap-authority audit helpers.

Bootstrap authority is intentionally transitional.  These helpers materialize a
receipt-like ledger object for every bootstrap Tier-2/Live grant, including direct
genesis-state grants that do not arrive as normal mempool transactions.  The
records are consensus-visible state, not local operator logs.
"""

import hashlib
import json
from typing import Any
from weall.runtime.json_tools import canonical_json_str

Json = dict[str, Any]


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _canonical_hash(value: Json) -> str:
    blob = canonical_json_str(value)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _poh_root(state: Json) -> Json:
    poh = state.get("poh")
    if not isinstance(poh, dict):
        poh = {}
        state["poh"] = poh
    return poh


def _bootstrap_grants_root(state: Json) -> Json:
    poh = _poh_root(state)
    root = poh.get("bootstrap_grants")
    if not isinstance(root, dict):
        root = {}
        poh["bootstrap_grants"] = root
    by_id = root.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        root["by_id"] = by_id
    by_account = root.get("by_account")
    if not isinstance(by_account, dict):
        by_account = {}
        root["by_account"] = by_account
    return root


def record_bootstrap_tier2_grant(
    state: Json,
    *,
    account_id: str,
    signer: str = "",
    mode: str = "",
    source: str = "",
    height: int | None = None,
    tx_type: str = "POH_BOOTSTRAP_TIER2_GRANT",
    nonce: int | None = None,
    authority_path: str = "",
    reason_code: str = "",
    expires_height: int | None = None,
    review_condition: str = "native_poh_juror_quorum_or_governance_review",
    pubkey: str = "",
) -> Json:
    """Write a deterministic, receipt-backed bootstrap grant audit record.

    The function is idempotent for the same semantic grant.  It also mirrors the
    generated grant/receipt identifiers onto the account record when present so
    operator/status surfaces can point users at the audit trail.
    """

    acct = str(account_id or "").strip()
    if not acct:
        raise ValueError("missing bootstrap account_id")

    h = _as_int(state.get("height"), 0) if height is None else _as_int(height, 0)
    n = _as_int(nonce, 0) if nonce is not None else 0
    mode_s = str(mode or "unknown").strip() or "unknown"
    source_s = str(source or "bootstrap").strip() or "bootstrap"
    signer_s = str(signer or "").strip()
    tx_type_s = str(tx_type or "POH_BOOTSTRAP_TIER2_GRANT").strip().upper()
    reason_s = str(reason_code or "bootstrap_tier2_live_verified").strip()
    authority_s = str(authority_path or mode_s).strip()
    expires = None if expires_height is None else _as_int(expires_height, 0)

    commitment: Json = {
        "account_id": acct,
        "authority_path": authority_s,
        "expires_height": expires,
        "grant_height": h,
        "grant_type": "poh_tier2_live_verified",
        "mode": mode_s,
        "nonce": n,
        "reason_code": reason_s,
        "source": source_s,
        "tx_type": tx_type_s,
    }
    if signer_s:
        commitment["signer"] = signer_s
    if pubkey:
        commitment["pubkey_sha256"] = hashlib.sha256(str(pubkey).encode("utf-8")).hexdigest()

    grant_hash = _canonical_hash(commitment)
    grant_id = f"poh_bootstrap_grant:{grant_hash[:24]}"
    receipt_id = f"poh_bootstrap_receipt:{_canonical_hash({'grant_id': grant_id})[:24]}"

    record: Json = dict(commitment)
    record.update(
        {
            "grant_id": grant_id,
            "receipt_id": receipt_id,
            "status": "active",
            "auditable": True,
            "transitional": True,
            "review_condition": str(review_condition or "").strip(),
        }
    )

    root = _bootstrap_grants_root(state)
    by_id = _as_dict(root.get("by_id"))
    by_id[grant_id] = record
    root["by_id"] = by_id

    by_account = _as_dict(root.get("by_account"))
    ids = by_account.get(acct)
    if not isinstance(ids, list):
        ids = []
    if grant_id not in ids:
        ids.append(grant_id)
    by_account[acct] = sorted(str(x) for x in ids if str(x).strip())
    root["by_account"] = by_account

    accounts = state.get("accounts")
    if isinstance(accounts, dict):
        account = accounts.get(acct)
        if isinstance(account, dict):
            account["poh_bootstrap_grant_id"] = grant_id
            account["poh_bootstrap_receipt_id"] = receipt_id
            account.setdefault("poh_bootstrap_review_condition", record["review_condition"])

    return record


__all__ = ["record_bootstrap_tier2_grant"]
