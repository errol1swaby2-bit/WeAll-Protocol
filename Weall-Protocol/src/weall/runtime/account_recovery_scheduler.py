from __future__ import annotations

"""Deterministic scheduler for already-authorized account recovery requests."""

from typing import Any

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def schedule_account_recovery_system_txs(state: Json, *, next_height: int) -> int:
    """Enqueue finalize and receipt transactions for authorized recoveries.

    The scheduler does not decide whether a recovery is valid.  User admission
    and the identity applier establish an ``approved`` request.  This scheduler
    only converts that committed authorization into deterministic system-owned
    finalization and receipt steps.
    """

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return 0

    enqueued = 0
    for account_id in sorted(str(key) for key in accounts.keys()):
        account = accounts.get(account_id)
        if not isinstance(account, dict):
            continue
        recovery = account.get("recovery")
        if not isinstance(recovery, dict):
            continue
        requests = recovery.get("requests")
        if not isinstance(requests, dict):
            continue

        for request_id in sorted(str(key) for key in requests.keys()):
            request = requests.get(request_id)
            if not isinstance(request, dict):
                continue
            status = _as_str(request.get("status")).lower()
            if status == "approved":
                enqueue_system_tx(
                    state,
                    tx_type="ACCOUNT_RECOVERY_FINALIZE",
                    payload={"request_id": request_id},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent="ACCOUNT_RECOVERY_APPROVE",
                    phase="pre",
                )
                enqueued += 1
            elif status == "finalized":
                enqueue_system_tx(
                    state,
                    tx_type="ACCOUNT_RECOVERY_RECEIPT",
                    payload={"request_id": request_id, "status": "finalized"},
                    due_height=int(next_height),
                    signer="SYSTEM",
                    once=True,
                    parent="ACCOUNT_RECOVERY_FINALIZE",
                    phase="pre",
                )
                enqueued += 1

    return enqueued


__all__ = ["schedule_account_recovery_system_txs"]
