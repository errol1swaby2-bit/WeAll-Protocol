from __future__ import annotations

"""Deterministic account-recovery lifecycle scheduler.

The scheduler assigns independent continuity/reversal reviewers, evaluates the
committed panel decisions, and emits finalization/receipt transactions. Every
choice depends only on canonical state and ``next_height``.
"""

import hashlib
from typing import Any

from weall.runtime.recovery_review import review_counts, select_recovery_reviewers
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _panel_commitment(request_id: str, reviewers: list[str]) -> str:
    material = f"RECOVERY_PANEL_V1|{request_id}|{'|'.join(reviewers)}".encode("utf-8")
    return f"sha256:{hashlib.sha256(material).hexdigest()}"


def _enqueue_receipt(state: Json, *, request_id: str, status: str, next_height: int) -> None:
    enqueue_system_tx(
        state,
        tx_type="ACCOUNT_RECOVERY_RECEIPT",
        payload={"request_id": request_id, "status": status},
        due_height=int(next_height),
        signer="SYSTEM",
        once=True,
        parent="ACCOUNT_RECOVERY_REQUEST",
        phase="pre",
    )


def schedule_account_recovery_system_txs(state: Json, *, next_height: int) -> int:
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
            method = _as_str(request.get("method")).lower()
            status = _as_str(request.get("status")).lower()

            if method == "continuity" and status == "awaiting_social_attestations":
                if int(next_height) > _as_int(request.get("review_deadline_height"), 0):
                    request["status"] = "expired"
                    request["resolved_height"] = int(next_height)
                    _enqueue_receipt(
                        state,
                        request_id=request_id,
                        status="expired",
                        next_height=next_height,
                    )
                    enqueued += 1
                    continue

            if method in {"continuity", "reversal"} and status == "awaiting_assignment":
                panel_size = max(1, _as_int(request.get("panel_size"), 1))
                reviewers = select_recovery_reviewers(
                    state,
                    request_id=request_id,
                    target_id=account_id,
                    panel_size=panel_size,
                    excluded_reviewers={
                        _as_str(value)
                        for value in request.get("excluded_reviewers", [])
                        if _as_str(value)
                    },
                )
                if len(reviewers) != panel_size:
                    request["status"] = "assignment_unavailable"
                    request["assignment_failed_height"] = int(next_height)
                    _enqueue_receipt(
                        state,
                        request_id=request_id,
                        status="assignment_unavailable",
                        next_height=next_height,
                    )
                    enqueued += 1
                    continue
                request["assigned_reviewers"] = reviewers
                request["panel_commitment"] = _panel_commitment(request_id, reviewers)
                request["assigned_height"] = int(next_height)
                request["status"] = "under_review"
                status = "under_review"

            if method in {"continuity", "reversal"} and status == "under_review":
                approvals, rejections, submitted = review_counts(request)
                panel_size = max(1, _as_int(request.get("panel_size"), 1))
                threshold = max(1, _as_int(request.get("approval_threshold"), 1))
                request["approval_count"] = approvals
                request["rejection_count"] = rejections
                request["submitted_review_count"] = submitted
                if approvals >= threshold:
                    request["status"] = "approved"
                    status = "approved"
                elif rejections > panel_size - threshold:
                    request["status"] = "rejected"
                    request["resolved_height"] = int(next_height)
                    _enqueue_receipt(
                        state,
                        request_id=request_id,
                        status="rejected",
                        next_height=next_height,
                    )
                    enqueued += 1
                    continue
                elif int(next_height) > _as_int(request.get("review_deadline_height"), 0):
                    request["status"] = "expired"
                    request["resolved_height"] = int(next_height)
                    _enqueue_receipt(
                        state,
                        request_id=request_id,
                        status="expired",
                        next_height=next_height,
                    )
                    enqueued += 1
                    continue

            if status == "approved" or _as_str(request.get("status")).lower() == "approved":
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
            elif status == "finalized" or _as_str(request.get("status")).lower() == "finalized":
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
