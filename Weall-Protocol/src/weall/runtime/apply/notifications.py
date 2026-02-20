# src/weall/runtime/apply/notifications.py
from __future__ import annotations

"""
Notifications domain apply semantics (production-ready; canon-correct).

Canon txs (v1.22.1):
- NOTIFICATION_SUBSCRIBE (USER, mempool)
- NOTIFICATION_UNSUBSCRIBE (USER, mempool)
- NOTIFICATION_EMIT_RECEIPT (SYSTEM, block, receipt_only, parent=BLOCK_FINALIZE)

State shape (deterministic, append-only where appropriate):
state["notify"] = {
  "subs_by_account": { "<acct>": {"topics": [...], "updated_at_nonce": n } },
  "emit_receipts": [ {"at_nonce": n, "payload": {...}} ],
}

IMPORTANT:
- This module is safe to use once the monolith delegates to it.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


@dataclass
class NotificationApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise NotificationApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_notify_root(state: Json) -> Json:
    n = state.get("notify")
    if not isinstance(n, dict):
        n = {}
        state["notify"] = n

    subs = n.get("subs_by_account")
    if not isinstance(subs, dict):
        subs = {}
        n["subs_by_account"] = subs

    receipts = n.get("emit_receipts")
    if not isinstance(receipts, list):
        receipts = []
        n["emit_receipts"] = receipts

    return n


def _normalize_topics(raw: Any) -> List[str]:
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    items = _as_list(raw)
    out: List[str] = []
    for it in items:
        if isinstance(it, str) and it.strip():
            out.append(it.strip())
    # stable ordering
    return sorted(set(out))


def _apply_notification_subscribe(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)

    # Accept either "topic" or "topics" (future-friendly)
    topics = _normalize_topics(payload.get("topics") if "topics" in payload else payload.get("topic"))
    if not topics:
        raise NotificationApplyError("invalid_payload", "missing_topic", {"tx_type": env.tx_type})

    n = _ensure_notify_root(state)
    subs_by = n["subs_by_account"]

    cur = subs_by.get(env.signer)
    if not isinstance(cur, dict):
        cur = {"topics": []}

    cur_topics = _normalize_topics(cur.get("topics"))
    merged = sorted(set(cur_topics).union(set(topics)))

    cur["topics"] = merged
    cur["updated_at_nonce"] = int(env.nonce)
    subs_by[env.signer] = cur

    return {"applied": "NOTIFICATION_SUBSCRIBE", "account": env.signer, "topics": topics}


def _apply_notification_unsubscribe(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    topics = _normalize_topics(payload.get("topics") if "topics" in payload else payload.get("topic"))
    if not topics:
        raise NotificationApplyError("invalid_payload", "missing_topic", {"tx_type": env.tx_type})

    n = _ensure_notify_root(state)
    subs_by = n["subs_by_account"]

    cur = subs_by.get(env.signer)
    if not isinstance(cur, dict):
        cur = {"topics": []}

    cur_topics = _normalize_topics(cur.get("topics"))
    remaining = sorted(set([t for t in cur_topics if t not in set(topics)]))

    cur["topics"] = remaining
    cur["updated_at_nonce"] = int(env.nonce)
    subs_by[env.signer] = cur

    return {"applied": "NOTIFICATION_UNSUBSCRIBE", "account": env.signer, "topics": topics}


def _apply_notification_emit_receipt(state: Json, env: TxEnvelope) -> Json:
    # receipt_only + system_only in canon (parent enforced by admission layer)
    _require_system_env(env)
    payload = _as_dict(env.payload)

    n = _ensure_notify_root(state)
    n["emit_receipts"].append({"at_nonce": int(env.nonce), "payload": payload})

    return {"applied": "NOTIFICATION_EMIT_RECEIPT"}


NOTIFICATION_TX_TYPES: Set[str] = {
    "NOTIFICATION_SUBSCRIBE",
    "NOTIFICATION_UNSUBSCRIBE",
    "NOTIFICATION_EMIT_RECEIPT",
}


def apply_notifications(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = str(env.tx_type or "").strip()
    if t not in NOTIFICATION_TX_TYPES:
        return None

    if t == "NOTIFICATION_SUBSCRIBE":
        return _apply_notification_subscribe(state, env)
    if t == "NOTIFICATION_UNSUBSCRIBE":
        return _apply_notification_unsubscribe(state, env)
    if t == "NOTIFICATION_EMIT_RECEIPT":
        return _apply_notification_emit_receipt(state, env)

    return None
