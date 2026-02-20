# src/weall/runtime/apply/messaging.py
from __future__ import annotations

"""
Messaging domain apply semantics (production-ready; canon-correct).

Canon Messaging txs (v1.22.1) = 2:
- DIRECT_MESSAGE_SEND (USER, mempool, gate Tier1+)
- DIRECT_MESSAGE_REDACT (USER, mempool, gate Tier1+)

Design goals:
- Deterministic state transitions
- Fail-closed on missing critical identifiers
- Redaction is enforced: only sender can redact their message
- Store enough structure for UI: inboxes, threads, message index

State shape (deterministic):
ledger["messaging"] = {
  "threads_by_id": {
      "<thread_id>": {
          "thread_id": str,
          "members": [acctA, acctB] (sorted unique),
          "created_at_nonce": int,
          "last_message_at_nonce": int,
          "last_message_id": str,
          "message_ids": [str, ...],        # append-only
      }
  },
  "messages_by_id": {
      "<message_id>": {
          "message_id": str,
          "thread_id": str,
          "sender": str,
          "to": str,
          "body": str,                      # optional if cid provided
          "cid": str,                       # optional (ipfs)
          "created_at_nonce": int,
          "redacted": bool,
          "redacted_at_nonce": int,
          "redact_reason": str,
          "payload": {...},
      }
  },
  "inbox_by_account": {
      "<acct>": {
          "threads": [thread_id, ...],      # sorted unique
          "messages": [message_id, ...],    # append-only (optional convenience index)
          "last_nonce": int,
      }
  }
}

Payload expectations (runtime enforced, since canon does not define schemas):
- DIRECT_MESSAGE_SEND requires:
  - recipient: one of ["to", "recipient", "to_account", "account_id"]
  - content: "body" (string) OR "cid" (string)
  - optional: "thread_id", "message_id"
- DIRECT_MESSAGE_REDACT requires:
  - "message_id" (or "id")
  - optional: "reason"
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@dataclass
class MessagingApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_messaging(state: Json) -> Json:
    m = _ensure_root_dict(state, "messaging")
    if not isinstance(m.get("threads_by_id"), dict):
        m["threads_by_id"] = {}
    if not isinstance(m.get("messages_by_id"), dict):
        m["messages_by_id"] = {}
    if not isinstance(m.get("inbox_by_account"), dict):
        m["inbox_by_account"] = {}
    return m


def _mk_id(prefix: str, env: TxEnvelope, provided: Any) -> str:
    p = _as_str(provided).strip()
    if p:
        return p
    return f"{prefix}:{env.signer}:{int(getattr(env, 'nonce', 0) or 0)}"


def _pick(payload: Json, *keys: str) -> str:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _sorted_unique_strs(items: List[Any]) -> List[str]:
    out: List[str] = []
    for it in items:
        if isinstance(it, str) and it.strip():
            out.append(it.strip())
    return sorted(set(out))


def _thread_id_default(a: str, b: str) -> str:
    # Deterministic thread id for 1:1 threads when caller doesn't provide one.
    # Uses sorted member pair so both sides converge.
    aa = a.strip()
    bb = b.strip()
    pair = sorted([aa, bb])
    return f"dm:{pair[0]}:{pair[1]}"


def _ensure_inbox(m: Json, acct: str) -> Json:
    inbox = m["inbox_by_account"].get(acct)
    if not isinstance(inbox, dict):
        inbox = {"threads": [], "messages": [], "last_nonce": 0}
        m["inbox_by_account"][acct] = inbox
    if not isinstance(inbox.get("threads"), list):
        inbox["threads"] = []
    if not isinstance(inbox.get("messages"), list):
        inbox["messages"] = []
    return inbox


def _ensure_thread(m: Json, thread_id: str, members: List[str], at_nonce: int) -> Json:
    threads = m["threads_by_id"]
    rec = threads.get(thread_id)
    if not isinstance(rec, dict):
        rec = {
            "thread_id": thread_id,
            "members": _sorted_unique_strs(members),
            "created_at_nonce": int(at_nonce),
            "last_message_at_nonce": 0,
            "last_message_id": "",
            "message_ids": [],
        }
        threads[thread_id] = rec
    # normalize
    if not isinstance(rec.get("members"), list):
        rec["members"] = _sorted_unique_strs(members)
    if not isinstance(rec.get("message_ids"), list):
        rec["message_ids"] = []
    # ensure members include both (safe)
    rec["members"] = _sorted_unique_strs(list(rec["members"]) + members)
    return rec


# ---------------------------------------------------------------------------
# DIRECT_MESSAGE_SEND
# ---------------------------------------------------------------------------

def _apply_direct_message_send(state: Json, env: TxEnvelope) -> Json:
    m = _ensure_messaging(state)
    payload = _as_dict(env.payload)

    sender = env.signer
    to = _pick(payload, "to", "recipient", "to_account", "account_id")
    if not to:
        raise MessagingApplyError("invalid_payload", "missing_recipient", {"tx_type": env.tx_type})

    body = _as_str(payload.get("body"))
    cid = _pick(payload, "cid", "content_cid", "ipfs_cid")
    if not body and not cid:
        raise MessagingApplyError("invalid_payload", "missing_body_or_cid", {"tx_type": env.tx_type})

    # thread_id is optional; deterministic default for 1:1
    thread_id = _pick(payload, "thread_id")
    if not thread_id:
        thread_id = _thread_id_default(sender, to)

    message_id = _mk_id("dm", env, payload.get("message_id") or payload.get("id"))

    messages = m["messages_by_id"]
    existing = messages.get(message_id)
    already = isinstance(existing, dict)

    if not already:
        # ensure thread exists
        thread = _ensure_thread(m, thread_id, [sender, to], int(env.nonce))

        # append message id to thread (append-only; idempotent)
        mids = thread.get("message_ids")
        if not isinstance(mids, list):
            mids = []
        if message_id not in mids:
            mids.append(message_id)
        thread["message_ids"] = mids
        thread["last_message_id"] = message_id
        thread["last_message_at_nonce"] = int(env.nonce)
        m["threads_by_id"][thread_id] = thread

        # write message
        messages[message_id] = {
            "message_id": message_id,
            "thread_id": thread_id,
            "sender": sender,
            "to": to,
            "body": body,
            "cid": cid,
            "created_at_nonce": int(env.nonce),
            "redacted": False,
            "redacted_at_nonce": 0,
            "redact_reason": "",
            "payload": payload,
        }

        # update inboxes
        for acct in (sender, to):
            inbox = _ensure_inbox(m, acct)
            threads = inbox.get("threads")
            if not isinstance(threads, list):
                threads = []
            if thread_id not in threads:
                threads.append(thread_id)
                inbox["threads"] = _sorted_unique_strs(threads)

            msgs = inbox.get("messages")
            if not isinstance(msgs, list):
                msgs = []
            msgs.append(message_id)  # append-only convenience index
            inbox["messages"] = msgs
            inbox["last_nonce"] = max(_as_int(inbox.get("last_nonce"), 0), int(env.nonce))
            m["inbox_by_account"][acct] = inbox

    return {
        "applied": "DIRECT_MESSAGE_SEND",
        "message_id": message_id,
        "thread_id": thread_id,
        "to": to,
        "deduped": already,
    }


# ---------------------------------------------------------------------------
# DIRECT_MESSAGE_REDACT
# ---------------------------------------------------------------------------

def _apply_direct_message_redact(state: Json, env: TxEnvelope) -> Json:
    m = _ensure_messaging(state)
    payload = _as_dict(env.payload)

    message_id = _pick(payload, "message_id", "id")
    if not message_id:
        raise MessagingApplyError("invalid_payload", "missing_message_id", {"tx_type": env.tx_type})

    messages = m["messages_by_id"]
    rec = messages.get(message_id)
    if not isinstance(rec, dict):
        raise MessagingApplyError("not_found", "message_not_found", {"message_id": message_id})

    if _as_str(rec.get("sender")) != env.signer:
        raise MessagingApplyError("forbidden", "only_sender_can_redact", {"message_id": message_id})

    already = bool(rec.get("redacted")) and _as_int(rec.get("redacted_at_nonce"), 0) == int(env.nonce)

    rec["redacted"] = True
    rec["redacted_at_nonce"] = int(env.nonce)
    reason = _as_str(payload.get("reason")).strip()
    if reason:
        rec["redact_reason"] = reason

    # For privacy, wipe body on redact; keep cid only if you want (here we wipe both)
    rec["body"] = ""
    rec["cid"] = ""

    # retain raw payload for traceability
    rec["redact_payload"] = payload
    messages[message_id] = rec

    return {"applied": "DIRECT_MESSAGE_REDACT", "message_id": message_id, "deduped": already}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

MESSAGING_TX_TYPES: Set[str] = {
    "DIRECT_MESSAGE_SEND",
    "DIRECT_MESSAGE_REDACT",
}


def apply_messaging(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply Messaging txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in MESSAGING_TX_TYPES:
        return None

    if t == "DIRECT_MESSAGE_SEND":
        return _apply_direct_message_send(state, env)
    if t == "DIRECT_MESSAGE_REDACT":
        return _apply_direct_message_redact(state, env)

    return None
