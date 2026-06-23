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
          "body": "",                       # plaintext is forbidden for DMs
          "cid": "",                        # plaintext content CIDs are forbidden for DMs
          "encrypted": True,
          "encryption": {...},              # client E2EE envelope only
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
  - encrypted client envelope: encryption=WEALL_E2EE_V1, ciphertext_b64, iv_b64,
    sender/recipient encryption public JWKs and key ids
  - plaintext "body" and plaintext content "cid" are rejected
  - optional: "thread_id", "message_id"
- DIRECT_MESSAGE_REDACT requires:
  - "message_id" (or "id")
  - optional: "reason"
"""

from dataclasses import dataclass
from typing import Any

from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


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


def _as_list(x: Any) -> list[Any]:
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


def _sorted_unique_strs(items: list[Any]) -> list[str]:
    out: list[str] = []
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




def _validate_public_jwk(value: Any, field: str) -> Json:
    jwk = _as_dict(value)
    if not jwk:
        raise MessagingApplyError("invalid_payload", f"missing_{field}", {"field": field})
    kty = _as_str(jwk.get("kty")).strip()
    crv = _as_str(jwk.get("crv")).strip()
    x = _as_str(jwk.get("x")).strip()
    if kty != "EC" or crv != "P-256" or not x:
        raise MessagingApplyError("invalid_payload", f"invalid_{field}", {"kty": kty, "crv": crv})
    # Keep only public, deterministic fields.  Never accept d/private material.
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": _as_str(jwk.get("y")).strip(),
        "ext": True,
    }


def _same_public_jwk(a: Any, b: Any) -> bool:
    aa = _as_dict(a)
    bb = _as_dict(b)
    return {
        "kty": _as_str(aa.get("kty")).strip(),
        "crv": _as_str(aa.get("crv")).strip(),
        "x": _as_str(aa.get("x")).strip(),
        "y": _as_str(aa.get("y")).strip(),
    } == {
        "kty": _as_str(bb.get("kty")).strip(),
        "crv": _as_str(bb.get("crv")).strip(),
        "x": _as_str(bb.get("x")).strip(),
        "y": _as_str(bb.get("y")).strip(),
    }


def _messaging_policy_for_account(state: Json, account: str) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return {}
    acct = accounts.get(account)
    if not isinstance(acct, dict):
        return {}
    return _as_dict(acct.get("security_policy"))


def _enforce_envelope_matches_account_keys(state: Json, *, sender: str, to: str, encrypted: Json) -> None:
    # Consensus-critical trust boundary: when account records are present, the
    # DM envelope must use the public messaging keys currently published by the
    # sender and recipient accounts.  This prevents a client, relay, stale node,
    # or compromised UI from silently substituting an arbitrary recipient key
    # while still submitting a canon-valid encrypted envelope.
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return

    sender_policy = _messaging_policy_for_account(state, sender)
    recipient_policy = _messaging_policy_for_account(state, to)
    sender_key_id = _as_str(sender_policy.get("messaging_encryption_key_id") or "").strip()
    recipient_key_id = _as_str(recipient_policy.get("messaging_encryption_key_id") or "").strip()
    if not sender_key_id:
        raise MessagingApplyError("invalid_payload", "sender_missing_messaging_encryption_key", {"account": sender})
    if not recipient_key_id:
        raise MessagingApplyError("invalid_payload", "recipient_missing_messaging_encryption_key", {"account": to})

    if _as_str(encrypted.get("sender_encryption_key_id") or "").strip() != sender_key_id:
        raise MessagingApplyError("invalid_payload", "sender_messaging_encryption_key_mismatch", {"account": sender})
    if _as_str(encrypted.get("recipient_encryption_key_id") or "").strip() != recipient_key_id:
        raise MessagingApplyError("invalid_payload", "recipient_messaging_encryption_key_mismatch", {"account": to})
    if not _same_public_jwk(encrypted.get("sender_encryption_public_jwk"), sender_policy.get("messaging_encryption_public_jwk")):
        raise MessagingApplyError("invalid_payload", "sender_messaging_encryption_public_key_mismatch", {"account": sender})
    if not _same_public_jwk(encrypted.get("recipient_encryption_public_jwk"), recipient_policy.get("messaging_encryption_public_jwk")):
        raise MessagingApplyError("invalid_payload", "recipient_messaging_encryption_public_key_mismatch", {"account": to})


def _encrypted_envelope(payload: Json) -> Json:
    if _as_str(payload.get("body")).strip():
        raise MessagingApplyError("invalid_payload", "plaintext_body_forbidden", {"tx_type": "DIRECT_MESSAGE_SEND"})
    if _pick(payload, "cid", "content_cid", "ipfs_cid"):
        raise MessagingApplyError("invalid_payload", "plaintext_cid_forbidden", {"tx_type": "DIRECT_MESSAGE_SEND"})

    scheme = _as_str(payload.get("encryption")).strip()
    if scheme != "WEALL_E2EE_V1":
        raise MessagingApplyError("invalid_payload", "e2ee_required", {"expected": "WEALL_E2EE_V1"})

    ciphertext_b64 = _as_str(payload.get("ciphertext_b64")).strip()
    iv_b64 = _as_str(payload.get("iv_b64")).strip()
    sender_key_id = _as_str(payload.get("sender_encryption_key_id")).strip()
    recipient_key_id = _as_str(payload.get("recipient_encryption_key_id")).strip()
    if not ciphertext_b64 or not iv_b64 or not sender_key_id or not recipient_key_id:
        raise MessagingApplyError("invalid_payload", "missing_encrypted_message_fields", {})
    if len(ciphertext_b64) > 262144:
        raise MessagingApplyError("invalid_payload", "ciphertext_too_large", {"max_b64_bytes": 262144})

    return {
        "scheme": scheme,
        "ciphertext_b64": ciphertext_b64,
        "iv_b64": iv_b64,
        "aad_b64": _as_str(payload.get("aad_b64")).strip(),
        "sender_encryption_key_id": sender_key_id,
        "recipient_encryption_key_id": recipient_key_id,
        "sender_encryption_public_jwk": _validate_public_jwk(payload.get("sender_encryption_public_jwk"), "sender_encryption_public_jwk"),
        "recipient_encryption_public_jwk": _validate_public_jwk(payload.get("recipient_encryption_public_jwk"), "recipient_encryption_public_jwk"),
    }

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


def _ensure_thread(m: Json, thread_id: str, members: list[str], at_nonce: int) -> Json:
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

    encrypted = _encrypted_envelope(payload)
    _enforce_envelope_matches_account_keys(state, sender=sender, to=to, encrypted=encrypted)

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

        # write encrypted message envelope only; plaintext never enters consensus state.
        messages[message_id] = {
            "message_id": message_id,
            "thread_id": thread_id,
            "sender": sender,
            "to": to,
            "body": "",
            "cid": "",
            "encrypted": True,
            "encryption": encrypted,
            "created_at_nonce": int(env.nonce),
            "redacted": False,
            "redacted_at_nonce": 0,
            "redact_reason": "",
            "payload": {
                "to": to,
                "thread_id": thread_id,
                "message_id": message_id,
                "encryption": encrypted["scheme"],
                "sender_encryption_key_id": encrypted["sender_encryption_key_id"],
                "recipient_encryption_key_id": encrypted["recipient_encryption_key_id"],
            },
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

    already = bool(rec.get("redacted")) and _as_int(rec.get("redacted_at_nonce"), 0) == int(
        env.nonce
    )

    rec["redacted"] = True
    rec["redacted_at_nonce"] = int(env.nonce)
    reason = _as_str(payload.get("reason")).strip()
    if reason:
        rec["redact_reason"] = reason

    # For privacy, wipe visible and encrypted content on redact.
    rec["body"] = ""
    rec["cid"] = ""
    rec["encrypted"] = False
    rec["encryption"] = {}

    # retain raw payload for traceability
    rec["redact_payload"] = payload
    messages[message_id] = rec

    return {"applied": "DIRECT_MESSAGE_REDACT", "message_id": message_id, "deduped": already}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

MESSAGING_TX_TYPES: set[str] = {
    "DIRECT_MESSAGE_SEND",
    "DIRECT_MESSAGE_REDACT",
}


def apply_messaging(state: Json, env: TxEnvelope) -> Json | None:
    """Reject legacy messaging txs deterministically.

    This direct module guard protects test harnesses, migrations, and any future
    dispatcher changes that might bypass the shared public_protocol_policy check.
    """
    t = str(env.tx_type or "").strip().upper()
    if t not in MESSAGING_TX_TYPES:
        return None
    raise MessagingApplyError(
        "PRIVATE_MESSAGING_UNSUPPORTED",
        "protocol_native_direct_messages_are_unsupported",
        {"tx_type": t},
    )
