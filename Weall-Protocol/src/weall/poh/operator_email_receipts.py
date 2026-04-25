from __future__ import annotations

import json
import os
import time
from typing import Any

from weall.crypto.sig import verify_ed25519_signature
from weall.runtime.reputation_units import account_reputation_units

Json = dict[str, Any]

RECEIPT_VERSION = 1
RECEIPT_KIND = "poh_email_tier1"
RELAY_TOKEN_VERSION = 1
RELAY_TOKEN_KIND = "email_challenge_completed"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _as_str(v: Any) -> str:
    try:
        return str(v).strip()
    except Exception:
        return ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def canonical_relay_token_payload(payload: Json) -> Json:
    return {
        "version": int(payload.get("version") or RELAY_TOKEN_VERSION),
        "type": _as_str(payload.get("type") or RELAY_TOKEN_KIND),
        "chain_id": _as_str(payload.get("chain_id") or ""),
        "challenge_id": _as_str(payload.get("challenge_id") or ""),
        "account_id": _as_str(payload.get("account_id") or ""),
        "operator_account_id": _as_str(payload.get("operator_account_id") or ""),
        "email_commitment": _as_str(payload.get("email_commitment") or ""),
        "issued_at_ms": _as_int(payload.get("issued_at_ms"), 0),
        "expires_at_ms": _as_int(payload.get("expires_at_ms"), 0),
        "relay_account_id": _as_str(payload.get("relay_account_id") or ""),
        "relay_pubkey": _as_str(payload.get("relay_pubkey") or ""),
    }


def canonical_relay_token_message(payload: Json) -> bytes:
    raw = json.dumps(canonical_relay_token_payload(payload), separators=(",", ":"), sort_keys=True)
    return raw.encode("utf-8")


def canonical_receipt_payload(receipt: Json) -> Json:
    return {
        "version": int(receipt.get("version") or RECEIPT_VERSION),
        "kind": _as_str(receipt.get("kind") or RECEIPT_KIND),
        "chain_id": _as_str(receipt.get("chain_id") or ""),
        "worker_account_id": _as_str(receipt.get("worker_account_id") or ""),
        "worker_pubkey": _as_str(receipt.get("worker_pubkey") or ""),
        "subject_account_id": _as_str(receipt.get("subject_account_id") or ""),
        "email_commitment": _as_str(receipt.get("email_commitment") or ""),
        "request_id": _as_str(receipt.get("request_id") or ""),
        "nonce": _as_str(receipt.get("nonce") or ""),
        "issued_at_ms": _as_int(receipt.get("issued_at_ms"), 0),
        "expires_at_ms": _as_int(receipt.get("expires_at_ms"), 0),
    }


def canonical_receipt_message(receipt: Json) -> bytes:
    raw = json.dumps(canonical_receipt_payload(receipt), separators=(",", ":"), sort_keys=True)
    return raw.encode("utf-8")


def _account_has_pubkey(acct: Json, pubkey: str) -> bool:
    if not pubkey:
        return False
    pk = str(pubkey).strip()
    keys = acct.get("keys")
    if isinstance(keys, dict) and pk in keys:
        return True
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for rec in by_id.values():
                if (
                    isinstance(rec, dict)
                    and str(rec.get("pubkey") or "").strip() == pk
                    and rec.get("revoked") is not True
                ):
                    return True
    if isinstance(keys, list):
        return any(str(it or "").strip() == pk for it in keys)
    return False


def _is_active_operator(state: Json, account_id: str) -> bool:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return False
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        return False
    active_set = ops.get("active_set")
    if isinstance(active_set, list) and account_id in [
        str(x).strip() for x in active_set if str(x).strip()
    ]:
        return True
    by_id = ops.get("by_id")
    if isinstance(by_id, dict):
        rec = by_id.get(account_id)
        if isinstance(rec, dict) and bool(rec.get("active")):
            return True
    return False


def _configured_relay_account_id() -> str:
    return _as_str(os.getenv("WEALL_EMAIL_RELAY_ACCOUNT_ID") or "")


def _configured_relay_pubkey() -> str:
    return _as_str(os.getenv("WEALL_EMAIL_RELAY_PUBKEY") or "")


def validate_relay_completion_token(
    relay_token: Json,
    *,
    account_id: str,
    operator_account_id: str,
    chain_id: str,
    max_ttl_ms: int = 15 * 60 * 1000,
    now_ms: int | None = None,
) -> tuple[bool, str, Json | None]:
    if not isinstance(relay_token, dict):
        return False, "relay_token_not_object", None
    payload_any = relay_token.get("payload")
    signature = _as_str(relay_token.get("signature") or "")
    if not isinstance(payload_any, dict):
        return False, "relay_payload_not_object", None
    if not signature:
        return False, "missing_relay_signature", None

    payload = canonical_relay_token_payload(payload_any)
    token_chain_id = _as_str(payload.get("chain_id") or "")
    expected_chain_id = _as_str(chain_id or "")
    challenge_id = _as_str(payload.get("challenge_id") or "")
    subject_account_id = _as_str(payload.get("account_id") or "")
    operator_account = _as_str(payload.get("operator_account_id") or "")
    email_commitment = _as_str(payload.get("email_commitment") or "")
    issued_at_ms = _as_int(payload.get("issued_at_ms"), 0)
    expires_at_ms = _as_int(payload.get("expires_at_ms"), 0)
    relay_account_id = _as_str(payload.get("relay_account_id") or "")
    relay_pubkey = _as_str(payload.get("relay_pubkey") or "")

    if int(payload.get("version") or 0) != RELAY_TOKEN_VERSION:
        return False, "bad_relay_version", None
    if _as_str(payload.get("type") or "") != RELAY_TOKEN_KIND:
        return False, "bad_relay_kind", None
    if not token_chain_id:
        return False, "missing_relay_chain_id", None
    if expected_chain_id and token_chain_id != expected_chain_id:
        return False, "relay_chain_id_mismatch", None
    if not challenge_id:
        return False, "missing_relay_challenge_id", None
    if subject_account_id != _as_str(account_id or ""):
        return False, "relay_account_mismatch", None
    if _as_str(operator_account_id or "") != operator_account:
        return False, "relay_operator_mismatch", None
    if not email_commitment:
        return False, "missing_relay_email_commitment", None
    if issued_at_ms <= 0 or expires_at_ms <= issued_at_ms:
        return False, "bad_relay_expiry_window", None
    if (expires_at_ms - issued_at_ms) > int(max_ttl_ms):
        return False, "relay_ttl_too_large", None
    now = _now_ms() if now_ms is None else int(now_ms)
    if now > expires_at_ms:
        return False, "relay_token_expired", None

    cfg_account = _configured_relay_account_id()
    cfg_pubkey = _configured_relay_pubkey()
    if not cfg_account or not cfg_pubkey:
        return False, "relay_not_configured", None
    if relay_account_id != cfg_account:
        return False, "relay_account_not_allowed", None
    if relay_pubkey != cfg_pubkey:
        return False, "relay_pubkey_not_allowed", None
    if not verify_ed25519_signature(
        message=canonical_relay_token_message(payload), sig=signature, pubkey=cfg_pubkey
    ):
        return False, "bad_relay_signature", None
    return True, "ok", payload


def validate_operator_email_receipt(
    state: Json,
    *,
    subject_account_id: str,
    receipt: Json,
    chain_id: str | None = None,
    max_ttl_ms: int = 15 * 60 * 1000,
    now_ms: int | None = None,
) -> tuple[bool, str, Json | None]:
    if not isinstance(receipt, dict):
        return False, "receipt_not_object", None
    payload = canonical_receipt_payload(receipt)
    sig = _as_str(receipt.get("signature") or "")
    relay_token = receipt.get("relay_token")
    if not sig:
        return False, "missing_signature", None
    if not isinstance(relay_token, dict):
        return False, "missing_relay_token", None
    if int(payload.get("version") or 0) != RECEIPT_VERSION:
        return False, "bad_version", None
    if _as_str(payload.get("kind") or "") != RECEIPT_KIND:
        return False, "bad_kind", None

    receipt_chain_id = _as_str(payload.get("chain_id") or "")
    expected_chain_id = _as_str(chain_id or state.get("chain_id") or "")
    if not receipt_chain_id:
        return False, "missing_chain_id", None
    if expected_chain_id and receipt_chain_id != expected_chain_id:
        return False, "chain_id_mismatch", None

    worker_account_id = _as_str(payload.get("worker_account_id") or "")
    worker_pubkey = _as_str(payload.get("worker_pubkey") or "")
    subject = _as_str(payload.get("subject_account_id") or "")
    email_commitment = _as_str(payload.get("email_commitment") or "")
    request_id = _as_str(payload.get("request_id") or "")
    nonce = _as_str(payload.get("nonce") or "")
    issued_at_ms = _as_int(payload.get("issued_at_ms"), 0)
    expires_at_ms = _as_int(payload.get("expires_at_ms"), 0)

    if not worker_account_id:
        return False, "missing_worker_account_id", None
    if not worker_pubkey:
        return False, "missing_worker_pubkey", None
    if subject != _as_str(subject_account_id or ""):
        return False, "subject_account_mismatch", None
    if not email_commitment:
        return False, "missing_email_commitment", None
    if not request_id:
        return False, "missing_request_id", None
    if not nonce:
        return False, "missing_nonce", None
    if issued_at_ms <= 0 or expires_at_ms <= issued_at_ms:
        return False, "bad_expiry_window", None
    if (expires_at_ms - issued_at_ms) > int(max_ttl_ms):
        return False, "ttl_too_large", None
    now = _now_ms() if now_ms is None else int(now_ms)
    if now > expires_at_ms:
        return False, "receipt_expired", None

    relay_ok, relay_code, relay_payload = validate_relay_completion_token(
        relay_token,
        account_id=subject_account_id,
        operator_account_id=worker_account_id,
        chain_id=expected_chain_id,
        max_ttl_ms=max_ttl_ms,
        now_ms=now,
    )
    if not relay_ok or not isinstance(relay_payload, dict):
        return False, relay_code, None
    if receipt_chain_id != _as_str(relay_payload.get("chain_id") or ""):
        return False, "relay_chain_id_mismatch", None
    if request_id != _as_str(relay_payload.get("challenge_id") or ""):
        return False, "relay_request_id_mismatch", None
    if email_commitment != _as_str(relay_payload.get("email_commitment") or ""):
        return False, "relay_email_commitment_mismatch", None
    if issued_at_ms != _as_int(relay_payload.get("issued_at_ms"), 0):
        return False, "relay_issued_at_mismatch", None
    if expires_at_ms != _as_int(relay_payload.get("expires_at_ms"), 0):
        return False, "relay_expires_at_mismatch", None
    if nonce != _as_str(relay_token.get("signature") or ""):
        return False, "relay_nonce_mismatch", None

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return False, "accounts_missing", None
    worker_acct = accounts.get(worker_account_id)
    if not isinstance(worker_acct, dict):
        return False, "worker_account_not_found", None
    if bool(worker_acct.get("banned")):
        return False, "worker_banned", None
    if bool(worker_acct.get("locked")):
        return False, "worker_locked", None
    if int(worker_acct.get("poh_tier") or 0) < 3:
        return False, "worker_not_tier3", None
    if account_reputation_units(worker_acct, default=0) <= 0:
        return False, "worker_reputation_too_low", None
    if not _account_has_pubkey(worker_acct, worker_pubkey):
        return False, "worker_pubkey_not_registered", None
    if not _is_active_operator(state, worker_account_id):
        return False, "worker_not_active_operator", None
    if not verify_ed25519_signature(
        message=canonical_receipt_message(receipt), sig=sig, pubkey=worker_pubkey
    ):
        return False, "bad_signature", None
    return True, "ok", payload
