# File: src/weall/runtime/sigverify.py
from __future__ import annotations

import os
from typing import Any, Dict, List

from weall.crypto.sig import canonical_tx_message, verify_ed25519_signature

Json = Dict[str, Any]


def _add_pubkey(out: List[str], seen: set[str], pk: Any) -> None:
    """Add a pubkey to out (deduped) if it's a non-empty string."""
    if not isinstance(pk, str):
        return
    pk2 = pk.strip()
    if not pk2 or pk2 in seen:
        return
    seen.add(pk2)
    out.append(pk2)


def _extract_active_keys(acct: Any) -> List[str]:
    """Extract active pubkeys from a signer account record.

    Supported shapes (tolerant):
      1) acct["active_keys"] = ["<pubkey>", ...]
      2) acct["keys"] = [{"pubkey": "...", "active": True}, ...]
      3) acct["keys"] = {"<pubkey>": {"active": True, ...}, ...}
      4) acct["keys"] = ["<pubkey>", ...]   (treated as active)
      5) acct["pubkey"] = "<pubkey>"        (treated as active)
      6) acct["keys"] = {"by_id": {"k:...": {"pubkey": "...", "revoked": False, ...}, ...}}
         (the canonical on-chain shape produced by identity.apply ACCOUNT_REGISTER)
    """
    if not isinstance(acct, dict):
        return []

    out: List[str] = []
    seen: set[str] = set()

    # (1) active_keys list
    active_keys = acct.get("active_keys")
    if isinstance(active_keys, list):
        for pk in active_keys:
            _add_pubkey(out, seen, pk)

    # (5) single pubkey fallback
    _add_pubkey(out, seen, acct.get("pubkey"))

    keys = acct.get("keys")

    # (2) list of records OR list of strings
    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                _add_pubkey(out, seen, item)
                continue
            if not isinstance(item, dict):
                continue
            # default to active unless explicitly False
            if item.get("active", True) is False:
                continue
            _add_pubkey(out, seen, item.get("pubkey"))

    # (3) dict keyed by pubkey OR (6) canonical keys.by_id mapping
    elif isinstance(keys, dict):
        # (6) canonical: {"by_id": {key_id: {"pubkey": "...", "revoked": False}}}
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for _kid, rec in by_id.items():
                if not isinstance(rec, dict):
                    continue
                if bool(rec.get("revoked", False)) is True:
                    continue
                _add_pubkey(out, seen, rec.get("pubkey"))
            return out

        # (3) dict keyed by pubkey
        for pk, rec in keys.items():
            if not isinstance(pk, str) or not pk.strip():
                continue
            if isinstance(rec, dict):
                if bool(rec.get("active", False)):
                    _add_pubkey(out, seen, pk)
            else:
                # tolerate odd shapes by treating presence as active
                _add_pubkey(out, seen, pk)

    return out


def _unsafe_dev_allows_unsigned() -> bool:
    """Allow unsigned txs ONLY in explicit unsafe dev mode.

    Requirements:
      - WEALL_MODE=testnet
      - WEALL_UNSAFE_DEV=1
    """
    mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
    unsafe = (os.environ.get("WEALL_UNSAFE_DEV") or "").strip()
    return bool(mode == "testnet" and unsafe == "1")


def verify_tx_signature(state: Json, tx: Json) -> bool:
    """Verify tx signature against active keys for the signer.

    Policy:
      - If protocol params disable signatures (require_signatures=False), return True.
      - If signer has active keys: signature must verify against one active key.
      - If signer has no active keys: fail-closed (unless require_signatures is False).

    NOTE: This function is pure (no I/O).
    """
    if not isinstance(tx, dict):
        return False

    signer = tx.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        return False

    params = state.get("params") if isinstance(state, dict) else None
    if not isinstance(params, dict):
        params = {}

    # Protocol flag: default is True (require signatures)
    require_sigs = bool(params.get("require_signatures", params.get("require_sigs", True)))
    if not require_sigs:
        return True

    accounts = state.get("accounts") if isinstance(state, dict) else None
    acct: Dict[str, Any] = {}
    if isinstance(accounts, dict):
        maybe = accounts.get(signer)
        if isinstance(maybe, dict):
            acct = maybe

    active_keys = _extract_active_keys(acct)

    sig = tx.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        # If there are active keys and signatures are required, missing sig is invalid.
        # If there are no keys, still fail-closed (require_sigs True).
        return False

    # NOTE: Back-compat with older clients:
    #  - legacy message excludes chain_id
    #  - newer web client includes chain_id as replay-domain separator
    chain_id = tx.get("chain_id")

    msg_candidates: List[bytes] = []
    try:
        msg_candidates.append(
            canonical_tx_message(
                chain_id=str(chain_id) if isinstance(chain_id, str) else None,
                tx_type=tx.get("tx_type"),
                signer=signer,
                nonce=tx.get("nonce"),
                payload=tx.get("payload"),
                parent=tx.get("parent"),
            )
        )
    except Exception:
        pass

    try:
        msg_candidates.append(
            canonical_tx_message(
                tx_type=tx.get("tx_type"),
                signer=signer,
                nonce=tx.get("nonce"),
                payload=tx.get("payload"),
                parent=tx.get("parent"),
            )
        )
    except Exception:
        pass

    # Fail-closed: if canonicalization fails, reject.
    if not msg_candidates:
        return False

    # If there are no keys, fail closed in prod (do NOT allow unsigned by default).
    if not active_keys:
        tx_type = str(tx.get("tx_type") or tx.get("type") or "").strip().upper()

        # Special case: bootstrap ACCOUNT_REGISTER (sign against payload pubkey)
        if tx_type == "ACCOUNT_REGISTER":
            payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
            pk = payload.get("pubkey")

            if isinstance(pk, str) and pk.strip():
                for msg in msg_candidates:
                    if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
                        return True

        # Otherwise fail closed (or allow only if explicitly unsafe dev)
        return _unsafe_dev_allows_unsigned()

    for pk in active_keys:
        for msg in msg_candidates:
            if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
                return True

    return False
