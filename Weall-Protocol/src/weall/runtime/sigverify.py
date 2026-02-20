# src/weall/runtime/sigverify.py

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

    # (3) dict keyed by pubkey
    elif isinstance(keys, dict):
        for pk, rec in keys.items():
            # if dict is keyed by pubkey, pk should be the pubkey string
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

    msg = canonical_tx_message(
        tx_type=tx.get("tx_type"),
        signer=signer,
        nonce=tx.get("nonce"),
        payload=tx.get("payload"),
        parent=tx.get("parent"),
    )

    # If there are no keys, fail closed in prod (do NOT allow unsigned by default).
    if not active_keys:
        # Even in unsafe dev mode, a missing/invalid account key-set shouldn't magically pass:
        # only allow if you explicitly want to bypass signature checks for bootstrap.
        return _unsafe_dev_allows_unsigned()

    for pk in active_keys:
        if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
            return True

    return False
