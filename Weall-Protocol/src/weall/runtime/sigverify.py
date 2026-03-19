from __future__ import annotations

import os
from typing import Any

from weall.crypto.sig import (
    canonical_tx_message,
    strict_tx_sig_domain_enabled,
    verify_ed25519_signature,
)

Json = dict[str, Any]


def _add_pubkey(out: list[str], seen: set[str], pk: Any) -> None:
    """Add a pubkey to out (deduped) if it's a non-empty string."""
    if not isinstance(pk, str):
        return
    pk2 = pk.strip()
    if not pk2 or pk2 in seen:
        return
    seen.add(pk2)
    out.append(pk2)


def _extract_active_keys(acct: Any) -> list[str]:
    """Extract active pubkeys from a signer account record."""
    if not isinstance(acct, dict):
        return []

    out: list[str] = []
    seen: set[str] = set()

    active_keys = acct.get("active_keys")
    if isinstance(active_keys, list):
        for pk in active_keys:
            _add_pubkey(out, seen, pk)

    _add_pubkey(out, seen, acct.get("pubkey"))

    keys = acct.get("keys")
    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                _add_pubkey(out, seen, item)
                continue
            if not isinstance(item, dict):
                continue
            if item.get("active", True) is False:
                continue
            _add_pubkey(out, seen, item.get("pubkey"))

    elif isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for _kid, rec in by_id.items():
                if not isinstance(rec, dict):
                    continue
                if bool(rec.get("revoked", False)) is True:
                    continue
                _add_pubkey(out, seen, rec.get("pubkey"))
            return out

        for pk, rec in keys.items():
            if not isinstance(pk, str) or not pk.strip():
                continue
            if isinstance(rec, dict):
                if bool(rec.get("active", False)):
                    _add_pubkey(out, seen, pk)
            else:
                _add_pubkey(out, seen, pk)

    return out


def _unsafe_dev_allows_unsigned() -> bool:
    mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
    unsafe = (os.environ.get("WEALL_UNSAFE_DEV") or "").strip()
    return bool(mode == "testnet" and unsafe == "1")


def _expected_chain_id(state: Json) -> str:
    if not isinstance(state, dict):
        return ""
    chain_id = state.get("chain_id")
    if isinstance(chain_id, str) and chain_id.strip():
        return chain_id.strip()
    params = state.get("params")
    if isinstance(params, dict):
        p = params.get("chain_id")
        if isinstance(p, str) and p.strip():
            return p.strip()
    return ""


def verify_tx_signature(state: Json, tx: Json) -> bool:
    """Verify tx signature against active keys for the signer.

    Production default is fail-closed on the tx replay domain:
      - tx.chain_id must be present
      - tx.chain_id must match the local/state chain_id when known
      - only the chain-bound signature payload is accepted

    Legacy no-chain-id signatures remain available only when explicitly allowed
    through WEALL_ALLOW_LEGACY_SIG_DOMAIN=1 (default outside prod).
    """
    if not isinstance(tx, dict):
        return False

    signer = tx.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        return False

    params = state.get("params") if isinstance(state, dict) else None
    if not isinstance(params, dict):
        params = {}

    require_sigs = bool(params.get("require_signatures", params.get("require_sigs", True)))
    if not require_sigs:
        return True

    accounts = state.get("accounts") if isinstance(state, dict) else None
    acct: dict[str, Any] = {}
    if isinstance(accounts, dict):
        maybe = accounts.get(signer)
        if isinstance(maybe, dict):
            acct = maybe

    active_keys = _extract_active_keys(acct)

    sig = tx.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        return False

    expected_chain_id = _expected_chain_id(state)
    tx_chain_id = tx.get("chain_id")
    tx_chain_id2 = str(tx_chain_id).strip() if isinstance(tx_chain_id, str) else ""
    strict_domain = strict_tx_sig_domain_enabled()

    if strict_domain:
        if not tx_chain_id2:
            return False
        if expected_chain_id and tx_chain_id2 != expected_chain_id:
            return False

    msg_candidates: list[bytes] = []
    try:
        if tx_chain_id2:
            msg_candidates.append(
                canonical_tx_message(
                    chain_id=tx_chain_id2,
                    tx_type=tx.get("tx_type"),
                    signer=signer,
                    nonce=tx.get("nonce"),
                    payload=tx.get("payload"),
                    parent=tx.get("parent"),
                )
            )
    except Exception:
        pass

    if not strict_domain:
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

    if not msg_candidates:
        return False

    if not active_keys:
        tx_type = str(tx.get("tx_type") or tx.get("type") or "").strip().upper()
        if tx_type == "ACCOUNT_REGISTER":
            payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
            pk = payload.get("pubkey")
            if isinstance(pk, str) and pk.strip():
                for msg in msg_candidates:
                    if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
                        return True
        return _unsafe_dev_allows_unsigned()

    for pk in active_keys:
        for msg in msg_candidates:
            if verify_ed25519_signature(message=msg, sig=sig, pubkey=pk):
                return True

    return False
