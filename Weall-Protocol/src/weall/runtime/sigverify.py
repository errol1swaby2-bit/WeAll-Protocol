from __future__ import annotations

import os
from typing import Any

from weall.crypto.sig import (
    canonical_tx_message,
    strict_tx_sig_domain_enabled,
    verify_signature_for_profile,
)
from weall.crypto.signature_profiles import (
    LEGACY_ED25519_V1,
    PQ_MLDSA_V1,
    mode_requires_explicit_sig_profile,
    normalize_signature_profile_id,
    profile_allowed_for_context,
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


def _extract_active_keys(acct: Any, *, sig_profile: str = "") -> list[str]:
    """Extract active profile-aware pubkeys from a signer account record."""
    if not isinstance(acct, dict):
        return []

    wanted = normalize_signature_profile_id(sig_profile)
    out: list[str] = []
    seen: set[str] = set()

    # Legacy compatibility fields. These are ignored in strict PQ profile mode.
    if not wanted or wanted == LEGACY_ED25519_V1:
        active_keys = acct.get("active_keys")
        if isinstance(active_keys, list):
            for pk in active_keys:
                _add_pubkey(out, seen, pk)
        _add_pubkey(out, seen, acct.get("pubkey"))

    keys = acct.get("keys")
    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                if not wanted or wanted == LEGACY_ED25519_V1:
                    _add_pubkey(out, seen, item)
                continue
            if not isinstance(item, dict):
                continue
            if item.get("active", True) is False:
                continue
            rec_profile = normalize_signature_profile_id(item.get("sig_profile"))
            if wanted and rec_profile and rec_profile != wanted:
                continue
            if rec_profile == PQ_MLDSA_V1:
                pubkeys = item.get("pubkeys") if isinstance(item.get("pubkeys"), dict) else {}
                _add_pubkey(out, seen, pubkeys.get("mldsa"))
            else:
                _add_pubkey(out, seen, item.get("pubkey"))

    elif isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for _kid, rec in by_id.items():
                if not isinstance(rec, dict):
                    continue
                if bool(rec.get("revoked", False)) is True:
                    continue
                rec_profile = normalize_signature_profile_id(rec.get("sig_profile"))
                if wanted and rec_profile and rec_profile != wanted:
                    continue
                if rec_profile == PQ_MLDSA_V1:
                    pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
                    _add_pubkey(out, seen, pubkeys.get("mldsa"))
                else:
                    _add_pubkey(out, seen, rec.get("pubkey"))
            return out

        if not wanted or wanted == LEGACY_ED25519_V1:
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

    raw_signature = tx.get("signature") if isinstance(tx.get("signature"), dict) else {}
    sig = raw_signature.get("sig") or tx.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        return False

    sig_profile = normalize_signature_profile_id(tx.get("sig_profile"))
    if not sig_profile:
        if mode_requires_explicit_sig_profile():
            return False
        sig_profile = LEGACY_ED25519_V1

    chain_config = state.get("chain_config") if isinstance(state.get("chain_config"), dict) else None
    ok_profile, _reason_profile = profile_allowed_for_context(
        sig_profile,
        chain_config=chain_config,
        require_verifier=False,
    )
    if not ok_profile:
        return False

    active_keys = _extract_active_keys(acct, sig_profile=sig_profile)

    expected_chain_id = _expected_chain_id(state)
    tx_chain_id = tx.get("chain_id")
    tx_chain_id2 = str(tx_chain_id).strip() if isinstance(tx_chain_id, str) else ""
    network_id = str(tx.get("network_id") or state.get("network_id") or "").strip()
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
                    network_id=network_id,
                    sig_profile=sig_profile,
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
                    sig_profile=sig_profile,
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
                    if verify_signature_for_profile(sig_profile=sig_profile, message=msg, sig=sig, pubkey=pk):
                        return True
        return _unsafe_dev_allows_unsigned()

    for pk in active_keys:
        for msg in msg_candidates:
            if verify_signature_for_profile(sig_profile=sig_profile, message=msg, sig=sig, pubkey=pk):
                return True

    return False
