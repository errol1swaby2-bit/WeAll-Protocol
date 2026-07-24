from __future__ import annotations

import os
from typing import Any

from weall.crypto.sig import (
    canonical_tx_message,
    strict_tx_sig_domain_enabled,
    verify_signature_for_profile,
)
from weall.crypto.signature_profiles import (
    PQ_MLDSA_V1,
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

    keys = acct.get("keys")
    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, str):
                continue
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
                # Historical genesis/bootstrap records predate explicit
                # sig_profile metadata but contain ML-DSA public keys.  Treat
                # only that missing-profile shape as the active ML-DSA profile;
                # explicit unknown or different profiles still fail closed.
                effective_profile = rec_profile or PQ_MLDSA_V1
                if wanted and effective_profile != wanted:
                    continue
                if effective_profile == PQ_MLDSA_V1:
                    pubkeys = rec.get("pubkeys") if isinstance(rec.get("pubkeys"), dict) else {}
                    _add_pubkey(out, seen, pubkeys.get("mldsa") or rec.get("pubkey"))
            return out

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

    Production default is fail-closed on the tx replay domain and pq-mldsa-v1 profile.
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
        return False

    chain_config = state.get("chain_config") if isinstance(state.get("chain_config"), dict) else None
    ok_profile, _reason_profile = profile_allowed_for_context(
        sig_profile,
        chain_config=chain_config,
        require_verifier=True,
    )
    if not ok_profile:
        return False

    active_keys = _extract_active_keys(acct, sig_profile=sig_profile)

    expected_chain_id = _expected_chain_id(state)
    tx_chain_id = tx.get("chain_id")
    tx_chain_id2 = str(tx_chain_id).strip() if isinstance(tx_chain_id, str) else ""
    network_id = str(tx.get("network_id") or state.get("network_id") or "").strip()
    strict_domain = True

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

    # Recovery authorization is purpose-limited and never falls through to an
    # ordinary active account key when independent authority is required.
    tx_type = str(tx.get("tx_type") or tx.get("type") or "").strip().upper()
    payload = tx.get("payload") if isinstance(tx.get("payload"), dict) else {}
    method = str(payload.get("method") or "").strip().lower()
    recovery = acct.get("recovery") if isinstance(acct, dict) else None
    if not isinstance(recovery, dict):
        recovery = {}

    def verifies_with(pubkey: str, profile: str | None = None) -> bool:
        wanted_profile = normalize_signature_profile_id(profile or sig_profile)
        if wanted_profile != sig_profile or not pubkey:
            return False
        return any(
            verify_signature_for_profile(
                sig_profile=sig_profile,
                message=msg,
                sig=sig,
                pubkey=pubkey,
            )
            for msg in msg_candidates
        )

    if tx_type == "ACCOUNT_RECOVERY_CONFIG_SET":
        current = recovery.get("offline_key")
        if isinstance(current, dict) and str(current.get("pubkey") or "").strip():
            if str(payload.get("authorization") or "").strip().lower() != "offline_key":
                return False
            return verifies_with(
                str(current.get("pubkey") or "").strip(),
                str(current.get("sig_profile") or sig_profile),
            )
        # Initial enrollment for legacy accounts may use the active key exactly
        # once. Subsequent rotations are handled above and cannot fall through.

    if tx_type == "ACCOUNT_RECOVERY_APPROVE" and str(payload.get("decision") or "").strip().lower() == "evidence_bind":
        request_id = str(payload.get("request_id") or "").strip()
        requests = recovery.get("requests") if isinstance(recovery.get("requests"), dict) else {}
        request = requests.get(request_id) if isinstance(requests, dict) else None
        if not isinstance(request, dict):
            return False
        request_method = str(request.get("method") or "").strip().lower()
        if request_method not in {"continuity", "reversal"}:
            return False
        return verifies_with(str(request.get("new_pubkey") or "").strip(), sig_profile)

    if tx_type == "ACCOUNT_RECOVERY_REQUEST":
        if method == "offline_key":
            current = recovery.get("offline_key")
            if not isinstance(current, dict):
                return False
            return verifies_with(
                str(current.get("pubkey") or "").strip(),
                str(current.get("sig_profile") or sig_profile),
            )
        if method == "continuity":
            # The claimant proves possession of the proposed replacement key;
            # reviewer consensus supplies continuity authority.
            return verifies_with(str(payload.get("new_pubkey") or "").strip(), sig_profile)
        if method == "reversal":
            authorization = str(payload.get("authorization") or "continuity").strip().lower()
            if authorization == "offline_key":
                wanted_key_id = str(payload.get("authorization_key_id") or "").strip()
                candidates = recovery.get("prior_offline_keys")
                if not isinstance(candidates, list):
                    return False
                for record in candidates:
                    if not isinstance(record, dict):
                        continue
                    if wanted_key_id and str(record.get("key_id") or "").strip() != wanted_key_id:
                        continue
                    if verifies_with(
                        str(record.get("pubkey") or "").strip(),
                        str(record.get("sig_profile") or sig_profile),
                    ):
                        return True
                return False
            if authorization == "continuity":
                return verifies_with(str(payload.get("new_pubkey") or "").strip(), sig_profile)
            return False

    if not active_keys:
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
