# File: src/weall/net/peer_identity.py
from __future__ import annotations

import time

"""
WeAll Protocol — Peer Identity Verification

This module verifies that an inbound PEER_HELLO contains a valid identity proof
binding:
  - hello.peer_id (account_id)
  - claimed pubkey
  - signature over canonical fields

Production posture additions:
  - Node participation requires an ACTIVE on-chain "node device" for the account.
    This makes "one node per user" enforceable as both:
      (a) ledger invariant (apply identity)
      (b) network participation gate (this module)

Node device definition (consistent with apply/identity.py):
  - device_type/kind/type == "node"
  OR device_id begins with "node:"
  OR label begins with "node" (legacy convenience)

Signing:
  - Outbound peers may include `hello.identity = {"pubkey":..., "sig_profile":..., "sig":...}`.
  - Peer identity proofs use pq-mldsa-v1 only.

We do NOT return secrets. We do not log. We return:
  (ok, reason, account_id, pubkey)
"""

from typing import Any

from weall.crypto.account_keys import account_key_pubkey
from weall.crypto.sig import sign_signature_for_profile, verify_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1, default_signature_profile_for_mode
from weall.net.messages import PeerHello, PeerHelloAck, WireHeader

Json = dict[str, Any]


def verify_mldsa_sig(pubkey: str, msg_bytes: bytes, sig: str) -> bool:
    return verify_signature_for_profile(
        sig_profile=PQ_MLDSA_V1,
        message=bytes(msg_bytes),
        sig=str(sig),
        pubkey=str(pubkey),
    )


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _is_node_device(device_id: str, rec: Json) -> bool:
    did = (device_id or "").strip()
    device_type = (
        _as_str(rec.get("device_type") or rec.get("kind") or rec.get("type")).strip().lower()
    )
    label = _as_str(rec.get("label")).strip()

    return (
        device_type == "node"
        or did.startswith("node:")
        or (label.lower().startswith("node") if label else False)
    )


def _count_active_node_devices(acct: Json) -> int:
    devices = acct.get("devices")
    if not isinstance(devices, dict):
        return 0

    # Support both shapes:
    #   - New/canonical identity schema: {"by_id": {device_id: {type,label,pubkey,revoked}}}
    #   - Older network gate schema: {device_id: {active: bool, ...}}
    by_id = devices.get("by_id") if isinstance(devices.get("by_id"), dict) else None
    items = list(by_id.items()) if isinstance(by_id, dict) else list(devices.items())

    n = 0
    for did, rec in items:
        if not isinstance(did, str):
            continue
        if not isinstance(rec, dict):
            continue

        # Active semantics:
        #  - if explicit active flag exists, require it
        #  - else treat "revoked" as the inverse of active
        if "active" in rec:
            if not bool(rec.get("active", False)):
                continue
        else:
            if bool(rec.get("revoked", False)):
                continue

        if _is_node_device(did, rec):
            n += 1
    return n


def _get_active_keys(acct: Json) -> set[str]:
    """Return the set of active pubkeys for an account.

    Supported shapes:
      - Canonical dict-form:
          keys = {"<pubkey>": {"active": true|false}, ...}
      - Legacy dict-form:
          keys = {"<pubkey>": true|false, ...}
      - Legacy list-form (used heavily in tests):
          keys = [{"pubkey": "<pubkey>", "active": true|false}, ...]
    """
    keys = acct.get("keys")
    out: set[str] = set()

    if isinstance(keys, list):
        for rec in keys:
            if not isinstance(rec, dict):
                continue
            if rec.get("active", True) is False:
                continue
            pk = account_key_pubkey(rec)
            if isinstance(pk, str) and pk.strip():
                out.add(pk.strip())
        return out

    if not isinstance(keys, dict):
        return out

    # New/canonical identity schema: keys={"by_id": {key_id: {pubkey, revoked}}}
    by_id = keys.get("by_id")
    if isinstance(by_id, dict):
        for _kid, rec in by_id.items():
            if not isinstance(rec, dict):
                continue
            if bool(rec.get("revoked", False)):
                continue
            pk = account_key_pubkey(rec)
            if isinstance(pk, str) and pk.strip():
                out.add(pk.strip())
        return out

    # Older shapes
    for pk, rec in keys.items():
        if not isinstance(pk, str) or not pk:
            continue
        if isinstance(rec, dict):
            if bool(rec.get("active", False)):
                rec_pk = account_key_pubkey(rec) or pk
                out.add(rec_pk)
        else:
            # tolerate older shape where keys is {pubkey: True/False}
            if bool(rec):
                out.add(pk)
    return out


def _canonical_hello_sign_bytes(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    agent: str,
    nonce: str,
) -> bytes:
    """Canonical bytes that must be signed by the peer for identity proof.

    Back-compat note:
      - This function returns the **V1** canonical bytes.
      - Newer callers should prefer V2, which also binds header sent_ts_ms and corr_id.
    """
    parts = [
        "WEALL_PEER_HELLO_V1",
        str(header.chain_id),
        str(header.schema_version),
        str(header.tx_index_hash),
        str(peer_id).strip(),
        str(pubkey).strip(),
        str(agent or "").strip(),
        str(nonce or "").strip(),
    ]
    return ("|".join(parts)).encode("utf-8")


def _canonical_hello_sign_bytes_v2(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    agent: str,
    nonce: str,
) -> bytes:
    """V2 canonical bytes.

    V2 binds additional header fields to reduce replay risk:
      - header.sent_ts_ms
      - header.corr_id
    """
    parts = [
        "WEALL_PEER_HELLO_V2",
        str(header.chain_id),
        str(header.schema_version),
        str(header.tx_index_hash),
        str(int(header.sent_ts_ms or 0)),
        str(header.corr_id or ""),
        str(peer_id).strip(),
        str(pubkey).strip(),
        str(agent or "").strip(),
        str(nonce or "").strip(),
    ]
    return ("|".join(parts)).encode("utf-8")


def _canonical_hello_sign_bytes_v3(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    sig_profile: str,
    agent: str,
    nonce: str,
) -> bytes:
    """Profile-aware canonical peer identity proof bytes."""
    parts = [
        "WEALL_PEER_HELLO_V3",
        str(header.chain_id),
        str(header.schema_version),
        str(header.tx_index_hash),
        str(int(header.sent_ts_ms or 0)),
        str(header.corr_id or ""),
        str(peer_id).strip(),
        str(pubkey).strip(),
        str(sig_profile or "").strip(),
        str(agent or "").strip(),
        str(nonce or "").strip(),
    ]
    return ("|".join(parts)).encode("utf-8")


def _canonical_hello_ack_sign_bytes(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    sig_profile: str,
    recipient_peer_id: str,
    phase: str,
    challenge: str,
    ok: bool,
) -> bytes:
    parts = [
        "WEALL_PEER_HELLO_ACK_V1",
        str(header.chain_id),
        str(header.schema_version),
        str(header.tx_index_hash),
        str(int(header.sent_ts_ms or 0)),
        str(header.corr_id or ""),
        str(peer_id).strip(),
        str(pubkey).strip(),
        str(sig_profile or "").strip(),
        str(recipient_peer_id or "").strip(),
        str(phase or "").strip(),
        str(challenge or "").strip(),
        "1" if bool(ok) else "0",
    ]
    return ("|".join(parts)).encode("utf-8")


def sign_peer_hello_ack_identity(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    privkey: str,
    recipient_peer_id: str,
    phase: str,
    challenge: str,
    ok: bool,
    sig_profile: str | None = None,
) -> Json:
    pid = str(peer_id or "").strip()
    pk = str(pubkey or "").strip()
    sk = str(privkey or "").strip()
    recipient = str(recipient_peer_id or "").strip()
    phase2 = str(phase or "").strip().lower()
    if (
        not pid
        or not pk
        or not sk
        or not recipient
        or phase2 not in {"challenge", "final", "reject"}
    ):
        return {}
    profile = str(sig_profile or default_signature_profile_for_mode()).strip() or PQ_MLDSA_V1
    msg_bytes = _canonical_hello_ack_sign_bytes(
        header=header,
        peer_id=pid,
        pubkey=pk,
        sig_profile=profile,
        recipient_peer_id=recipient,
        phase=phase2,
        challenge=str(challenge or "").strip(),
        ok=bool(ok),
    )
    sig = sign_signature_for_profile(
        sig_profile=profile, message=msg_bytes, privkey=sk, encoding="hex"
    )
    return {"pubkey": pk, "sig_profile": profile, "sig_alg": "ML-DSA", "sig": sig}


def _verify_peer_account_binding(*, account_id: str, pubkey: str, ledger: Json) -> tuple[bool, str]:
    accounts = ledger.get("accounts")
    if not isinstance(accounts, dict):
        return False, "ledger_missing_accounts"
    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        return False, "account_not_found"
    node_count = _count_active_node_devices(acct)
    if node_count <= 0:
        return False, "node_device_required"
    if node_count > 1:
        return False, "multiple_node_devices"
    if pubkey not in _get_active_keys(acct):
        return False, "pubkey_not_active_for_account"
    return True, "ok"


def verify_peer_hello_ack_identity(
    *,
    ack: PeerHelloAck,
    ledger: Json,
    expected_recipient_peer_id: str,
    expected_corr_id: str,
    now_ms: int | None = None,
    max_clock_skew_ms: int = 30_000,
) -> tuple[bool, str, str, str]:
    peer_id = _as_str(getattr(ack, "peer_id", "")).strip()
    identity = _as_dict(getattr(ack, "identity", None))
    pubkey = _as_str(identity.get("pubkey")).strip()
    sig = _as_str(identity.get("sig")).strip()
    sig_profile = _as_str(identity.get("sig_profile")).strip()
    recipient = _as_str(getattr(ack, "recipient_peer_id", "")).strip()
    phase = _as_str(getattr(ack, "phase", "")).strip().lower()
    challenge = _as_str(getattr(ack, "challenge", "")).strip()
    corr_id = _as_str(getattr(ack.header, "corr_id", "")).strip()
    sent_ts_ms = getattr(ack.header, "sent_ts_ms", None)
    if not peer_id:
        return False, "missing_peer_id", "", ""
    if not pubkey:
        return False, "missing_pubkey", peer_id, ""
    if not sig:
        return False, "missing_sig", peer_id, pubkey
    if sig_profile != PQ_MLDSA_V1:
        return False, "unsupported_signature_profile", peer_id, pubkey
    if recipient != str(expected_recipient_peer_id or "").strip():
        return False, "recipient_peer_id_mismatch", peer_id, pubkey
    if not corr_id or corr_id != str(expected_corr_id or "").strip():
        return False, "corr_id_mismatch", peer_id, pubkey
    if phase not in {"challenge", "final", "reject"}:
        return False, "invalid_ack_phase", peer_id, pubkey
    if phase in {"challenge", "final"} and not challenge:
        return False, "challenge_missing", peer_id, pubkey
    if not isinstance(sent_ts_ms, int) or isinstance(sent_ts_ms, bool) or sent_ts_ms <= 0:
        return False, "sent_ts_ms_missing", peer_id, pubkey
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    if abs(now - int(sent_ts_ms)) > max(1, int(max_clock_skew_ms)):
        return False, "stale_identity_proof", peer_id, pubkey
    ok_binding, why_binding = _verify_peer_account_binding(
        account_id=peer_id, pubkey=pubkey, ledger=ledger
    )
    if not ok_binding:
        return False, why_binding, peer_id, pubkey
    msg_bytes = _canonical_hello_ack_sign_bytes(
        header=ack.header,
        peer_id=peer_id,
        pubkey=pubkey,
        sig_profile=sig_profile,
        recipient_peer_id=recipient,
        phase=phase,
        challenge=challenge,
        ok=bool(getattr(ack, "ok", False)),
    )
    try:
        if not bool(verify_mldsa_sig(pubkey, msg_bytes, sig)):
            return False, "bad_signature", peer_id, pubkey
    except Exception:
        return False, "sig_verify_exception", peer_id, pubkey
    return True, "ok", peer_id, pubkey


def sign_peer_hello_identity(
    *,
    header: WireHeader,
    peer_id: str,
    pubkey: str,
    privkey: str,
    agent: str = "",
    nonce: str = "",
    sig_profile: str | None = None,
) -> Json:
    """Return the `identity` object for a PEER_HELLO.

    Shape:
      {"pubkey": <hex/b64 pubkey>, "sig_profile": "pq-mldsa-v1", "sig": <hex signature>}

    Notes:
      - `privkey` is interpreted according to the selected signature profile.
      - The signature binds the canonical hello fields and the signature profile.
    """
    pid = str(peer_id or "").strip()
    pk = str(pubkey or "").strip()
    sk = str(privkey or "").strip()
    if not pid or not pk or not sk:
        return {}

    profile = str(sig_profile or default_signature_profile_for_mode()).strip() or PQ_MLDSA_V1
    msg_bytes = _canonical_hello_sign_bytes_v3(
        header=header, peer_id=pid, pubkey=pk, sig_profile=profile, agent=agent, nonce=nonce
    )
    sig = sign_signature_for_profile(
        sig_profile=profile, message=msg_bytes, privkey=sk, encoding="hex"
    )
    return {
        "pubkey": pk,
        "sig_profile": profile,
        "sig_alg": "ML-DSA",
        "sig": sig,
    }


def verify_peer_hello_identity(
    *,
    hello: PeerHello,
    ledger: Json,
    strict: bool = False,
    now_ms: int | None = None,
    max_clock_skew_ms: int = 30_000,
) -> tuple[bool, str, str, str]:
    """Verify peer identity proof for inbound PEER_HELLO.

    Returns:
      (ok, reason, account_id, pubkey)
    """
    # --- Basic shape ---
    peer_id = _as_str(getattr(hello, "peer_id", "")).strip()
    if not peer_id:
        return (False, "missing_peer_id", "", "")

    identity = _as_dict(getattr(hello, "identity", None))
    pubkey = _as_str(identity.get("pubkey")).strip()
    sig = _as_str(identity.get("sig")).strip()
    sig_profile = _as_str(identity.get("sig_profile")).strip()
    if not sig_profile:
        sig_profile = PQ_MLDSA_V1

    if not pubkey:
        return (False, "missing_pubkey", peer_id, "")
    if not sig:
        return (False, "missing_sig", peer_id, pubkey)

    if strict:
        sent_ts_ms = getattr(hello.header, "sent_ts_ms", None)
        corr_id = _as_str(getattr(hello.header, "corr_id", "")).strip()
        nonce = _as_str(getattr(hello, "nonce", "")).strip()
        if sig_profile != PQ_MLDSA_V1:
            return (False, "unsupported_signature_profile", peer_id, pubkey)
        if not isinstance(sent_ts_ms, int) or isinstance(sent_ts_ms, bool) or sent_ts_ms <= 0:
            return (False, "sent_ts_ms_missing", peer_id, pubkey)
        if not corr_id:
            return (False, "corr_id_missing", peer_id, pubkey)
        if not nonce:
            return (False, "nonce_missing", peer_id, pubkey)
        now = int(now_ms if now_ms is not None else time.time() * 1000)
        if abs(now - int(sent_ts_ms)) > max(1, int(max_clock_skew_ms)):
            return (False, "stale_identity_proof", peer_id, pubkey)

    # peer_id MUST equal account_id in this build
    account_id = peer_id

    # --- Ledger lookup ---
    accounts = ledger.get("accounts")
    if not isinstance(accounts, dict):
        return (False, "ledger_missing_accounts", account_id, pubkey)

    acct = accounts.get(account_id)
    if not isinstance(acct, dict):
        return (False, "account_not_found", account_id, pubkey)

    # --- Production gate: must have exactly one ACTIVE node device ---
    node_count = _count_active_node_devices(acct)
    if node_count <= 0:
        return (False, "node_device_required", account_id, pubkey)
    if node_count > 1:
        return (False, "multiple_node_devices", account_id, pubkey)

    # --- Pubkey must be active on-chain for this account ---
    active_keys = _get_active_keys(acct)
    if pubkey not in active_keys:
        return (False, "pubkey_not_active_for_account", account_id, pubkey)

    # --- Signature verification ---
    agent = _as_str(getattr(hello, "agent", "")).strip()
    nonce = _as_str(getattr(hello, "nonce", "")).strip()

    v3 = _canonical_hello_sign_bytes_v3(
        header=hello.header,
        peer_id=peer_id,
        pubkey=pubkey,
        sig_profile=sig_profile,
        agent=agent,
        nonce=nonce,
    )
    v2 = _canonical_hello_sign_bytes_v2(
        header=hello.header,
        peer_id=peer_id,
        pubkey=pubkey,
        agent=agent,
        nonce=nonce,
    )
    v1 = _canonical_hello_sign_bytes(
        header=hello.header,
        peer_id=peer_id,
        pubkey=pubkey,
        agent=agent,
        nonce=nonce,
    )

    try:
        ok = bool(verify_mldsa_sig(pubkey, v3, sig))
        if not strict and not ok and sig_profile == PQ_MLDSA_V1:
            ok = bool(verify_mldsa_sig(pubkey, v2, sig))
        if not strict and not ok and sig_profile == PQ_MLDSA_V1:
            ok = bool(verify_mldsa_sig(pubkey, v1, sig))
    except Exception:
        return (False, "sig_verify_exception", account_id, pubkey)

    if not ok:
        return (False, "bad_signature", account_id, pubkey)

    return (True, "ok", account_id, pubkey)
