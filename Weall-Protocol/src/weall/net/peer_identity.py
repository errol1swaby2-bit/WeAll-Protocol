from __future__ import annotations

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

We do NOT return secrets. We do not log. We return:
  (ok, reason, account_id, pubkey)
"""

from typing import Any, Dict, Optional, Tuple

from weall.crypto.ed25519 import verify_ed25519_sig  # expects (pubkey_str, message_bytes, sig_str)
from weall.net.messages import PeerHello

Json = Dict[str, Any]


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _is_node_device(device_id: str, rec: Json) -> bool:
    did = (device_id or "").strip()
    device_type = _as_str(rec.get("device_type") or rec.get("kind") or rec.get("type")).strip().lower()
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

    n = 0
    for did, rec in devices.items():
        if not isinstance(did, str):
            continue
        if not isinstance(rec, dict):
            continue
        if not bool(rec.get("active", False)):
            continue
        if _is_node_device(did, rec):
            n += 1
    return n


def _get_active_keys(acct: Json) -> set[str]:
    keys = acct.get("keys")
    if not isinstance(keys, dict):
        return set()

    out: set[str] = set()
    for pk, rec in keys.items():
        if not isinstance(pk, str) or not pk:
            continue
        if isinstance(rec, dict):
            if bool(rec.get("active", False)):
                out.add(pk)
        else:
            # tolerate older shape where keys is {pubkey: True/False}
            if bool(rec):
                out.add(pk)
    return out


def _canonical_hello_sign_bytes(hello: PeerHello, *, pubkey: str) -> bytes:
    """
    Canonical bytes that must be signed by the peer for identity proof.

    IMPORTANT:
      - Must be stable and deterministic
      - Must bind the peer_id (account_id) and key usage
      - Must include chain_id + schema_version + tx_index_hash so signatures can't
        be replayed cross-chain or across incompatible schema indexes
    """
    # Keep it simple: deterministic string fields joined with "|"
    # Avoid JSON here to reduce ambiguity.
    chain_id = hello.header.chain_id
    schema_version = hello.header.schema_version
    tx_index_hash = hello.header.tx_index_hash

    peer_id = _as_str(getattr(hello, "peer_id", "")).strip()
    agent = _as_str(getattr(hello, "agent", "")).strip()
    nonce = _as_str(getattr(hello, "nonce", "")).strip()

    # identity object may contain other fields; proof binds these canonical ones.
    parts = [
        "WEALL_PEER_HELLO_V1",
        chain_id,
        schema_version,
        tx_index_hash,
        peer_id,
        pubkey,
        agent,
        nonce,
    ]
    return ("|".join(parts)).encode("utf-8")


def verify_peer_hello_identity(
    *,
    hello: PeerHello,
    ledger: Json,
) -> Tuple[bool, str, str, str]:
    """
    Verify peer identity proof for inbound PEER_HELLO.

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

    if not pubkey:
        return (False, "missing_pubkey", peer_id, "")
    if not sig:
        return (False, "missing_sig", peer_id, pubkey)

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
        # This should not happen if apply/identity enforcement is active, but fail-closed.
        return (False, "multiple_node_devices", account_id, pubkey)

    # --- Pubkey must be active on-chain for this account ---
    active_keys = _get_active_keys(acct)
    if pubkey not in active_keys:
        return (False, "pubkey_not_active_for_account", account_id, pubkey)

    # --- Signature verification ---
    msg_bytes = _canonical_hello_sign_bytes(hello, pubkey=pubkey)
    try:
        ok = bool(verify_ed25519_sig(pubkey, msg_bytes, sig))
    except Exception:
        return (False, "sig_verify_exception", account_id, pubkey)

    if not ok:
        return (False, "bad_signature", account_id, pubkey)

    return (True, "ok", account_id, pubkey)
