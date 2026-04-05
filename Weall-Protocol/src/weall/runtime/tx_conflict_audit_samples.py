from __future__ import annotations

from typing import Any, Mapping

from weall.runtime.tx_conflicts import build_conflict_descriptor


Json = dict[str, Any]


def _seeded(seed: str, prefix: str) -> str:
    token = str(seed or "1").strip() or "1"
    return f"{prefix}-{token}"


def _namespace_prefixes(*keys: str) -> list[str]:
    prefixes: set[str] = set()
    for key in keys:
        item = str(key or "").strip().lower()
        if not item:
            continue
        if ":" not in item:
            continue
        head = item.split(":", 1)[0]
        if head:
            prefixes.add(f"{head}:")
    return sorted(prefixes)


def build_conflict_probe_payload(tx_type: str, *, seed: str = "1") -> Json:
    tx_type_norm = str(tx_type or "").strip().upper()
    payload: Json = {
        "account_id": _seeded(seed, "acct-alice"),
        "user_id": _seeded(seed, "acct-alice"),
        "actor_id": _seeded(seed, "acct-alice"),
        "target_account_id": _seeded(seed, "acct-bob"),
        "target_user_id": _seeded(seed, "acct-bob"),
        "group_id": _seeded(seed, "group"),
        "wallet_id": _seeded(seed, "wallet"),
        "treasury_id": _seeded(seed, "wallet"),
        "program_wallet_id": _seeded(seed, "wallet"),
        "spend_id": _seeded(seed, "spend"),
        "payment_id": _seeded(seed, "spend"),
        "proposal_id": _seeded(seed, "proposal"),
        "governance_proposal_id": _seeded(seed, "proposal"),
        "upgrade_id": _seeded(seed, "upgrade"),
        "voter_id": _seeded(seed, "acct-alice"),
        "post_id": _seeded(seed, "post"),
        "content_id": _seeded(seed, "post"),
        "comment_id": _seeded(seed, "comment"),
        "media_id": _seeded(seed, "media"),
        "cid": _seeded(seed, "bafy"),
        "case_id": _seeded(seed, "case"),
        "dispute_id": _seeded(seed, "case"),
        "challenge_id": _seeded(seed, "challenge"),
        "application_id": _seeded(seed, "application"),
        "request_id": _seeded(seed, "request"),
        "guardian_id": _seeded(seed, "guardian"),
        "key_id": _seeded(seed, "key"),
        "device_id": _seeded(seed, "device"),
        "session_key": _seeded(seed, "session"),
        "peer_id": _seeded(seed, "peer"),
        "node_id": _seeded(seed, "peer"),
        "lease_id": _seeded(seed, "lease"),
        "offer_id": _seeded(seed, "offer"),
        "receipt_id": _seeded(seed, "receipt"),
        "action_id": _seeded(seed, "action"),
        "escalation_id": _seeded(seed, "escalation"),
        "case_type_id": _seeded(seed, "case-type"),
        "election_id": _seeded(seed, "election"),
        "validator_id": _seeded(seed, "validator"),
        "subject_id": _seeded(seed, "subject"),
        "member_id": _seeded(seed, "acct-bob"),
        "recipient_id": _seeded(seed, "acct-bob"),
        "creator_id": _seeded(seed, "acct-alice"),
        "from_account_id": _seeded(seed, "acct-alice"),
        "to_account_id": _seeded(seed, "acct-bob"),
        "source_account_id": _seeded(seed, "acct-alice"),
        "destination_account_id": _seeded(seed, "acct-bob"),
        "thread_id": _seeded(seed, "thread"),
        "conversation_id": _seeded(seed, "thread"),
        "message_id": _seeded(seed, "message"),
        "topic": _seeded(seed, "topic"),
        "anchor_id": _seeded(seed, "anchor"),
        "snapshot_id": _seeded(seed, "snapshot"),
        "role": "juror",
        "capability": "juror",
        "role_name": "juror",
        "height": f"{100 + int(seed or '1')}",
        "block_height": f"{100 + int(seed or '1')}",
        "block_id": _seeded(seed, "block"),
    }

    if tx_type_norm in {"FOLLOW_SET", "BLOCK_SET", "MUTE_SET"}:
        payload["actor_id"] = _seeded(seed, "acct-actor")
        payload["target_user_id"] = _seeded(seed, "acct-target")
    elif tx_type_norm == "DIRECT_MESSAGE_SEND":
        payload["recipient_id"] = _seeded(seed, "acct-bob")
        payload["body"] = f"hello-{seed}"
    elif tx_type_norm == "DIRECT_MESSAGE_REDACT":
        payload["message_id"] = _seeded(seed, "message")
    elif tx_type_norm in {"NOTIFICATION_SUBSCRIBE", "NOTIFICATION_UNSUBSCRIBE", "NOTIFICATION_EMIT_RECEIPT"}:
        payload["topic"] = _seeded(seed, "notifications")
    elif tx_type_norm == "BALANCE_TRANSFER":
        payload["from_account_id"] = _seeded(seed, "acct-src")
        payload["to_account_id"] = _seeded(seed, "acct-dst")
    elif tx_type_norm == "FEE_PAY":
        payload["account_id"] = _seeded(seed, "acct-src")
        payload["from_account_id"] = payload["account_id"]
    elif tx_type_norm.startswith(("VALIDATOR_", "BLOCK_", "EPOCH_", "SLASH_")):
        payload["validator_id"] = _seeded(seed, "validator")
        payload["subject_id"] = payload["validator_id"]
    elif tx_type_norm.startswith("GROUP_"):
        payload["group_id"] = _seeded(seed, "group")
    elif tx_type_norm.startswith("TREASURY_"):
        payload["wallet_id"] = _seeded(seed, "wallet")
        payload["treasury_id"] = payload["wallet_id"]
    elif tx_type_norm.startswith(("GOV_", "PROTOCOL_UPGRADE_")):
        payload["proposal_id"] = _seeded(seed, "proposal")
        payload["governance_proposal_id"] = payload["proposal_id"]
        payload["upgrade_id"] = _seeded(seed, "upgrade")
    elif tx_type_norm.startswith("CONTENT_"):
        payload["post_id"] = _seeded(seed, "post")
        payload["content_id"] = payload["post_id"]
        payload["cid"] = _seeded(seed, "bafy")
    elif tx_type_norm.startswith("POH_"):
        payload["account_id"] = _seeded(seed, "acct-poh")
        payload["case_id"] = _seeded(seed, "case")
        payload["challenge_id"] = _seeded(seed, "challenge")
        payload["application_id"] = _seeded(seed, "application")
    elif tx_type_norm.startswith("DISPUTE_"):
        payload["dispute_id"] = _seeded(seed, "dispute")
        payload["case_id"] = payload["dispute_id"]
    elif tx_type_norm.startswith(("IPFS_", "STORAGE_")):
        payload["lease_id"] = _seeded(seed, "lease")
        payload["offer_id"] = _seeded(seed, "offer")
        payload["cid"] = _seeded(seed, "bafy")
    elif tx_type_norm.startswith("PEER_"):
        payload["peer_id"] = _seeded(seed, "peer")
        payload["node_id"] = payload["peer_id"]
    elif tx_type_norm.startswith(("INDEX_", "STATE_SNAPSHOT_", "COLD_SYNC_")) or tx_type_norm == "TX_RECEIPT_EMIT":
        payload["anchor_id"] = _seeded(seed, "anchor")
        payload["snapshot_id"] = _seeded(seed, "snapshot")
        payload["request_id"] = _seeded(seed, "request")
    elif tx_type_norm.startswith("CASE_"):
        payload["case_id"] = _seeded(seed, "case")
        payload["case_type_id"] = _seeded(seed, "case-type")
    return payload


def build_conflict_probe_tx(
    tx_type: str,
    *,
    seed: str = "1",
    signer: str | None = None,
    payload_overrides: Mapping[str, Any] | None = None,
    envelope_overrides: Mapping[str, Any] | None = None,
) -> Json:
    payload = build_conflict_probe_payload(tx_type, seed=seed)
    if payload_overrides:
        payload.update(dict(payload_overrides))
    tx: Json = {
        "tx_id": f"{str(tx_type or '').lower()}-{seed}",
        "tx_type": str(tx_type or "").strip().upper(),
        "signer": str(signer or _seeded(seed, "acct-signer")),
        "payload": payload,
    }
    if envelope_overrides:
        tx.update(dict(envelope_overrides))
    return tx


def build_helper_conflict_probe_tx(
    tx_type: str,
    *,
    seed: str = "1",
    signer: str | None = None,
    payload_overrides: Mapping[str, Any] | None = None,
    envelope_overrides: Mapping[str, Any] | None = None,
) -> Json:
    tx = build_conflict_probe_tx(
        tx_type,
        seed=seed,
        signer=signer,
        payload_overrides=payload_overrides,
        envelope_overrides=envelope_overrides,
    )
    descriptor = build_conflict_descriptor(tx)
    explicit = dict(tx)
    explicit["read_set"] = list(descriptor.read_keys)
    explicit["write_set"] = list(tuple(descriptor.write_keys) + tuple(descriptor.subject_keys) + tuple(descriptor.authority_keys))
    explicit["subject_set"] = list(descriptor.subject_keys)
    explicit["authority_set"] = list(descriptor.authority_keys)
    explicit["family"] = descriptor.family.value
    explicit["barrier_class"] = descriptor.barrier_class.value
    explicit["state_prefixes"] = _namespace_prefixes(
        *descriptor.read_keys,
        *descriptor.write_keys,
        *descriptor.subject_keys,
        *descriptor.authority_keys,
    )
    return explicit


__all__ = [
    "build_conflict_probe_payload",
    "build_conflict_probe_tx",
    "build_helper_conflict_probe_tx",
]
