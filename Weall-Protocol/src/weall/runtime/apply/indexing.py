# src/weall/runtime/apply/indexing.py
from __future__ import annotations

"""
Indexing domain apply semantics (production-ready; canon-correct).

Canon Indexing txs (v1.22.1) = 8:
- INDEX_ANCHOR_SET (SYSTEM, block, receipt_only, parent=BLOCK_FINALIZE, gate Validator, system_only)
- STATE_SNAPSHOT_DECLARE (SYSTEM, block, receipt_only, parent=BLOCK_FINALIZE, gate Validator, system_only)
- STATE_SNAPSHOT_ACCEPT (SYSTEM, block, receipt_only, parent=STATE_SNAPSHOT_DECLARE, gate Validator, system_only)
- COLD_SYNC_REQUEST (SYSTEM, block, receipt_only, parent=STATE_SNAPSHOT_ACCEPT, gate Validator, system_only)
- COLD_SYNC_COMPLETE (SYSTEM, block, receipt_only, parent=COLD_SYNC_REQUEST, gate Validator, system_only)

- INDEX_TOPIC_REGISTER (SYSTEM, block, receipt_only, parent=GOV_EXECUTE, gate GovExecutor, via_gov_execute)
- INDEX_TOPIC_ANCHOR_SET (SYSTEM, block, receipt_only, parent=BLOCK_FINALIZE, gate Validator, system_only)

- TX_RECEIPT_EMIT (SYSTEM, block, receipt_only, parent=BLOCK_FINALIZE, system_only)

Goals:
- Deterministic state transitions
- Idempotent receipts (repeat-safe)
- Fail-closed on missing critical identifiers
- Keep raw payload for traceability
- Store enough structure for replay, audit, and UI

State shape (deterministic):
ledger["indexing"] = {
  "index_anchors": [ {anchor_id, at_nonce, payload} ... ],           # append-only
  "topic_registry": { topic: {topic, active, created_at_nonce, ...} },
  "topic_anchors":  [ {topic, anchor_id, at_nonce, payload} ... ],   # append-only
  "snapshots": {
     "declares_by_id": {snapshot_id: {...}},
     "accepts_by_id":  {snapshot_id: {...}},
     "cold_sync": {
        "requests_by_id": {req_id: {...}},
        "completes_by_id": {req_id: {...}},
     },
     "latest": {"snapshot_id": str, "accepted_at_nonce": int}
  },
  "tx_receipts": [ {receipt_id, at_nonce, payload} ... ],            # append-only
}

Notes:
- This module only records anchors/snapshot/receipts. It does not compute them.
- Parent constraints are enforced in admission; this module enforces system_only as well.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@dataclass
class IndexingApplyError(RuntimeError):
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


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise IndexingApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_root_list(state: Json, key: str) -> List[Any]:
    cur = state.get(key)
    if not isinstance(cur, list):
        cur = []
        state[key] = cur
    return cur


def _ensure_indexing(state: Json) -> Json:
    idx = _ensure_root_dict(state, "indexing")

    if not isinstance(idx.get("topic_registry"), dict):
        idx["topic_registry"] = {}

    idx["index_anchors"] = _ensure_root_list(idx, "index_anchors")
    idx["topic_anchors"] = _ensure_root_list(idx, "topic_anchors")
    idx["tx_receipts"] = _ensure_root_list(idx, "tx_receipts")

    snaps = idx.get("snapshots")
    if not isinstance(snaps, dict):
        snaps = {}
        idx["snapshots"] = snaps

    if not isinstance(snaps.get("declares_by_id"), dict):
        snaps["declares_by_id"] = {}
    if not isinstance(snaps.get("accepts_by_id"), dict):
        snaps["accepts_by_id"] = {}
    if not isinstance(snaps.get("latest"), dict):
        snaps["latest"] = {"snapshot_id": "", "accepted_at_nonce": 0}

    cold = snaps.get("cold_sync")
    if not isinstance(cold, dict):
        cold = {}
        snaps["cold_sync"] = cold
    if not isinstance(cold.get("requests_by_id"), dict):
        cold["requests_by_id"] = {}
    if not isinstance(cold.get("completes_by_id"), dict):
        cold["completes_by_id"] = {}

    return idx


def _mk_id(prefix: str, env: TxEnvelope, provided: Any) -> str:
    p = _as_str(provided).strip()
    if p:
        return p
    return f"{prefix}:{env.signer}:{int(getattr(env, 'nonce', 0) or 0)}"


def _find_existing_by_id(items: List[Any], key: str, value: str) -> Optional[Json]:
    for it in items:
        if isinstance(it, dict) and _as_str(it.get(key)).strip() == value:
            return it
    return None


# ---------------------------------------------------------------------------
# INDEX_ANCHOR_SET
# ---------------------------------------------------------------------------

def _apply_index_anchor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    anchor_id = _as_str(payload.get("anchor_id") or payload.get("id") or payload.get("cid")).strip()
    if not anchor_id:
        raise IndexingApplyError("invalid_payload", "missing_anchor_id", {"tx_type": env.tx_type})

    anchors = idx["index_anchors"]
    already = _find_existing_by_id(anchors, "anchor_id", anchor_id) is not None
    if not already:
        anchors.append({"anchor_id": anchor_id, "at_nonce": int(env.nonce), "payload": payload})

    return {"applied": "INDEX_ANCHOR_SET", "anchor_id": anchor_id, "deduped": already}


# ---------------------------------------------------------------------------
# STATE_SNAPSHOT_DECLARE / ACCEPT
# ---------------------------------------------------------------------------

def _apply_state_snapshot_declare(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    snapshot_id = _as_str(payload.get("snapshot_id") or payload.get("id") or payload.get("cid")).strip()
    if not snapshot_id:
        raise IndexingApplyError("invalid_payload", "missing_snapshot_id", {"tx_type": env.tx_type})

    snaps = idx["snapshots"]
    declares = snaps["declares_by_id"]
    rec = declares.get(snapshot_id)
    already = isinstance(rec, dict)

    declares[snapshot_id] = {
        "snapshot_id": snapshot_id,
        "declared_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "STATE_SNAPSHOT_DECLARE", "snapshot_id": snapshot_id, "deduped": already}


def _apply_state_snapshot_accept(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    snapshot_id = _as_str(payload.get("snapshot_id") or payload.get("id") or payload.get("cid")).strip()
    if not snapshot_id:
        raise IndexingApplyError("invalid_payload", "missing_snapshot_id", {"tx_type": env.tx_type})

    snaps = idx["snapshots"]
    accepts = snaps["accepts_by_id"]
    already = snapshot_id in accepts

    # Fail-closed: accept must correspond to an existing declare
    declares = snaps["declares_by_id"]
    if snapshot_id not in declares:
        raise IndexingApplyError("not_found", "snapshot_declare_not_found", {"snapshot_id": snapshot_id})

    accepts[snapshot_id] = {
        "snapshot_id": snapshot_id,
        "accepted_at_nonce": int(env.nonce),
        "payload": payload,
    }

    # Update latest pointer deterministically (highest nonce wins)
    latest = snaps.get("latest")
    if not isinstance(latest, dict):
        latest = {"snapshot_id": "", "accepted_at_nonce": 0}
    if int(env.nonce) >= _as_int(latest.get("accepted_at_nonce"), 0):
        latest["snapshot_id"] = snapshot_id
        latest["accepted_at_nonce"] = int(env.nonce)
    snaps["latest"] = latest

    return {"applied": "STATE_SNAPSHOT_ACCEPT", "snapshot_id": snapshot_id, "deduped": already}


# ---------------------------------------------------------------------------
# COLD_SYNC_REQUEST / COMPLETE
# ---------------------------------------------------------------------------

def _apply_cold_sync_request(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    req_id = _mk_id("coldsync", env, payload.get("request_id") or payload.get("id"))
    snapshot_id = _as_str(payload.get("snapshot_id")).strip()
    if not snapshot_id:
        raise IndexingApplyError("invalid_payload", "missing_snapshot_id", {"tx_type": env.tx_type})

    snaps = idx["snapshots"]
    if snapshot_id not in snaps["accepts_by_id"]:
        raise IndexingApplyError("not_found", "snapshot_accept_not_found", {"snapshot_id": snapshot_id})

    cold = snaps["cold_sync"]
    reqs = cold["requests_by_id"]
    already = req_id in reqs

    reqs[req_id] = {
        "request_id": req_id,
        "snapshot_id": snapshot_id,
        "requested_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "COLD_SYNC_REQUEST", "request_id": req_id, "snapshot_id": snapshot_id, "deduped": already}


def _apply_cold_sync_complete(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    req_id = _as_str(payload.get("request_id") or payload.get("id")).strip()
    if not req_id:
        raise IndexingApplyError("invalid_payload", "missing_request_id", {"tx_type": env.tx_type})

    snaps = idx["snapshots"]
    cold = snaps["cold_sync"]
    reqs = cold["requests_by_id"]
    comps = cold["completes_by_id"]

    if req_id not in reqs:
        raise IndexingApplyError("not_found", "cold_sync_request_not_found", {"request_id": req_id})

    already = req_id in comps
    comps[req_id] = {
        "request_id": req_id,
        "completed_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "COLD_SYNC_COMPLETE", "request_id": req_id, "deduped": already}


# ---------------------------------------------------------------------------
# INDEX_TOPIC_REGISTER / ANCHOR_SET
# ---------------------------------------------------------------------------

def _apply_index_topic_register(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    topic = _as_str(payload.get("topic") or payload.get("name")).strip()
    if not topic:
        raise IndexingApplyError("invalid_payload", "missing_topic", {"tx_type": env.tx_type})

    reg = idx["topic_registry"]
    existing = reg.get(topic)
    already = isinstance(existing, dict) and bool(existing.get("active", True))

    rec: Json = existing if isinstance(existing, dict) else {"topic": topic}
    rec["topic"] = topic
    rec["active"] = True
    rec["registered_at_nonce"] = int(env.nonce)
    # store optional config deterministically
    if "config" in payload:
        rec["config"] = payload.get("config")
    rec["payload"] = payload
    reg[topic] = rec

    return {"applied": "INDEX_TOPIC_REGISTER", "topic": topic, "deduped": already}


def _apply_index_topic_anchor_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    topic = _as_str(payload.get("topic")).strip()
    anchor_id = _as_str(payload.get("anchor_id") or payload.get("id") or payload.get("cid")).strip()
    if not topic:
        raise IndexingApplyError("invalid_payload", "missing_topic", {"tx_type": env.tx_type})
    if not anchor_id:
        raise IndexingApplyError("invalid_payload", "missing_anchor_id", {"tx_type": env.tx_type})

    anchors = idx["topic_anchors"]
    # Idempotent by (topic, anchor_id)
    already = False
    for it in anchors:
        if isinstance(it, dict) and _as_str(it.get("topic")) == topic and _as_str(it.get("anchor_id")) == anchor_id:
            already = True
            break
    if not already:
        anchors.append({"topic": topic, "anchor_id": anchor_id, "at_nonce": int(env.nonce), "payload": payload})

    return {"applied": "INDEX_TOPIC_ANCHOR_SET", "topic": topic, "anchor_id": anchor_id, "deduped": already}


# ---------------------------------------------------------------------------
# TX_RECEIPT_EMIT
# ---------------------------------------------------------------------------

def _apply_tx_receipt_emit(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    idx = _ensure_indexing(state)
    payload = _as_dict(env.payload)

    # Receipt ID is required for deterministic dedupe.
    receipt_id = _as_str(payload.get("receipt_id") or payload.get("id")).strip()
    if not receipt_id:
        # As a fallback, allow tx_id + type
        tx_id = _as_str(payload.get("tx_id") or payload.get("txhash") or payload.get("tx_hash")).strip()
        tx_type = _as_str(payload.get("tx_type")).strip()
        if not tx_id or not tx_type:
            raise IndexingApplyError(
                "invalid_payload",
                "missing_receipt_id_or_tx_id",
                {"tx_type": env.tx_type},
            )
        receipt_id = f"rcpt:{tx_type}:{tx_id}"

    receipts = idx["tx_receipts"]
    already = _find_existing_by_id(receipts, "receipt_id", receipt_id) is not None
    if not already:
        receipts.append({"receipt_id": receipt_id, "at_nonce": int(env.nonce), "payload": payload})

    return {"applied": "TX_RECEIPT_EMIT", "receipt_id": receipt_id, "deduped": already}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

INDEXING_TX_TYPES: Set[str] = {
    "INDEX_ANCHOR_SET",
    "STATE_SNAPSHOT_DECLARE",
    "STATE_SNAPSHOT_ACCEPT",
    "COLD_SYNC_REQUEST",
    "COLD_SYNC_COMPLETE",
    "INDEX_TOPIC_REGISTER",
    "INDEX_TOPIC_ANCHOR_SET",
    "TX_RECEIPT_EMIT",
}


def apply_indexing(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply Indexing txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in INDEXING_TX_TYPES:
        return None

    if t == "INDEX_ANCHOR_SET":
        return _apply_index_anchor_set(state, env)
    if t == "STATE_SNAPSHOT_DECLARE":
        return _apply_state_snapshot_declare(state, env)
    if t == "STATE_SNAPSHOT_ACCEPT":
        return _apply_state_snapshot_accept(state, env)
    if t == "COLD_SYNC_REQUEST":
        return _apply_cold_sync_request(state, env)
    if t == "COLD_SYNC_COMPLETE":
        return _apply_cold_sync_complete(state, env)
    if t == "INDEX_TOPIC_REGISTER":
        return _apply_index_topic_register(state, env)
    if t == "INDEX_TOPIC_ANCHOR_SET":
        return _apply_index_topic_anchor_set(state, env)
    if t == "TX_RECEIPT_EMIT":
        return _apply_tx_receipt_emit(state, env)

    return None
