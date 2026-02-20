# src/weall/runtime/system_tx_engine.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import TxIndex

Json = Dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        return ""


def _as_opt_str(v: Any) -> str:
    """Like _as_str, but treats None as empty string (critical for parent refs)."""
    if v is None:
        return ""
    return _as_str(v)


def _canon_info(canon: Any, tx_type: str) -> Optional[Dict[str, Any]]:
    """Return canon entry for tx_type, supporting both TxIndex and lightweight dict stubs.

    TxIndex: canon.get(tx_type) -> dict|None
    Dict stub (tests): {"by_name": {tx_type: {...}}}
    Dict fallback: {tx_type: {...}}
    """
    tx_u = _as_str(tx_type).strip().upper()
    if not tx_u:
        return None

    try:
        if isinstance(canon, TxIndex):
            info = canon.get(tx_u)
            return info if isinstance(info, dict) else None
    except Exception:
        pass

    if isinstance(canon, dict):
        by_name = canon.get("by_name")
        if isinstance(by_name, dict):
            info = by_name.get(tx_u)
            return info if isinstance(info, dict) else None

        info = canon.get(tx_u)
        return info if isinstance(info, dict) else None

    try:
        info = canon.get(tx_u)  # type: ignore[attr-defined]
        return info if isinstance(info, dict) else None
    except Exception:
        return None


def _canon_context(canon: Any, tx_type: str) -> str:
    info = _canon_info(canon, tx_type)
    ctx = _as_str(info.get("context", "") if isinstance(info, dict) else "")
    return ctx.strip().lower()


def _is_system_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get("system_only") is True) if isinstance(info, dict) else False


def _is_receipt_only(canon: Any, tx_type: str) -> bool:
    info = _canon_info(canon, tx_type)
    return bool(info.get("receipt_only") is True) if isinstance(info, dict) else False


def _canon_parent_required(canon: Any, tx_type: str) -> str:
    """Return the canon-declared parent type (string) for receipt-only txs, if any."""
    info = _canon_info(canon, tx_type)
    if not isinstance(info, dict):
        return ""
    p = info.get("parent")
    return _as_opt_str(p).strip().upper()


@dataclass(frozen=True)
class SystemQueueItem:
    queue_id: str
    tx_type: str
    payload: Json
    signer: str
    due_height: int
    parent: str
    phase: str  # "pre" or "post"
    once: bool = True
    emitted_height: Optional[int] = None

    def to_ledger_obj(self) -> Json:
        return {
            "queue_id": self.queue_id,
            "tx_type": self.tx_type,
            "payload": self.payload,
            "signer": self.signer,
            "due_height": self.due_height,
            "parent": self.parent,
            "phase": self.phase,
            "once": bool(self.once),
            "emitted_height": self.emitted_height,
        }

    @staticmethod
    def from_ledger_obj(obj: Any) -> "SystemQueueItem":
        if not isinstance(obj, dict):
            raise ValueError("bad_system_queue_item")
        return SystemQueueItem(
            queue_id=_as_str(obj.get("queue_id")).strip(),
            tx_type=_as_str(obj.get("tx_type")).strip().upper(),
            payload=obj.get("payload") if isinstance(obj.get("payload"), dict) else {},
            signer=_as_str(obj.get("signer")).strip() or "SYSTEM",
            due_height=_as_int(obj.get("due_height"), 0),
            parent=_as_opt_str(obj.get("parent")).strip(),
            phase=_as_str(obj.get("phase")).strip().lower() or "post",
            once=bool(obj.get("once", True)),
            emitted_height=obj.get("emitted_height") if isinstance(obj.get("emitted_height"), int) else None,
        )


def _queue_root(state: Json) -> List[Json]:
    root = state.get("system_queue")
    if not isinstance(root, list):
        root = []
        state["system_queue"] = root
    return root


def _queue_ids(state: Json) -> set[str]:
    ids: set[str] = set()
    for obj in _queue_root(state):
        if isinstance(obj, dict):
            qid = _as_str(obj.get("queue_id")).strip()
            if qid:
                ids.add(qid)
    return ids


def enqueue_system_tx(
    state: Json,
    *,
    tx_type: str,
    payload: Json,
    due_height: int,
    signer: str = "SYSTEM",
    once: bool = True,
    parent: Optional[str] = None,
    phase: str = "post",
) -> str:
    tx_type_u = _as_str(tx_type).strip().upper()
    phase_n = _as_str(phase).strip().lower() or "post"
    parent_norm = _as_opt_str(parent).strip() if parent is not None else ""

    base = {
        "tx_type": tx_type_u,
        "payload": payload or {},
        "signer": _as_str(signer).strip() or "SYSTEM",
        "due_height": int(due_height),
        "parent": parent_norm,
        "phase": phase_n,
        "once": bool(once),
    }

    raw = json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
    qid = hashlib.sha256(raw).hexdigest()
    base["queue_id"] = qid

    if qid in _queue_ids(state):
        return qid

    _queue_root(state).append(base)
    return qid


def _select_due_items(state: Json, *, next_height: int, phase: str) -> List[SystemQueueItem]:
    out: List[SystemQueueItem] = []
    phase_n = _as_str(phase).strip().lower() or "post"
    for obj in _queue_root(state):
        if not isinstance(obj, dict):
            continue
        try:
            item = SystemQueueItem.from_ledger_obj(obj)
        except Exception:
            continue

        if item.emitted_height is not None and item.once:
            continue
        if item.phase != phase_n:
            continue
        if int(item.due_height) != int(next_height):
            continue

        out.append(item)
    return out


def system_tx_emitter(state: Json, canon: Any, *, next_height: int, phase: str) -> List[TxEnvelope]:
    out: List[TxEnvelope] = []

    items = _select_due_items(state, next_height=int(next_height), phase=phase)
    ledger = state

    for it in items:
        # Internal queue emits system envelopes.
        _ = _is_system_only(canon, it.tx_type)
        _ = _canon_context(canon, it.tx_type)

        payload = dict(it.payload or {})
        payload.setdefault("_due_height", int(it.due_height))
        payload.setdefault("_system_queue_id", it.queue_id)

        signer = it.signer or "SYSTEM"
        if str(signer).strip() == "SYSTEM":
            params = ledger.get("params")
            if isinstance(params, dict):
                override = str(params.get("system_signer") or "").strip()
                if override:
                    signer = override

        # IMPORTANT: treat missing _parent_ref as "" (not "None")
        payload_parent_ref = _as_opt_str(payload.get("_parent_ref")).strip()

        # Prefer explicit queue parent, then payload ref
        parent_ref = it.parent.strip() if it.parent else payload_parent_ref

        # Receipt-only means it can only be emitted on the system/block path,
        # but it does *not* necessarily imply a parent reference is required.
        # Parent requirements are tracked separately in canon.
        is_receipt = _is_receipt_only(canon, it.tx_type)
        parent_required = _canon_parent_required(canon, it.tx_type)

        # Autofill parent_ref from canon *only* when canon explicitly requires it.
        if parent_required and not parent_ref:
            parent_ref = parent_required

        # If canon requires a parent and we still do not have one, skip emission
        # rather than emitting an invalid receipt envelope.
        if parent_required and not parent_ref:
            continue

        # Keep payload consistent with envelope (helps downstream apply paths)
        if parent_ref:
            payload.setdefault("_parent_ref", parent_ref)

        out.append(
            TxEnvelope(
                tx_type=it.tx_type,
                signer=signer,
                nonce=0,
                payload=payload,
                sig="",
                parent=parent_ref if parent_ref else None,
                system=True,
            )
        )

        if it.once:
            confirm_system_tx_emitted(state, queue_id=it.queue_id, emitted_height=int(next_height))

    return out


def confirm_system_tx_emitted(state: Json, *, queue_id: str, emitted_height: int) -> bool:
    qid = _as_str(queue_id).strip()
    if not qid:
        return False
    for obj in _queue_root(state):
        if not isinstance(obj, dict):
            continue
        if _as_str(obj.get("queue_id")).strip() == qid:
            obj["emitted_height"] = int(emitted_height)
            return True
    return False


def prune_emitted_system_queue(state: Json) -> int:
    root = _queue_root(state)
    before = len(root)
    kept: List[Json] = []
    for obj in root:
        if not isinstance(obj, dict):
            continue
        once = bool(obj.get("once", True))
        eh = obj.get("emitted_height")
        if once and isinstance(eh, int):
            continue
        kept.append(obj)
    state["system_queue"] = kept
    return before - len(kept)

