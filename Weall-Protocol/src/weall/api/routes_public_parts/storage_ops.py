# projects/Weall-Protocol/src/weall/api/routes_public_parts/storage_ops.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Set, Tuple

from fastapi import APIRouter, Request

from weall.api.errors import ApiError
from weall.api.routes_public_parts.common import _snapshot

Json = Dict[str, Any]

router = APIRouter()


def _env_int(name: str, default: int) -> int:
    try:
        v = os.getenv(name)
        if v is None:
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _storage_get(st: Json) -> Json:
    storage = st.get("storage")
    return storage if isinstance(storage, dict) else {}


def _replication_factor(st: Json) -> int:
    """
    Source-of-truth order:
      1) env WEALL_IPFS_REPLICATION_FACTOR (int)
      2) state params.ipfs_replication_factor (int) if present
      3) default 1
    """
    env_rf = _env_int("WEALL_IPFS_REPLICATION_FACTOR", 0)
    if env_rf > 0:
        return env_rf

    params = st.get("params")
    if isinstance(params, dict):
        try:
            v = int(params.get("ipfs_replication_factor") or 0)
            if v > 0:
                return v
        except Exception:
            pass

    return 1


def _enabled_operators(storage: Json) -> List[str]:
    ops_any = storage.get("operators")
    if not isinstance(ops_any, dict):
        return []
    out: List[str] = []
    for k, rec_any in ops_any.items():
        acc = str(k or "").strip()
        if not acc:
            continue
        rec = rec_any if isinstance(rec_any, dict) else {}
        if bool(rec.get("enabled", True)):
            out.append(acc)
    out.sort()
    return out


def _pin_status_counts(storage: Json) -> Dict[str, int]:
    pins_any = storage.get("pins")
    if not isinstance(pins_any, dict):
        return {}

    counts: Dict[str, int] = {}
    for _, rec_any in pins_any.items():
        if not isinstance(rec_any, dict):
            continue
        st = str(rec_any.get("status") or "").strip().lower() or "unknown"
        counts[st] = counts.get(st, 0) + 1
    return counts


def _pin_targets_stats(storage: Json) -> Dict[str, int]:
    pins_any = storage.get("pins")
    if not isinstance(pins_any, dict):
        return {"with_targets": 0, "without_targets": 0}

    with_targets = 0
    without_targets = 0
    for _, rec_any in pins_any.items():
        if not isinstance(rec_any, dict):
            continue
        targets = rec_any.get("targets")
        if isinstance(targets, list):
            with_targets += 1
        else:
            without_targets += 1
    return {"with_targets": int(with_targets), "without_targets": int(without_targets)}


def _durability_stats(st: Json, rf: int) -> Dict[str, int]:
    """
    Compute best-effort durable CID counts:
      durable := unique_ok_operator_confirms >= rf
    """
    storage = _storage_get(st)
    pins_any = storage.get("pins")
    confirms_any = storage.get("pin_confirms")

    # Collect CIDs we care about (from pins).
    cids: Set[str] = set()
    if isinstance(pins_any, dict):
        for _, rec_any in pins_any.items():
            if not isinstance(rec_any, dict):
                continue
            cid = str(rec_any.get("cid") or "").strip()
            if cid:
                cids.add(cid)

    # Build cid -> set(operator_id) for ok confirms.
    ok_ops_by_cid: Dict[str, Set[str]] = {}
    if isinstance(confirms_any, list):
        for item_any in confirms_any:
            if not isinstance(item_any, dict):
                continue
            cid = str(item_any.get("cid") or "").strip()
            if not cid:
                continue
            if cids and cid not in cids:
                # Focus on pinned/requested CIDs if pins map exists.
                continue
            if not bool(item_any.get("ok")):
                continue
            op = item_any.get("operator_id")
            if not isinstance(op, str) or not op.strip():
                continue
            ok_ops_by_cid.setdefault(cid, set()).add(op.strip())

    total = len(cids)
    durable = 0
    pending = 0

    for cid in cids:
        n = len(ok_ops_by_cid.get(cid, set()))
        if n >= rf:
            durable += 1
        else:
            pending += 1

    return {"cids_total": int(total), "cids_durable": int(durable), "cids_pending": int(pending)}


@router.get("/storage/ipfs/ops")
def v1_storage_ipfs_ops(request: Request) -> Json:
    """
    Public read-only ops surface for storage/IPFS health.

    Returns:
      - replication_factor
      - enabled_operators (+ count)
      - pin status counts
      - how many pin records include deterministic targets
      - durable vs pending CID counts (best-effort)
    """
    st = _snapshot(request)
    storage = _storage_get(st)

    rf = _replication_factor(st)
    enabled_ops = _enabled_operators(storage)
    status_counts = _pin_status_counts(storage)
    targets_stats = _pin_targets_stats(storage)
    dur_stats = _durability_stats(st, rf=rf)

    # Minimal sanity: if storage domain hasn't been initialized, still return ok.
    return {
        "ok": True,
        "replication_factor": int(rf),
        "enabled_operators": enabled_ops,
        "enabled_operator_count": int(len(enabled_ops)),
        "pin_status_counts": status_counts,
        "pin_targeting": targets_stats,
        "durability": dur_stats,
    }
