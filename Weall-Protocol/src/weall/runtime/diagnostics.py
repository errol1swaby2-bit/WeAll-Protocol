from __future__ import annotations

"""Read-only diagnostics and small state/status access delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""



from weall.runtime.executor import (
    Json,
    _now_ms,
)

def mempool(self) -> PersistentMempool:
    return self._mempool

def attestation_pool(self) -> PersistentAttestationPool:
    return self._att_pool

def read_mempool(self, *, limit: int = 10_000) -> list[Json]:
    """Ops/test helper: inspect the current mempool."""
    lim = int(limit) if int(limit) > 0 else 10_000
    return self._mempool.peek(limit=lim)

def mempool_selection_diagnostics(self, *, preview_limit: int = 10) -> Json:
    base: Json = {}
    fn = getattr(self._mempool, "selection_diagnostics", None)
    if callable(fn):
        try:
            out = fn(limit=int(preview_limit))
            if isinstance(out, dict):
                base = dict(out)
        except Exception:
            base = {}
    if not isinstance(base.get("items"), list):
        base["items"] = []
    last = self._last_mempool_selection_diag
    if isinstance(last, dict):
        base["last_candidate"] = dict(last)
    return base

def helper_execution_diagnostics(self) -> Json:
    meta_root = self.state.get("meta") if isinstance(self.state.get("meta"), dict) else {}
    marker = meta_root.get("helper_execution_last") if isinstance(meta_root.get("helper_execution_last"), dict) else None
    if not isinstance(marker, dict):
        return {}
    out = dict(marker)
    merge_summary = out.get("merge_summary") if isinstance(out.get("merge_summary"), dict) else {}
    lane_decisions = merge_summary.get("lane_decisions") if isinstance(merge_summary.get("lane_decisions"), list) else []
    lanes = out.get("lanes") if isinstance(out.get("lanes"), list) else []
    fallback_reason_counts: dict[str, int] = {}
    helper_lane_count = 0
    fallback_lane_count = 0
    lane_count = 0
    if lane_decisions:
        for item in lane_decisions:
            if not isinstance(item, dict):
                continue
            lane_count += 1
            if bool(item.get("used_helper")):
                helper_lane_count += 1
                continue
            fallback_lane_count += 1
            reason = str(item.get("fallback_reason") or "").strip() or "unknown"
            fallback_reason_counts[reason] = int(fallback_reason_counts.get(reason, 0)) + 1
    else:
        for item in lanes:
            if not isinstance(item, dict):
                continue
            lane_count += 1
            helper_id = str(item.get("helper_id") or item.get("original_helper_id") or "").strip()
            if helper_id:
                helper_lane_count += 1
                continue
            fallback_lane_count += 1
            reason = str(item.get("routing_mode") or "").strip() or "serial"
            fallback_reason_counts[reason] = int(fallback_reason_counts.get(reason, 0)) + 1
    out["summary"] = {
        "lane_count": int(lane_count),
        "helper_lane_count": int(helper_lane_count),
        "fallback_lane_count": int(fallback_lane_count),
        "fallback_reason_counts": dict(sorted(fallback_reason_counts.items())),
        "fraud_suspected": bool(out.get("fraud_suspected") or False),
    }
    return out

def transition_guardrail_diagnostics(self) -> Json:
    meta_root = self.state.get("meta") if isinstance(self.state.get("meta"), dict) else {}
    marker = meta_root.get("transition_guardrail_last")
    if isinstance(marker, dict):
        return dict(marker)
    return {}

def get_tx_status(self, tx_id: str) -> dict[str, object]:
    """Resolve transaction lifecycle state.

    Order of checks:
      1. confirmed (tx_index)
      2. pending (mempool)
      3. unknown

    This is the canonical runtime interface used by tests and by the API
    tx-status route. Keeping this logic inside the executor avoids direct
    database access from callers and ensures tx lifecycle semantics stay
    centralized.
    """
    tx_id = str(tx_id or "").strip()
    if not tx_id:
        return {"ok": True, "tx_id": tx_id, "status": "unknown"}

    with self._db.connection() as con:
        row = con.execute(
            """
            SELECT tx_id, height, block_id, tx_type, signer, nonce, ok, included_ts_ms
            FROM tx_index
            WHERE tx_id = ?
            LIMIT 1
            """,
            (tx_id,),
        ).fetchone()
        if row is not None:
            return {
                "ok": True,
                "tx_id": str(row["tx_id"]),
                "status": "confirmed",
                "height": int(row["height"]),
                "block_id": str(row["block_id"]),
                "tx_type": str(row["tx_type"]),
                "signer": str(row["signer"]),
                "nonce": int(row["nonce"]),
                "included_ts_ms": int(row["included_ts_ms"]),
            }

        row = con.execute(
            """
            SELECT tx_id
            FROM mempool
            WHERE tx_id = ?
            LIMIT 1
            """,
            (tx_id,),
        ).fetchone()
        if row is not None:
            return {
                "ok": True,
                "tx_id": tx_id,
                "status": "pending",
            }

    return {
        "ok": True,
        "tx_id": tx_id,
        "status": "unknown",
    }

def read_state(self) -> Json:
    """Return the latest persisted ledger snapshot.

    This keeps read-only API processes coherent when a separate producer
    process commits blocks into the shared SQLite store.
    """
    try:
        self.state = self._ledger_store.read()
    except Exception:
        pass
    return self.state

def tx_index_hash(self) -> str:
    """Return SHA-256 hex digest of the canonical tx index file."""
    return str(getattr(self, "_tx_index_hash", "") or "")

def sqlite_maintenance_tick(self) -> None:
    """Best-effort SQLite maintenance.

    - periodic WAL checkpoint to keep WAL bounded
    - occasional PRAGMA optimize

    This must never be consensus-critical: it should not mutate chain state.
    """
    if not getattr(self, "_sqlite_maintenance_enabled", False):
        return

    now = _now_ms()

    # WAL checkpoint
    interval = int(getattr(self, "_sqlite_checkpoint_interval_ms", 0) or 0)
    if interval > 0 and (now - int(getattr(self, "_last_sqlite_maint_ms", 0) or 0)) >= interval:
        try:
            # PASSIVE is non-blocking; it will not stall writers for long.
            self._db.wal_checkpoint(mode="PASSIVE")
        except Exception:
            # Never crash the node due to maintenance.
            pass
        self._last_sqlite_maint_ms = now

    # Optimize
    opt_interval = int(getattr(self, "_sqlite_optimize_interval_ms", 0) or 0)
    if (
        opt_interval > 0
        and (now - int(getattr(self, "_last_sqlite_optimize_ms", 0) or 0)) >= opt_interval
    ):
        try:
            self._db.optimize()
        except Exception:
            pass
        self._last_sqlite_optimize_ms = now

