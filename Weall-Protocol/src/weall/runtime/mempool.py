from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from weall.runtime.sqlite_db import SqliteDB, _canon_json

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _env_int(name: str, default: int) -> int:
    try:
        raw = str(os.environ.get(name, "")).strip()
        return int(raw) if raw else int(default)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    try:
        raw = str(os.environ.get(name, "")).strip().lower()
        if not raw:
            return bool(default)
        if raw in {"1", "true", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "no", "n", "off"}:
            return False
        return bool(default)
    except Exception:
        return bool(default)


def _envelope_for_id(env: Json) -> Json:
    """Return the subset of an envelope used to derive its tx_id.

    We intentionally exclude fields that are:
      - assigned locally (tx_id/received_ms/expires_ms)
      - inherently non-deterministic

    This prevents tx_id spoofing/poisoning and avoids hash changes when the node
    stamps received/expiry times.
    """
    out: Json = {}
    for k, v in env.items():
        if k in {"tx_id", "received_ms", "expires_ms"}:
            continue
        out[k] = v
    return out


def compute_tx_id(env: Json) -> str:
    """Compute a deterministic tx_id from envelope content."""
    base = _envelope_for_id(env)
    h = hashlib.sha256(_canon_json(base).encode("utf-8")).hexdigest()
    return f"tx:{h}"


def _expires_ms(env: Json, *, fallback_ttl_ms: int) -> int:
    ex = env.get("expires_ms")
    if ex is not None:
        return _safe_int(ex, _now_ms() + fallback_ttl_ms)
    return _now_ms() + fallback_ttl_ms


@dataclass
class PersistentMempool:
    """SQLite-backed mempool.

    Table schema:
      mempool(tx_id PK, envelope_json, signer, tx_type, received_ms, expires_ms)

    Security/correctness guarantees:
      - tx_id is ALWAYS derived from envelope content (not trusted from user)
      - idempotent insert: same tx_id + identical envelope is accepted
      - conflicting insert: same tx_id + different envelope is rejected

    Determinism:
      - peek order is (received_ms ASC, tx_id ASC)
      - peek filters expired items

    Production safety:
      - optional hard caps (global + per-signer)
      - optional prune-on-add to keep DB bounded without a separate cron

    Env overrides:
      - WEALL_MEMPOOL_TTL_MS
      - WEALL_MEMPOOL_MAX
      - WEALL_MEMPOOL_MAX_PER_SIGNER
      - WEALL_MEMPOOL_PRUNE_ON_ADD
    """

    db: SqliteDB

    # Defaults are conservative for a public node.
    default_ttl_ms: int = 30 * 60 * 1000  # 30 minutes
    max_items: int = 50_000
    max_per_signer: int = 2_000
    prune_on_add: bool = True

    def __post_init__(self) -> None:
        self.db.init_schema()

        # Allow env overrides without forcing callers to plumb config everywhere.
        self.default_ttl_ms = _env_int("WEALL_MEMPOOL_TTL_MS", self.default_ttl_ms)
        self.max_items = max(0, _env_int("WEALL_MEMPOOL_MAX", self.max_items))
        self.max_per_signer = max(0, _env_int("WEALL_MEMPOOL_MAX_PER_SIGNER", self.max_per_signer))
        self.prune_on_add = _env_bool("WEALL_MEMPOOL_PRUNE_ON_ADD", self.prune_on_add)

    def _count_total(self, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool;").fetchone()
        return int(row["n"]) if row is not None else 0

    def _count_signer(self, signer: str, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool WHERE signer=?;", (signer,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def add(self, env: Json) -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        signer = str(env.get("signer") or "").strip()
        if not signer:
            return {"ok": False, "error": "bad_env:missing_signer"}

        tx_type = str(env.get("tx_type") or "").strip()
        if not tx_type:
            return {"ok": False, "error": "bad_env:missing_tx_type"}

        provided = str(env.get("tx_id") or "").strip()
        tx_id = compute_tx_id(env)
        if provided and provided != tx_id:
            return {"ok": False, "error": "bad_env:tx_id_mismatch"}

        received_ms = _safe_int(env.get("received_ms"), _now_ms())
        expires_ms = _expires_ms(env, fallback_ttl_ms=self.default_ttl_ms)

        # Persist canonical envelope including computed stamps (but id derived from base fields).
        env_persist: Json = dict(env)
        env_persist["tx_id"] = tx_id
        env_persist["received_ms"] = received_ms
        env_persist["expires_ms"] = expires_ms
        env_json = _canon_json(env_persist)

        with self.db.write_tx() as con:
            if self.prune_on_add:
                now = _now_ms()
                con.execute("DELETE FROM mempool WHERE expires_ms <= ?;", (int(now),))

            # Enforce caps (if enabled). Reject rather than dropping random txs.
            if self.max_items > 0:
                n_total = self._count_total(con=con)
                if n_total >= self.max_items:
                    return {"ok": False, "error": "mempool_full", "details": {"max": self.max_items}}

            if self.max_per_signer > 0:
                n_s = self._count_signer(signer, con=con)
                if n_s >= self.max_per_signer:
                    return {
                        "ok": False,
                        "error": "mempool_signer_quota",
                        "details": {"signer": signer, "max": self.max_per_signer},
                    }

            # Fast path: attempt insert.
            con.execute(
                """
                INSERT OR IGNORE INTO mempool(tx_id, envelope_json, signer, tx_type, received_ms, expires_ms)
                VALUES(?, ?, ?, ?, ?, ?);
                """,
                (tx_id, env_json, signer, tx_type, int(received_ms), int(expires_ms)),
            )

            row = con.execute(
                "SELECT envelope_json FROM mempool WHERE tx_id=? LIMIT 1;",
                (tx_id,),
            ).fetchone()

            if row is None:
                return {"ok": False, "error": "db_error:missing_after_insert"}

            # Idempotency check: existing envelope must match exactly.
            if str(row["envelope_json"]) != env_json:
                return {"ok": False, "error": "tx_id_conflict"}

        # Reflect computed stamps back into caller env for downstream consistency.
        env["tx_id"] = tx_id
        env["received_ms"] = received_ms
        env["expires_ms"] = expires_ms
        return {"ok": True, "tx_id": tx_id, "received_ms": received_ms, "expires_ms": expires_ms}

    def remove(self, env_or_tx_id: Any) -> Json:
        if isinstance(env_or_tx_id, str):
            tx_id = env_or_tx_id.strip()
        elif isinstance(env_or_tx_id, dict):
            tx_id = str(env_or_tx_id.get("tx_id") or "").strip() or compute_tx_id(env_or_tx_id)
        else:
            return {"ok": False, "error": "bad_arg"}

        if not tx_id:
            return {"ok": False, "error": "missing_tx_id"}

        with self.db.write_tx() as con:
            con.execute("DELETE FROM mempool WHERE tx_id=?;", (tx_id,))
        return {"ok": True, "tx_id": tx_id}

    def peek(self, *, limit: int = 1000) -> List[Json]:
        lim = int(limit) if int(limit) > 0 else 1000
        now = _now_ms()
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT envelope_json
                FROM mempool
                WHERE expires_ms > ?
                ORDER BY received_ms ASC, tx_id ASC
                LIMIT ?;
                """,
                (int(now), lim),
            ).fetchall()

        out: List[Json] = []
        for r in rows:
            try:
                env = json.loads(str(r["envelope_json"]))
            except Exception:
                continue
            if isinstance(env, dict):
                out.append(env)
        return out

    def size(self) -> int:
        with self.db.connection() as con:
            row = con.execute("SELECT COUNT(1) AS n FROM mempool;").fetchone()
            return int(row["n"]) if row is not None else 0

    def prune_expired(self) -> int:
        now = _now_ms()
        with self.db.write_tx() as con:
            cur = con.execute("DELETE FROM mempool WHERE expires_ms <= ?;", (int(now),))
            return int(cur.rowcount or 0)

    def list_by_signer(self, signer: str, *, limit: int = 500) -> List[Json]:
        s = str(signer).strip()
        if not s:
            return []
        lim = int(limit) if int(limit) > 0 else 500
        now = _now_ms()
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT envelope_json
                FROM mempool
                WHERE signer=? AND expires_ms > ?
                ORDER BY received_ms ASC, tx_id ASC
                LIMIT ?;
                """,
                (s, int(now), lim),
            ).fetchall()

        out: List[Json] = []
        for r in rows:
            try:
                env = json.loads(str(r["envelope_json"]))
            except Exception:
                continue
            if isinstance(env, dict):
                out.append(env)
        return out

    def dump_debug(self, *, limit: int = 200) -> Json:
        txs = self.peek(limit=limit)
        return {"ok": True, "items": txs, "count": len(txs)}
