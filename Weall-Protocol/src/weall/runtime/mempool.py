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


def _env_str(name: str, default: str) -> str:
    try:
        raw = os.environ.get(name)
        if raw is None:
            return str(default)
        s = str(raw)
        return s if s else str(default)
    except Exception:
        return str(default)


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


def compute_tx_id(env: Json, *, chain_id: str | None = None) -> str:
    """Compute a deterministic tx_id from envelope content.

    Notes:
      - We incorporate chain_id (if provided) to prevent cross-chain collisions.
      - We still ignore locally-stamped fields (tx_id/received_ms/expires_ms).
    """
    base = _envelope_for_id(env)
    if chain_id:
        # Only stamp if the envelope does not already declare a chain_id.
        # This keeps backward compatibility with callers that already include it.
        if "chain_id" not in base:
            base["chain_id"] = str(chain_id)
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
      - optional per-tx-type cap
      - optional prune-on-add to keep DB bounded without a separate cron
      - optional deterministic eviction on full (oldest-first)

    Env overrides:
      - WEALL_MEMPOOL_TTL_MS
      - WEALL_MEMPOOL_MAX
      - WEALL_MEMPOOL_MAX_PER_SIGNER
      - WEALL_MEMPOOL_MAX_PER_TX_TYPE
      - WEALL_MEMPOOL_PRUNE_ON_ADD
      - WEALL_MEMPOOL_PRUNE_INTERVAL_MS
      - WEALL_MEMPOOL_EVICT_ON_FULL
      - WEALL_MEMPOOL_EVICT_BATCH
    """

    db: SqliteDB
    chain_id: str = ""

    # Defaults are conservative for a public node.
    default_ttl_ms: int = 30 * 60 * 1000  # 30 minutes
    max_items: int = 50_000
    max_per_signer: int = 2_000
    max_per_tx_type: int = 0  # 0 disables
    prune_on_add: bool = True
    prune_interval_ms: int = 5_000
    evict_on_full: bool = False
    evict_batch: int = 64

    _last_prune_ms: int = 0

    def __post_init__(self) -> None:
        self.db.init_schema()

        # Chain id is used for tx_id derivation (avoid cross-chain collisions).
        if not str(self.chain_id or "").strip():
            self.chain_id = _env_str("WEALL_CHAIN_ID", "weall-devnet").strip() or "weall-devnet"

        # Allow env overrides without forcing callers to plumb config everywhere.
        self.default_ttl_ms = _env_int("WEALL_MEMPOOL_TTL_MS", self.default_ttl_ms)
        self.max_items = max(0, _env_int("WEALL_MEMPOOL_MAX", self.max_items))
        self.max_per_signer = max(0, _env_int("WEALL_MEMPOOL_MAX_PER_SIGNER", self.max_per_signer))
        self.max_per_tx_type = max(0, _env_int("WEALL_MEMPOOL_MAX_PER_TX_TYPE", self.max_per_tx_type))
        self.prune_on_add = _env_bool("WEALL_MEMPOOL_PRUNE_ON_ADD", self.prune_on_add)
        self.prune_interval_ms = max(0, _env_int("WEALL_MEMPOOL_PRUNE_INTERVAL_MS", self.prune_interval_ms))
        self.evict_on_full = _env_bool("WEALL_MEMPOOL_EVICT_ON_FULL", self.evict_on_full)
        self.evict_batch = max(1, _env_int("WEALL_MEMPOOL_EVICT_BATCH", self.evict_batch))

    def _count_total(self, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool;").fetchone()
        return int(row["n"]) if row is not None else 0

    def _count_signer(self, signer: str, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool WHERE signer=?;", (signer,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def _count_tx_type(self, tx_type: str, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool WHERE tx_type=?;", (tx_type,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def _prune_expired_if_due(self, *, con, now_ms: int) -> None:
        if not self.prune_on_add:
            return
        if self.prune_interval_ms <= 0:
            con.execute("DELETE FROM mempool WHERE expires_ms <= ?;", (int(now_ms),))
            self._last_prune_ms = int(now_ms)
            return
        if int(now_ms) - int(self._last_prune_ms) >= int(self.prune_interval_ms):
            con.execute("DELETE FROM mempool WHERE expires_ms <= ?;", (int(now_ms),))
            self._last_prune_ms = int(now_ms)

    def _evict_oldest(self, *, con, need: int, signer: str | None = None, tx_type: str | None = None) -> int:
        """Deterministically evict oldest items (received_ms ASC, tx_id ASC).

        Returns number of rows deleted.
        """

        n = max(0, int(need))
        if n <= 0:
            return 0

        where = []
        args: list[Any] = []
        if signer is not None:
            where.append("signer=?")
            args.append(str(signer))
        if tx_type is not None:
            where.append("tx_type=?")
            args.append(str(tx_type))

        where_sql = "WHERE " + " AND ".join(where) if where else ""
        lim = int(min(n, self.evict_batch))

        # Select victim tx_ids first to preserve deterministic order, then delete.
        rows = con.execute(
            f"""
            SELECT tx_id
            FROM mempool
            {where_sql}
            ORDER BY received_ms ASC, tx_id ASC
            LIMIT ?;
            """,
            tuple(args + [lim]),
        ).fetchall()

        if not rows:
            return 0

        tx_ids = [str(r["tx_id"]) for r in rows if r is not None and r.get("tx_id") is not None]
        if not tx_ids:
            return 0

        q = ",".join(["?"] * len(tx_ids))
        con.execute(f"DELETE FROM mempool WHERE tx_id IN ({q});", tuple(tx_ids))
        return len(tx_ids)

    def prune_expired(self, *, now_ms: int | None = None) -> int:
        """Prune expired mempool entries and return number removed.

        This is a local non-consensus maintenance operation used by the block loop.
        """
        now = int(_now_ms() if now_ms is None else int(now_ms))
        with self.db.write_tx() as con:
            # Count first for a deterministic return value.
            row = con.execute("SELECT COUNT(1) AS n FROM mempool WHERE expires_ms <= ?;", (now,)).fetchone()
            n = int(row["n"]) if row is not None else 0
            if n > 0:
                con.execute("DELETE FROM mempool WHERE expires_ms <= ?;", (now,))
            # Update last prune stamp to avoid immediate re-prune churn when prune_on_add is enabled.
            self._last_prune_ms = int(now)
            return int(n)

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
        tx_id = compute_tx_id(env, chain_id=self.chain_id)
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
            now = _now_ms()
            self._prune_expired_if_due(con=con, now_ms=int(now))

            # Enforce caps (if enabled). Reject by default. Optional deterministic eviction.
            if self.max_items > 0:
                n_total = self._count_total(con=con)
                if n_total >= self.max_items:
                    if self.evict_on_full:
                        need = (n_total - self.max_items) + 1
                        self._evict_oldest(con=con, need=int(need))
                        n2 = self._count_total(con=con)
                        if n2 >= self.max_items:
                            return {"ok": False, "error": "mempool_full", "details": {"max": self.max_items}}
                    else:
                        return {"ok": False, "error": "mempool_full", "details": {"max": self.max_items}}

            if self.max_per_signer > 0:
                n_s = self._count_signer(signer, con=con)
                if n_s >= self.max_per_signer:
                    if self.evict_on_full:
                        need = (n_s - self.max_per_signer) + 1
                        self._evict_oldest(con=con, need=int(need), signer=signer)
                        n_s2 = self._count_signer(signer, con=con)
                        if n_s2 >= self.max_per_signer:
                            return {
                                "ok": False,
                                "error": "mempool_signer_quota",
                                "details": {"signer": signer, "max": self.max_per_signer},
                            }
                    else:
                        return {
                            "ok": False,
                            "error": "mempool_signer_quota",
                            "details": {"signer": signer, "max": self.max_per_signer},
                        }

            if self.max_per_tx_type > 0:
                n_t = self._count_tx_type(tx_type, con=con)
                if n_t >= self.max_per_tx_type:
                    if self.evict_on_full:
                        need = (n_t - self.max_per_tx_type) + 1
                        self._evict_oldest(con=con, need=int(need), tx_type=tx_type)
                        n_t2 = self._count_tx_type(tx_type, con=con)
                        if n_t2 >= self.max_per_tx_type:
                            return {
                                "ok": False,
                                "error": "mempool_tx_type_quota",
                                "details": {"tx_type": tx_type, "max": self.max_per_tx_type},
                            }
                    else:
                        return {
                            "ok": False,
                            "error": "mempool_tx_type_quota",
                            "details": {"tx_type": tx_type, "max": self.max_per_tx_type},
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
            tx_id = str(env_or_tx_id.get("tx_id") or "").strip() or compute_tx_id(
                env_or_tx_id, chain_id=self.chain_id
            )
        else:
            return {"ok": False, "error": "bad_arg"}

        if not tx_id:
            return {"ok": False, "error": "missing_tx_id"}

        with self.db.write_tx() as con:
            con.execute("DELETE FROM mempool WHERE tx_id=?;", (tx_id,))
        return {"ok": True, "tx_id": tx_id}

    def contains(self, tx_id: str) -> bool:
        t = str(tx_id or "").strip()
        if not t:
            return False
        try:
            with self.db.connection() as con:
                row = con.execute("SELECT 1 AS ok FROM mempool WHERE tx_id=? LIMIT 1;", (t,)).fetchone()
                return row is not None
        except Exception:
            return False

    def size(self) -> int:
        try:
            with self.db.connection() as con:
                row = con.execute("SELECT COUNT(1) AS n FROM mempool;").fetchone()
                return int(row["n"]) if row is not None else 0
        except Exception:
            return 0

    def peek(self, *, limit: int = 1000) -> List[Json]:
        lim = int(limit) if int(limit) > 0 else 1000
        now = _now_ms()
        out: List[Json] = []
        try:
            with self.db.connection() as con:
                rows = con.execute(
                    """
                    SELECT envelope_json
                    FROM mempool
                    WHERE expires_ms > ?
                    ORDER BY received_ms ASC, tx_id ASC
                    LIMIT ?;
                    """,
                    (int(now), int(lim)),
                ).fetchall()
            for r in rows:
                try:
                    out.append(json.loads(str(r["envelope_json"])))
                except Exception:
                    out.append({})
        except Exception:
            return []
        return out
