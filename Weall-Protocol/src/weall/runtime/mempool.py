from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from weall.runtime.sqlite_db import SqliteDB, _canon_json

Json = dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _mode() -> str:
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    s = str(raw).strip()
    if not s:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}")
        return int(default)
    try:
        return int(s)
    except Exception:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}")
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        if _mode() == "prod":
            raise ValueError(f"invalid_boolean_env:{name}")
        return bool(default)
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    if _mode() == "prod":
        raise ValueError(f"invalid_boolean_env:{name}")
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


def _selection_policy_name(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in {"canonical", "canon", "stable", "deterministic"}:
        return "canonical"
    return "fifo"


def _read_selection_policy(name: str = "WEALL_MEMPOOL_SELECTION_POLICY", *, default: str = "canonical") -> str:
    raw = os.environ.get(name)
    if raw is None:
        normalized_default = _selection_policy_name(default)
        if _mode() == "prod" and normalized_default != "canonical":
            raise ValueError(f"invalid_mempool_selection_policy_env:{name}")
        return normalized_default
    s = str(raw).strip()
    if not s:
        if _mode() == "prod":
            raise ValueError(f"invalid_mempool_selection_policy_env:{name}")
        return _selection_policy_name(default)
    normalized = _selection_policy_name(s)
    if normalized == "fifo":
        if _mode() == "prod":
            raise ValueError(f"invalid_mempool_selection_policy_env:{name}")
        if str(s).strip().lower() not in {"fifo", "first_seen", "arrival", "arrival_order"}:
            raise ValueError(f"invalid_mempool_selection_policy_env:{name}")
    return normalized


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


def _extract_nonce(env: Json) -> int | None:
    try:
        if not isinstance(env, dict):
            return None
        raw = env.get("nonce")
        if raw is None:
            return None
        return int(raw)
    except Exception:
        return None


def _matching_signer_nonce_entry(*, con, signer: str, nonce: int) -> tuple[str, Json] | None:
    """Return the mempool item for (signer, nonce), if any.

    Production hardening: the mempool persists ``nonce`` as a first-class column and
    maintains an index on ``(signer, nonce)`` so conflict checks remain bounded even
    under large same-signer bursts. As a safety backstop for legacy rows created
    before the nonce column existed or before a startup backfill completed, we still
    perform a deterministic envelope scan only if the indexed lookup does not find a
    match.
    """

    row = con.execute(
        """
        SELECT tx_id, envelope_json
        FROM mempool
        WHERE signer=? AND nonce=?
        ORDER BY received_ms ASC, tx_id ASC
        LIMIT 1;
        """,
        (str(signer), int(nonce)),
    ).fetchone()
    if row is not None:
        try:
            env_existing = json.loads(str(row["envelope_json"]))
        except Exception:
            env_existing = {}
        return str(row["tx_id"]), env_existing

    rows = con.execute(
        """
        SELECT tx_id, envelope_json
        FROM mempool
        WHERE signer=?
        ORDER BY received_ms ASC, tx_id ASC;
        """,
        (str(signer),),
    ).fetchall()
    for row in rows:
        if row is None:
            continue
        try:
            env_existing = json.loads(str(row["envelope_json"]))
        except Exception:
            continue
        existing_nonce = _extract_nonce(env_existing)
        if existing_nonce is not None and int(existing_nonce) == int(nonce):
            return str(row["tx_id"]), env_existing
    return None


@dataclass
class PersistentMempool:
    """SQLite-backed mempool.

    Table schema:
      mempool(tx_id PK, envelope_json, signer, tx_type, nonce, received_ms, expires_ms)

    Admission hardening:
      - at most one pending tx per (signer, nonce) pair (indexed in SQLite)
      - exact duplicates are rejected deterministically as tx_id_conflict
      - conflicting same-signer/same-nonce envelopes are rejected

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
    _selection_policy: str = "canonical"

    def __post_init__(self) -> None:
        self.db.init_schema()

        # Chain id is consensus-relevant for tx_id derivation. Prefer the explicit
        # executor-supplied chain id; only fall back to environment for legacy callers.
        explicit_chain_id = str(self.chain_id or "").strip()
        if explicit_chain_id:
            self.chain_id = explicit_chain_id
        else:
            env_chain_id = _env_str("WEALL_CHAIN_ID", "").strip()
            if _mode() == "prod":
                raise ValueError(
                    "PersistentMempool requires an explicit chain_id in production"
                )
            if not env_chain_id:
                raise ValueError(
                    "PersistentMempool requires an explicit chain_id or WEALL_CHAIN_ID"
                )
            self.chain_id = env_chain_id

        # Allow env overrides without forcing callers to plumb config everywhere.
        self.default_ttl_ms = _env_int("WEALL_MEMPOOL_TTL_MS", self.default_ttl_ms)
        self.max_items = max(0, _env_int("WEALL_MEMPOOL_MAX", self.max_items))
        self.max_per_signer = max(0, _env_int("WEALL_MEMPOOL_MAX_PER_SIGNER", self.max_per_signer))
        self.max_per_tx_type = max(
            0, _env_int("WEALL_MEMPOOL_MAX_PER_TX_TYPE", self.max_per_tx_type)
        )
        self.prune_on_add = _env_bool("WEALL_MEMPOOL_PRUNE_ON_ADD", self.prune_on_add)
        self.prune_interval_ms = max(
            0, _env_int("WEALL_MEMPOOL_PRUNE_INTERVAL_MS", self.prune_interval_ms)
        )
        self.evict_on_full = _env_bool("WEALL_MEMPOOL_EVICT_ON_FULL", self.evict_on_full)
        self.evict_batch = max(1, _env_int("WEALL_MEMPOOL_EVICT_BATCH", self.evict_batch))
        self._selection_policy = _read_selection_policy()
        self._ensure_nonce_index_ready()

    def _count_total(self, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool;").fetchone()
        return int(row["n"]) if row is not None else 0

    def _count_signer(self, signer: str, *, con) -> int:
        row = con.execute("SELECT COUNT(1) AS n FROM mempool WHERE signer=?;", (signer,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def _count_tx_type(self, tx_type: str, *, con) -> int:
        row = con.execute(
            "SELECT COUNT(1) AS n FROM mempool WHERE tx_type=?;", (tx_type,)
        ).fetchone()
        return int(row["n"]) if row is not None else 0

    def _mempool_has_nonce_column(self, *, con) -> bool:
        rows = con.execute("PRAGMA table_info(mempool);").fetchall()
        for row in rows:
            try:
                if str(row["name"]) == "nonce":
                    return True
            except Exception:
                continue
        return False

    def _add_nonce_column_if_missing(self, *, con) -> None:
        if self._mempool_has_nonce_column(con=con):
            return
        con.execute("ALTER TABLE mempool ADD COLUMN nonce INTEGER;")

    def _backfill_nonce_column(self, *, con) -> None:
        rows = con.execute(
            """
            SELECT tx_id, signer, envelope_json
            FROM mempool
            WHERE nonce IS NULL
            ORDER BY received_ms ASC, tx_id ASC;
            """
        ).fetchall()
        seen: dict[tuple[str, int], str] = {}
        for row in rows:
            if row is None:
                continue
            tx_id = str(row["tx_id"])
            signer = str(row["signer"])
            try:
                env = json.loads(str(row["envelope_json"]))
            except Exception as exc:
                raise ValueError(f"mempool_nonce_backfill_bad_envelope:{tx_id}") from exc
            nonce = _extract_nonce(env)
            if nonce is None:
                continue
            key = (signer, int(nonce))
            other_tx_id = seen.get(key)
            if other_tx_id is not None and other_tx_id != tx_id:
                raise ValueError(
                    f"mempool_nonce_backfill_conflict:{signer}:{int(nonce)}:{other_tx_id}:{tx_id}"
                )
            existing = con.execute(
                """
                SELECT tx_id
                FROM mempool
                WHERE signer=? AND nonce=? AND tx_id<>?
                ORDER BY received_ms ASC, tx_id ASC
                LIMIT 1;
                """,
                (signer, int(nonce), tx_id),
            ).fetchone()
            if existing is not None:
                raise ValueError(
                    f"mempool_nonce_backfill_conflict:{signer}:{int(nonce)}:{str(existing['tx_id'])}:{tx_id}"
                )
            con.execute("UPDATE mempool SET nonce=? WHERE tx_id=?;", (int(nonce), tx_id))
            seen[key] = tx_id

    def _ensure_nonce_indexes(self, *, con) -> None:
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_mempool_signer_nonce_lookup ON mempool(signer, nonce);"
        )
        con.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mempool_signer_nonce_unique
            ON mempool(signer, nonce)
            WHERE nonce IS NOT NULL;
            """
        )

    def _ensure_nonce_index_ready(self) -> None:
        with self.db.write_tx() as con:
            self._add_nonce_column_if_missing(con=con)
            self._backfill_nonce_column(con=con)
            self._ensure_nonce_indexes(con=con)

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

    def _evict_oldest(
        self, *, con, need: int, signer: str | None = None, tx_type: str | None = None
    ) -> int:
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
            row = con.execute(
                "SELECT COUNT(1) AS n FROM mempool WHERE expires_ms <= ?;", (now,)
            ).fetchone()
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

        requested_received_ms = _now_ms()
        expires_ms = _expires_ms(env, fallback_ttl_ms=self.default_ttl_ms)

        with self.db.write_tx() as con:
            now = _now_ms()
            self._prune_expired_if_due(con=con, now_ms=int(now))

            row_last = con.execute(
                "SELECT MAX(received_ms) AS last_received_ms FROM mempool;"
            ).fetchone()
            last_received_ms = (
                int(row_last["last_received_ms"])
                if row_last is not None and row_last["last_received_ms"] is not None
                else 0
            )
            received_ms = int(requested_received_ms)
            if received_ms <= last_received_ms:
                received_ms = int(last_received_ms) + 1

            # Persist canonical envelope including computed stamps (but id derived from base fields).
            env_persist: Json = dict(env)
            env_persist["tx_id"] = tx_id
            env_persist["received_ms"] = received_ms
            env_persist["expires_ms"] = expires_ms
            env_json = _canon_json(env_persist)

            nonce = _extract_nonce(env)
            if nonce is not None:
                existing = _matching_signer_nonce_entry(con=con, signer=signer, nonce=int(nonce))
                if existing is not None:
                    existing_tx_id, existing_env = existing
                    existing_base = _canon_json(_envelope_for_id(existing_env))
                    incoming_base = _canon_json(_envelope_for_id(env))
                    if existing_base == incoming_base:
                        return {
                            "ok": False,
                            "error": "tx_id_conflict",
                            "details": {
                                "signer": signer,
                                "nonce": int(nonce),
                                "existing_tx_id": existing_tx_id,
                            },
                        }
                    return {
                        "ok": False,
                        "error": "mempool_signer_nonce_conflict",
                        "details": {
                            "signer": signer,
                            "nonce": int(nonce),
                            "existing_tx_id": existing_tx_id,
                        },
                    }

            # Enforce caps (if enabled). Reject by default. Optional deterministic eviction.
            if self.max_items > 0:
                n_total = self._count_total(con=con)
                if n_total >= self.max_items:
                    if self.evict_on_full:
                        need = (n_total - self.max_items) + 1
                        self._evict_oldest(con=con, need=int(need))
                        n2 = self._count_total(con=con)
                        if n2 >= self.max_items:
                            return {
                                "ok": False,
                                "error": "mempool_full",
                                "details": {"max": self.max_items},
                            }
                    else:
                        return {
                            "ok": False,
                            "error": "mempool_full",
                            "details": {"max": self.max_items},
                        }

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
                INSERT OR IGNORE INTO mempool(
                    tx_id, envelope_json, signer, tx_type, nonce, received_ms, expires_ms
                )
                VALUES(?, ?, ?, ?, ?, ?, ?);
                """,
                (tx_id, env_json, signer, tx_type, nonce, int(received_ms), int(expires_ms)),
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
                row = con.execute(
                    "SELECT 1 AS ok FROM mempool WHERE tx_id=? LIMIT 1;", (t,)
                ).fetchone()
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

    def selection_policy(self) -> str:
        return str(self._selection_policy or "canonical")

    def _selection_key(self, env: Json) -> tuple[str, int, str, str, str]:
        signer = str(env.get("signer") or "").strip()
        nonce = _extract_nonce(env)
        tx_type = str(env.get("tx_type") or "").strip()
        tx_id = str(env.get("tx_id") or compute_tx_id(env, chain_id=self.chain_id)).strip()
        chain_id = str(env.get("chain_id") or self.chain_id or "").strip()
        return (chain_id, int(nonce or 0), signer, tx_type, tx_id)

    def _decode_rows(self, rows: list[Any]) -> list[tuple[Json, int, str]]:
        out: list[tuple[Json, int, str]] = []
        for r in rows:
            try:
                env = json.loads(str(r["envelope_json"]))
            except Exception:
                env = {}
            out.append((env, int(r["received_ms"]), str(r["tx_id"])))
        return out

    def _load_live_rows_fifo(self, *, now_ms: int, limit: int) -> list[tuple[Json, int, str]]:
        lim = int(limit) if int(limit) > 0 else 1000
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT envelope_json, received_ms, tx_id
                FROM mempool
                WHERE expires_ms > ?
                ORDER BY received_ms ASC, tx_id ASC
                LIMIT ?;
                """,
                (int(now_ms), int(lim)),
            ).fetchall()
        return self._decode_rows(list(rows or []))

    def _load_live_rows_canonical(self, *, now_ms: int, limit: int) -> list[tuple[Json, int, str]]:
        lim = int(limit) if int(limit) > 0 else 1000
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT envelope_json, received_ms, tx_id
                FROM mempool
                WHERE expires_ms > ?
                ORDER BY nonce ASC, signer ASC, tx_type ASC, tx_id ASC
                LIMIT ?;
                """,
                (int(now_ms), int(lim)),
            ).fetchall()
        return self._decode_rows(list(rows or []))

    def fetch_for_block(self, *, limit: int = 1000, policy: str | None = None) -> list[Json]:
        lim = int(limit) if int(limit) > 0 else 1000
        pol = _selection_policy_name(policy or self.selection_policy())
        now = _now_ms()
        try:
            if pol == "canonical":
                rows = self._load_live_rows_canonical(now_ms=now, limit=lim)
            else:
                rows = self._load_live_rows_fifo(now_ms=now, limit=lim)
        except Exception:
            return []
        if pol == "canonical":
            rows.sort(key=lambda item: self._selection_key(item[0]))
        return [dict(env) if isinstance(env, dict) else {} for env, _received_ms, _tx_id in rows]

    def selection_diagnostics(self, *, limit: int = 10, policy: str | None = None) -> Json:
        lim = int(limit) if int(limit) > 0 else 10
        pol = _selection_policy_name(policy or self.selection_policy())
        try:
            if pol == "canonical":
                rows = self._load_live_rows_canonical(now_ms=_now_ms(), limit=lim)
            else:
                rows = self._load_live_rows_fifo(now_ms=_now_ms(), limit=lim)
        except Exception as exc:
            return {
                "policy": pol,
                "preview_limit": lim,
                "error": type(exc).__name__,
                "items": [],
            }
        ordered = list(rows)
        if pol == "canonical":
            ordered.sort(key=lambda item: self._selection_key(item[0]))
        items: list[Json] = []
        for env, received_ms, tx_id in ordered:
            base = dict(env) if isinstance(env, dict) else {}
            items.append(
                {
                    "tx_id": str(base.get("tx_id") or tx_id),
                    "tx_type": str(base.get("tx_type") or ""),
                    "signer": str(base.get("signer") or ""),
                    "nonce": int(_extract_nonce(base) or 0),
                    "received_ms": int(base.get("received_ms") or received_ms),
                    "order_key": list(self._selection_key(base)),
                }
            )
        return {
            "policy": pol,
            "preview_limit": lim,
            "size": self.size(),
            "items": items,
        }

    def peek(self, *, limit: int = 1000) -> list[Json]:
        return self.fetch_for_block(limit=limit, policy=self.selection_policy())
