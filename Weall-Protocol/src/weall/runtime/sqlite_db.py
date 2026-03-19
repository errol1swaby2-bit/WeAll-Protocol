from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

Json = dict[str, Any]


_PROCESS_LOCAL_WRITE_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCAL_WRITE_LOCKS_GUARD = threading.Lock()


def derive_aux_db_path(main_db_path: str) -> str:
    """Derive the non-consensus auxiliary DB path for a node.

    The auxiliary DB is intended for high-churn, non-consensus local data that
    should not contend with the consensus-critical ledger commit path.

    We intentionally keep the canonical ledger snapshot, blocks, tx index, and
    mempool in the main DB so block commit remains a single atomic transaction.
    """
    p = Path(str(main_db_path)).expanduser()
    suffix = "".join(p.suffixes)
    stem = p.name[: -len(suffix)] if suffix else p.name
    if not stem:
        stem = "weall"
    aux_name = f"{stem}.aux.sqlite"
    return str((p.parent / aux_name).resolve())


def _process_local_write_lock_for(path: str) -> threading.RLock:
    key = str(Path(str(path)).expanduser().resolve())
    with _PROCESS_LOCAL_WRITE_LOCKS_GUARD:
        lock = _PROCESS_LOCAL_WRITE_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCAL_WRITE_LOCKS[key] = lock
        return lock


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canon_json(obj: Any) -> str:
    """Canonical JSON encoding.

    Keep this stable across nodes.
    """
    # IMPORTANT: Do not silently coerce unknown types (e.g. default=str). If
    # non-JSON types leak into consensus or persisted structures, we must fail
    # fast to avoid non-determinism across nodes.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


class SqliteDB:
    """SQLite manager for WeAll node runtime.

    Design goals:
      - single durable DB file for ledger + queues
      - cross-process safe (SQLite locks)
      - cross-thread safe by never sharing connections

    Production note:
      SQLite allows only one writer at a time. Under multi-process workloads,
      BEGIN IMMEDIATE can transiently fail with "database is locked".
      We therefore implement a bounded retry loop in write_tx().
    """

    SCHEMA_VERSION = 1

    def __init__(self, *, path: str) -> None:
        self.path = str(path)

    @staticmethod
    def _sqlite_synchronous_pragma() -> str:
        """Return a safe PRAGMA synchronous value.

        SQLite durability is a production-critical knob.

        Defaults:
          - prod        -> FULL
          - dev/testnet -> NORMAL

        Override with WEALL_SQLITE_SYNCHRONOUS in {OFF,NORMAL,FULL,EXTRA}.
        """
        mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
        default = "FULL" if mode == "prod" else "NORMAL"
        raw = (os.environ.get("WEALL_SQLITE_SYNCHRONOUS") or default).strip().upper()

        allowed = {"OFF", "NORMAL", "FULL", "EXTRA"}
        if raw not in allowed:
            # Fail-safe: never accept unknown values.
            raw = default
        return raw

    def ensure_parent_dir(self) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        self.ensure_parent_dir()

        # sqlite3.connect(timeout=...) controls how long SQLite will wait internally
        # on locks for many operations. We also set PRAGMA busy_timeout to match.
        connect_timeout_s = float(_env_int("WEALL_SQLITE_CONNECT_TIMEOUT_MS", 30_000)) / 1000.0

        con = sqlite3.connect(
            self.path,
            timeout=connect_timeout_s,
            isolation_level=None,  # we manage BEGIN/COMMIT ourselves
            check_same_thread=False,
        )
        con.row_factory = sqlite3.Row

        # ---- Operational pragmas (production defaults) ----
        # Applied per-connection so every code path (read/write) shares the same
        # durability and concurrency behavior.

        # WAL improves concurrent read/write behavior and is strongly preferred.
        # In production we prefer to fail-closed if WAL cannot be enabled, since
        # rollback-journal mode is far more prone to writer contention.
        allow_non_wal = (os.environ.get("WEALL_SQLITE_ALLOW_NON_WAL") or "").strip() in {
            "1",
            "true",
            "TRUE",
        }
        try:
            row = con.execute("PRAGMA journal_mode=WAL;").fetchone()
            mode = ""
            if row is not None:
                # sqlite3.Row is indexable by position.
                mode = str(row[0]).strip().lower()
            if mode and mode != "wal" and not allow_non_wal:
                raise RuntimeError(f"sqlite journal_mode is '{mode}', expected 'wal'")
        except Exception:
            if not allow_non_wal:
                raise

        # Durability knob.
        con.execute(f"PRAGMA synchronous={self._sqlite_synchronous_pragma()};")

        # Safety.
        con.execute("PRAGMA foreign_keys=ON;")

        # Ensure temp objects stay in memory under load.
        con.execute("PRAGMA temp_store=MEMORY;")

        # Reduce risk of unbounded WAL growth.
        wal_ckpt = _env_int("WEALL_SQLITE_WAL_AUTOCHECKPOINT", 1000)
        wal_ckpt = max(1, int(wal_ckpt))
        con.execute(f"PRAGMA wal_autocheckpoint={wal_ckpt};")

        # Prefer a large-ish WAL for throughput but keep a hard cap via
        # journal_size_limit. A periodic checkpoint (see maintenance helpers
        # below) keeps disk usage and recovery times stable.

        # Cap journal size (WAL or rollback journal, depending on mode).
        jsl = _env_int("WEALL_SQLITE_JOURNAL_SIZE_LIMIT", 64 * 1024 * 1024)
        jsl = max(0, int(jsl))
        con.execute(f"PRAGMA journal_size_limit={jsl};")

        # Cache sizing: negative means KiB. Default 64 MiB.
        cache_kib = _env_int("WEALL_SQLITE_CACHE_SIZE_KIB", 64 * 1024)
        cache_kib = max(0, int(cache_kib))
        con.execute(f"PRAGMA cache_size={-cache_kib};")

        # Memory-mapped IO can help performance; allow disabling via env.
        mmap_bytes = _env_int("WEALL_SQLITE_MMAP_SIZE", 0)
        mmap_bytes = max(0, int(mmap_bytes))
        if mmap_bytes:
            con.execute(f"PRAGMA mmap_size={mmap_bytes};")

        # How long SQLite should wait when encountering locks.
        # Must be set per-connection.
        busy_ms = _env_int("WEALL_SQLITE_BUSY_TIMEOUT_MS", int(connect_timeout_s * 1000))
        busy_ms = max(0, int(busy_ms))
        con.execute(f"PRAGMA busy_timeout={busy_ms};")

        return con

    # -----------------------------------------------------------------
    # Maintenance (ops hardening)
    # -----------------------------------------------------------------

    def wal_checkpoint(self, *, mode: str = "PASSIVE") -> Json:
        """Run a WAL checkpoint.

        SQLite in WAL mode can accumulate large WAL files under sustained write
        load. Autocheckpoint helps, but an explicit periodic checkpoint provides
        more predictable disk usage and recovery time.

        Returns:
          {ok:bool, mode:str, busy:int, log:int, checkpointed:int}
        """
        m = str(mode or "PASSIVE").strip().upper()
        allowed = {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}
        if m not in allowed:
            m = "PASSIVE"

        with self.connection() as con:
            row = con.execute(f"PRAGMA wal_checkpoint({m});").fetchone()
            busy = int(row[0]) if row is not None and row[0] is not None else 0
            log = int(row[1]) if row is not None and row[1] is not None else 0
            ckpt = int(row[2]) if row is not None and row[2] is not None else 0
            return {"ok": True, "mode": m, "busy": busy, "log": log, "checkpointed": ckpt}

    def optimize(self) -> Json:
        """Run PRAGMA optimize (best-effort)."""
        with self.connection() as con:
            try:
                con.execute("PRAGMA optimize;")
                return {"ok": True}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def init_schema(self) -> None:
        # Schema creation takes write locks; do it with write_tx() so we inherit
        # the same bounded retry policy used for all other writes.
        with self.write_tx() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                """
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS ledger_state (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  height INTEGER NOT NULL,
                  block_id TEXT NOT NULL,
                  state_json TEXT NOT NULL,
                  updated_ts_ms INTEGER NOT NULL
                );
                """
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS blocks (
                  height INTEGER PRIMARY KEY,
                  block_id TEXT NOT NULL,
                  block_json TEXT NOT NULL,
                  created_ts_ms INTEGER NOT NULL
                );
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_blocks_block_id ON blocks(block_id);")
            # Helps retention/pruning scans (non-consensus operational index).
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocks_created_ts ON blocks(created_ts_ms);"
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS block_hash_index (
                  block_id TEXT PRIMARY KEY,
                  block_hash TEXT NOT NULL,
                  height INTEGER NOT NULL,
                  created_ts_ms INTEGER NOT NULL
                );
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_block_hash_index_height ON block_hash_index(height);"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_block_hash_index_hash ON block_hash_index(block_hash);"
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS tx_index (
                  tx_id TEXT PRIMARY KEY,
                  height INTEGER NOT NULL,
                  block_id TEXT NOT NULL,
                  tx_type TEXT NOT NULL,
                  signer TEXT NOT NULL,
                  nonce INTEGER NOT NULL,
                  ok INTEGER NOT NULL,
                  included_ts_ms INTEGER NOT NULL
                );
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_tx_index_height ON tx_index(height);")
            con.execute("CREATE INDEX IF NOT EXISTS idx_tx_index_block_id ON tx_index(block_id);")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_tx_index_signer_nonce ON tx_index(signer, nonce);"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_tx_index_included_ts ON tx_index(included_ts_ms);"
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS mempool (
                  tx_id TEXT PRIMARY KEY,
                  envelope_json TEXT NOT NULL,
                  signer TEXT NOT NULL,
                  tx_type TEXT NOT NULL,
                  received_ms INTEGER NOT NULL,
                  expires_ms INTEGER NOT NULL
                );
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_mempool_received ON mempool(received_ms);")
            con.execute("CREATE INDEX IF NOT EXISTS idx_mempool_signer ON mempool(signer);")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS attestations (
                  att_id TEXT PRIMARY KEY,
                  envelope_json TEXT NOT NULL,
                  block_id TEXT NOT NULL,
                  received_ms INTEGER NOT NULL,
                  expires_ms INTEGER NOT NULL
                );
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_atts_block_id ON attestations(block_id);")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS system_queue (
                  queue_id TEXT PRIMARY KEY,
                  envelope_json TEXT NOT NULL,
                  due_height INTEGER NOT NULL,
                  phase TEXT NOT NULL,
                  once INTEGER NOT NULL,
                  created_ms INTEGER NOT NULL
                );
                """
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_sysq_due ON system_queue(due_height);")
            con.execute("CREATE INDEX IF NOT EXISTS idx_sysq_phase ON system_queue(phase);")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS bft_candidates (
                  block_id TEXT PRIMARY KEY,
                  height INTEGER NOT NULL,
                  payload_json TEXT NOT NULL,
                  created_ms INTEGER NOT NULL
                );
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_bft_candidates_height ON bft_candidates(height);"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_bft_candidates_created ON bft_candidates(created_ms);"
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS bft_pending_artifacts (
                  kind TEXT NOT NULL,
                  block_id TEXT NOT NULL,
                  block_hash TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  created_ms INTEGER NOT NULL,
                  updated_ms INTEGER NOT NULL,
                  PRIMARY KEY (kind, block_id)
                );
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_bft_pending_artifacts_kind ON bft_pending_artifacts(kind);"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_bft_pending_artifacts_updated ON bft_pending_artifacts(updated_ms);"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_bft_pending_artifacts_block_hash ON bft_pending_artifacts(block_hash);"
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS ipfs_replication_jobs (
                  cid TEXT PRIMARY KEY,
                  job_json TEXT NOT NULL,
                  updated_ts_ms INTEGER NOT NULL
                );
                """
            )

            row = con.execute(
                "SELECT value FROM meta WHERE key='schema_version' LIMIT 1;"
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?);",
                    (str(self.SCHEMA_VERSION),),
                )
            else:
                try:
                    v = int(str(row["value"]))
                except Exception:
                    v = 0
                if v != self.SCHEMA_VERSION:
                    raise RuntimeError(
                        f"sqlite schema_version mismatch: have={v} want={self.SCHEMA_VERSION}. "
                        "Refuse to start to avoid corrupting data."
                    )

    # -----------------------------------------------------------------
    # Retention / pruning (ops hardening; non-consensus)
    # -----------------------------------------------------------------

    def prune_history(
        self,
        *,
        retain_last_blocks: int = 0,
        retain_blocks_ms: int = 0,
        retain_bft_candidates_ms: int = 0,
    ) -> Json:
        """Prune persisted history tables to bound disk growth.

        This is **non-consensus** operational maintenance:
          - pruning affects only local history availability (e.g. serving old blocks)
          - pruning must never mutate consensus state (ledger_state)

        Policy:
          - If retain_last_blocks > 0, always keep the most recent N blocks.
          - If retain_blocks_ms > 0, always keep blocks newer than now-retain_blocks_ms.
          - A block is eligible for deletion only if it is outside BOTH retention windows.

        Returns:
          {ok:bool, deleted_blocks:int, deleted_bft_candidates:int}
        """
        try:
            keep_n = max(0, int(retain_last_blocks))
        except Exception:
            keep_n = 0
        try:
            keep_ms = max(0, int(retain_blocks_ms))
        except Exception:
            keep_ms = 0
        try:
            cand_ms = max(0, int(retain_bft_candidates_ms))
        except Exception:
            cand_ms = 0

        now = _now_ms()

        deleted_blocks = 0
        deleted_cands = 0

        with self.write_tx() as con:
            # --- Blocks retention ---
            row = con.execute("SELECT MAX(height) AS h FROM blocks;").fetchone()
            max_h = int(row["h"]) if row is not None and row["h"] is not None else 0

            min_keep_height = 0
            if keep_n > 0 and max_h > 0:
                min_keep_height = max(1, max_h - keep_n + 1)

            min_keep_ts = 0
            if keep_ms > 0:
                min_keep_ts = max(0, now - keep_ms)

            if (min_keep_height > 0) or (min_keep_ts > 0):
                if min_keep_height <= 0:
                    cur = con.execute(
                        "DELETE FROM blocks WHERE created_ts_ms < ?;",
                        (int(min_keep_ts),),
                    )
                    deleted_blocks = int(cur.rowcount or 0)
                elif min_keep_ts <= 0:
                    cur = con.execute(
                        "DELETE FROM blocks WHERE height < ?;",
                        (int(min_keep_height),),
                    )
                    deleted_blocks = int(cur.rowcount or 0)
                else:
                    cur = con.execute(
                        "DELETE FROM blocks WHERE height < ? AND created_ts_ms < ?;",
                        (int(min_keep_height), int(min_keep_ts)),
                    )
                    deleted_blocks = int(cur.rowcount or 0)

            # --- BFT candidates retention ---
            if cand_ms > 0:
                min_cand_ts = max(0, now - cand_ms)
                cur = con.execute(
                    "DELETE FROM bft_candidates WHERE created_ms < ?;",
                    (int(min_cand_ts),),
                )
                deleted_cands = int(cur.rowcount or 0)

        return {
            "ok": True,
            "deleted_blocks": int(deleted_blocks),
            "deleted_bft_candidates": int(deleted_cands),
        }

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        con = self._connect()
        try:
            yield con
        finally:
            try:
                con.close()
            except Exception:
                pass

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Back-compat alias for older code that used db.connect().

        Prefer `connection()` for new code.
        """
        with self.connection() as con:
            yield con

    @staticmethod
    def _is_locked_error(e: Exception) -> bool:
        msg = str(e).lower()
        return (
            ("database is locked" in msg)
            or ("database is busy" in msg)
            or ("locked" in msg and "database" in msg)
        )

    @contextmanager
    def write_tx(self) -> Iterator[sqlite3.Connection]:
        """Open a write transaction with bounded retry on writer-lock contention.

        Why:
          Under multi-process concurrency, multiple writers will contend. SQLite allows
          only one writer at a time. `BEGIN IMMEDIATE` can raise OperationalError if a
          competing writer holds the lock.

        Policy:
          - retry BEGIN IMMEDIATE until a deadline
          - exponential backoff with jitter
          - then raise (fail closed) if we cannot acquire within deadline
        """
        # Total time we are willing to spend trying to acquire the write lock.
        deadline_ms = _env_int("WEALL_SQLITE_WRITE_DEADLINE_MS", 30_000)
        deadline_ms = max(250, int(deadline_ms))
        deadline_ts = _now_ms() + deadline_ms

        # Backoff tuning
        base_sleep = float(_env_int("WEALL_SQLITE_WRITE_BACKOFF_BASE_MS", 5)) / 1000.0
        max_sleep = float(_env_int("WEALL_SQLITE_WRITE_BACKOFF_MAX_MS", 250)) / 1000.0
        base_sleep = max(0.001, base_sleep)
        max_sleep = max(base_sleep, max_sleep)

        process_local_lock_enabled = str(
            os.environ.get("WEALL_SQLITE_PROCESS_LOCAL_WRITE_MUTEX", "1") or "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        process_local_lock = (
            _process_local_write_lock_for(self.path) if process_local_lock_enabled else None
        )

        with self.connection() as con:
            ctx = process_local_lock if process_local_lock is not None else nullcontext()
            with ctx:
                attempt = 0
                while True:
                    try:
                        con.execute("BEGIN IMMEDIATE;")
                        break
                    except sqlite3.OperationalError as e:
                        if not self._is_locked_error(e):
                            raise
                        if _now_ms() >= deadline_ts:
                            # Keep original exception context; this is a real failure.
                            raise
                        # exponential backoff with jitter
                        sleep_s = min(max_sleep, base_sleep * (2.0 ** min(attempt, 8)))
                        sleep_s = sleep_s * (0.5 + random.random())  # jitter in [0.5x, 1.5x]
                        time.sleep(sleep_s)
                        attempt += 1

                try:
                    yield con

                    # COMMIT can also transiently fail under contention (rare but
                    # possible when other connections are checkpointing). Treat it
                    # with the same bounded retry policy.
                    c_attempt = 0
                    while True:
                        try:
                            con.execute("COMMIT;")
                            break
                        except sqlite3.OperationalError as e:
                            if not self._is_locked_error(e):
                                raise
                            if _now_ms() >= deadline_ts:
                                raise
                            sleep_s = min(max_sleep, base_sleep * (2.0 ** min(c_attempt, 8)))
                            sleep_s = sleep_s * (0.5 + random.random())
                            time.sleep(sleep_s)
                            c_attempt += 1
                except Exception:
                    try:
                        con.execute("ROLLBACK;")
                    except Exception:
                        pass
                    raise


class SqliteLedgerStore:
    """Ledger snapshot store persisted in SQLite.

    This provides:
      - atomic read/write of the ledger snapshot JSON
      - future-friendly schema upgrades
    """

    def __init__(self, *, db: SqliteDB) -> None:
        self.db = db

    def exists(self) -> bool:
        with self.db.connection() as con:
            row = con.execute("SELECT height FROM ledger_state WHERE id=1;").fetchone()
            return row is not None

    def read(self) -> Json:
        with self.db.connection() as con:
            row = con.execute("SELECT state_json FROM ledger_state WHERE id=1;").fetchone()
            if row is None:
                raise RuntimeError("ledger_state missing")
            return json.loads(row["state_json"])

    def write(self, state: Json) -> None:
        payload = _canon_json(state)
        with self.db.write_tx() as con:
            # NOTE: block_id is persisted separately in some schemas; we keep it here for consistency.
            height = int(state.get("height") or 0)
            block_id = str(state.get("tip") or "")
            con.execute(
                "INSERT OR REPLACE INTO ledger_state(id, height, block_id, state_json, updated_ts_ms) VALUES(1,?,?,?,?);",
                (height, block_id, payload, _now_ms()),
            )

    # -----------------------------------------------------------------
    # Test/back-compat helpers
    # -----------------------------------------------------------------

    def write_state_snapshot(self, state: Json) -> None:
        """Back-compat alias used by tests.

        The production API is `write(state)`; this is a thin alias.
        """
        self.write(state)

    def update(self, fn: Callable[[Json], Any]) -> Json:
        """Read-modify-write update guarded by a single SQLite write transaction.

        This is the cross-process safe primitive used by tests and by production
        components that must atomically update the ledger snapshot.
        """
        if not callable(fn):
            raise TypeError("fn must be callable")

        with self.db.write_tx() as con:
            row = con.execute("SELECT state_json FROM ledger_state WHERE id=1;").fetchone()
            if row is None:
                raise RuntimeError("ledger_state missing")

            try:
                cur = json.loads(row["state_json"])
            except Exception as e:
                raise RuntimeError("ledger_state corrupted") from e

            if not isinstance(cur, dict):
                raise RuntimeError("ledger_state corrupted:not_object")

            tmp = dict(cur)
            res = fn(tmp)
            # Allow in-place mutation functions (returning None), or returning a new dict.
            nxt = tmp if res is None else res
            if not isinstance(nxt, dict):
                raise TypeError("update fn must mutate a dict or return a dict")

            payload = _canon_json(nxt)
            height = int(nxt.get("height") or 0)
            block_id = str(nxt.get("tip") or "")
            con.execute(
                "INSERT OR REPLACE INTO ledger_state(id, height, block_id, state_json, updated_ts_ms) VALUES(1,?,?,?,?);",
                (height, block_id, payload, _now_ms()),
            )
            return nxt
