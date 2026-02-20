# src/weall/runtime/sqlite_db.py
from __future__ import annotations

import os
import json
import sqlite3
import time
import random
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator

Json = Dict[str, Any]


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


def _env_int(name: str, default: int) -> int:
    try:
        raw = str(os.environ.get(name, "")).strip()
        return int(raw) if raw else int(default)
    except Exception:
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
        allow_non_wal = (os.environ.get("WEALL_SQLITE_ALLOW_NON_WAL") or "").strip() in {"1", "true", "TRUE"}
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
            con.execute("CREATE INDEX IF NOT EXISTS idx_atts_received ON attestations(received_ms);")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS poh_email_verifications (
                  account TEXT PRIMARY KEY,
                  contact_hash TEXT NOT NULL,
                  pubkey TEXT NOT NULL,
                  token_hash TEXT,
                  created_ts_ms INTEGER NOT NULL,
                  expires_ts_ms INTEGER NOT NULL,
                  attempts INTEGER NOT NULL,
                  verified INTEGER NOT NULL
                );
                """
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

            row = con.execute("SELECT value FROM meta WHERE key='schema_version' LIMIT 1;").fetchone()
            if row is None:
                con.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?);", (str(self.SCHEMA_VERSION),))
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

    @staticmethod
    def _is_locked_error(e: Exception) -> bool:
        msg = str(e).lower()
        return ("database is locked" in msg) or ("database is busy" in msg) or ("locked" in msg and "database" in msg)

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

        with self.connection() as con:
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
      - read(): load latest ledger snapshot
      - write(st): overwrite the snapshot atomically
      - update(mut): read-modify-write inside a single write transaction

    The store is intentionally simple: the authoritative snapshot is a single row.
    """

    def __init__(self, *, db: SqliteDB) -> None:
        self._db = db
        self._db.init_schema()

    def exists(self) -> bool:
        with self._db.connection() as con:
            return con.execute("SELECT 1 FROM ledger_state WHERE id=1;").fetchone() is not None

    def read(self) -> Json:
        with self._db.connection() as con:
            row = con.execute("SELECT state_json FROM ledger_state WHERE id=1;").fetchone()
            if row is None:
                raise FileNotFoundError("sqlite ledger_state is missing")
            st = json.loads(str(row["state_json"]))
            if not isinstance(st, dict):
                raise ValueError("ledger_state is not a JSON object")
            return st

    def write(self, st: Json) -> None:
        if not isinstance(st, dict):
            raise ValueError("ledger write expects dict")
        height = int(st.get("height", 0))
        block_id = str(st.get("tip") or "").strip()
        now = _now_ms()
        payload = _canon_json(st)
        with self._db.write_tx() as con:
            con.execute(
                """
                INSERT INTO ledger_state(id, height, block_id, state_json, updated_ts_ms)
                VALUES(1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  height=excluded.height,
                  block_id=excluded.block_id,
                  state_json=excluded.state_json,
                  updated_ts_ms=excluded.updated_ts_ms;
                """,
                (height, block_id, payload, now),
            )

    def update(self, mut: Callable[[Json], Any]) -> None:
        with self._db.write_tx() as con:
            row = con.execute("SELECT state_json FROM ledger_state WHERE id=1;").fetchone()
            if row is None:
                raise FileNotFoundError("sqlite ledger_state is missing")
            st = json.loads(str(row["state_json"]))
            if not isinstance(st, dict):
                raise ValueError("ledger_state is not a JSON object")

            mut(st)

            height = int(st.get("height", 0))
            block_id = str(st.get("tip") or "").strip()
            now = _now_ms()
            payload = _canon_json(st)
            con.execute(
                "UPDATE ledger_state SET height=?, block_id=?, state_json=?, updated_ts_ms=? WHERE id=1;",
                (height, block_id, payload, now),
            )
