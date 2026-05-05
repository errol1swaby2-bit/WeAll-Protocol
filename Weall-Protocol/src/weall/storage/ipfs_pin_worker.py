from __future__ import annotations

"""Node-local IPFS pin queue worker.

This module is deliberately outside consensus execution. It stores operator-local
pin work in the auxiliary SQLite database derived from the node's main DB path,
so high-churn storage service work does not contend with consensus-critical
ledger writes.
"""

import json
import os
import sqlite3
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from weall.runtime.sqlite_db import derive_aux_db_path
from weall.util.ipfs_cid import validate_ipfs_cid

Json = dict[str, Any]
T = TypeVar("T")

_DEFAULT_IPFS_API_URL = "http://127.0.0.1:5001"
_DEFAULT_MAX_ATTEMPTS = 12


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return bool(default)
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    if _mode() == "prod":
        raise ValueError(f"invalid_boolean_env:{name}")
    return bool(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception as exc:
        if _mode() == "prod":
            raise ValueError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _valid_http_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _env_url(name: str, default: str) -> str:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    value = str(raw).strip().rstrip("/")
    if _valid_http_url(value):
        return value
    if _mode() == "prod":
        raise ValueError(f"invalid_url_env:{name}")
    return default


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_loads_obj(text: str) -> Json:
    try:
        obj = json.loads(text or "{}")
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _json_loads_list(text: str) -> list[str]:
    try:
        obj = json.loads(text or "[]")
    except Exception:
        return []
    if not isinstance(obj, list):
        return []
    out: list[str] = []
    for item in obj:
        value = str(item or "").strip()
        if value and value not in out:
            out.append(value)
    return out


class _LocalPinDB:
    def __init__(self, *, path: str) -> None:
        self.path = str(path)

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        con = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA busy_timeout=5000;")
        return con

    def execute_write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE;")
            result = fn(con)
            con.execute("COMMIT;")
            return result
        except Exception:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            con.close()

    def execute_read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        con = self._connect()
        try:
            return fn(con)
        finally:
            con.close()


@dataclass(frozen=True)
class IpfsPinWorkerConfig:
    db_path: str
    operator_account: str
    dry_run: bool = False
    max_jobs: int = 25
    ipfs_enabled: bool | None = None
    ipfs_api_url: str | None = None
    max_attempts: int | None = None
    request_timeout_s: int = 10

    def __post_init__(self) -> None:
        if not str(self.db_path or "").strip():
            raise ValueError("db_path_required")
        if not str(self.operator_account or "").strip():
            raise ValueError("operator_account_required")

        ipfs_enabled = self.ipfs_enabled
        if ipfs_enabled is None:
            ipfs_enabled = _env_bool("WEALL_IPFS_ENABLED", False)
        object.__setattr__(self, "ipfs_enabled", bool(ipfs_enabled))

        max_attempts = self.max_attempts
        if max_attempts is None:
            max_attempts = _env_int("WEALL_IPFS_MAX_ATTEMPTS", _DEFAULT_MAX_ATTEMPTS)
        object.__setattr__(self, "max_attempts", max(1, int(max_attempts)))

        api_url = self.ipfs_api_url
        if api_url is None:
            raw = os.environ.get("WEALL_IPFS_API_URL")
            env_name = "WEALL_IPFS_API_URL"
            if raw is None or str(raw).strip() == "":
                raw = os.environ.get("WEALL_IPFS_API_BASE")
                env_name = "WEALL_IPFS_API_BASE"
            if raw is None or str(raw).strip() == "":
                api_url = _DEFAULT_IPFS_API_URL
            else:
                api_url = _env_url(env_name, _DEFAULT_IPFS_API_URL)
        else:
            api_url = str(api_url).strip().rstrip("/")
            if not _valid_http_url(api_url):
                raise ValueError("invalid_url:ipfs_api_url")
        object.__setattr__(self, "ipfs_api_url", api_url)

        object.__setattr__(self, "max_jobs", max(1, int(self.max_jobs or 1)))
        object.__setattr__(self, "request_timeout_s", max(1, int(self.request_timeout_s or 1)))


class IpfsPinWorker:
    def __init__(self, config: IpfsPinWorkerConfig) -> None:
        self.config = config
        self.operator_account = str(config.operator_account).strip()
        self.db = _LocalPinDB(path=derive_aux_db_path(config.db_path))
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        def _write(con: sqlite3.Connection) -> None:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS ipfs_pin_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cid TEXT NOT NULL,
                    targets_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    last_error TEXT NOT NULL DEFAULT '',
                    meta_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_ipfs_pin_jobs_status_id ON ipfs_pin_jobs(status, id);"
            )

        self.db.execute_write(_write)

    def enqueue_job(
        self,
        cid: str,
        *,
        targets: list[str] | tuple[str, ...] | None = None,
        meta: Json | None = None,
    ) -> Json:
        cid_s = str(cid or "").strip()
        if not cid_s:
            return {"ok": False, "reason": "missing_cid"}

        # Tests and local demos use deterministic pseudo-CIDs such as cid:demo1.
        # Real IPFS CIDs are validated before entering the local queue.
        if not cid_s.startswith("cid:"):
            valid = validate_ipfs_cid(cid_s)
            if not valid.ok:
                return {"ok": False, "reason": f"invalid_cid:{valid.reason}"}

        clean_targets: list[str] = []
        for target in targets or []:
            value = str(target or "").strip()
            if value and value not in clean_targets:
                clean_targets.append(value)

        now = _now_ms()

        def _write(con: sqlite3.Connection) -> int:
            cur = con.execute(
                """
                INSERT INTO ipfs_pin_jobs(
                    cid, targets_json, status, attempts, created_ms, updated_ms, last_error, meta_json
                ) VALUES (?, ?, 'queued', 0, ?, ?, '', ?)
                """,
                (
                    cid_s,
                    json.dumps(clean_targets, sort_keys=True, separators=(",", ":")),
                    now,
                    now,
                    json.dumps(meta or {}, sort_keys=True, separators=(",", ":")),
                ),
            )
            return int(cur.lastrowid or 0)

        job_id = int(self.db.execute_write(_write) or 0)
        return {"ok": True, "job_id": job_id, "cid": cid_s, "targets": clean_targets}

    def _row_to_job(self, row: sqlite3.Row) -> Json:
        return {
            "id": int(row["id"]),
            "cid": str(row["cid"]),
            "targets": _json_loads_list(str(row["targets_json"] or "[]")),
            "status": str(row["status"]),
            "attempts": int(row["attempts"] or 0),
            "created_ms": int(row["created_ms"] or 0),
            "updated_ms": int(row["updated_ms"] or 0),
            "last_error": str(row["last_error"] or ""),
            "meta": _json_loads_obj(str(row["meta_json"] or "{}")),
        }

    def _list_jobs(self) -> list[Json]:
        def _read(con: sqlite3.Connection) -> list[sqlite3.Row]:
            rows = con.execute(
                """
                SELECT id, cid, targets_json, status, attempts, created_ms, updated_ms, last_error, meta_json
                FROM ipfs_pin_jobs
                ORDER BY id ASC
                """
            ).fetchall()
            return list(rows)

        return [self._row_to_job(row) for row in self.db.execute_read(_read)]

    def _pending_jobs(self) -> list[Json]:
        def _read(con: sqlite3.Connection) -> list[sqlite3.Row]:
            rows = con.execute(
                """
                SELECT id, cid, targets_json, status, attempts, created_ms, updated_ms, last_error, meta_json
                FROM ipfs_pin_jobs
                WHERE status IN ('queued', 'retry')
                ORDER BY id ASC
                LIMIT ?
                """,
                (int(self.config.max_jobs),),
            ).fetchall()
            return list(rows)

        return [self._row_to_job(row) for row in self.db.execute_read(_read)]

    def _targeted_to_this_operator(self, job: Json) -> bool:
        targets = job.get("targets")
        if not isinstance(targets, list) or not targets:
            return True
        return self.operator_account in {str(item).strip() for item in targets}

    def _mark_job(self, job_id: int, *, status: str, attempts: int | None = None, error: str = "") -> None:
        now = _now_ms()

        def _write(con: sqlite3.Connection) -> None:
            if attempts is None:
                con.execute(
                    "UPDATE ipfs_pin_jobs SET status=?, updated_ms=?, last_error=? WHERE id=?",
                    (status, now, str(error or ""), int(job_id)),
                )
            else:
                con.execute(
                    "UPDATE ipfs_pin_jobs SET status=?, attempts=?, updated_ms=?, last_error=? WHERE id=?",
                    (status, int(attempts), now, str(error or ""), int(job_id)),
                )

        self.db.execute_write(_write)

    def _delete_job(self, job_id: int) -> None:
        def _write(con: sqlite3.Connection) -> None:
            con.execute("DELETE FROM ipfs_pin_jobs WHERE id=?", (int(job_id),))

        self.db.execute_write(_write)

    def _pin_cid(self, cid: str) -> None:
        if not bool(self.config.ipfs_enabled):
            # Deterministic offline success path for local tests/demos where Kubo
            # is intentionally disabled. This worker is node-local and does not
            # affect consensus state.
            return

        base = str(self.config.ipfs_api_url or _DEFAULT_IPFS_API_URL).rstrip("/")
        arg = urllib.parse.quote(str(cid), safe="")
        url = f"{base}/api/v0/pin/add?arg={arg}"
        req = urllib.request.Request(url, method="POST")
        with urllib.request.urlopen(req, timeout=int(self.config.request_timeout_s)) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            if status < 200 or status >= 300:
                raise RuntimeError(f"ipfs_pin_http_status:{status}")
            resp.read()

    def run_once(self) -> Json:
        stats: Json = {
            "ok": True,
            "processed": 0,
            "skipped": 0,
            "pinned": 0,
            "failed": 0,
            "dry_run": bool(self.config.dry_run),
        }
        for job in self._pending_jobs():
            job_id = int(job.get("id") or 0)
            if not self._targeted_to_this_operator(job):
                stats["skipped"] += 1
                continue

            attempts = int(job.get("attempts") or 0) + 1
            stats["processed"] += 1

            if bool(self.config.dry_run):
                self._mark_job(job_id, status="dry_run_seen", attempts=attempts)
                continue

            try:
                self._pin_cid(str(job.get("cid") or ""))
            except Exception as exc:  # pragma: no cover - network path is environment-dependent
                stats["failed"] += 1
                if attempts >= int(self.config.max_attempts or _DEFAULT_MAX_ATTEMPTS):
                    self._mark_job(job_id, status="failed", attempts=attempts, error=str(exc))
                else:
                    self._mark_job(job_id, status="retry", attempts=attempts, error=str(exc))
                continue

            stats["pinned"] += 1
            self._delete_job(job_id)

        return stats


__all__ = ["IpfsPinWorker", "IpfsPinWorkerConfig"]
