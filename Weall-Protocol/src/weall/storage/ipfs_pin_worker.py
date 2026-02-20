from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from weall.runtime.sqlite_db import SqliteDB, _canon_json

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _sleep_ms(ms: int) -> None:
    if ms <= 0:
        return
    time.sleep(ms / 1000.0)


def _job_for_id(job: Json) -> Json:
    """Subset used to derive a deterministic job fingerprint.

    We exclude ephemeral fields that operators/workers may update over time
    and derived fields that must not participate in their own derivation.
    """
    out: Json = {}
    for k, v in job.items():
        # Ephemeral / derived fields:
        if k in {
            "updated_ts_ms",
            "last_seen_ms",
            "last_error_ms",
            "last_error",
            "attempts",
            "next_attempt_ms",
            "last_pinned_ms",
            "status",
            "fingerprint",
        }:
            continue
        out[k] = v
    return out


def compute_job_fingerprint(job: Json) -> str:
    # Hash only stable content (fingerprint excluded).
    h = hashlib.sha256(_canon_json(_job_for_id(job)).encode("utf-8")).hexdigest()
    return f"job:{h}"


@dataclass
class IpfsPinWorkerConfig:
    db_path: str
    operator_account: str
    dry_run: bool = False
    max_jobs: int = 200

    # Production safety: by default, we do NOT perform real network pinning.
    # This keeps local dev/tests deterministic without requiring a running Kubo.
    # Operators must explicitly enable live pinning.
    ipfs_enabled: bool = str(os.environ.get("WEALL_IPFS_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}

    # IPFS/Kubo API
    ipfs_api_url: str = os.environ.get("WEALL_IPFS_API_URL", "http://127.0.0.1:5001").strip()
    ipfs_timeout_s: float = float(os.environ.get("WEALL_IPFS_TIMEOUT_S", "10").strip() or "10")

    # Retry / backoff
    max_attempts: int = int(os.environ.get("WEALL_IPFS_MAX_ATTEMPTS", "12").strip() or "12")
    backoff_base_ms: int = int(os.environ.get("WEALL_IPFS_BACKOFF_BASE_MS", "750").strip() or "750")
    backoff_cap_ms: int = int(os.environ.get("WEALL_IPFS_BACKOFF_CAP_MS", "60000").strip() or "60000")


class IpfsPinWorker:
    """SQLite-backed IPFS pin/replication worker.

    Table: ipfs_replication_jobs(cid PRIMARY KEY, job_json, updated_ts_ms)

    Guarantees:
      - Upsert is idempotent only if existing job_json is identical.
      - If a CID already exists with different stable job content, we reject the write
        to prevent "job overwrites" via the same CID.

    Note:
      - Ephemeral fields (last_seen_ms/last_error_ms/updated_ts_ms/attempts/etc.) are allowed to evolve
        without being treated as conflicts.
      - fingerprint is derived from stable content and must not create conflicts.
    """

    def __init__(self, cfg: IpfsPinWorkerConfig) -> None:
        self.cfg = cfg
        self.db = SqliteDB(path=self.cfg.db_path)
        self.db.init_schema()

    def _list_jobs(self) -> List[Json]:
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT job_json
                FROM ipfs_replication_jobs
                ORDER BY updated_ts_ms ASC, cid ASC
                LIMIT ?;
                """,
                (int(self.cfg.max_jobs),),
            ).fetchall()

        out: List[Json] = []
        for r in rows:
            try:
                j = json.loads(str(r["job_json"]))
            except Exception:
                continue
            if isinstance(j, dict):
                out.append(j)
        return out

    def _insert_or_verify(self, cid: str, job_json: str) -> bool:
        """Insert if absent; otherwise require exact match for strict idempotency."""
        with self.db.write_tx() as con:
            con.execute(
                """
                INSERT OR IGNORE INTO ipfs_replication_jobs(cid, job_json, updated_ts_ms)
                VALUES(?, ?, ?);
                """,
                (cid, job_json, _now_ms()),
            )
            row = con.execute(
                "SELECT job_json FROM ipfs_replication_jobs WHERE cid=? LIMIT 1;",
                (cid,),
            ).fetchone()
            if row is None:
                return False
            return str(row["job_json"]) == job_json

    def _touch_ephemeral_job_fields(self, cid: str, updated_job: Json) -> bool:
        """Update ephemeral job fields without creating conflicts.

        Returns True if:
          - CID exists, and
          - stable job content matches (ignoring ephemeral/derived keys), and
          - row is updated.

        Returns False if:
          - CID missing, or
          - stable content mismatch (true conflict)
        """
        c = str(cid).strip()
        if not c:
            return False

        # Ensure fingerprint is present and consistent with stable content.
        updated_job = dict(updated_job)
        updated_job["fingerprint"] = compute_job_fingerprint(updated_job)
        updated_json = _canon_json(updated_job)

        with self.db.write_tx() as con:
            row = con.execute(
                "SELECT job_json FROM ipfs_replication_jobs WHERE cid=? LIMIT 1;",
                (c,),
            ).fetchone()
            if row is None:
                return False

            try:
                existing = json.loads(str(row["job_json"]))
            except Exception:
                return False
            if not isinstance(existing, dict):
                return False

            # Compare stable content only (fingerprint excluded).
            if _job_for_id(existing) != _job_for_id(updated_job):
                return False

            con.execute(
                """
                UPDATE ipfs_replication_jobs
                SET job_json=?, updated_ts_ms=?
                WHERE cid=?;
                """,
                (updated_json, _now_ms(), c),
            )
            return True

    def upsert_job(self, job: Json) -> Json:
        cid = str(job.get("cid") or "").strip()
        if not cid:
            return {"ok": False, "error": "missing_cid"}

        # Normalize shape a bit:
        targets = job.get("targets")
        if targets is None:
            job["targets"] = []
        elif isinstance(targets, list):
            job["targets"] = [str(x) for x in targets if str(x).strip()]
        else:
            return {"ok": False, "error": "bad_targets"}

        # Ensure deterministic fingerprint (derived from stable content).
        job["fingerprint"] = compute_job_fingerprint(job)

        # Strict canonical JSON (will raise if non-JSON types leak in).
        job_json = _canon_json(job)

        ok = self._insert_or_verify(cid, job_json)
        if not ok:
            return {"ok": False, "error": "cid_conflict"}

        return {"ok": True, "cid": cid}

    def delete_job(self, cid: str) -> Json:
        c = str(cid).strip()
        if not c:
            return {"ok": False, "error": "missing_cid"}
        with self.db.write_tx() as con:
            con.execute("DELETE FROM ipfs_replication_jobs WHERE cid=?;", (c,))
        return {"ok": True, "cid": c}

    def enqueue_job(self, cid: str, *, targets: Optional[List[str]] = None) -> Json:
        c = str(cid).strip()
        if not c:
            return {"ok": False, "error": "missing_cid"}
        job: Json = {
            "cid": c,
            "created_ms": _now_ms(),
            "targets": list(targets or []),
        }
        return self.upsert_job(job)

    # ----------------------------
    # Real IPFS pin implementation
    # ----------------------------

    def _ipfs_api_base(self) -> str:
        base = str(self.cfg.ipfs_api_url or "").strip()
        if not base:
            base = "http://127.0.0.1:5001"
        return base.rstrip("/")

    def _ipfs_call(self, path: str, query: Dict[str, str], *, timeout_s: float) -> Tuple[bool, str, int]:
        """Call Kubo HTTP API. Returns (ok, body_text, status_code)."""
        base = self._ipfs_api_base()
        qs = urllib.parse.urlencode(query)
        url = f"{base}{path}?{qs}" if qs else f"{base}{path}"

        # Kubo API often expects POST, but accepts GET for some endpoints.
        # pin/add works with POST and no body.
        req = urllib.request.Request(url=url, method="POST", data=b"")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                status = int(getattr(resp, "status", 200))
                body = resp.read().decode("utf-8", errors="replace")
                return (200 <= status < 300), body, status
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = str(e)
            return False, body or str(e), int(getattr(e, "code", 0) or 0)
        except Exception as e:
            return False, str(e), 0

    def _ipfs_pin(self, cid: str) -> Tuple[bool, str]:
        """Pin a CID via Kubo API. Returns (ok, error_or_empty)."""
        c = str(cid).strip()
        if not c:
            return False, "missing_cid"

        # Deterministic-by-default behavior:
        # If live pinning isn't enabled, treat the pin as successful.
        # This matches the Phase 1 behavior and keeps unit tests local/offline.
        if not bool(self.cfg.ipfs_enabled):
            return True, ""

        ok, body, status = self._ipfs_call(
            "/api/v0/pin/add",
            {"arg": c, "recursive": "true"},
            timeout_s=float(self.cfg.ipfs_timeout_s),
        )
        if ok:
            return True, ""

        # Try to extract a useful message from kubo error payloads.
        msg = body.strip()
        if not msg:
            msg = f"http_status:{status}"
        return False, msg

    def _compute_backoff_ms(self, attempts: int) -> int:
        # Exponential backoff, capped.
        # attempts starts at 1 for first failure.
        a = max(1, int(attempts))
        base = max(50, int(self.cfg.backoff_base_ms))
        cap = max(base, int(self.cfg.backoff_cap_ms))
        # base * 2^(a-1), capped
        delay = base * (2 ** (a - 1))
        if delay > cap:
            delay = cap
        return int(delay)

    def run_once(self) -> Json:
        """Process queued replication jobs.

        Behavior:
          - If targets are specified and operator_account is not included: skip.
          - If job has next_attempt_ms in the future: skip for now.
          - dry_run=True: do not perform network I/O; only updates last_seen_ms.
          - On success: pin and delete the job.
          - On failure: update ephemeral fields (attempts/last_error/next_attempt_ms) and keep the job.
        """
        jobs = self._list_jobs()
        processed = 0
        skipped = 0
        pinned = 0
        conflicts = 0
        failed = 0

        now = _now_ms()

        for job in jobs:
            cid = str(job.get("cid") or "").strip()
            targets = job.get("targets") or []
            if not cid:
                skipped += 1
                continue

            # Respect targeting (operator sharding).
            if targets and isinstance(targets, list):
                if self.cfg.operator_account not in [str(x) for x in targets]:
                    skipped += 1
                    continue

            # Respect retry schedule if present.
            next_attempt_ms = _safe_int(job.get("next_attempt_ms"), 0)
            if next_attempt_ms and next_attempt_ms > now:
                skipped += 1
                continue

            if self.cfg.dry_run:
                job["last_seen_ms"] = now
                job["status"] = "dry_run_seen"
                ok = self._touch_ephemeral_job_fields(cid, job)
                if not ok:
                    conflicts += 1
                processed += 1
                continue

            # Attempt pin
            ok, err = self._ipfs_pin(cid)
            processed += 1

            if ok:
                pinned += 1
                # Best-effort ephemeral stamp (not required since we delete, but useful if delete fails)
                job["last_seen_ms"] = now
                job["last_pinned_ms"] = now
                job["status"] = "pinned"
                _ = self._touch_ephemeral_job_fields(cid, job)
                self.delete_job(cid)
                continue

            # Failure: update ephemeral fields and keep job for retry
            failed += 1
            attempts = _safe_int(job.get("attempts"), 0) + 1
            job["attempts"] = attempts
            job["last_seen_ms"] = now
            job["last_error_ms"] = now
            job["last_error"] = str(err)[:2000]  # prevent DB bloat
            job["status"] = "retrying" if attempts < int(self.cfg.max_attempts) else "failed"

            if attempts >= int(self.cfg.max_attempts):
                # Stop hot-looping forever. Keep the job for manual inspection/retry.
                job["next_attempt_ms"] = now + int(self.cfg.backoff_cap_ms)
            else:
                job["next_attempt_ms"] = now + self._compute_backoff_ms(attempts)

            touched = self._touch_ephemeral_job_fields(cid, job)
            if not touched:
                conflicts += 1

            # If we failed due to transient issues and there are many jobs,
            # avoid hammering IPFS by sleeping a tiny amount between failures.
            _sleep_ms(25)

        return {
            "ok": True,
            "processed": processed,
            "skipped": skipped,
            "pinned": pinned,
            "failed": failed,
            "conflicts": conflicts,
        }


def _parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="WeAll IPFS pin/replication worker (SQLite-backed)")
    ap.add_argument("--db", dest="db_path", default=os.environ.get("WEALL_DB_PATH", "./data/weall.db"))
    ap.add_argument("--operator", dest="operator_account", default=os.environ.get("WEALL_OPERATOR_ACCOUNT", ""))
    ap.add_argument("--dry-run", dest="dry_run", action="store_true")
    ap.add_argument("--max-jobs", dest="max_jobs", type=int, default=200)

    ap.add_argument(
        "--ipfs-api",
        dest="ipfs_api_url",
        default=os.environ.get("WEALL_IPFS_API_URL", os.environ.get("WEALL_IPFS_API_URL", "http://127.0.0.1:5001")),
    )
    ap.add_argument("--ipfs-timeout", dest="ipfs_timeout_s", type=float, default=float(os.environ.get("WEALL_IPFS_TIMEOUT_S", "10") or "10"))
    ap.add_argument("--max-attempts", dest="max_attempts", type=int, default=int(os.environ.get("WEALL_IPFS_MAX_ATTEMPTS", "12") or "12"))
    ap.add_argument("--backoff-base-ms", dest="backoff_base_ms", type=int, default=int(os.environ.get("WEALL_IPFS_BACKOFF_BASE_MS", "750") or "750"))
    ap.add_argument("--backoff-cap-ms", dest="backoff_cap_ms", type=int, default=int(os.environ.get("WEALL_IPFS_BACKOFF_CAP_MS", "60000") or "60000"))

    ap.add_argument("--enqueue", dest="enqueue", default="")
    ap.add_argument("--targets", dest="targets", default="")

    return ap.parse_args(argv)


def main(argv: List[str]) -> int:
    args = _parse_args(argv)

    operator = str(args.operator_account or "").strip()
    if not operator:
        print("ERROR: --operator (or WEALL_OPERATOR_ACCOUNT) is required", file=sys.stderr)
        return 2

    cfg = IpfsPinWorkerConfig(
        db_path=str(args.db_path),
        operator_account=operator,
        dry_run=bool(args.dry_run),
        max_jobs=int(args.max_jobs),
        ipfs_api_url=str(args.ipfs_api_url or "").strip(),
        ipfs_timeout_s=float(args.ipfs_timeout_s),
        max_attempts=int(args.max_attempts),
        backoff_base_ms=int(args.backoff_base_ms),
        backoff_cap_ms=int(args.backoff_cap_ms),
    )

    worker = IpfsPinWorker(cfg)

    if args.enqueue:
        targets: List[str] = []
        if args.targets:
            targets = [t.strip() for t in str(args.targets).split(",") if t.strip()]
        res = worker.enqueue_job(str(args.enqueue), targets=targets)
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    res = worker.run_once()
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
