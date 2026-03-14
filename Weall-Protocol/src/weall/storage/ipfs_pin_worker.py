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
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.storage.ipfs_partition import read_partition_config, can_accept_bytes

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
    h = hashlib.sha256(_canon_json(_job_for_id(job)).encode("utf-8")).hexdigest()
    return f"job:{h}"


@dataclass
class IpfsPinWorkerConfig:
    db_path: str
    operator_account: str
    dry_run: bool = False
    max_jobs: int = 200

    # Production safety: by default, do NOT perform live network pinning.
    ipfs_enabled: bool = str(os.environ.get("WEALL_IPFS_ENABLED", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    # IPFS/Kubo API
    ipfs_api_url: str = os.environ.get("WEALL_IPFS_API_URL", "http://127.0.0.1:5001").strip()
    ipfs_timeout_s: float = float(os.environ.get("WEALL_IPFS_TIMEOUT_S", "10").strip() or "10")

    # Retry / backoff
    max_attempts: int = int(os.environ.get("WEALL_IPFS_MAX_ATTEMPTS", "12").strip() or "12")
    backoff_base_ms: int = int(os.environ.get("WEALL_IPFS_BACKOFF_BASE_MS", "750").strip() or "750")
    backoff_cap_ms: int = int(os.environ.get("WEALL_IPFS_BACKOFF_CAP_MS", "60000").strip() or "60000")

    # Local partition enforcement (mounted path you control)
    ipfs_partition_path: str = os.environ.get("WEALL_IPFS_PARTITION_PATH", "").strip()
    ipfs_partition_cap_bytes: int = int(os.environ.get("WEALL_IPFS_PARTITION_CAP_BYTES", "0").strip() or "0")
    ipfs_partition_free_reserve_bytes: int = int(
        os.environ.get(
            "WEALL_IPFS_PARTITION_FREE_RESERVE_BYTES",
            str(512 * 1024 * 1024),
        ).strip()
        or str(512 * 1024 * 1024)
    )


class IpfsPinWorker:
    """SQLite-backed IPFS pin/replication worker."""

    def __init__(self, cfg: IpfsPinWorkerConfig) -> None:
        self.cfg = cfg
        self.db = SqliteDB(path=self.cfg.db_path)
        self.db.init_schema()

    def _read_job(self, cid: str) -> Optional[Json]:
        c = str(cid or "").strip()
        if not c:
            return None
        with self.db.connection() as con:
            row = con.execute(
                "SELECT job_json FROM ipfs_replication_jobs WHERE cid=? LIMIT 1;",
                (c,),
            ).fetchone()
        if row is None:
            return None
        try:
            obj = json.loads(str(row["job_json"]))
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def _replace_job(self, cid: str, job: Json) -> Json:
        c = str(cid or "").strip()
        if not c:
            return {"ok": False, "error": "missing_cid"}
        j = dict(job or {})
        j["cid"] = c
        j["fingerprint"] = compute_job_fingerprint(j)
        payload = _canon_json(j)
        with self.db.write_tx() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO ipfs_replication_jobs(cid, job_json, updated_ts_ms)
                VALUES(?, ?, ?);
                """,
                (c, payload, _now_ms()),
            )
        return {"ok": True, "cid": c}

    def _pin_confirms_any(self, state: Json) -> List[Json]:
        storage = state.get("storage")
        if not isinstance(storage, dict):
            return []
        confirms = storage.get("pin_confirms")
        return confirms if isinstance(confirms, list) else []

    def _operator_already_confirmed_ok(self, confirms: List[Json], *, pin_id: str, cid: str) -> bool:
        want_pin = str(pin_id or "").strip()
        want_cid = str(cid or "").strip()
        op = str(self.cfg.operator_account or "").strip()
        if not want_pin or not op:
            return False
        for item in confirms:
            if not isinstance(item, dict):
                continue
            if str(item.get("pin_id") or "").strip() != want_pin:
                continue
            if str(item.get("operator_id") or "").strip() != op:
                continue
            if want_cid and str(item.get("cid") or "").strip() != want_cid:
                continue
            if bool(item.get("ok")):
                return True
        return False

    def _sync_chain_pin_requests(self) -> Json:
        try:
            with self.db.connection() as con:
                row = con.execute("SELECT state_json FROM ledger_state WHERE id=1 LIMIT 1;").fetchone()
        except Exception as e:
            return {"ok": False, "error": f"ledger_state_read_failed:{e}"}

        if row is None:
            return {"ok": True, "queued": 0, "merged": 0, "seen": 0}

        try:
            state = json.loads(str(row["state_json"]))
        except Exception:
            return {"ok": False, "error": "ledger_state_corrupted"}

        if not isinstance(state, dict):
            return {"ok": False, "error": "ledger_state_not_object"}

        storage = state.get("storage")
        if not isinstance(storage, dict):
            return {"ok": True, "queued": 0, "merged": 0, "seen": 0}

        pins = storage.get("pins")
        if not isinstance(pins, dict):
            return {"ok": True, "queued": 0, "merged": 0, "seen": 0}

        confirms = self._pin_confirms_any(state)

        grouped: Dict[str, Json] = {}
        seen = 0
        for pin_id, rec_any in pins.items():
            if not isinstance(rec_any, dict):
                continue
            rec = rec_any
            cid = str(rec.get("cid") or "").strip()
            if not cid:
                continue
            targets_any = rec.get("targets")
            targets = [str(x).strip() for x in targets_any if str(x).strip()] if isinstance(targets_any, list) else []
            if targets and str(self.cfg.operator_account) not in targets:
                continue
            if self._operator_already_confirmed_ok(confirms, pin_id=str(pin_id), cid=cid):
                continue

            seen += 1
            cur = grouped.get(cid)
            if cur is None:
                grouped[cid] = {
                    "cid": cid,
                    "created_ms": _now_ms(),
                    "targets": list(targets),
                    "pin_ids": [str(pin_id)],
                    "size_bytes": _safe_int(rec.get("size_bytes"), 0),
                    "requested_by": str(rec.get("requested_by") or "").strip(),
                    "replication_factor": _safe_int(rec.get("replication_factor"), 0),
                    "requested_at_nonce": _safe_int(rec.get("requested_at_nonce"), 0),
                    "requested_at_height": _safe_int(rec.get("requested_at_height"), 0),
                }
                continue

            cur["targets"] = sorted(
                {
                    str(x).strip()
                    for x in list(cur.get("targets") or []) + list(targets)
                    if str(x).strip()
                }
            )
            cur["pin_ids"] = sorted(
                {
                    str(x).strip()
                    for x in list(cur.get("pin_ids") or []) + [str(pin_id)]
                    if str(x).strip()
                }
            )
            cur["size_bytes"] = max(_safe_int(cur.get("size_bytes"), 0), _safe_int(rec.get("size_bytes"), 0))
            cur["replication_factor"] = max(
                _safe_int(cur.get("replication_factor"), 0),
                _safe_int(rec.get("replication_factor"), 0),
            )
            cur["requested_at_nonce"] = min(
                [
                    x
                    for x in [
                        _safe_int(cur.get("requested_at_nonce"), 0),
                        _safe_int(rec.get("requested_at_nonce"), 0),
                    ]
                    if x > 0
                ]
                or [0]
            )
            cur["requested_at_height"] = min(
                [
                    x
                    for x in [
                        _safe_int(cur.get("requested_at_height"), 0),
                        _safe_int(rec.get("requested_at_height"), 0),
                    ]
                    if x > 0
                ]
                or [0]
            )

        queued = 0
        merged = 0
        for cid, job in grouped.items():
            existing = self._read_job(cid)
            if existing is None:
                res = self.upsert_job(job)
                if bool(res.get("ok")):
                    queued += 1
                continue

            merged_job = dict(existing)
            merged_job.setdefault("created_ms", job.get("created_ms") or _now_ms())
            merged_job["targets"] = sorted(
                {
                    str(x).strip()
                    for x in list(existing.get("targets") or []) + list(job.get("targets") or [])
                    if str(x).strip()
                }
            )
            merged_job["pin_ids"] = sorted(
                {
                    str(x).strip()
                    for x in list(existing.get("pin_ids") or []) + list(job.get("pin_ids") or [])
                    if str(x).strip()
                }
            )
            merged_job["size_bytes"] = max(_safe_int(existing.get("size_bytes"), 0), _safe_int(job.get("size_bytes"), 0))
            merged_job["replication_factor"] = max(
                _safe_int(existing.get("replication_factor"), 0),
                _safe_int(job.get("replication_factor"), 0),
            )
            if not str(merged_job.get("requested_by") or "").strip():
                merged_job["requested_by"] = str(job.get("requested_by") or "").strip()
            if _safe_int(merged_job.get("requested_at_nonce"), 0) <= 0 and _safe_int(job.get("requested_at_nonce"), 0) > 0:
                merged_job["requested_at_nonce"] = _safe_int(job.get("requested_at_nonce"), 0)
            if _safe_int(merged_job.get("requested_at_height"), 0) <= 0 and _safe_int(job.get("requested_at_height"), 0) > 0:
                merged_job["requested_at_height"] = _safe_int(job.get("requested_at_height"), 0)

            if _job_for_id(existing) != _job_for_id(merged_job):
                rep = self._replace_job(cid, merged_job)
                if bool(rep.get("ok")):
                    merged += 1

        return {"ok": True, "queued": queued, "merged": merged, "seen": seen}

    def _enqueue_pin_confirm(self, *, pin_id: str, cid: str, ok: bool, error: str = "") -> bool:
        p = str(pin_id or "").strip()
        c = str(cid or "").strip()
        if not p or not c:
            return False

        def _mutate(state: Json) -> Json:
            h = _safe_int(state.get("height"), 0)
            payload: Json = {
                "pin_id": p,
                "cid": c,
                "operator_id": str(self.cfg.operator_account or "").strip(),
                "ok": bool(ok),
            }
            if error:
                payload["error"] = str(error)[:1000]
            enqueue_system_tx(
                state,
                tx_type="IPFS_PIN_CONFIRM",
                payload=payload,
                due_height=max(1, int(h) + 1),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            return state

        try:
            with self.db.write_tx() as con:
                row = con.execute("SELECT state_json FROM ledger_state WHERE id=1 LIMIT 1;").fetchone()
                if row is None:
                    return False
                state = json.loads(str(row["state_json"]))
                if not isinstance(state, dict):
                    return False
                state = _mutate(state)
                con.execute(
                    "INSERT OR REPLACE INTO ledger_state(id, height, block_id, state_json, updated_ts_ms) VALUES(1,?,?,?,?);",
                    (
                        int(state.get("height") or 0),
                        str(state.get("tip") or ""),
                        _canon_json(state),
                        _now_ms(),
                    ),
                )
            return True
        except Exception:
            return False

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
        c = str(cid).strip()
        if not c:
            return False

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

        targets = job.get("targets")
        if targets is None:
            job["targets"] = []
        elif isinstance(targets, list):
            job["targets"] = [str(x) for x in targets if str(x).strip()]
        else:
            return {"ok": False, "error": "bad_targets"}

        job["fingerprint"] = compute_job_fingerprint(job)
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

    def _ipfs_api_base(self) -> str:
        base = str(self.cfg.ipfs_api_url or "").strip()
        if not base:
            base = "http://127.0.0.1:5001"
        return base.rstrip("/")

    def _ipfs_call(self, path: str, query: Dict[str, str], *, timeout_s: float) -> Tuple[bool, str, int]:
        base = self._ipfs_api_base()
        qs = urllib.parse.urlencode(query)
        url = f"{base}{path}?{qs}" if qs else f"{base}{path}"

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
        c = str(cid).strip()
        if not c:
            return False, "missing_cid"

        if not bool(self.cfg.ipfs_enabled):
            return True, ""

        ok, body, status = self._ipfs_call(
            "/api/v0/pin/add",
            {"arg": c, "recursive": "true"},
            timeout_s=float(self.cfg.ipfs_timeout_s),
        )
        if ok:
            return True, ""

        msg = body.strip()
        if not msg:
            msg = f"http_status:{status}"
        return False, msg

    def _lookup_cid_size_bytes(self, cid: str) -> int:
        c = str(cid or "").strip()
        if not c:
            return 0

        try:
            with self.db.connection() as con:
                row = con.execute("SELECT state_json FROM ledger_state WHERE id=1 LIMIT 1;").fetchone()
            if row is None:
                return 0
            st = json.loads(str(row["state_json"]))
        except Exception:
            return 0

        if not isinstance(st, dict):
            return 0
        storage = st.get("storage")
        if not isinstance(storage, dict):
            return 0
        pins = storage.get("pins")
        if not isinstance(pins, dict):
            return 0

        best = 0
        for _, rec_any in pins.items():
            if not isinstance(rec_any, dict):
                continue
            if str(rec_any.get("cid") or "").strip() != c:
                continue
            try:
                sz = int(rec_any.get("size_bytes") or 0)
            except Exception:
                sz = 0
            if sz > best:
                best = sz
        return int(best)

    def _enforce_partition_budget(self, *, cid: str, need_bytes: int) -> Tuple[bool, str]:
        part_path = str(self.cfg.ipfs_partition_path or "").strip()
        cap = int(self.cfg.ipfs_partition_cap_bytes or 0)
        reserve = int(self.cfg.ipfs_partition_free_reserve_bytes or 0)

        if not part_path and cap == 0 and reserve == 0:
            p2, c2, r2 = read_partition_config()
            part_path = part_path or p2
            cap = cap or c2
            reserve = reserve or r2

        need = int(need_bytes or 0)
        if need <= 0:
            need = 1

        ok, reason, details = can_accept_bytes(
            partition_path=part_path,
            cap_bytes=cap,
            reserve_bytes=reserve,
            need_bytes=need,
        )
        if ok:
            return True, ""
        return False, f"partition:{reason}:{details.get('partition_path')}"

    def _compute_backoff_ms(self, attempts: int) -> int:
        a = max(1, int(attempts))
        base = max(50, int(self.cfg.backoff_base_ms))
        cap = max(base, int(self.cfg.backoff_cap_ms))
        delay = base * (2 ** (a - 1))
        if delay > cap:
            delay = cap
        return int(delay)

    def run_once(self) -> Json:
        """Process queued replication jobs.

        Important behavior:
          - dry_run=True: do not pin, just touch rows
          - ipfs_enabled=False: simulate a successful pin path and do NOT apply
            partition/disk enforcement, because no real pin will happen
          - live pinning (ipfs_enabled=True): enforce partition budget first
        """
        sync_res = self._sync_chain_pin_requests()
        jobs = self._list_jobs()
        processed = 0
        skipped = 0
        pinned = 0
        conflicts = 0
        failed = 0
        confirms_enqueued = 0

        now = _now_ms()

        for job in jobs:
            cid = str(job.get("cid") or "").strip()
            targets = job.get("targets") or []
            if not cid:
                skipped += 1
                continue

            if targets and isinstance(targets, list):
                if self.cfg.operator_account not in [str(x) for x in targets]:
                    skipped += 1
                    continue

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

            # Only enforce real disk/partition budget when live IPFS pinning is enabled.
            if bool(self.cfg.ipfs_enabled):
                cid_size = self._lookup_cid_size_bytes(cid)
                ok_budget, budget_err = self._enforce_partition_budget(cid=cid, need_bytes=int(cid_size))
                if not ok_budget:
                    processed += 1
                    failed += 1
                    attempts = _safe_int(job.get("attempts"), 0) + 1
                    job["attempts"] = attempts
                    job["last_seen_ms"] = now
                    job["last_error_ms"] = now
                    job["last_error"] = str(budget_err)[:2000]
                    job["status"] = "failed"
                    job["next_attempt_ms"] = now + int(self.cfg.backoff_cap_ms)
                    touched = self._touch_ephemeral_job_fields(cid, job)
                    if not touched:
                        conflicts += 1
                    continue

            ok, err = self._ipfs_pin(cid)
            processed += 1

            if ok:
                pinned += 1
                job["last_seen_ms"] = now
                job["last_pinned_ms"] = now
                job["status"] = "pinned"
                _ = self._touch_ephemeral_job_fields(cid, job)

                pin_ids = [str(x).strip() for x in list(job.get("pin_ids") or []) if str(x).strip()]
                if not pin_ids:
                    pin_ids = [cid]
                for pin_id in pin_ids:
                    if self._enqueue_pin_confirm(pin_id=pin_id, cid=cid, ok=True):
                        confirms_enqueued += 1

                self.delete_job(cid)
                continue

            failed += 1
            attempts = _safe_int(job.get("attempts"), 0) + 1
            job["attempts"] = attempts
            job["last_seen_ms"] = now
            job["last_error_ms"] = now
            job["last_error"] = str(err)[:2000]
            job["status"] = "retrying" if attempts < int(self.cfg.max_attempts) else "failed"

            if attempts >= int(self.cfg.max_attempts):
                job["next_attempt_ms"] = now + int(self.cfg.backoff_cap_ms)
            else:
                job["next_attempt_ms"] = now + self._compute_backoff_ms(attempts)

            touched = self._touch_ephemeral_job_fields(cid, job)
            if not touched:
                conflicts += 1

            if attempts >= int(self.cfg.max_attempts):
                pin_ids = [str(x).strip() for x in list(job.get("pin_ids") or []) if str(x).strip()]
                if not pin_ids:
                    pin_ids = [cid]
                for pin_id in pin_ids:
                    if self._enqueue_pin_confirm(pin_id=pin_id, cid=cid, ok=False, error=str(err)):
                        confirms_enqueued += 1
                self.delete_job(cid)

            _sleep_ms(25)

        return {
            "ok": True,
            "processed": processed,
            "skipped": skipped,
            "pinned": pinned,
            "failed": failed,
            "conflicts": conflicts,
            "confirms_enqueued": confirms_enqueued,
            "synced_jobs": sync_res,
        }


def _parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="WeAll IPFS pin/replication worker (SQLite-backed)")
    ap.add_argument("--db-path", required=True, help="Path to WeAll SQLite DB")
    ap.add_argument("--operator-account", required=True, help="Operator account id for target filtering")
    ap.add_argument("--dry-run", action="store_true", help="Do not actually pin; only touch rows")
    ap.add_argument("--once", action="store_true", help="Run a single pass and exit")
    ap.add_argument("--poll-ms", type=int, default=1000, help="Polling interval when not using --once")
    ap.add_argument("--max-jobs", type=int, default=200, help="Max jobs to scan per pass")
    return ap.parse_args(argv)


def main(argv: List[str]) -> int:
    ns = _parse_args(argv)
    cfg = IpfsPinWorkerConfig(
        db_path=str(ns.db_path),
        operator_account=str(ns.operator_account),
        dry_run=bool(ns.dry_run),
        max_jobs=int(ns.max_jobs),
    )
    worker = IpfsPinWorker(cfg)

    if ns.once:
        print(json.dumps(worker.run_once(), sort_keys=True))
        return 0

    poll_ms = max(50, int(ns.poll_ms))
    while True:
        try:
            print(json.dumps(worker.run_once(), sort_keys=True))
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}), file=sys.stderr)
        time.sleep(poll_ms / 1000.0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
