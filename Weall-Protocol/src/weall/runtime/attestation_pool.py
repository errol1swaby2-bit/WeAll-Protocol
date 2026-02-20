from __future__ import annotations

import hashlib
import json
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


def _envelope_for_id(env: Json) -> Json:
    """Return the subset of an attestation envelope used to derive its att_id."""
    out: Json = {}
    for k, v in env.items():
        if k in {"att_id", "received_ms", "expires_ms"}:
            continue
        out[k] = v
    return out


def compute_att_id(env: Json) -> str:
    """Compute a deterministic attestation id."""
    base = _envelope_for_id(env)
    h = hashlib.sha256(_canon_json(base).encode("utf-8")).hexdigest()
    return f"att:{h}"


def _expires_ms(env: Json, *, fallback_ttl_ms: int) -> int:
    ex = env.get("expires_ms")
    if ex is not None:
        return _safe_int(ex, _now_ms() + fallback_ttl_ms)
    return _now_ms() + fallback_ttl_ms


@dataclass
class PersistentAttestationPool:
    """SQLite-backed attestation pool.

    Table schema:
      attestations(att_id PK, envelope_json, block_id, received_ms, expires_ms)

    Security/correctness guarantees:
      - att_id is ALWAYS derived from envelope content (not trusted from user)
      - idempotent insert: same att_id + identical envelope is accepted
      - conflicting insert: same att_id + different envelope is rejected

    Determinism:
      - fetch order is (received_ms ASC, att_id ASC)
      - fetch filters expired items
    """

    db: SqliteDB
    default_ttl_ms: int = 30 * 60 * 1000  # 30 minutes

    def __post_init__(self) -> None:
        self.db.init_schema()

    def add(self, env: Json) -> Json:
        if not isinstance(env, dict):
            return {"ok": False, "error": "bad_env:not_object"}

        block_id = str(env.get("block_id") or "").strip()
        if not block_id:
            return {"ok": False, "error": "bad_env:missing_block_id"}

        provided = str(env.get("att_id") or "").strip()
        att_id = compute_att_id(env)
        if provided and provided != att_id:
            return {"ok": False, "error": "bad_env:att_id_mismatch"}

        received_ms = _safe_int(env.get("received_ms"), _now_ms())
        expires_ms = _expires_ms(env, fallback_ttl_ms=self.default_ttl_ms)

        env_persist: Json = dict(env)
        env_persist["att_id"] = att_id
        env_persist["received_ms"] = received_ms
        env_persist["expires_ms"] = expires_ms
        env_json = _canon_json(env_persist)

        with self.db.write_tx() as con:
            con.execute(
                """
                INSERT OR IGNORE INTO attestations(att_id, envelope_json, block_id, received_ms, expires_ms)
                VALUES(?, ?, ?, ?, ?);
                """,
                (att_id, env_json, block_id, int(received_ms), int(expires_ms)),
            )

            row = con.execute(
                "SELECT envelope_json FROM attestations WHERE att_id=? LIMIT 1;",
                (att_id,),
            ).fetchone()

            if row is None:
                return {"ok": False, "error": "db_error:missing_after_insert"}

            if str(row["envelope_json"]) != env_json:
                return {"ok": False, "error": "att_id_conflict"}

        env["att_id"] = att_id
        env["received_ms"] = received_ms
        env["expires_ms"] = expires_ms
        return {"ok": True, "att_id": att_id, "received_ms": received_ms, "expires_ms": expires_ms}

    def remove(self, env_or_att_id: Any) -> Json:
        if isinstance(env_or_att_id, str):
            att_id = env_or_att_id.strip()
        elif isinstance(env_or_att_id, dict):
            att_id = str(env_or_att_id.get("att_id") or "").strip() or compute_att_id(env_or_att_id)
        else:
            return {"ok": False, "error": "bad_arg"}

        if not att_id:
            return {"ok": False, "error": "missing_att_id"}

        with self.db.write_tx() as con:
            con.execute("DELETE FROM attestations WHERE att_id=?;", (att_id,))
        return {"ok": True, "att_id": att_id}

    def fetch_for_block(self, block_id: str, *, limit: int = 1000) -> List[Json]:
        bid = str(block_id).strip()
        if not bid:
            return []
        lim = int(limit) if int(limit) > 0 else 1000
        now = _now_ms()
        with self.db.connection() as con:
            rows = con.execute(
                """
                SELECT envelope_json
                FROM attestations
                WHERE block_id=? AND expires_ms > ?
                ORDER BY received_ms ASC, att_id ASC
                LIMIT ?;
                """,
                (bid, int(now), lim),
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

    def prune_expired(self) -> int:
        now = _now_ms()
        with self.db.write_tx() as con:
            cur = con.execute("DELETE FROM attestations WHERE expires_ms <= ?;", (int(now),))
            return int(cur.rowcount or 0)

    def size(self) -> int:
        with self.db.connection() as con:
            row = con.execute("SELECT COUNT(1) AS n FROM attestations;").fetchone()
            return int(row["n"]) if row is not None else 0
