from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from weall.runtime.sqlite_db import SqliteDB, _now_ms


@dataclass(frozen=True, slots=True)
class PeerSecurityRecord:
    peer_id: str
    strikes: int
    banned_until_ms: int
    score: float
    updated_ts_ms: int


class PeerSecurityStore:
    """Persisted peer security state.

    This is intentionally small and boring:
      - peer_id primary key
      - strikes / ban window
      - score (soft reputation)

    The goal is to survive restarts so a reboot doesn't "forgive" abusive peers.
    """

    def __init__(self, *, db: SqliteDB) -> None:
        self._db = db
        # Ensure schema exists.
        self._db.init_schema()

    def load(self, peer_id: str) -> Optional[PeerSecurityRecord]:
        pid = str(peer_id or "").strip()
        if not pid:
            return None

        with self._db.connection() as con:
            row = con.execute(
                "SELECT peer_id, strikes, banned_until_ms, score, updated_ts_ms FROM peer_security WHERE peer_id=?;",
                (pid,),
            ).fetchone()
            if row is None:
                return None
            try:
                return PeerSecurityRecord(
                    peer_id=str(row["peer_id"]),
                    strikes=int(row["strikes"]),
                    banned_until_ms=int(row["banned_until_ms"]),
                    score=float(row["score"]),
                    updated_ts_ms=int(row["updated_ts_ms"]),
                )
            except Exception:
                return None

    def upsert(self, *, peer_id: str, strikes: int, banned_until_ms: int, score: float) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return

        ts = _now_ms()
        s = int(strikes)
        b = int(banned_until_ms)
        sc = float(score)

        with self._db.write_tx() as con:
            con.execute(
                """
                INSERT INTO peer_security(peer_id, strikes, banned_until_ms, score, updated_ts_ms)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                  strikes=excluded.strikes,
                  banned_until_ms=excluded.banned_until_ms,
                  score=excluded.score,
                  updated_ts_ms=excluded.updated_ts_ms;
                """,
                (pid, s, b, sc, ts),
            )

    def clear(self, peer_id: str) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        with self._db.write_tx() as con:
            con.execute("DELETE FROM peer_security WHERE peer_id=?;", (pid,))

    def prune_expired(self, *, now_ms: Optional[int] = None, limit: int = 5000) -> int:
        """Drop rows that are fully neutral: no strikes, no ban, near-zero score.

        This keeps the table from growing unbounded on long-lived nodes.
        """
        now = int(_now_ms() if now_ms is None else now_ms)
        lim = max(1, int(limit))
        with self._db.write_tx() as con:
            cur = con.execute(
                """
                DELETE FROM peer_security
                WHERE peer_id IN (
                  SELECT peer_id
                  FROM peer_security
                  WHERE strikes <= 0
                    AND banned_until_ms <= ?
                    AND score BETWEEN -0.01 AND 0.01
                  LIMIT ?
                );
                """,
                (now, lim),
            )
            # sqlite3's cursor.rowcount is best-effort.
            try:
                return int(cur.rowcount or 0)
            except Exception:
                return 0
