from __future__ import annotations

from dataclasses import dataclass

from weall.runtime.sqlite_db import SqliteDB, _now_ms


class PeerSecurityStoreError(RuntimeError):
    """Raised when persisted peer-security state cannot be trusted."""


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

    Keys are stable security principals (authenticated account identities or
    pre-auth transport hosts), never ephemeral connection identifiers. The goal
    is to survive reconnects/restarts without growing one row per source port.
    """

    def __init__(self, *, db: SqliteDB) -> None:
        self._db = db
        # Ensure schema exists.
        self._db.init_schema()

    def load(self, peer_id: str) -> PeerSecurityRecord | None:
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
            except Exception as exc:
                raise PeerSecurityStoreError(f"peer_security_record_corrupt:{pid}") from exc

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

    def prune_expired(
        self,
        *,
        now_ms: int | None = None,
        retention_ms: int = 7 * 24 * 60 * 60 * 1000,
        limit: int = 5000,
    ) -> int:
        """Prune security history only after its ban is inactive and TTL elapsed.

        Persisted strikes are intentionally not immortal. A stable principal key
        plus a bounded retention window prevents reconnect/source-port churn from
        growing this auxiliary table forever while preserving active bans.
        """
        now = int(_now_ms() if now_ms is None else now_ms)
        retention = max(0, int(retention_ms))
        cutoff = int(now - retention)
        lim = max(1, int(limit))
        with self._db.write_tx() as con:
            cur = con.execute(
                """
                DELETE FROM peer_security
                WHERE peer_id IN (
                  SELECT peer_id
                  FROM peer_security
                  WHERE banned_until_ms <= ?
                    AND updated_ts_ms <= ?
                  ORDER BY updated_ts_ms ASC
                  LIMIT ?
                );
                """,
                (now, cutoff, lim),
            )
            try:
                return int(cur.rowcount or 0)
            except Exception:
                return 0
