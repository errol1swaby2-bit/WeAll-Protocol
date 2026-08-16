from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from weall.runtime.sqlite_db import SqliteDB, _now_ms

Json = dict[str, Any]


class BftOutboxStoreError(RuntimeError):
    """Raised when the durable BFT outbox cannot be trusted or updated."""


@dataclass(frozen=True, slots=True)
class BftOutboxRecord:
    key: str
    kind: str
    payload: Json
    enqueue_seq: int
    enqueued_ts_ms: int
    updated_ts_ms: int


class BftOutboxStore:
    """Authoritative durable BFT send obligations.

    The bounded JSONL BFT journal is diagnostic history and restart hints.  Send
    obligations live here instead so diagnostic retention/compaction can never
    silently discard an unsent consensus message.
    """

    def __init__(self, *, db: SqliteDB, max_pending: int = 10_000) -> None:
        self._db = db
        self._max_pending = max(1, int(max_pending))
        self._db.init_schema()

    @staticmethod
    def _encode_payload(payload: Json) -> str:
        return json.dumps(dict(payload or {}), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _decode_payload(raw: str, *, key: str) -> Json:
        try:
            value = json.loads(str(raw))
        except Exception as exc:
            raise BftOutboxStoreError(f"bft_outbox_payload_corrupt:{key}") from exc
        if not isinstance(value, dict):
            raise BftOutboxStoreError(f"bft_outbox_payload_corrupt:{key}")
        return dict(value)

    @classmethod
    def _semantic_payload(cls, *, kind: str, payload: Json) -> str:
        """Return the deterministic obligation payload used for idempotency.

        ML-DSA signatures are permitted to differ when the same canonical vote or
        timeout is signed again after restart.  The signature bytes are therefore
        not part of durable-outbox identity.  Every other field remains covered so
        a reused key cannot hide a changed signed message, validator identity,
        epoch/set binding, public key, or consensus phase.
        """

        normalized = dict(payload or {})
        if str(kind or "").strip().lower() in {"vote", "timeout"}:
            normalized.pop("sig", None)
        return cls._encode_payload(normalized)

    @classmethod
    def _payloads_equivalent(cls, *, kind: str, left: Json, right: Json) -> bool:
        return cls._semantic_payload(kind=kind, payload=left) == cls._semantic_payload(
            kind=kind, payload=right
        )

    def enqueue(self, *, key: str, kind: str, payload: Json) -> None:
        outbound_key = str(key or "").strip()
        outbound_kind = str(kind or "").strip().lower()
        if not outbound_key or not outbound_kind or not isinstance(payload, dict):
            raise BftOutboxStoreError("bft_outbox_enqueue_invalid")

        encoded = self._encode_payload(payload)
        now = int(_now_ms())
        with self._db.write_tx() as con:
            existing = con.execute(
                "SELECT kind, payload_json FROM bft_outbox WHERE outbound_key=?;",
                (outbound_key,),
            ).fetchone()
            if existing is not None:
                existing_kind = str(existing["kind"] or "").strip().lower()
                if existing_kind != outbound_kind:
                    raise BftOutboxStoreError(f"bft_outbox_key_collision:{outbound_key}")
                existing_payload = self._decode_payload(
                    str(existing["payload_json"]), key=outbound_key
                )
                if not self._payloads_equivalent(
                    kind=outbound_kind, left=existing_payload, right=payload
                ):
                    raise BftOutboxStoreError(f"bft_outbox_key_collision:{outbound_key}")
                # Preserve the originally durable payload. A restart may produce a
                # different valid ML-DSA signature for the same canonical message;
                # replacing the row would make durable replay depend on a re-sign.
                con.execute(
                    "UPDATE bft_outbox SET updated_ts_ms=? WHERE outbound_key=?;",
                    (now, outbound_key),
                )
                return

            row = con.execute("SELECT COUNT(*) AS n FROM bft_outbox;").fetchone()
            count = int(row["n"] if row is not None else 0)
            if count >= self._max_pending:
                raise BftOutboxStoreError(
                    f"bft_outbox_capacity_exceeded:{count}:{self._max_pending}"
                )
            seq_row = con.execute(
                "SELECT COALESCE(MAX(enqueue_seq), 0) + 1 AS next_seq FROM bft_outbox;"
            ).fetchone()
            enqueue_seq = int(seq_row["next_seq"] if seq_row is not None else 1)
            con.execute(
                """
                INSERT INTO bft_outbox(
                  outbound_key, kind, payload_json, enqueue_seq,
                  enqueued_ts_ms, updated_ts_ms
                ) VALUES(?, ?, ?, ?, ?, ?);
                """,
                (outbound_key, outbound_kind, encoded, enqueue_seq, now, now),
            )

    def mark_sent(self, *, key: str) -> None:
        outbound_key = str(key or "").strip()
        if not outbound_key:
            raise BftOutboxStoreError("bft_outbox_sent_key_missing")
        with self._db.write_tx() as con:
            con.execute("DELETE FROM bft_outbox WHERE outbound_key=?;", (outbound_key,))

    def pending(self) -> list[BftOutboxRecord]:
        with self._db.connection() as con:
            rows = con.execute(
                """
                SELECT outbound_key, kind, payload_json, enqueue_seq,
                       enqueued_ts_ms, updated_ts_ms
                FROM bft_outbox
                ORDER BY enqueue_seq ASC;
                """
            ).fetchall()
        out: list[BftOutboxRecord] = []
        for row in rows:
            key = str(row["outbound_key"] or "").strip()
            kind = str(row["kind"] or "").strip().lower()
            if not key or not kind:
                raise BftOutboxStoreError("bft_outbox_record_corrupt")
            out.append(
                BftOutboxRecord(
                    key=key,
                    kind=kind,
                    payload=self._decode_payload(str(row["payload_json"]), key=key),
                    enqueue_seq=int(row["enqueue_seq"]),
                    enqueued_ts_ms=int(row["enqueued_ts_ms"]),
                    updated_ts_ms=int(row["updated_ts_ms"]),
                )
            )
        return out

    def legacy_migration_complete(self) -> bool:
        with self._db.connection() as con:
            row = con.execute(
                "SELECT value FROM meta WHERE key='bft_outbox_v1_migrated';"
            ).fetchone()
        return row is not None and str(row["value"] or "") == "1"

    def import_legacy_pending_once(self, items: list[Json]) -> int:
        if self.legacy_migration_complete():
            return 0

        normalized: list[tuple[str, str, str]] = []
        seen: dict[str, tuple[str, str, str]] = {}
        for item in list(items or []):
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "").strip()
            kind = str(item.get("kind") or "").strip().lower()
            payload = item.get("payload")
            if not key or not kind or not isinstance(payload, dict):
                continue
            encoded = self._encode_payload(dict(payload))
            semantic = self._semantic_payload(kind=kind, payload=dict(payload))
            previous = seen.get(key)
            if previous is not None:
                previous_kind, previous_semantic, _previous_encoded = previous
                if previous_kind != kind or previous_semantic != semantic:
                    raise BftOutboxStoreError(f"bft_outbox_key_collision:{key}")
                continue
            seen[key] = (kind, semantic, encoded)
        normalized = [
            (key, kind, encoded) for key, (kind, _semantic, encoded) in seen.items()
        ]

        now = int(_now_ms())
        with self._db.write_tx() as con:
            marker = con.execute(
                "SELECT value FROM meta WHERE key='bft_outbox_v1_migrated';"
            ).fetchone()
            if marker is not None and str(marker["value"] or "") == "1":
                return 0
            row = con.execute("SELECT COUNT(*) AS n FROM bft_outbox;").fetchone()
            current = int(row["n"] if row is not None else 0)
            new_keys = 0
            for key, kind, encoded in normalized:
                existing = con.execute(
                    "SELECT kind, payload_json FROM bft_outbox WHERE outbound_key=?;",
                    (key,),
                ).fetchone()
                if existing is not None:
                    existing_kind = str(existing["kind"] or "").strip().lower()
                    existing_payload = self._decode_payload(str(existing["payload_json"]), key=key)
                    incoming_payload = self._decode_payload(encoded, key=key)
                    if existing_kind != kind or not self._payloads_equivalent(
                        kind=kind, left=existing_payload, right=incoming_payload
                    ):
                        raise BftOutboxStoreError(f"bft_outbox_key_collision:{key}")
                    continue
                new_keys += 1
            if current + new_keys > self._max_pending:
                raise BftOutboxStoreError(
                    f"bft_outbox_capacity_exceeded:{current + new_keys}:{self._max_pending}"
                )
            seq_row = con.execute(
                "SELECT COALESCE(MAX(enqueue_seq), 0) + 1 AS next_seq FROM bft_outbox;"
            ).fetchone()
            next_seq = int(seq_row["next_seq"] if seq_row is not None else 1)
            imported = 0
            for key, kind, encoded in normalized:
                existing = con.execute(
                    "SELECT 1 FROM bft_outbox WHERE outbound_key=?;",
                    (key,),
                ).fetchone()
                if existing is not None:
                    continue
                cur = con.execute(
                    """
                    INSERT INTO bft_outbox(
                      outbound_key, kind, payload_json, enqueue_seq,
                      enqueued_ts_ms, updated_ts_ms
                    ) VALUES(?, ?, ?, ?, ?, ?);
                    """,
                    (key, kind, encoded, next_seq, now, now),
                )
                imported += int(cur.rowcount or 0)
                next_seq += 1
            con.execute(
                """
                INSERT INTO meta(key, value) VALUES('bft_outbox_v1_migrated', '1')
                ON CONFLICT(key) DO UPDATE SET value='1';
                """
            )
        return imported
