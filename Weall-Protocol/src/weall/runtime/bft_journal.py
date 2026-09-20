from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from weall.runtime.runtime_time import now_ms as _now_ms

Json = dict[str, Any]


class BftJournalCorruptionError(RuntimeError):
    """Raised when durable BFT journal bytes cannot be trusted."""


class BftJournal:
    """Append-only node-local journal for BFT diagnostics and restart hints.

    The authoritative durable send obligations live in ``BftOutboxStore``.  This
    journal retains outbound enqueue/sent events for diagnostics and one-time
    migration of legacy nodes, but retention/compaction is never correctness state.

    Records written by this version are checksummed. Well-formed legacy records
    without integrity fields remain readable for upgrade compatibility, but any
    record that advertises integrity metadata must verify successfully.
    """

    _FORMAT = "weall.bft-journal.v2"
    _FORMAT_KEY = "_journal_format"
    _CHECKSUM_KEY = "_journal_checksum"

    def __init__(self, path: str, *, max_events: int = 2000) -> None:
        self.path = str(path)
        self.max_events = max(100, int(max_events))
        self._lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if not Path(self.path).exists():
            Path(self.path).write_text("", encoding="utf-8")

    @staticmethod
    def _canon_record(record: Json) -> str:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def _record_with_integrity(cls, record: Json) -> Json:
        payload = dict(record)
        payload.pop(cls._FORMAT_KEY, None)
        payload.pop(cls._CHECKSUM_KEY, None)
        protected = {cls._FORMAT_KEY: cls._FORMAT, **payload}
        checksum = hashlib.sha256(cls._canon_record(protected).encode("utf-8")).hexdigest()
        return {**protected, cls._CHECKSUM_KEY: checksum}

    @classmethod
    def _verify_and_strip_integrity(cls, obj: Json, *, line_no: int) -> Json:
        has_format = cls._FORMAT_KEY in obj
        has_checksum = cls._CHECKSUM_KEY in obj
        if not has_format and not has_checksum:
            # Upgrade compatibility for pre-v2, well-formed journal records.
            return dict(obj)
        if not has_format or not has_checksum:
            raise BftJournalCorruptionError(
                f"bft_journal_integrity_fields_incomplete:line={line_no}"
            )
        fmt = str(obj.get(cls._FORMAT_KEY) or "")
        checksum = str(obj.get(cls._CHECKSUM_KEY) or "")
        if fmt != cls._FORMAT or not checksum:
            raise BftJournalCorruptionError(f"bft_journal_integrity_fields_invalid:line={line_no}")
        protected = dict(obj)
        protected.pop(cls._CHECKSUM_KEY, None)
        expected = hashlib.sha256(cls._canon_record(protected).encode("utf-8")).hexdigest()
        if checksum != expected:
            raise BftJournalCorruptionError(f"bft_journal_checksum_mismatch:line={line_no}")
        protected.pop(cls._FORMAT_KEY, None)
        return protected

    @staticmethod
    def _validate_record_shape(record: Json, *, line_no: int) -> None:
        event = str(record.get("event") or "").strip()
        payload = record.get("payload")
        if not event:
            raise BftJournalCorruptionError(f"bft_journal_event_missing:line={line_no}")
        if not isinstance(payload, dict):
            raise BftJournalCorruptionError(f"bft_journal_payload_not_object:line={line_no}")
        try:
            int(record.get("ts_ms"))
        except Exception as exc:
            raise BftJournalCorruptionError(
                f"bft_journal_timestamp_invalid:line={line_no}"
            ) from exc

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        fd = os.open(str(path.parent), flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def append(self, event_type: str, **payload: Any) -> None:
        rec: Json = {
            "ts_ms": _now_ms(),
            "event": str(event_type),
            "payload": payload,
        }
        line = self._canon_record(self._record_with_integrity(rec)) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            self._trim_locked()

    def read_tail(self, limit: int = 100, *, strict: bool = False) -> list[Json]:
        lim = max(1, min(int(limit), self.max_events))
        path = Path(self.path)
        try:
            with self._lock:
                raw = path.read_bytes()
        except Exception:
            if strict:
                raise
            return []
        if strict and raw and not raw.endswith(b"\n"):
            raise BftJournalCorruptionError("bft_journal_truncated_final_record")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            if strict:
                raise BftJournalCorruptionError("bft_journal_invalid_utf8") from exc
            return []

        lines = text.splitlines()
        out: list[Json] = []
        start_line = max(1, len(lines) - lim + 1)
        for line_no, line in enumerate(lines[-lim:], start=start_line):
            value = line.strip()
            if not value:
                continue
            try:
                obj = json.loads(value)
            except json.JSONDecodeError as exc:
                if strict:
                    raise BftJournalCorruptionError(
                        f"bft_journal_invalid_json:line={line_no}"
                    ) from exc
                continue
            if not isinstance(obj, dict):
                if strict:
                    raise BftJournalCorruptionError(f"bft_journal_record_not_object:line={line_no}")
                continue
            try:
                record = self._verify_and_strip_integrity(obj, line_no=line_no)
                self._validate_record_shape(record, line_no=line_no)
            except BftJournalCorruptionError:
                if strict:
                    raise
                continue
            out.append(record)
        return out

    def last_event(self, event_type: str) -> Json | None:
        for rec in reversed(self.read_tail(limit=self.max_events)):
            if str(rec.get("event") or "") == str(event_type):
                return rec
        return None

    def bootstrap_state(self, *, strict: bool = False) -> Json:
        out: Json = {
            "last_view": 0,
            "last_timeout_view": -1,
            "last_high_qc_id": "",
            "fetch_requests": [],
            "pending_outbound": [],
        }
        for rec in self.read_tail(limit=self.max_events, strict=strict):
            payload = rec.get("payload") if isinstance(rec, dict) else None
            if not isinstance(payload, dict):
                continue
            ev = str(rec.get("event") or "")
            if ev == "bft_checkpoint_reset":
                # A destructive trusted checkpoint adopts a different canonical
                # history. Restart hints and legacy outbound reconstruction from
                # the prior branch must not cross that boundary. Events after the
                # reset remain eligible restart evidence.
                out = {
                    "last_view": 0,
                    "last_timeout_view": -1,
                    "last_high_qc_id": "",
                    "fetch_requests": [],
                    "pending_outbound": [],
                }
            elif ev == "bft_view_advanced":
                try:
                    out["last_view"] = max(int(out["last_view"]), int(payload.get("view") or 0))
                except Exception:
                    pass
            elif ev == "bft_timeout_emitted":
                try:
                    out["last_timeout_view"] = max(
                        int(out["last_timeout_view"]), int(payload.get("view") or -1)
                    )
                except Exception:
                    pass
                hqc = str(payload.get("high_qc_id") or "").strip()
                if hqc:
                    out["last_high_qc_id"] = hqc
            elif ev == "bft_fetch_requested":
                bid = str(payload.get("block_id") or "").strip()
                if bid:
                    wants = list(out.get("fetch_requests") or [])
                    if bid not in wants:
                        wants.append(bid)
                        out["fetch_requests"] = wants[-256:]
            elif ev == "bft_fetch_satisfied":
                bid = str(payload.get("block_id") or "").strip()
                if bid:
                    wants = [x for x in list(out.get("fetch_requests") or []) if x != bid]
                    out["fetch_requests"] = wants
            elif ev == "bft_outbound_enqueued":
                kind = str(payload.get("kind") or "").strip().lower()
                key = str(payload.get("key") or "").strip()
                body = payload.get("payload")
                if kind and key and isinstance(body, dict):
                    cur = []
                    for item in list(out.get("pending_outbound") or []):
                        if not isinstance(item, dict):
                            continue
                        if str(item.get("key") or "").strip() == key:
                            continue
                        cur.append(item)
                    cur.append({"kind": kind, "key": key, "payload": dict(body)})
                    out["pending_outbound"] = cur
            elif ev == "bft_outbound_sent":
                key = str(payload.get("key") or "").strip()
                if key:
                    cur = []
                    for item in list(out.get("pending_outbound") or []):
                        if not isinstance(item, dict):
                            continue
                        if str(item.get("key") or "").strip() == key:
                            continue
                        cur.append(item)
                    out["pending_outbound"] = cur
        return out

    def _trim_locked(self) -> None:
        path = Path(self.path)
        try:
            raw = path.read_bytes()
        except Exception:
            return
        if raw.count(b"\n") <= int(self.max_events):
            return

        # Strict parsing prevents trimming from silently laundering corrupt bytes.
        records = self.read_tail(limit=self.max_events, strict=True)
        encoded = "".join(
            self._canon_record(self._record_with_integrity(record)) + "\n" for record in records
        ).encode("utf-8")
        tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            with open(tmp, "xb") as fh:
                fh.write(encoded)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            self._fsync_parent(path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
