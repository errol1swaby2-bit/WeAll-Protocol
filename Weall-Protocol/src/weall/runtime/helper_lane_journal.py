from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

Json = dict[str, Any]


class HelperLaneJournalCorruptionError(RuntimeError):
    """Raised when durable helper-lane journal bytes cannot be trusted."""


class HelperLaneJournal:
    """Durable append-only persistence for helper-lane orchestration."""

    _FORMAT = "weall.helper-lane-journal.v2"
    _FORMAT_KEY = "_journal_format"
    _CHECKSUM_KEY = "_journal_checksum"

    def __init__(self, path: str) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

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
        fmt = str(obj.get(cls._FORMAT_KEY) or "")
        checksum = str(obj.get(cls._CHECKSUM_KEY) or "")
        if fmt != cls._FORMAT or not checksum:
            raise HelperLaneJournalCorruptionError(
                f"helper_lane_journal_integrity_fields_missing:line={line_no}"
            )
        protected = dict(obj)
        protected.pop(cls._CHECKSUM_KEY, None)
        expected = hashlib.sha256(cls._canon_record(protected).encode("utf-8")).hexdigest()
        if checksum != expected:
            raise HelperLaneJournalCorruptionError(
                f"helper_lane_journal_checksum_mismatch:line={line_no}"
            )
        protected.pop(cls._FORMAT_KEY, None)
        return protected

    def append(self, record: Json) -> None:
        line = self._canon_record(self._record_with_integrity(record))
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append_plan(self, *, plan_id: str, lanes: list[Json] | tuple[Json, ...]) -> None:
        self.append(
            {
                "kind": "helper_plan",
                "plan_id": str(plan_id or ""),
                "lanes": [dict(item) for item in list(lanes or [])],
            }
        )

    def append_receipt_accept(
        self, *, plan_id: str, lane_id: str, helper_id: str, receipt_fingerprint: str
    ) -> None:
        self.append(
            {
                "kind": "helper_receipt_accepted",
                "plan_id": str(plan_id or ""),
                "lane_id": str(lane_id or ""),
                "helper_id": str(helper_id or ""),
                "receipt_fingerprint": str(receipt_fingerprint or ""),
            }
        )

    def append_receipt_reject(
        self, *, plan_id: str, lane_id: str, helper_id: str, receipt_fingerprint: str, reason: str
    ) -> None:
        self.append(
            {
                "kind": "helper_receipt_rejected",
                "plan_id": str(plan_id or ""),
                "lane_id": str(lane_id or ""),
                "helper_id": str(helper_id or ""),
                "receipt_fingerprint": str(receipt_fingerprint or ""),
                "reason": str(reason or ""),
            }
        )

    def append_fallback(self, *, plan_id: str, lane_id: str, helper_id: str) -> None:
        self.append(
            {
                "kind": "fallback_finalized",
                "plan_id": str(plan_id or ""),
                "lane_id": str(lane_id or ""),
                "helper_id": str(helper_id or ""),
            }
        )

    def load(self) -> list[Json]:
        p = Path(self.path)
        if not p.exists():
            return []
        raw = p.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise HelperLaneJournalCorruptionError("helper_lane_journal_truncated_final_record")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HelperLaneJournalCorruptionError("helper_lane_journal_invalid_utf8") from exc
        out: list[Json] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            value = line.strip()
            if not value:
                continue
            try:
                obj = json.loads(value)
            except json.JSONDecodeError as exc:
                raise HelperLaneJournalCorruptionError(
                    f"helper_lane_journal_invalid_json:line={line_no}"
                ) from exc
            if not isinstance(obj, dict):
                raise HelperLaneJournalCorruptionError(
                    f"helper_lane_journal_record_not_object:line={line_no}"
                )
            out.append(self._verify_and_strip_integrity(obj, line_no=line_no))
        return out

    def load_resolution_state(self) -> Json:
        state: Json = {
            "plan_id": "",
            "accepted_helper_lanes": {},
            "fallback_lanes": {},
            "rejected_receipts": {},
            "accepted_receipts": {},
        }
        for record in self.load():
            kind = str(record.get("kind") or "")
            if kind == "helper_plan":
                state["plan_id"] = str(record.get("plan_id") or "")
            elif kind == "helper_finalized":
                lane_id = str(record.get("lane_id") or "")
                if lane_id:
                    state["accepted_helper_lanes"][lane_id] = {
                        "helper_id": str(record.get("helper_id") or ""),
                        "certificate": dict(record.get("certificate") or {}),
                    }
            elif kind == "fallback_finalized":
                lane_id = str(record.get("lane_id") or "")
                if lane_id:
                    state["fallback_lanes"][lane_id] = {
                        "helper_id": str(record.get("helper_id") or ""),
                        "plan_id": str(record.get("plan_id") or ""),
                    }
            elif kind == "helper_receipt_rejected":
                fingerprint = str(record.get("receipt_fingerprint") or "")
                if fingerprint:
                    state["rejected_receipts"][fingerprint] = {
                        "lane_id": str(record.get("lane_id") or ""),
                        "helper_id": str(record.get("helper_id") or ""),
                        "reason": str(record.get("reason") or ""),
                        "plan_id": str(record.get("plan_id") or ""),
                    }
            elif kind == "helper_receipt_accepted":
                fingerprint = str(record.get("receipt_fingerprint") or "")
                if fingerprint:
                    state["accepted_receipts"][fingerprint] = {
                        "lane_id": str(record.get("lane_id") or ""),
                        "helper_id": str(record.get("helper_id") or ""),
                        "plan_id": str(record.get("plan_id") or ""),
                    }
        return state
