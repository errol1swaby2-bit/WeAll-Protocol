from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

Json = dict[str, Any]


class HelperLaneJournal:
    """Durable append-only persistence for helper-lane orchestration."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _canon_record(record: Json) -> str:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def append(self, record: Json) -> None:
        line = self._canon_record(record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append_plan(self, *, plan_id: str, lanes: list[Json] | tuple[Json, ...]) -> None:
        self.append({"kind": "helper_plan", "plan_id": str(plan_id or ""), "lanes": [dict(item) for item in list(lanes or [])]})

    def append_receipt_accept(self, *, plan_id: str, lane_id: str, helper_id: str, receipt_fingerprint: str) -> None:
        self.append({
            "kind": "helper_receipt_accepted",
            "plan_id": str(plan_id or ""),
            "lane_id": str(lane_id or ""),
            "helper_id": str(helper_id or ""),
            "receipt_fingerprint": str(receipt_fingerprint or ""),
        })

    def append_receipt_reject(self, *, plan_id: str, lane_id: str, helper_id: str, receipt_fingerprint: str, reason: str) -> None:
        self.append({
            "kind": "helper_receipt_rejected",
            "plan_id": str(plan_id or ""),
            "lane_id": str(lane_id or ""),
            "helper_id": str(helper_id or ""),
            "receipt_fingerprint": str(receipt_fingerprint or ""),
            "reason": str(reason or ""),
        })

    def append_fallback(self, *, plan_id: str, lane_id: str, helper_id: str) -> None:
        self.append({
            "kind": "fallback_finalized",
            "plan_id": str(plan_id or ""),
            "lane_id": str(lane_id or ""),
            "helper_id": str(helper_id or ""),
        })

    def load(self) -> list[Json]:
        p = Path(self.path)
        if not p.exists():
            return []
        out: list[Json] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
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
