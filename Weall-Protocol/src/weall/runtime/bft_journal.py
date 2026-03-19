from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


class BftJournal:
    """Append-only local journal for consensus diagnostics and restart hints.

    This journal is intentionally node-local and non-consensus-critical. It gives
    operators a durable trace of view changes, timeout escalation, fetch gaps,
    and restart context without altering block validity.
    """

    def __init__(self, path: str, *, max_events: int = 2000) -> None:
        self.path = str(path)
        self.max_events = max(100, int(max_events))
        self._lock = threading.Lock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if not Path(self.path).exists():
            Path(self.path).write_text("", encoding="utf-8")

    def append(self, event_type: str, **payload: Any) -> None:
        rec: Json = {
            "ts_ms": _now_ms(),
            "event": str(event_type),
            "payload": payload,
        }
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
            self._trim_locked()

    def read_tail(self, limit: int = 100) -> list[Json]:
        lim = max(1, min(int(limit), self.max_events))
        try:
            lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        except Exception:
            return []
        out: list[Json] = []
        for line in lines[-lim:]:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except Exception:
                continue
        return out

    def last_event(self, event_type: str) -> Json | None:
        for rec in reversed(self.read_tail(limit=self.max_events)):
            if str(rec.get("event") or "") == str(event_type):
                return rec
        return None

    def bootstrap_state(self) -> Json:
        out: Json = {
            "last_view": 0,
            "last_timeout_view": -1,
            "last_high_qc_id": "",
            "fetch_requests": [],
            "pending_outbound": [],
        }
        for rec in self.read_tail(limit=self.max_events):
            payload = rec.get("payload") if isinstance(rec, dict) else None
            if not isinstance(payload, dict):
                continue
            ev = str(rec.get("event") or "")
            if ev == "bft_view_advanced":
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
                    out["pending_outbound"] = cur[-256:]
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
                    out["pending_outbound"] = cur[-256:]
        return out

    def _trim_locked(self) -> None:
        try:
            lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        except Exception:
            return
        extra = len(lines) - int(self.max_events)
        if extra <= 0:
            return
        Path(self.path).write_text(
            "\n".join(lines[-self.max_events :]) + ("\n" if lines else ""),
            encoding="utf-8",
        )
