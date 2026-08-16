from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_outbound.py)."""

from typing import Any

from weall.runtime.executor import (
    Json,
    _canon_json,
)


def _bft_outbound_key(self, kind: str, payload: Json) -> str:
    try:
        if str(kind) == "vote":
            return f"vote:{int(payload.get('view') or 0)}:{str(payload.get('signer') or '')}:{str(payload.get('block_id') or '')}"
        if str(kind) == "timeout":
            return f"timeout:{int(payload.get('view') or 0)}:{str(payload.get('signer') or '')}:{str(payload.get('high_qc_id') or '')}"
        if str(kind) == "proposal":
            return f"proposal:{int(payload.get('view') or 0)}:{str(payload.get('proposer') or '')}:{str(payload.get('block_id') or '')}"
        if str(kind) == "qc":
            return f"qc:{int(payload.get('view') or 0)}:{str(payload.get('block_id') or '')}"
        return f"{str(kind)}:{_canon_json(payload)}"
    except Exception:
        return f"{str(kind)}:{repr(payload)}"


def _bft_enqueue_outbound(self, kind: str, payload: Json) -> str:
    """Durably enqueue an outbound consensus message before it can be emitted.

    The SQLite outbox is authoritative and intentionally independent from the
    bounded diagnostic BFT journal.  If this durable write fails, the obligation
    is not returned to the networking layer and the error propagates fail-closed.
    """

    key = self._bft_outbound_key(kind, payload)
    self._bft_outbox_store.enqueue(
        key=key,
        kind=str(kind),
        payload=dict(payload or {}),
    )
    _bft_record_event(
        self,
        "bft_outbound_enqueued",
        kind=str(kind),
        key=key,
        payload=dict(payload or {}),
    )
    return key


def bft_mark_outbound_sent(self, kind: str, payload: Json) -> None:
    key = self._bft_outbound_key(kind, payload)
    # Deletion happens only after the networking layer reports the send. If a
    # crash happens before this point, restart will replay the obligation. A
    # duplicate BFT artifact is safer than silently forgetting an unsent one.
    self._bft_outbox_store.mark_sent(key=key)
    _bft_record_event(self, "bft_outbound_sent", kind=str(kind), key=key)


def bft_pending_outbound_messages(self) -> list[Json]:
    out: list[Json] = []
    for item in self._bft_outbox_store.pending():
        kind = str(item.kind or "").strip().lower()
        payload = item.payload
        if kind and isinstance(payload, dict) and payload:
            out.append({"kind": kind, "payload": dict(payload)})
    return out


def _bft_record_event(self, event: str, **payload: Any) -> None:
    try:
        self._bft_journal.append(event, chain_id=self.chain_id, node_id=self.node_id, **payload)
    except Exception:
        # Diagnostic history must never control the authoritative durable outbox.
        pass


def _restore_bft_restart_hints(self) -> None:
    try:
        info = self._bft_journal.bootstrap_state()
    except Exception:
        return
    try:
        self._bft.view = max(int(self._bft.view), int(info.get("last_view") or 0))
    except Exception:
        pass
