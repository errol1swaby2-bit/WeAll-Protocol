from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_outbound.py)."""

from weall.runtime.bft_executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

def _bft_outbound_key(self, kind: str, payload: Json) -> str:
    _bind_executor_globals()
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
    _bind_executor_globals()
    key = self._bft_outbound_key(kind, payload)
    self._bft_record_event(
        "bft_outbound_enqueued", kind=str(kind), key=key, payload=dict(payload or {})
    )
    return key

def bft_mark_outbound_sent(self, kind: str, payload: Json) -> None:
    _bind_executor_globals()
    key = self._bft_outbound_key(kind, payload)
    self._bft_record_event("bft_outbound_sent", kind=str(kind), key=key)

def bft_pending_outbound_messages(self) -> list[Json]:
    _bind_executor_globals()
    try:
        info = self._bft_journal.bootstrap_state()
    except Exception:
        return []
    out: list[Json] = []
    for item in list(info.get("pending_outbound") or []):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip().lower()
        payload = item.get("payload")
        if kind and isinstance(payload, dict) and payload:
            out.append({"kind": kind, "payload": dict(payload)})
    return out

def _bft_record_event(self, event: str, **payload: Any) -> None:
    _bind_executor_globals()
    try:
        self._bft_journal.append(event, chain_id=self.chain_id, node_id=self.node_id, **payload)
    except Exception:
        pass

def _restore_bft_restart_hints(self) -> None:
    _bind_executor_globals()
    try:
        info = self._bft_journal.bootstrap_state()
    except Exception:
        return
    try:
        self._bft.view = max(int(self._bft.view), int(info.get("last_view") or 0))
    except Exception:
        pass

