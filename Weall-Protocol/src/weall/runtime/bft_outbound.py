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


def _bft_local_artifact_is_current(self, kind: str, payload: Json) -> bool:
    """Return whether a locally produced artifact still belongs to this branch."""
    k = str(kind or "").strip().lower()
    if not isinstance(payload, dict) or not payload:
        return False

    if k in {"vote", "timeout"}:
        key = self._bft_outbound_key(k, payload)
        contains = getattr(self._bft_outbox_store, "contains_equivalent", None)
        if callable(contains):
            return bool(contains(key=key, kind=k, payload=payload))
        for item in self._bft_outbox_store.pending():
            if str(getattr(item, "key", "") or "") != key:
                continue
            if str(getattr(item, "kind", "") or "").strip().lower() != k:
                continue
            existing = getattr(item, "payload", None)
            if isinstance(existing, dict) and self._bft_outbox_store._payloads_equivalent(
                kind=k,
                left=existing,
                right=payload,
            ):
                return True
        return False

    if k == "proposal":
        block_id = str(payload.get("block_id") or "").strip()
        if not block_id:
            return False
        item = getattr(self, "_pending_candidates", {}).get(block_id)
        block = item[0] if isinstance(item, tuple) and item else None
        return isinstance(block, dict) and _canon_json(block) == _canon_json(payload)

    if k == "qc":
        accepted = getattr(self, "bft_artifact_was_accepted", None)
        return bool(callable(accepted) and accepted("qc", payload))

    return False


def bft_send_local_artifact_if_current(self, kind: str, payload: Json, send_fn) -> bool:
    """Emit a local BFT artifact only while its branch-local authority still exists.

    The executor wrapper holds the canonical-branch lock across this function.
    A checkpoint therefore either purges the artifact before this check, causing
    a clean drop, or waits until the already-authorized transport send finishes.
    """
    if not callable(send_fn):
        raise TypeError("bft_outbound_send_callback_required")
    k = str(kind or "").strip().lower()
    if not _bft_local_artifact_is_current(self, k, payload):
        return False

    send_fn()

    if k in {"vote", "timeout"}:
        bft_mark_outbound_sent(self, k, payload)
    return True


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
        info = {}
    try:
        self._bft.view = max(int(self._bft.view), int(info.get("last_view") or 0))
    except Exception:
        pass

    # The authoritative outbox may contain a timeout that was durably enqueued
    # just before a crash but whose BFT cursor had not yet been persisted.  Treat
    # that exact pending signed artifact as evidence that the same view must not
    # be signed again; the outbox will replay it verbatim.
    try:
        pending_timeout_view = int(getattr(self._bft, "last_timeout_view", -1))
        for item in self._bft_outbox_store.pending():
            if str(getattr(item, "kind", "") or "").strip().lower() != "timeout":
                continue
            payload = getattr(item, "payload", None)
            if not isinstance(payload, dict):
                continue
            try:
                pending_timeout_view = max(pending_timeout_view, int(payload.get("view")))
            except Exception:
                continue
        self._bft.last_timeout_view = pending_timeout_view
    except Exception:
        pass
