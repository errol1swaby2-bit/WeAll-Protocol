from __future__ import annotations

import runpy
from pathlib import Path

from weall.runtime import bft_votecheck
from weall.runtime import block_replay
from weall.runtime.executor import WeAllExecutor


_orig_seed = bft_votecheck._seed_spec_exec_to_parent
_orig_apply = WeAllExecutor.apply_block
_orig_admit_block_txs = block_replay.admit_block_txs
_orig_schedule_finality = block_replay.schedule_bft_finality_receipt
_orig_run_pre = block_replay.run_replay_pre_schedulers
_orig_bind_lineage = block_replay.bind_same_block_system_lineage
_orig_emit = block_replay.emit_system_txs
_orig_validate_binding = block_replay.validate_system_tx_queue_binding


def _queue_summary(state):
    root = state.get("system_queue") if isinstance(state, dict) else None
    if not isinstance(root, list):
        return []
    out = []
    for raw in root:
        if not isinstance(raw, dict):
            out.append({"corrupt": type(raw).__name__})
            continue
        out.append(
            {
                "qid": str(raw.get("queue_id") or ""),
                "type": str(raw.get("tx_type") or ""),
                "due": int(raw.get("due_height") or 0),
                "phase": str(raw.get("phase") or ""),
                "emitted": raw.get("emitted_height"),
            }
        )
    return out


def _traced_schedule_finality(state, *args, **kwargs):
    qid = _orig_schedule_finality(state, *args, **kwargs)
    if qid:
        print(
            "P0DIAG_FINALITY_SCHEDULE",
            {"qid": str(qid), "queue": _queue_summary(state)},
            flush=True,
        )
    return qid


def _traced_run_pre(state, *args, **kwargs):
    before = _queue_summary(state)
    result = _orig_run_pre(state, *args, **kwargs)
    after = _queue_summary(state)
    if before or after:
        print("P0DIAG_PRE_SCHEDULERS", {"before": before, "after": after}, flush=True)
    return result


def _traced_bind_lineage(state, *args, **kwargs):
    before = _queue_summary(state)
    result = _orig_bind_lineage(state, *args, **kwargs)
    after = _queue_summary(state)
    if before or after:
        print(
            "P0DIAG_LINEAGE_BIND",
            {
                "phase": str(kwargs.get("phase") or ""),
                "result": int(result or 0),
                "before": before,
                "after": after,
            },
            flush=True,
        )
    return result


def _traced_emit(state, *args, **kwargs):
    before = _queue_summary(state)
    result = _orig_emit(state, *args, **kwargs)
    after = _queue_summary(state)
    if before or after:
        emitted = []
        for env in result or []:
            payload = getattr(env, "payload", None)
            emitted.append(
                {
                    "type": str(getattr(env, "tx_type", "") or ""),
                    "qid": str(payload.get("_system_queue_id") or "") if isinstance(payload, dict) else "",
                }
            )
        print(
            "P0DIAG_EMIT",
            {
                "phase": str(kwargs.get("phase") or ""),
                "before": before,
                "after": after,
                "emitted": emitted,
            },
            flush=True,
        )
    return result


def _traced_validate_binding(state, canon, env, *args, **kwargs):
    payload = getattr(env, "payload", None)
    qid = str(payload.get("_system_queue_id") or "") if isinstance(payload, dict) else ""
    lookup = kwargs.get("queue_objects_by_id")
    result = _orig_validate_binding(state, canon, env, *args, **kwargs)
    if str(getattr(env, "tx_type", "") or "").strip().upper() == "BLOCK_FINALIZE":
        print(
            "P0DIAG_FINALITY_BIND",
            {
                "qid": qid,
                "phase": str(kwargs.get("phase") or ""),
                "lookup_keys": sorted(str(k) for k in lookup.keys()) if isinstance(lookup, dict) else None,
                "queue": _queue_summary(state),
                "result": result,
            },
            flush=True,
        )
    return result


def _traced_seed(self, clone, parent_id):
    try:
        result = _orig_seed(self, clone, parent_id)
        print(
            "P0DIAG_SEED_RESULT",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "parent_id": str(parent_id or ""),
                "result": bool(result),
                "clone_height": int(clone.state.get("height") or 0),
                "clone_tip": str(clone.state.get("tip") or ""),
            },
            flush=True,
        )
        return result
    except Exception as exc:
        print(
            "P0DIAG_SEED_EXCEPTION",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "parent_id": str(parent_id or ""),
                "type": type(exc).__name__,
                "error": repr(exc),
            },
            flush=True,
        )
        raise


def _traced_admit_block_txs(*args, **kwargs):
    result = _orig_admit_block_txs(*args, **kwargs)
    try:
        envs = args[0] if args else kwargs.get("txs")
        per_tx = result[2] if isinstance(result, tuple) and len(result) >= 3 else []
        rejects = []
        for index, rej in enumerate(per_tx or []):
            if rej is None:
                continue
            env = envs[index] if isinstance(envs, list) and index < len(envs) else None
            payload = getattr(env, "payload", None)
            rejects.append(
                {
                    "index": index,
                    "code": str(getattr(rej, "code", "") or ""),
                    "reason": str(getattr(rej, "reason", "") or ""),
                    "details": dict(getattr(rej, "details", {}) or {}),
                    "tx_type": str(getattr(env, "tx_type", "") or "") if env is not None else "",
                    "signer": str(getattr(env, "signer", "") or "") if env is not None else "",
                    "nonce": int(getattr(env, "nonce", 0) or 0) if env is not None else 0,
                    "system": bool(getattr(env, "system", False)) if env is not None else False,
                    "queue_id": (
                        str(payload.get("_system_queue_id") or "")
                        if isinstance(payload, dict)
                        else ""
                    ),
                    "payload": dict(payload) if isinstance(payload, dict) else None,
                }
            )
        if rejects:
            print("P0DIAG_TX_ADMISSION_REJECTS", rejects, flush=True)
    except Exception as exc:
        print(
            "P0DIAG_TX_ADMISSION_TRACE_ERROR",
            {"type": type(exc).__name__, "error": repr(exc)},
            flush=True,
        )
    return result


def _traced_apply(self, block):
    meta = _orig_apply(self, block)
    if meta is None or not bool(getattr(meta, "ok", False)):
        txs = block.get("txs") if isinstance(block, dict) else None
        summaries = []
        if isinstance(txs, list):
            for index, tx in enumerate(txs):
                payload = tx.get("payload") if isinstance(tx, dict) else None
                summaries.append(
                    {
                        "index": index,
                        "tx_type": str(tx.get("type") or tx.get("tx_type") or "") if isinstance(tx, dict) else "",
                        "signer": str(tx.get("signer") or "") if isinstance(tx, dict) else "",
                        "nonce": int(tx.get("nonce") or 0) if isinstance(tx, dict) else 0,
                        "system": bool(tx.get("system") is True) if isinstance(tx, dict) else False,
                        "queue_id": (
                            str(payload.get("_system_queue_id") or "")
                            if isinstance(payload, dict)
                            else ""
                        ),
                    }
                )
        print(
            "P0DIAG_APPLY_FAILURE",
            {
                "node": str(getattr(self, "node_id", "") or ""),
                "block_id": str(block.get("block_id") or "") if isinstance(block, dict) else "",
                "height": int(block.get("height") or 0) if isinstance(block, dict) else 0,
                "error": "<none>" if meta is None else str(getattr(meta, "error", "") or ""),
                "state_height": int(getattr(self, "state", {}).get("height") or 0),
                "state_tip": str(getattr(self, "state", {}).get("tip") or ""),
                "txs": summaries,
            },
            flush=True,
        )
    return meta


bft_votecheck._seed_spec_exec_to_parent = _traced_seed
block_replay.schedule_bft_finality_receipt = _traced_schedule_finality
block_replay.run_replay_pre_schedulers = _traced_run_pre
block_replay.bind_same_block_system_lineage = _traced_bind_lineage
block_replay.emit_system_txs = _traced_emit
block_replay.validate_system_tx_queue_binding = _traced_validate_binding
block_replay.admit_block_txs = _traced_admit_block_txs
WeAllExecutor.apply_block = _traced_apply

runpy.run_path(
    str(Path(__file__).with_name("tmp-p0-03-follower-diagnostic.py")),
    run_name="__main__",
)
