from __future__ import annotations

import runpy
from pathlib import Path

from weall.runtime import bft_votecheck
from weall.runtime import block_replay
from weall.runtime.executor import WeAllExecutor


_orig_seed = bft_votecheck._seed_spec_exec_to_parent
_orig_apply = WeAllExecutor.apply_block
_orig_admit_block_txs = block_replay.admit_block_txs


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
block_replay.admit_block_txs = _traced_admit_block_txs
WeAllExecutor.apply_block = _traced_apply

runpy.run_path(
    str(Path(__file__).with_name("tmp-p0-03-follower-diagnostic.py")),
    run_name="__main__",
)
