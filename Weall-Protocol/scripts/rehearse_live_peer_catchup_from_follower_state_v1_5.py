#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from rehearse_public_style_validator_network_mechanics_v1_5 import VALIDATORS, _account_tx, _keys, _node_env, _seed_validator_set, _tx_index_path
from weall.runtime.executor import WeAllExecutor
from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.runtime.state_hash import compute_state_root
from weall.services.block_producer import ProducerConfig, _produce_once


def _header(chain_id: str, corr_id: str) -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id=chain_id, schema_version="1", tx_index_hash="dev", corr_id=corr_id)


def _make_local_executor(root: Path, name: str, chain_id: str, pubs: dict[str, str]) -> WeAllExecutor:
    ex = WeAllExecutor(db_path=str(root / f"{name}.sqlite"), node_id=name, chain_id=chain_id, tx_index_path=_tx_index_path())
    _seed_validator_set(ex, pubs)
    return ex


def _prepare_block(block: dict[str, Any]) -> dict[str, Any]:
    out = dict(block)
    if isinstance(out.get("header"), dict):
        out["header"] = dict(out["header"])
    out["proposer"] = VALIDATORS[0]
    out["view"] = 0
    return out


def _produce_and_apply(leader, follower, pubs: dict[str, str], privs: dict[str, str], *, tx_account: str, nonce: int) -> dict[str, Any]:
    tx = _account_tx(tx_account, nonce)
    tx["chain_id"] = "batch563-follower-source-sync"
    leader._mempool.add(dict(tx))
    follower._mempool.add(dict(tx))
    with _node_env(VALIDATORS[0], pubs, privs):
        _produce_once(leader, ProducerConfig(interval_ms=25, max_txs=1, allow_empty=False))
    block = leader.get_block_by_height(int(leader.state.get("height") or 0))
    if not isinstance(block, dict):
        raise RuntimeError("leader_block_missing")
    prepared = _prepare_block(block)
    with _node_env(VALIDATORS[1], pubs, privs):
        meta = follower.apply_block(prepared)
    if not bool(getattr(meta, "ok", False)):
        raise RuntimeError(f"follower_apply_failed:{getattr(meta, 'error', '')}")
    return prepared


def _apply_blocks(executor, blocks: list[dict[str, Any]], pubs: dict[str, str], privs: dict[str, str]) -> list[bool]:
    results: list[bool] = []
    for block in blocks:
        with _node_env(VALIDATORS[2], pubs, privs):
            meta = executor.apply_block(_prepare_block(block))
        results.append(bool(getattr(meta, "ok", False)))
    return results


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    pubs, privs = _keys()
    try:
        for key in list(os.environ):
            if key.startswith("WEALL_"):
                os.environ.pop(key, None)
        os.environ.update({
            "WEALL_MODE": "testnet",
            "WEALL_SIGVERIFY": "0",
            "WEALL_UNSAFE_DEV": "1",
            "WEALL_REQUIRE_VRF": "0",
            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",
            "WEALL_PRODUCE_EMPTY_BLOCKS": "1",
            "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        })
        with tempfile.TemporaryDirectory(prefix="weall-b563-follower-sync-") as td:
            root = Path(td)
            chain_id = "batch563-follower-source-sync"
            leader = _make_local_executor(root, VALIDATORS[0], chain_id, pubs)
            follower = _make_local_executor(root, VALIDATORS[1], chain_id, pubs)
            # Align chain IDs created by the shared helper with this harness.
            leader.state["chain_id"] = chain_id
            follower.state["chain_id"] = chain_id
            leader._ledger_store.write(leader.state); leader.state = leader._ledger_store.read()
            follower._ledger_store.write(follower.state); follower.state = follower._ledger_store.read()
            committed: list[dict[str, Any]] = []
            for idx in range(1, 4):
                committed.append(_produce_and_apply(leader, follower, pubs, privs, tx_account=f"@catchup-{idx}", nonce=1))
            follower_height = int(follower.state.get("height") or 0)
            follower_root = compute_state_root(follower.state)
            anchor = build_snapshot_anchor(follower.read_state())
            service = StateSyncService(
                chain_id=chain_id,
                schema_version="1",
                tx_index_hash="dev",
                state_provider=follower.read_state,
                block_provider=follower.get_block_by_height,
                enable_delta=True,
                require_trusted_anchor=True,
                fallback_to_snapshot=False,
            )
            fresh = _make_local_executor(root, VALIDATORS[2], chain_id, pubs)
            fresh.state["chain_id"] = chain_id
            fresh._ledger_store.write(fresh.state); fresh.state = fresh._ledger_store.read()
            first_req = StateSyncRequestMsg(header=_header(chain_id, "b563-first"), mode="delta", from_height=0, to_height=1, selector={"trusted_anchor": anchor})
            first_resp = service.handle_request(first_req)
            service.verify_response(first_resp, trusted_anchor=anchor)
            first_results = _apply_blocks(fresh, list(first_resp.blocks or ()), pubs, privs)
            interrupted_height = int(fresh.state.get("height") or 0)
            resumed = _make_local_executor(root, VALIDATORS[2], chain_id, pubs)
            resumed.state["chain_id"] = chain_id
            resumed._ledger_store.write(resumed.state); resumed.state = resumed._ledger_store.read()
            resume_req = StateSyncRequestMsg(header=_header(chain_id, "b563-resume"), mode="delta", from_height=interrupted_height, to_height=follower_height, selector={"trusted_anchor": anchor})
            resume_resp = service.handle_request(resume_req)
            service.verify_response(resume_resp, trusted_anchor=anchor)
            resume_results = _apply_blocks(resumed, list(resume_resp.blocks or ()), pubs, privs)
            fresh_root = compute_state_root(resumed.state)
            return {
                "ok": bool(follower_height == len(committed) and all(first_results) and all(resume_results) and fresh_root == follower_root),
                "batch": "563",
                "source_peer": "follower-validator-state",
                "follower_height": follower_height,
                "fresh_node_started_empty": True,
                "interrupted_height": interrupted_height,
                "first_sync_block_count": len(first_resp.blocks or ()),
                "resume_sync_block_count": len(resume_resp.blocks or ()),
                "state_roots_match": fresh_root == follower_root,
                "trusted_anchor_height": anchor.get("height"),
                "snapshot_used": False,
            }
    finally:
        os.environ.clear(); os.environ.update(old)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
