#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.services.block_producer import ProducerConfig, _produce_once


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _make_executor(root: Path, name: str, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(db_path=str(root / f"{name}.sqlite"), node_id=name, chain_id=chain_id, tx_index_path=_tx_index_path())


def _tx(account: str, nonce: int, chain_id: str) -> dict[str, Any]:
    return {"tx_type": "ACCOUNT_REGISTER", "signer": account, "nonce": nonce, "chain_id": chain_id, "payload": {"pubkey": f"k:{account}"}, "sig": "sig"}


def _header(chain_id: str, *, corr_id: str = "b557") -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id=chain_id, schema_version="1", tx_index_hash="dev", corr_id=corr_id)


def _apply_blocks(fresh: WeAllExecutor, blocks: list[dict[str, Any]]) -> list[bool]:
    results: list[bool] = []
    for block in blocks:
        meta = fresh.apply_block(block)
        results.append(bool(getattr(meta, "ok", False)))
    return results


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    try:
        for key in list(os.environ):
            if key.startswith("WEALL_"):
                os.environ.pop(key, None)
        os.environ.update({"WEALL_MODE": "testnet", "WEALL_SIGVERIFY": "0", "WEALL_REQUIRE_VRF": "0", "WEALL_PRODUCE_EMPTY_BLOCKS": "1", "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1"})
        chain_id = "batch557-live-peer-sync"
        with tempfile.TemporaryDirectory(prefix="weall-b557-peer-sync-") as td:
            root = Path(td)
            source = _make_executor(root, "source", chain_id)
            for idx in range(1, 5):
                source._mempool.add(_tx(f"@sync-{idx}", 1, chain_id))
                _produce_once(source, ProducerConfig(interval_ms=25, max_txs=1, allow_empty=False))
            height = int(source.state.get("height") or 0)
            source_root = compute_state_root(source.state)
            anchor = build_snapshot_anchor(source.read_state())
            service = StateSyncService(
                chain_id=chain_id,
                schema_version="1",
                tx_index_hash="dev",
                state_provider=source.read_state,
                block_provider=source.get_block_by_height,
                enable_delta=True,
                require_trusted_anchor=True,
                fallback_to_snapshot=False,
            )
            req1 = StateSyncRequestMsg(header=_header(chain_id, corr_id="b557-a"), mode="delta", from_height=0, to_height=2, selector={"trusted_anchor": anchor})
            resp1 = service.handle_request(req1)
            service.verify_response(resp1, trusted_anchor=anchor)
            req2 = StateSyncRequestMsg(header=_header(chain_id, corr_id="b557-b"), mode="delta", from_height=2, to_height=height, selector={"trusted_anchor": anchor})
            resp2 = service.handle_request(req2)
            service.verify_response(resp2, trusted_anchor=anchor)
            fresh = _make_executor(root, "fresh", chain_id)
            first_results = _apply_blocks(fresh, list(resp1.blocks or ()))
            interrupted_height = int(fresh.state.get("height") or 0)
            # Restart from durable DB and resume from the last applied height.
            resumed = _make_executor(root, "fresh", chain_id)
            resume_req = StateSyncRequestMsg(header=_header(chain_id, corr_id="b557-resume"), mode="delta", from_height=interrupted_height, to_height=height, selector={"trusted_anchor": anchor})
            resume_resp = service.handle_request(resume_req)
            service.verify_response(resume_resp, trusted_anchor=anchor)
            second_results = _apply_blocks(resumed, list(resume_resp.blocks or ()))
            fresh_root = compute_state_root(resumed.state)
            corrupt_rejected = False
            if resume_resp.blocks:
                bad_blocks = [dict(b) for b in resume_resp.blocks]
                bad_blocks[0] = dict(bad_blocks[0])
                bad_blocks[0].setdefault("header", {})["state_root"] = "bad-root"
                try:
                    corrupt_fresh = _make_executor(root, "corrupt-fresh", chain_id)
                    _apply_blocks(corrupt_fresh, list(resp1.blocks or ()))
                    for bad in bad_blocks:
                        meta = corrupt_fresh.apply_block(bad)
                        if not bool(getattr(meta, "ok", False)):
                            corrupt_rejected = True
                            break
                except Exception:
                    corrupt_rejected = True
            wrong_chain_rejected = False
            wrong_req = StateSyncRequestMsg(header=_header("wrong-chain", corr_id="b557-wrong"), mode="delta", from_height=0, to_height=height, selector={"trusted_anchor": anchor})
            wrong_resp = service.handle_request(wrong_req)
            wrong_chain_rejected = wrong_resp.ok is False and wrong_resp.reason == "chain_mismatch"
            return {
                "ok": bool(height >= 4 and all(first_results) and all(second_results) and source_root == fresh_root and corrupt_rejected and wrong_chain_rejected),
                "batch": "557",
                "source_height": height,
                "trusted_anchor_height": anchor.get("height"),
                                "mode": "delta",
                "fresh_node_started_empty": True,
                "first_sync_block_count": len(resp1.blocks or ()),
                "resume_sync_block_count": len(resume_resp.blocks or ()),
                "interrupted_height": interrupted_height,
                                "state_roots_match": source_root == fresh_root,
                "corrupt_peer_data_rejected": corrupt_rejected,
                "wrong_chain_rejected": wrong_chain_rejected,
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
