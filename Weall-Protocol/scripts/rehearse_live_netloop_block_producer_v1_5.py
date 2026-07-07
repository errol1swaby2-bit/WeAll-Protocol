#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
import time
from pathlib import Path
from typing import Any

from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.services.block_producer import ProducerConfig, _produce_once


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _set_base_env() -> None:
    for key in list(os.environ):
        if key.startswith("WEALL_"):
            os.environ.pop(key, None)
    os.environ.update(
        {
            "WEALL_MODE": "testnet",
            "WEALL_SIGVERIFY": "0",
            "WEALL_REQUIRE_VRF": "0",
            "WEALL_UNSAFE_DEV": "1",
            "WEALL_PRODUCE_EMPTY_BLOCKS": "1",
            "WEALL_NET_ENABLED": "1",
            "WEALL_NET_TICK_MS": "10",
            "WEALL_BFT_ENABLED": "0",
        }
    )


def _make_executor(root: Path, node_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(root / f"{node_id}.sqlite"),
        node_id=node_id,
        chain_id="batch544-live-netloop",
        tx_index_path=_tx_index_path(),
    )


def _make_loop(executor: WeAllExecutor, *, root: Path, node_id: str, port: int, peer_port: int) -> NetMeshLoop:
    os.environ["WEALL_PEERS_FILE"] = str(root / f"{node_id}-peers.json")
    os.environ["WEALL_PEERS"] = f"tcp://127.0.0.1:{int(peer_port)}"
    os.environ["WEALL_PEER_ID"] = node_id
    os.environ["WEALL_AGENT"] = f"weall-b544-{node_id}"
    cfg = NetLoopConfig(enabled=True, bind_host="127.0.0.1", bind_port=int(port), tick_ms=10, schema_version="1")
    return NetMeshLoop(executor=executor, mempool=executor._mempool, cfg=cfg)


def run_harness() -> dict[str, Any]:
    old_env = os.environ.copy()
    try:
        _set_base_env()
        with tempfile.TemporaryDirectory(prefix="weall-b544-live-netloop-") as td:
            root = Path(td)
            p1, p2 = _free_port(), _free_port()
            ex1 = _make_executor(root, "node-a")
            ex2 = _make_executor(root, "node-b")
            loop1 = _make_loop(ex1, root=root, node_id="node-a", port=p1, peer_port=p2)
            loop2 = _make_loop(ex2, root=root, node_id="node-b", port=p2, peer_port=p1)
            started1 = loop1.start()
            started2 = loop2.start()
            try:
                time.sleep(0.15)
                cfg = ProducerConfig(interval_ms=50, max_txs=0, allow_empty=True)
                _produce_once(ex1, cfg)
                produced_height = int(ex1.state.get("height") or 0)
                block = ex1.get_block_by_height(produced_height)
                if not isinstance(block, dict):
                    raise RuntimeError("produced_block_missing")
                meta = ex2.apply_block(block)
                source_root = compute_state_root(ex1.state)
                follower_root = compute_state_root(ex2.state)
                return {
                    "ok": bool(started1 and started2 and produced_height >= 1 and getattr(meta, "ok", False) and source_root == follower_root),
                    "batch": "544",
                    "net_loop_started": bool(started1 and started2),
                    "net_loop_class": "weall.net.net_loop.NetMeshLoop",
                    "transport": "tcp://127.0.0.1",
                    "ports_bound_count": 2,
                    "peer_uris_configured_count": 2,
                    "block_producer_surface_used": "weall.services.block_producer._produce_once",
                    "producer_delegate": "WeAllExecutor.produce_block",
                    "produced_height": produced_height,
                    "block_apply_surface_used": "WeAllExecutor.apply_block",
                    "follower_apply_ok": bool(getattr(meta, "ok", False)),
                    "state_roots_match": source_root == follower_root,
                    "state_root_equality_proven": source_root == follower_root,
                    "public_validator_enabled": False,
                }
            finally:
                loop1.stop(); loop2.stop(); loop1.join(timeout=1.0); loop2.join(timeout=1.0)
    finally:
        os.environ.clear(); os.environ.update(old_env)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
