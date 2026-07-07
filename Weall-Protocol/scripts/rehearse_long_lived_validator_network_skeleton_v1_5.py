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


def _make_executor(root: Path, node_id: str) -> WeAllExecutor:
    return WeAllExecutor(db_path=str(root / f"{node_id}.sqlite"), node_id=node_id, chain_id="batch550-long-lived", tx_index_path=_tx_index_path())


def _make_loop(root: Path, ex: WeAllExecutor, node_id: str, port: int, peer_ports: list[int]) -> NetMeshLoop:
    os.environ["WEALL_PEER_ID"] = node_id
    os.environ["WEALL_PEERS"] = ",".join(f"tcp://127.0.0.1:{p}" for p in peer_ports)
    os.environ["WEALL_PEERS_FILE"] = str(root / f"{node_id}-peers.json")
    cfg = NetLoopConfig(enabled=True, bind_host="127.0.0.1", bind_port=int(port), tick_ms=10, schema_version="1")
    return NetMeshLoop(executor=ex, mempool=ex._mempool, cfg=cfg)


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    loops: list[NetMeshLoop] = []
    try:
        for key in list(os.environ):
            if key.startswith("WEALL_"):
                os.environ.pop(key, None)
        os.environ.update({"WEALL_MODE": "testnet", "WEALL_SIGVERIFY": "0", "WEALL_UNSAFE_DEV": "1", "WEALL_PRODUCE_EMPTY_BLOCKS": "1", "WEALL_NET_ENABLED": "1", "WEALL_NET_TICK_MS": "10", "WEALL_BFT_ENABLED": "0"})
        with tempfile.TemporaryDirectory(prefix="weall-b550-long-lived-net-", ignore_cleanup_errors=True) as td:
            root = Path(td)
            ports = [_free_port() for _ in range(4)]
            node_ids = [f"validator-{i}" for i in range(4)]
            executors = [_make_executor(root, node_id) for node_id in node_ids]
            for idx, (node_id, port, ex) in enumerate(zip(node_ids, ports, executors)):
                peers = [p for j, p in enumerate(ports) if j != idx]
                loop = _make_loop(root, ex, node_id, port, peers)
                loops.append(loop)
            started = [loop.start() for loop in loops]
            time.sleep(0.25)
            cfg = ProducerConfig(interval_ms=25, max_txs=0, allow_empty=True)
            _produce_once(executors[0], cfg)
            _produce_once(executors[0], cfg)
            produced_height = int(executors[0].state.get("height") or 0)
            committed_blocks = [executors[0].get_block_by_height(h) for h in range(1, produced_height + 1)]
            for block in committed_blocks:
                if not isinstance(block, dict):
                    raise RuntimeError("missing_committed_block")
                for ex in executors[1:]:
                    ex.apply_block(block)
            roots_before = [compute_state_root(ex.state) for ex in executors]
            # Restart one loop and executor from its durable DB, then replay any missing blocks.
            loops[3].stop(); loops[3].join(timeout=1.0)
            restarted = _make_executor(root, node_ids[3])
            restart_loop = _make_loop(root, restarted, node_ids[3], ports[3], ports[:3])
            loops[3] = restart_loop
            restarted_ok = restart_loop.start()
            time.sleep(0.15)
            for h in range(int(restarted.state.get("height") or 0) + 1, produced_height + 1):
                block = executors[0].get_block_by_height(h)
                if isinstance(block, dict):
                    restarted.apply_block(block)
            roots_after = [compute_state_root(ex.state) for ex in executors[:3]] + [compute_state_root(restarted.state)]
            return {
                "ok": bool(all(started) and restarted_ok and len(set(roots_after)) == 1 and produced_height >= 2),
                "batch": "550",
                "node_count": 4,
                "net_loop_class": "weall.net.net_loop.NetMeshLoop",
                "transport": "tcp://127.0.0.1",
                "ports_bound_count": len(ports),
                "peer_uris_configured_count": sum(3 for _ in ports),
                "long_lived_tick_window_ms": 400,
                "block_producer_surface_used": "weall.services.block_producer._produce_once",
                "producer_delegate": "WeAllExecutor.produce_block",
                "produced_height": produced_height,
                "all_nodes_replayed_committed_blocks": True,
                "restart_exercised": True,
                "restart_root_matches": len(set(roots_after)) == 1,
                "roots_before": roots_before,
                "roots_after": roots_after,
                "public_validator_enabled": False,
                "public_beta_ready": False,
            }
    finally:
        for loop in loops:
            try:
                loop.stop(); loop.join(timeout=1.0)
            except Exception:
                pass
        os.environ.clear(); os.environ.update(old)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
