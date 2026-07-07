#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import queue
import tempfile
import time
from pathlib import Path
from typing import Any

VALIDATORS = ["v-a", "v-b", "v-c", "v-d"]
QUORUM = 3


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _node_loop(node_id: str, input_queue: mp.Queue, tx_queue: mp.Queue, state_file: str) -> None:
    state: dict[str, Any] = {"node_id": node_id, "height": 0, "root": "genesis", "mempool": {}, "votes": {}, "committed": {}, "running_pid": os.getpid()}
    Path(state_file).write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    while True:
        msg = input_queue.get()
        t = msg.get("type")
        if t == "stop":
            Path(state_file).write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
            break
        if t == "tx":
            tx = dict(msg["tx"])
            txid = tx.get("tx_id") or _h(tx)
            tx["tx_id"] = txid
            state["mempool"][txid] = tx
            tx_queue.put({"from": node_id, "type": "tx_seen", "tx_id": txid})
        elif t == "proposal":
            block = dict(msg["block"])
            tx_queue.put({"from": node_id, "type": "vote", "block_id": block["block_id"], "height": block["height"]})
        elif t == "commit":
            block = dict(msg["block"])
            hgt = int(block["height"])
            if hgt > int(state["height"]):
                root = _h({"prev": state["root"], "height": hgt, "tx_ids": block.get("tx_ids", []), "block_id": block["block_id"]})
                state["height"] = hgt
                state["root"] = root
                state["committed"][str(hgt)] = {**block, "state_root": root}
                Path(state_file).write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
                tx_queue.put({"from": node_id, "type": "commit_ack", "height": hgt, "root": root})
        elif t == "catchup":
            for block in msg.get("blocks") or []:
                hgt = int(block["height"])
                if hgt > int(state["height"]):
                    root = _h({"prev": state["root"], "height": hgt, "tx_ids": block.get("tx_ids", []), "block_id": block["block_id"]})
                    state["height"] = hgt
                    state["root"] = root
                    state["committed"][str(hgt)] = {**block, "state_root": root}
            Path(state_file).write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
            tx_queue.put({"from": node_id, "type": "catchup_ack", "height": state["height"], "root": state["root"]})


def _drain(tx_queue: mp.Queue, *, timeout: float = 0.2) -> list[dict[str, Any]]:
    end = time.time() + timeout
    out: list[dict[str, Any]] = []
    while time.time() < end:
        try:
            out.append(tx_queue.get(timeout=0.02))
        except queue.Empty:
            pass
    return out


def run_harness() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="weall-b572-") as td:
        tx_queue: mp.Queue = mp.Queue()
        input_queuees: dict[str, mp.Queue] = {v: mp.Queue() for v in VALIDATORS}
        files = {v: str(Path(td) / f"{v}.json") for v in VALIDATORS}
        procs = {v: mp.Process(target=_node_loop, args=(v, input_queuees[v], tx_queue, files[v]), daemon=True) for v in VALIDATORS}
        for p in procs.values():
            p.start()
        time.sleep(0.1)
        try:
            txs = [{"signer": "alice", "nonce": 1}, {"signer": "bob", "nonce": 1}, {"signer": "carol", "nonce": 1}]
            for tx in txs:
                payload = {**tx, "tx_id": _h(tx)}
                for q in input_queuees.values():
                    q.put({"type": "tx", "tx": payload})
            events = _drain(tx_queue, timeout=0.5)
            tx_seen = [e for e in events if e.get("type") == "tx_seen"]
            committed_blocks: list[dict[str, Any]] = []
            roots_by_height: dict[str, list[str]] = {}
            for height in range(1, 7):
                leader = VALIDATORS[(height - 1) % len(VALIDATORS)]
                block = {"height": height, "proposer": leader, "tx_ids": sorted(_h(t) for t in txs) if height == 1 else [], "view": height}
                block["block_id"] = _h(block)
                # proposal gossip
                for v, q in input_queuees.items():
                    q.put({"type": "proposal", "block": block})
                votes = [e for e in _drain(tx_queue, timeout=0.4) if e.get("type") == "vote" and e.get("block_id") == block["block_id"]]
                if len({v["from"] for v in votes}) >= QUORUM:
                    for q in input_queuees.values():
                        q.put({"type": "commit", "block": block})
                acks = [e for e in _drain(tx_queue, timeout=0.4) if e.get("type") == "commit_ack" and e.get("height") == height]
                roots_by_height[str(height)] = sorted(e["root"] for e in acks)
                committed_blocks.append(block)
                if height == 3:
                    # restart one process from scratch, then catch it up from committed log.
                    input_queuees["v-d"].put({"type": "stop"})
                    procs["v-d"].join(timeout=1.0)
                    input_queuees["v-d"] = mp.Queue()
                    procs["v-d"] = mp.Process(target=_node_loop, args=("v-d", input_queuees["v-d"], tx_queue, files["v-d"]), daemon=True)
                    procs["v-d"].start()
                    time.sleep(0.1)
                    input_queuees["v-d"].put({"type": "catchup", "blocks": committed_blocks})
                    _drain(tx_queue, timeout=0.3)
            for q in input_queuees.values():
                q.put({"type": "stop"})
            for p in procs.values():
                p.join(timeout=1.0)
            states = {v: json.loads(Path(files[v]).read_text(encoding="utf-8")) for v in VALIDATORS}
            roots = {v: states[v]["root"] for v in VALIDATORS}
            heights = {v: states[v]["height"] for v in VALIDATORS}
            pids = {v: states[v].get("running_pid") for v in VALIDATORS}
            return {
                "ok": len(set(roots.values())) == 1 and set(heights.values()) == {6} and len(tx_seen) == len(VALIDATORS) * len(txs),
                "batch": "572",
                "process_model": "independent_multiprocessing_validator_nodes",
                "node_count": len(VALIDATORS),
                "process_ids_unique": len(set(pids.values())) == len(VALIDATORS),
                "rounds": 6,
                "leader_rotation_exercised": True,
                "tx_seen_count": len(tx_seen),
                "proposal_vote_commit_rounds": 6,
                "restart_catchup_exercised": True,
                "heights_final": heights,
                "roots_final": roots,
                "state_roots_match": len(set(roots.values())) == 1,
                "public_validator_readiness_claimed": False,
            }
        finally:
            for q in input_queuees.values():
                try:
                    q.put({"type": "stop"})
                except Exception:
                    pass
            for p in procs.values():
                if p.is_alive():
                    p.terminate(); p.join(timeout=1.0)


def main() -> int:
    argparse.ArgumentParser().parse_args()
    print(json.dumps(run_harness(), sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
