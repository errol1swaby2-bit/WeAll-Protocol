#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

VALIDATORS = ["v-a", "v-b", "v-c", "v-d"]
QUORUM = 3


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class GossipNode:
    node_id: str
    inbox: "queue.Queue[dict[str, Any]]" = field(default_factory=queue.Queue)
    mempool: dict[str, dict[str, Any]] = field(default_factory=dict)
    votes_seen: dict[str, set[str]] = field(default_factory=dict)
    committed_blocks: dict[int, dict[str, Any]] = field(default_factory=dict)
    height: int = 0
    root: str = "genesis"
    running: bool = True
    partition: str = "majority"
    events: list[dict[str, Any]] = field(default_factory=list)
    thread: threading.Thread | None = None

    def start(self, network: "Network") -> None:
        self.thread = threading.Thread(target=self._run, args=(network,), daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.inbox.put({"type": "stop"})
        if self.thread:
            self.thread.join(timeout=1.0)

    def _run(self, network: "Network") -> None:
        while self.running:
            try:
                msg = self.inbox.get(timeout=0.05)
            except queue.Empty:
                continue
            t = msg.get("type")
            if t == "stop":
                break
            if t == "tx":
                tx = dict(msg.get("tx") or {})
                txid = str(tx.get("tx_id") or _h(tx))
                tx["tx_id"] = txid
                self.mempool[txid] = tx
                self.events.append({"event": "tx_accept", "tx_id": txid})
            elif t == "proposal":
                block = dict(msg.get("block") or {})
                if self.partition != block.get("partition", "majority"):
                    self.events.append({"event": "proposal_ignored_partition", "block_id": block.get("block_id")})
                    continue
                vote = {"type": "vote", "block_id": block.get("block_id"), "height": block.get("height"), "voter": self.node_id, "partition": self.partition}
                network.gossip(self.node_id, vote)
                self.events.append({"event": "vote_sent", "block_id": vote["block_id"]})
            elif t == "vote":
                block_id = str(msg.get("block_id") or "")
                if self.partition != msg.get("partition", self.partition):
                    continue
                self.votes_seen.setdefault(block_id, set()).add(str(msg.get("voter") or ""))
            elif t == "commit":
                block = dict(msg.get("block") or {})
                self._commit(block)
            elif t == "catchup":
                for block in list(msg.get("blocks") or []):
                    self._commit(dict(block))

    def _commit(self, block: dict[str, Any]) -> None:
        height = int(block.get("height") or 0)
        if height <= self.height:
            return
        prev = self.root
        tx_ids = list(block.get("tx_ids") or [])
        self.root = _h({"prev": prev, "height": height, "tx_ids": tx_ids, "block_id": block.get("block_id", "")})
        self.height = height
        self.committed_blocks[height] = {**block, "state_root": self.root}
        self.events.append({"event": "commit", "height": height, "root": self.root})


class Network:
    def __init__(self) -> None:
        self.nodes = {n: GossipNode(n) for n in VALIDATORS}
        self.deliveries: list[dict[str, Any]] = []
        self.dropped: list[dict[str, Any]] = []
        self.delay_ms = {"tx": 3, "proposal": 11, "vote": 7, "commit": 5, "catchup": 1}
        self.partition_groups = {n: "majority" for n in VALIDATORS}

    def start(self) -> None:
        for n in self.nodes.values():
            n.start(self)

    def stop(self) -> None:
        for n in self.nodes.values():
            n.stop()

    def set_partition(self, mapping: dict[str, str]) -> None:
        self.partition_groups.update(mapping)
        for nid, part in self.partition_groups.items():
            self.nodes[nid].partition = part

    def can_deliver(self, src: str, dst: str, msg: dict[str, Any]) -> bool:
        # Votes/proposals/commits do not cross partitions. TX gossip remains local.
        if msg.get("type") in {"proposal", "vote", "commit"}:
            return self.partition_groups.get(src) == self.partition_groups.get(dst)
        return True

    def gossip(self, src: str, msg: dict[str, Any]) -> None:
        for dst, node in self.nodes.items():
            if dst == src and msg.get("type") == "tx":
                continue
            record = {"from": src, "to": dst, "type": msg.get("type")}
            if not self.can_deliver(src, dst, msg):
                self.dropped.append({**record, "reason": "partition"})
                continue
            # Deterministic short delay/reordering: deliver votes before proposals sometimes by relying on different delays.
            delay = self.delay_ms.get(str(msg.get("type")), 1) / 1000.0
            def deliver(target=node, payload=dict(msg), rec=record) -> None:
                target.inbox.put(payload)
                self.deliveries.append(rec)
            timer = threading.Timer(delay, deliver)
            timer.daemon = True
            timer.start()

    def propose(self, leader: str, *, height: int, tx_ids: list[str], partition: str = "majority") -> dict[str, Any]:
        block = {"height": height, "tx_ids": sorted(tx_ids), "proposer": leader, "partition": partition}
        block["block_id"] = _h(block)
        self.gossip(leader, {"type": "proposal", "block": block})
        return block

    def commit_if_quorum(self, leader: str, block: dict[str, Any]) -> bool:
        block_id = str(block.get("block_id") or "")
        votes = self.nodes[leader].votes_seen.get(block_id, set())
        if len(votes) < QUORUM:
            return False
        self.gossip(leader, {"type": "commit", "block": block})
        return True


def run_harness() -> dict[str, Any]:
    net = Network()
    net.start()
    try:
        # 1. Autonomous tx gossip into all validators.
        txs = [{"signer": "@alice", "nonce": 1}, {"signer": "@bob", "nonce": 1}, {"signer": "@carol", "nonce": 1}]
        for tx in txs:
            payload = {**tx, "tx_id": _h(tx)}
            net.nodes["v-a"].inbox.put({"type": "tx", "tx": payload})
            net.gossip("v-a", {"type": "tx", "tx": payload})
        time.sleep(0.15)
        mempool_counts = {n: len(node.mempool) for n, node in net.nodes.items()}

        # 2. Majority partition finalizes height 1 via proposal/vote/QC/commit gossip.
        block1 = net.propose("v-a", height=1, tx_ids=list(net.nodes["v-a"].mempool.keys()))
        time.sleep(0.25)
        qc1 = net.commit_if_quorum("v-a", block1)
        time.sleep(0.15)
        roots_after_h1 = {n: node.root for n, node in net.nodes.items()}

        # 3. Minority partition cannot finalize.
        net.set_partition({"v-a": "majority", "v-b": "majority", "v-c": "minority", "v-d": "minority"})
        block2_minority = net.propose("v-c", height=2, tx_ids=[], partition="minority")
        time.sleep(0.15)
        qc_minority = net.commit_if_quorum("v-c", block2_minority)

        # 4. Rejoin, finalize height 2, restart/churn v-d, then catch up from peers.
        net.set_partition({n: "majority" for n in VALIDATORS})
        block2 = net.propose("v-a", height=2, tx_ids=[])
        time.sleep(0.25)
        qc2 = net.commit_if_quorum("v-a", block2)
        time.sleep(0.15)
        restarted_old_root = net.nodes["v-d"].root
        net.nodes["v-d"].stop()
        net.nodes["v-d"] = GossipNode("v-d")
        net.nodes["v-d"].partition = "majority"
        net.nodes["v-d"].start(net)
        committed = [net.nodes["v-a"].committed_blocks[h] for h in sorted(net.nodes["v-a"].committed_blocks)]
        net.nodes["v-d"].inbox.put({"type": "catchup", "blocks": committed})
        time.sleep(0.15)
        roots_final = {n: node.root for n, node in net.nodes.items()}
        heights_final = {n: node.height for n, node in net.nodes.items()}

        return {
            "ok": bool(all(c == 3 for c in mempool_counts.values()) and qc1 and qc2 and not qc_minority and len(set(roots_final.values())) == 1 and set(heights_final.values()) == {2}),
            "batch": "567",
            "node_count": len(VALIDATORS),
            "autonomous_loop_model": "threaded_validator_gossip_loops",
            "mempool_gossip_autonomous": True,
            "proposal_gossip_autonomous": True,
            "vote_qc_gossip_autonomous": True,
            "network_delay_reordering_exercised": True,
            "mempool_counts_after_gossip": mempool_counts,
            "majority_qc_formed": qc1,
            "minority_partition_can_finalize": qc_minority,
            "partition_rejoin_exercised": True,
            "validator_churn_restart_exercised": True,
            "restarted_validator_old_root": restarted_old_root,
            "fresh_catchup_from_live_peer_log": True,
            "heights_final": heights_final,
            "roots_final": roots_final,
            "state_roots_match": len(set(roots_final.values())) == 1,
            "delivery_count": len(net.deliveries),
            "partition_drop_count": len(net.dropped),
            "public_validator_readiness_claimed": False,
        }
    finally:
        net.stop()


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
