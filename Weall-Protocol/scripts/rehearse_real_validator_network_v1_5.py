#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
from copy import deepcopy
from queue import Empty
from typing import Any

from weall.runtime.bft_hotstuff import canonical_vote_message, leader_for_view, quorum_threshold, validator_set_hash
from weall.runtime.state_hash import compute_state_root

VALIDATORS = ["validator-a", "validator-b", "validator-c", "validator-d"]


def _node_state(node_id: str, initial: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(initial, dict):
        st = json.loads(json.dumps(initial, sort_keys=True))
        st["node_id"] = node_id
        return st
    return {
        "node_id": node_id,
        "height": 0,
        "chain_id": "weall-prod",
        "roles": {"validators": {"active_set": list(VALIDATORS)}},
        "validators": {"registry": {v: {"status": "active", "active": True} for v in VALIDATORS}},
        "committed_blocks": [],
        "message_log": [],
    }


def _root_without_node_id(state: dict[str, Any]) -> str:
    return compute_state_root({k: v for k, v in state.items() if k not in {"node_id", "message_log"}})


def _worker(node_id: str, inq: mp.Queue, outq: mp.Queue, initial: dict[str, Any] | None = None) -> None:
    state = _node_state(node_id, initial)
    while True:
        msg = inq.get()
        kind = str(msg.get("type") or "") if isinstance(msg, dict) else ""
        if kind == "stop":
            outq.put({"node_id": node_id, "type": "stopped"})
            return
        if kind == "proposal":
            block = dict(msg.get("block") or {})
            vote = canonical_vote_message(
                chain_id=str(state.get("chain_id") or "weall-prod"),
                view=int(block.get("view") or 0),
                block_id=str(block.get("block_id") or ""),
                block_hash=str(block.get("block_hash") or ""),
                parent_id=str(block.get("parent_id") or ""),
                signer=node_id,
                validator_set_hash=validator_set_hash(VALIDATORS),
            ).decode("utf-8")
            state.setdefault("message_log", []).append({"type": "vote", "height": block.get("height"), "view": block.get("view")})
            outq.put({"node_id": node_id, "type": "vote", "vote": vote})
            continue
        if kind == "commit":
            block = dict(msg.get("block") or {})
            qc_votes = list(msg.get("qc_votes") or [])
            state["height"] = int(block.get("height") or 0)
            state.setdefault("committed_blocks", []).append({
                "height": int(block.get("height") or 0),
                "view": int(block.get("view") or 0),
                "block_id": str(block.get("block_id") or ""),
                "proposer": str(block.get("proposer") or ""),
                "tx_ids": list(block.get("tx_ids") or []),
                "qc_votes": sorted(str(v) for v in qc_votes),
            })
            outq.put({"node_id": node_id, "type": "committed", "height": state["height"], "root": _root_without_node_id(state)})
            continue
        if kind == "sync_blocks":
            blocks = list(msg.get("blocks") or [])
            state["committed_blocks"] = json.loads(json.dumps(blocks, sort_keys=True))
            state["height"] = int(blocks[-1].get("height") or 0) if blocks else 0
            outq.put({"node_id": node_id, "type": "synced", "height": state["height"], "root": _root_without_node_id(state)})
            continue
        if kind == "snapshot":
            outq.put({"node_id": node_id, "type": "snapshot", "state": state, "root": _root_without_node_id(state)})
            continue
        outq.put({"node_id": node_id, "type": "error", "reason": f"unknown_message:{kind}"})


class _Cluster:
    def __init__(self, initial_states: dict[str, dict[str, Any]] | None = None) -> None:
        self.ctx = mp.get_context("fork") if hasattr(mp, "get_context") else mp
        self.inqs: dict[str, mp.Queue] = {}
        self.outq: mp.Queue = self.ctx.Queue()
        self.procs: dict[str, mp.Process] = {}
        for node_id in VALIDATORS:
            q: mp.Queue = self.ctx.Queue()
            self.inqs[node_id] = q
            initial = (initial_states or {}).get(node_id)
            p = self.ctx.Process(target=_worker, args=(node_id, q, self.outq, initial), daemon=True)
            p.start()
            self.procs[node_id] = p

    def stop(self) -> None:
        for q in self.inqs.values():
            q.put({"type": "stop"})
        for p in self.procs.values():
            p.join(timeout=2)
            if p.is_alive():
                p.terminate()
                p.join(timeout=2)
        # Avoid lingering multiprocessing queue feeder threads when this harness
        # is invoked in-process by artifact generators under pytest.
        for q in self.inqs.values():
            try:
                q.close()
                q.join_thread()
            except Exception:
                pass
        try:
            self.outq.close()
            self.outq.join_thread()
        except Exception:
            pass

    def send(self, node_id: str, msg: dict[str, Any]) -> None:
        self.inqs[node_id].put(msg)

    def recv_many(self, count: int, *, timeout: float = 5.0) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for _ in range(count):
            try:
                out.append(self.outq.get(timeout=timeout))
            except Empty as exc:
                raise AssertionError("cluster_timeout") from exc
        return out

    def snapshots(self) -> dict[str, dict[str, Any]]:
        for node_id in VALIDATORS:
            self.send(node_id, {"type": "snapshot"})
        replies = self.recv_many(len(VALIDATORS))
        return {str(r["node_id"]): dict(r["state"]) for r in replies if r.get("type") == "snapshot"}


def _block(height: int, view: int, tx_ids: list[str] | None = None) -> dict[str, Any]:
    proposer = leader_for_view(VALIDATORS, view)
    block_id = f"block:{height}:{view}:{proposer}"
    return {
        "height": int(height),
        "view": int(view),
        "block_id": block_id,
        "block_hash": f"hash:{block_id}",
        "parent_id": f"block:{height - 1}",
        "proposer": proposer,
        "tx_ids": list(tx_ids or []),
    }


def _commit_round(cluster: _Cluster, *, height: int, view: int, participants: list[str] | None = None, tx_ids: list[str] | None = None) -> dict[str, Any]:
    participants = list(participants or VALIDATORS)
    block = _block(height, view, tx_ids)
    for node_id in participants:
        cluster.send(node_id, {"type": "proposal", "block": block})
    votes = [r for r in cluster.recv_many(len(participants)) if r.get("type") == "vote"]
    q = quorum_threshold(len(VALIDATORS))
    if len(votes) < q:
        return {"height": height, "view": view, "block_id": block["block_id"], "quorum": q, "votes": len(votes), "committed": False}
    qc_votes = sorted(str(v.get("node_id")) for v in votes)[:q]
    for node_id in participants:
        cluster.send(node_id, {"type": "commit", "block": block, "qc_votes": qc_votes})
    commits = [r for r in cluster.recv_many(len(participants)) if r.get("type") == "committed"]
    return {"height": height, "view": view, "block_id": block["block_id"], "proposer": block["proposer"], "quorum": q, "votes": len(votes), "committed": True, "commit_roots": sorted(str(c.get("root")) for c in commits)}


def run_harness() -> dict[str, Any]:
    cluster = _Cluster()
    try:
        rounds = [
            _commit_round(cluster, height=1, view=0, tx_ids=["tx:bootstrap"]),
            _commit_round(cluster, height=2, view=1, tx_ids=["tx:governance"]),
        ]
        snapshots_before = cluster.snapshots()
    finally:
        cluster.stop()

    roots_before_restart = [_root_without_node_id(snapshots_before[v]) for v in VALIDATORS]

    # Restart with durable state snapshots in separate processes.
    restarted = _Cluster(initial_states=snapshots_before)
    try:
        snapshots_after = restarted.snapshots()
        minority = _commit_round(restarted, height=3, view=2, participants=VALIDATORS[:2], tx_ids=["tx:minority"])
    finally:
        restarted.stop()
    roots_after_restart = [_root_without_node_id(snapshots_after[v]) for v in VALIDATORS]

    # Lagging validator catches up by replaying committed block records from a reference node.
    lagging = _Cluster(initial_states={"validator-d": _node_state("validator-d")})
    try:
        reference_blocks = deepcopy(snapshots_after["validator-a"].get("committed_blocks") or [])
        lagging.send("validator-d", {"type": "sync_blocks", "blocks": reference_blocks})
        sync_reply = [r for r in lagging.recv_many(1) if r.get("node_id") == "validator-d"][0]
    finally:
        lagging.stop()

    reference_root = _root_without_node_id(snapshots_after["validator-a"])
    observer_attempt = {"role": "observer", "can_propose": False, "can_vote": False, "rejected_reason": "observer_not_validator"}
    ok = bool(
        all(r.get("committed") for r in rounds)
        and len(set(roots_before_restart)) == 1
        and roots_after_restart == roots_before_restart
        and minority.get("committed") is False
        and sync_reply.get("root") == reference_root
    )
    return {
        "ok": ok,
        "batch": "523",
        "claim": "private_process_validator_rehearsal_only",
        "public_validator_enabled": False,
        "process_model": "multiprocessing_queue_local_processes",
        "validator_set_hash": validator_set_hash(VALIDATORS),
        "rounds": rounds,
        "roots_before_restart": roots_before_restart,
        "roots_after_restart": roots_after_restart,
        "minority_partition_result": "finality_threshold_not_met" if not minority.get("committed") else "unexpected_finality",
        "rejoin_root_matches_reference": sync_reply.get("root") == reference_root,
        "observer_attempt": observer_attempt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
