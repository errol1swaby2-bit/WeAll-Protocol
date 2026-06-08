#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from weall.runtime.bft_hotstuff import quorum_threshold, validator_set_hash
from weall.runtime.state_hash import compute_state_root

VALIDATORS = ["validator-a", "validator-b", "validator-c", "validator-d"]


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _state_path(root: Path, node_id: str) -> Path:
    return root / f"{node_id}.json"


def _load_state(path: Path, node_id: str, role: str = "validator") -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "node_id": node_id,
        "role": role,
        "chain_id": "weall-prod",
        "height": 0,
        "validator_set": list(VALIDATORS),
        "committed_blocks": [],
        "finalized": {"height": 0, "block_id": "genesis"},
    }


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")


def _root_without_ephemeral_node_id(state: dict[str, Any]) -> str:
    clean = dict(state)
    clean.pop("node_id", None)
    return compute_state_root(clean)


def _serve_node(port: int, state_file: Path, node_id: str, role: str) -> int:
    st = _load_state(state_file, node_id=node_id, role=role)
    _save_state(state_file, st)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", int(port)))
    srv.listen(32)
    srv.settimeout(0.2)
    running = True
    while running:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
            try:
                msg = json.loads(data.decode("utf-8").strip() or "{}")
                typ = str(msg.get("type") or "")
                st = _load_state(state_file, node_id=node_id, role=role)
                if typ == "ping":
                    out = {"ok": True, "node_id": node_id, "role": role, "height": st.get("height", 0)}
                elif typ == "vote":
                    if role != "validator" or node_id not in VALIDATORS:
                        out = {"ok": False, "node_id": node_id, "error": "not_validator"}
                    else:
                        proposal = msg.get("proposal") if isinstance(msg.get("proposal"), dict) else {}
                        payload = {"node_id": node_id, "height": proposal.get("height"), "view": proposal.get("view"), "block_hash": proposal.get("block_hash")}
                        out = {"ok": True, "node_id": node_id, "vote": {**payload, "vote_hash": _hash(payload)}}
                elif typ == "commit":
                    block = msg.get("block") if isinstance(msg.get("block"), dict) else {}
                    votes = msg.get("votes") if isinstance(msg.get("votes"), list) else []
                    if role != "validator":
                        out = {"ok": False, "node_id": node_id, "error": "not_validator"}
                    elif len(votes) < quorum_threshold(len(VALIDATORS)):
                        out = {"ok": False, "node_id": node_id, "error": "finality_threshold_not_met"}
                    else:
                        committed = st.get("committed_blocks") if isinstance(st.get("committed_blocks"), list) else []
                        if not any(isinstance(b, dict) and b.get("block_id") == block.get("block_id") for b in committed):
                            committed.append(block)
                        st["committed_blocks"] = committed
                        st["height"] = int(block.get("height") or st.get("height") or 0)
                        st["finalized"] = {"height": st["height"], "block_id": str(block.get("block_id") or "")}
                        _save_state(state_file, st)
                        out = {"ok": True, "node_id": node_id, "height": st["height"], "root": _root_without_ephemeral_node_id(st)}
                elif typ == "sync_blocks":
                    blocks = msg.get("blocks") if isinstance(msg.get("blocks"), list) else []
                    committed = []
                    prev = "genesis"
                    for block in blocks:
                        if not isinstance(block, dict):
                            raise AssertionError("bad_block")
                        if str(block.get("parent_block_id") or "genesis") != prev:
                            raise AssertionError("parent_mismatch")
                        committed.append(block)
                        prev = str(block.get("block_id") or "")
                    st["committed_blocks"] = committed
                    st["height"] = int(committed[-1]["height"]) if committed else 0
                    st["finalized"] = {"height": st["height"], "block_id": committed[-1].get("block_id") if committed else "genesis"}
                    _save_state(state_file, st)
                    out = {"ok": True, "node_id": node_id, "height": st["height"], "root": _root_without_ephemeral_node_id(st)}
                elif typ == "snapshot":
                    out = {"ok": True, "node_id": node_id, "state": st, "root": _root_without_ephemeral_node_id(st)}
                elif typ == "stop":
                    running = False
                    out = {"ok": True, "node_id": node_id, "stopping": True}
                else:
                    out = {"ok": False, "node_id": node_id, "error": "unknown_command"}
            except Exception as exc:  # pragma: no cover - surfaced to parent harness
                out = {"ok": False, "node_id": node_id, "error": str(exc)}
            conn.sendall((json.dumps(out, sort_keys=True) + "\n").encode("utf-8"))
    srv.close()
    return 0


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _rpc(port: int, msg: dict[str, Any], *, timeout: float = 3.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as sock:
                sock.sendall((json.dumps(msg, sort_keys=True) + "\n").encode("utf-8"))
                data = b""
                while not data.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                return json.loads(data.decode("utf-8").strip() or "{}")
        except Exception as exc:
            last = exc
            time.sleep(0.05)
    raise RuntimeError(f"rpc_timeout:{port}:{last}")


def _start_node(root: Path, node_id: str, port: int, role: str = "validator") -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, __file__, "--node", "--port", str(port), "--state-file", str(_state_path(root, node_id)), "--node-id", node_id, "--role", role],
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _proposal(height: int, view: int, parent_id: str, tx_ids: list[str]) -> dict[str, Any]:
    payload = {"height": height, "view": view, "parent_block_id": parent_id, "tx_ids": list(tx_ids), "validator_set_hash": validator_set_hash(VALIDATORS)}
    payload["block_id"] = f"block-{height}-{view}"
    payload["block_hash"] = _hash(payload)
    return payload


def _commit_round(ports: dict[str, int], *, height: int, view: int, participants: list[str] | None = None, parent_id: str = "genesis", tx_ids: list[str] | None = None) -> dict[str, Any]:
    participants = participants or list(VALIDATORS)
    prop = _proposal(height, view, parent_id, tx_ids or [])
    votes = []
    for vid in participants:
        reply = _rpc(ports[vid], {"type": "vote", "proposal": prop})
        if reply.get("ok"):
            votes.append(reply["vote"])
    block = {"height": height, "block_id": prop["block_id"], "parent_block_id": parent_id, "block_hash": prop["block_hash"], "votes_hash": _hash(votes), "tx_ids": list(tx_ids or [])}
    commit_replies = [_rpc(ports[vid], {"type": "commit", "block": block, "votes": votes}) for vid in VALIDATORS]
    return {"committed": all(r.get("ok") for r in commit_replies), "height": height, "votes": len(votes), "threshold": quorum_threshold(len(VALIDATORS)), "block": block, "commit_replies": commit_replies}


def run_harness() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="weall-live-validator-") as td:
        root = Path(td)
        ports = {vid: _free_port() for vid in VALIDATORS}
        procs = {vid: _start_node(root, vid, ports[vid]) for vid in VALIDATORS}
        try:
            for vid, port in ports.items():
                ping = _rpc(port, {"type": "ping"})
                assert ping.get("ok"), ping
            r1 = _commit_round(ports, height=1, view=0, tx_ids=["tx:bootstrap"])
            r2 = _commit_round(ports, height=2, view=1, parent_id=r1["block"]["block_id"], tx_ids=["tx:gov"])
            roots_before = {vid: _rpc(port, {"type": "snapshot"})["root"] for vid, port in ports.items()}
            _rpc(ports["validator-d"], {"type": "stop"})
            procs["validator-d"].wait(timeout=3)
            procs["validator-d"] = _start_node(root, "validator-d", ports["validator-d"])
            restarted_root = _rpc(ports["validator-d"], {"type": "snapshot"})["root"]
            minority = _commit_round(ports, height=3, view=2, parent_id=r2["block"]["block_id"], participants=VALIDATORS[:2], tx_ids=["tx:minority"])
            reference_snapshot = _rpc(ports["validator-a"], {"type": "snapshot"})
            lag_port = _free_port()
            lag_proc = _start_node(root, "validator-lagging", lag_port)
            try:
                sync = _rpc(lag_port, {"type": "sync_blocks", "blocks": reference_snapshot["state"].get("committed_blocks", [])})
            finally:
                try:
                    _rpc(lag_port, {"type": "stop"})
                except Exception:
                    pass
                lag_proc.terminate(); lag_proc.wait(timeout=3)
            obs_port = _free_port()
            obs_proc = _start_node(root, "observer-1", obs_port, role="observer")
            try:
                observer_vote = _rpc(obs_port, {"type": "vote", "proposal": _proposal(9, 0, "genesis", [])})
            finally:
                try:
                    _rpc(obs_port, {"type": "stop"})
                except Exception:
                    pass
                obs_proc.terminate(); obs_proc.wait(timeout=3)
            roots_after = {vid: _rpc(port, {"type": "snapshot"})["root"] for vid, port in ports.items()}
        finally:
            for vid, port in ports.items():
                try:
                    _rpc(port, {"type": "stop"}, timeout=0.5)
                except Exception:
                    pass
            for proc in procs.values():
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        ok = bool(r1.get("committed") and r2.get("committed") and len(set(roots_before.values())) == 1 and restarted_root == roots_before["validator-d"] and minority.get("committed") is False and sync.get("root") == reference_snapshot.get("root") and observer_vote.get("ok") is False and len(set(roots_after.values())) == 1)
        return {
            "ok": ok,
            "batch": "528",
            "claim": "local_private_tcp_process_rehearsal_only",
            "public_validator_enabled": False,
            "process_model": "subprocess_tcp_json_rpc",
            "network_transport": "127.0.0.1_tcp_json_lines",
            "ports_bound": len(ports),
            "rounds": [r1, r2],
            "minority_partition_result": "finality_threshold_not_met" if not minority.get("committed") else "unexpected_finality",
            "restart_root_preserved": restarted_root == roots_before["validator-d"],
            "lagging_rejoin_root_matches_reference": sync.get("root") == reference_snapshot.get("root"),
            "observer_vote_rejected": observer_vote.get("ok") is False,
            "roots_after_restart": roots_after,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--state-file", default="")
    parser.add_argument("--node-id", default="")
    parser.add_argument("--role", default="validator")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.node:
        return _serve_node(int(args.port), Path(args.state_file), str(args.node_id), str(args.role))
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
