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
from urllib import request as urlrequest
from urllib.error import URLError

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
        "chain_id": "weall-prod",
        "height": 0,
        "node_id": node_id,
        "role": role,
        "validator_set": list(VALIDATORS),
        "committed_blocks": [],
        "finalized": {"height": 0, "block_id": "genesis"},
    }


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")


def _state_root(state: dict[str, Any]) -> str:
    clean = dict(state)
    clean.pop("node_id", None)
    return compute_state_root(clean)


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _proposal(height: int, view: int, parent_id: str, tx_ids: list[str]) -> dict[str, Any]:
    payload = {
        "height": int(height),
        "view": int(view),
        "parent_block_id": parent_id,
        "tx_ids": list(tx_ids),
        "validator_set_hash": validator_set_hash(VALIDATORS),
    }
    payload["block_id"] = f"block-{height}-{view}"
    payload["block_hash"] = _hash(payload)
    return payload


def _node_app_main(port: int, state_file: Path, node_id: str, role: str) -> int:
    # This child process runs the real FastAPI app and mounts proof-only local
    # rehearsal endpoints.  Public production routes are still available, so the
    # parent probes /v1/readyz; the added endpoints are isolated under /__controlled_validator.
    import uvicorn
    from fastapi import Body
    from weall.api.app import create_app

    app = create_app(boot_runtime=False)
    _save_state(state_file, _load_state(state_file, node_id=node_id, role=role))

    @app.get("/__controlled_validator/state")
    def state() -> dict[str, Any]:
        st = _load_state(state_file, node_id=node_id, role=role)
        return {"ok": True, "node_id": node_id, "role": role, "height": int(st.get("height") or 0), "root": _state_root(st), "state": st}

    @app.post("/__controlled_validator/vote")
    def vote(body: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        if role != "validator" or node_id not in VALIDATORS:
            return {"ok": False, "node_id": node_id, "error": "not_validator"}
        proposal = body.get("proposal") if isinstance(body.get("proposal"), dict) else {}
        payload = {"node_id": node_id, "height": proposal.get("height"), "view": proposal.get("view"), "block_hash": proposal.get("block_hash")}
        return {"ok": True, "node_id": node_id, "vote": {**payload, "vote_hash": _hash(payload)}}

    @app.post("/__controlled_validator/commit")
    def commit(body: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        if role != "validator":
            return {"ok": False, "node_id": node_id, "error": "not_validator"}
        block = body.get("block") if isinstance(body.get("block"), dict) else {}
        votes = body.get("votes") if isinstance(body.get("votes"), list) else []
        if len(votes) < quorum_threshold(len(VALIDATORS)):
            return {"ok": False, "node_id": node_id, "error": "finality_threshold_not_met"}
        st = _load_state(state_file, node_id=node_id, role=role)
        committed = st.get("committed_blocks") if isinstance(st.get("committed_blocks"), list) else []
        if not any(isinstance(b, dict) and b.get("block_id") == block.get("block_id") for b in committed):
            committed.append(block)
        st["committed_blocks"] = committed
        st["height"] = int(block.get("height") or st.get("height") or 0)
        st["finalized"] = {"height": st["height"], "block_id": str(block.get("block_id") or "")}
        _save_state(state_file, st)
        return {"ok": True, "node_id": node_id, "height": st["height"], "root": _state_root(st)}

    @app.post("/__controlled_validator/sync")
    def sync(body: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        blocks = body.get("blocks") if isinstance(body.get("blocks"), list) else []
        parent = "genesis"
        committed: list[dict[str, Any]] = []
        for block in blocks:
            if not isinstance(block, dict):
                return {"ok": False, "error": "bad_block"}
            if str(block.get("parent_block_id") or "genesis") != parent:
                return {"ok": False, "error": "parent_mismatch"}
            committed.append(block)
            parent = str(block.get("block_id") or "")
        st = _load_state(state_file, node_id=node_id, role=role)
        st["committed_blocks"] = committed
        st["height"] = int(committed[-1]["height"]) if committed else 0
        st["finalized"] = {"height": st["height"], "block_id": committed[-1].get("block_id") if committed else "genesis"}
        _save_state(state_file, st)
        return {"ok": True, "node_id": node_id, "height": st["height"], "root": _state_root(st)}

    uvicorn.run(app, host="127.0.0.1", port=int(port), log_level="error")
    return 0


def _start_node(root: Path, node_id: str, port: int, role: str = "validator") -> subprocess.Popen[str]:
    env = os.environ.copy()
    repo = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = f"{repo / 'src'}:{repo / 'scripts'}" + ((":" + env["PYTHONPATH"]) if env.get("PYTHONPATH") else "")
    env.setdefault("WEALL_MODE", "test")
    return subprocess.Popen(
        [sys.executable, __file__, "--node", "--port", str(port), "--state-file", str(_state_path(root, node_id)), "--node-id", node_id, "--role", role],
        cwd=str(repo),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _http_json(method: str, port: int, path: str, body: dict[str, Any] | None = None, *, timeout: float = 3.0) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, sort_keys=True).encode("utf-8")
    req = urlrequest.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers={"Content-Type": "application/json"})
    with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost test harness
        return json.loads(resp.read().decode("utf-8") or "{}")


def _wait_ready(port: int, *, timeout: float = 5.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            return _http_json("GET", port, "/v1/readyz", timeout=1.0)
        except Exception as exc:
            last = exc
            time.sleep(0.05)
    raise RuntimeError(f"ready_timeout:{port}:{last}")


def _commit_round(ports: dict[str, int], *, height: int, view: int, participants: list[str] | None = None, parent_id: str = "genesis", tx_ids: list[str] | None = None) -> dict[str, Any]:
    participants = participants or list(VALIDATORS)
    prop = _proposal(height, view, parent_id, tx_ids or [])
    votes = []
    for vid in participants:
        reply = _http_json("POST", ports[vid], "/__controlled_validator/vote", {"proposal": prop})
        if reply.get("ok"):
            votes.append(reply["vote"])
    block = {"height": height, "block_id": prop["block_id"], "parent_block_id": parent_id, "block_hash": prop["block_hash"], "votes_hash": _hash(votes), "tx_ids": list(tx_ids or [])}
    commit_replies = [_http_json("POST", ports[vid], "/__controlled_validator/commit", {"block": block, "votes": votes}) for vid in VALIDATORS]
    return {"committed": all(r.get("ok") for r in commit_replies), "height": height, "votes": len(votes), "threshold": quorum_threshold(len(VALIDATORS)), "block": block, "commit_replies": commit_replies}


def run_harness() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="weall-full-node-process-") as td:
        root = Path(td)
        ports = {vid: _free_port() for vid in VALIDATORS}
        procs = {vid: _start_node(root, vid, ports[vid]) for vid in VALIDATORS}
        try:
            readyz = {vid: _wait_ready(port) for vid, port in ports.items()}
            r1 = _commit_round(ports, height=1, view=0, tx_ids=["tx:account"])
            r2 = _commit_round(ports, height=2, view=1, parent_id=r1["block"]["block_id"], tx_ids=["tx:poh"])
            roots_before = {vid: _http_json("GET", port, "/__controlled_validator/state")["root"] for vid, port in ports.items()}
            procs["validator-d"].terminate(); procs["validator-d"].wait(timeout=5)
            procs["validator-d"] = _start_node(root, "validator-d", ports["validator-d"])
            _wait_ready(ports["validator-d"])
            restart_root = _http_json("GET", ports["validator-d"], "/__controlled_validator/state")["root"]
            minority = _commit_round(ports, height=3, view=2, parent_id=r2["block"]["block_id"], participants=["validator-a", "validator-b"], tx_ids=["tx:minority"])
            r3 = _commit_round(ports, height=3, view=3, parent_id=r2["block"]["block_id"], tx_ids=["tx:dispute"])
            lag_port = _free_port()
            lag_proc = _start_node(root, "validator-lag", lag_port)
            try:
                _wait_ready(lag_port)
                sync = _http_json("POST", lag_port, "/__controlled_validator/sync", {"blocks": [r1["block"], r2["block"], r3["block"]]})
            finally:
                lag_proc.terminate(); lag_proc.wait(timeout=5)
            obs_port = _free_port()
            obs_proc = _start_node(root, "observer-1", obs_port, role="observer")
            try:
                _wait_ready(obs_port)
                observer_vote = _http_json("POST", obs_port, "/__controlled_validator/vote", {"proposal": _proposal(9, 0, "genesis", [])})
            finally:
                obs_proc.terminate(); obs_proc.wait(timeout=5)
            roots_after = {vid: _http_json("GET", port, "/__controlled_validator/state")["root"] for vid, port in ports.items()}
        finally:
            for proc in procs.values():
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
    ok = (
        all(bool(v.get("service") == "weall-node") for v in readyz.values())
        and r1["committed"]
        and r2["committed"]
        and not minority["committed"]
        and r3["committed"]
        and len(set(roots_before.values())) == 1
        and restart_root == roots_before["validator-d"]
        and sync.get("root") == next(iter(roots_after.values()))
        and len(set(roots_after.values())) == 1
        and bool(observer_vote.get("ok")) is False
    )
    return {
        "ok": bool(ok),
        "batch": "534",
        "process_model": "actual_fastapi_uvicorn_processes",
        "network_transport": "127.0.0.1_http_json",
        "readyz_route_checked": True,
        "node_processes": 4,
        "ports_bound": 4,
        "quorum_threshold": quorum_threshold(len(VALIDATORS)),
        "minority_partition_result": "finality_threshold_not_met" if not minority["committed"] else "unexpected_commit",
        "restart_root_preserved": restart_root == roots_before["validator-d"],
        "lagging_rejoin_root_matches_reference": sync.get("root") == next(iter(roots_after.values())),
        "observer_vote_rejected": bool(observer_vote.get("ok")) is False,
        "claim": "local_private_node_process_rehearsal_not_public_validator_readiness",
        "public_validator_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--node", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--state-file", default="")
    parser.add_argument("--node-id", default="")
    parser.add_argument("--role", default="validator")
    args = parser.parse_args()
    if args.node:
        return _node_app_main(int(args.port), Path(args.state_file), str(args.node_id), str(args.role))
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
