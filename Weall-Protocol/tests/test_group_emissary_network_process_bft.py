"""Loopback-process transport for the production four-validator election BFT lifecycle.

Four *separate Python interpreter processes*, each with its own production
WeAllExecutor and persisted SQLite DB, communicate via localhost TCP RPC. The
controller forwards genuine signed proposals/votes/QCs to production BFT entry
points. This is not autonomous NetMeshLoop gossip or a public testnet proof.

All bootstrap authority, group membership, account keys and activation height
are synthetic test fixtures. Signed ballots disclose signer and ranking.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import test_p0_03_production_composition as bft
from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.bft_hotstuff import leader_for_view
from weall.runtime.state_hash import compute_state_root
from weall.testing.sigtools import deterministic_mldsa_keypair

Json = dict[str, Any]
ROOT = Path(__file__).resolve().parents[1]
VOTERS = [f"@e{i:02d}" for i in range(5)]
GROUP = "g:bft-election"
ELECTION = "e:process-qc"
CREATOR = "@emissarycreator"


def _worker_snapshot(node: Any) -> Json:
    state = node.state
    election = (state.get("group_emissary_elections") or {}).get(ELECTION)
    group = state["roles"]["groups_by_id"][GROUP]
    treasury = state["roles"]["treasuries_by_id"][group["treasury_id"]]
    return {
        "height": int(state["height"]),
        "tip": str(state.get("tip") or ""),
        "state_root": str(compute_state_root(state)),
        "finalized_block_id": str(node._bft.finalized_block_id or ""),
        "election": election,
        "group_signers": list(group["signers"]),
        "group_threshold": int(group["threshold"]),
        "treasury_signers": list(treasury["signers"]),
        "treasury_threshold": int(treasury["threshold"]),
    }


def _worker_command(node: Any, request: Json) -> Any:
    command = request["command"]
    if command == "snapshot":
        return _worker_snapshot(node)
    if command == "transition_vote":
        assert node.bft_leader_propose(max_txs=0) is None
        boundary = str(request["block_id"])
        choices = [
            entry["payload"]
            for entry in node.bft_pending_outbound_messages()
            if entry.get("kind") == "vote"
            and isinstance(entry.get("payload"), dict)
            and str(entry["payload"].get("block_id")) == boundary
            and int(entry["payload"].get("view") or -1) == 0
        ]
        assert len(choices) == 1
        return choices[0]
    if command == "receive_vote":
        return node.bft_on_vote(request["vote"])
    if command == "receive_qc":
        node.bft_on_qc(request["qc"])
        return {"accepted": True}
    if command == "set_view":
        node.bft_set_view(int(request["view"]))
        return {"view": int(request["view"])}
    if command == "submit_tx":
        return node.submit_tx(request["tx"], ingress="http")
    if command == "propose":
        proposal = node.bft_leader_propose(max_txs=int(request["max_txs"]))
        assert isinstance(proposal, dict)
        return proposal
    if command == "vote_proposal":
        vote = node.bft_on_proposal(request["proposal"])
        assert isinstance(vote, dict)
        return vote
    if command == "block":
        block = node.get_block_by_height(int(request["height"]))
        assert isinstance(block, dict)
        return {
            "block_id": block["block_id"],
            "tx_types": [receipt["tx_type"] for receipt in block["receipts"]],
            "receipt_count": len(block["receipts"]),
            "all_receipts_ok": all(receipt.get("ok") is True for receipt in block["receipts"]),
            "receipt_signers": [
                receipt.get("signer") for receipt in block["receipts"]
            ],
        }
    if command == "stop":
        node.mark_clean_shutdown()
        return {"stopping": True}
    raise ValueError(f"unknown_command:{command}")


def _run_worker(root: Path, validator: str, ready: Path) -> None:
    pubs, privs = bft._key_material()
    with bft._env(
        bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])
    ):
        executor = bft._make_executor(root, validator, node_id=validator)
        assert executor._validator_signing_permitted() is True
        assert executor._active_validators() == bft.VALIDATORS
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(0.5)
            ready.write_text(
                json.dumps({"port": listener.getsockname()[1], "pid": os.getpid()}),
                encoding="utf-8",
            )
            running = True
            while running:
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(55)
                    stream = connection.makefile("rwb")
                    try:
                        request = json.loads(stream.readline().decode())
                        result = _worker_command(executor, request)
                        response = {"ok": True, "result": result}
                        if request["command"] == "stop":
                            running = False
                    except Exception as exc:
                        response = {
                            "ok": False,
                            "error": f"{type(exc).__name__}:{exc}",
                        }
                    stream.write((json.dumps(response, sort_keys=True) + "\n").encode())
                    stream.flush()


class _NodeProcess:
    def __init__(self, root: Path, validator: str) -> None:
        self.validator = validator
        self.ready = root / f"rpc-{validator.replace('@', '')}.json"
        self.log_path = root / f"rpc-{validator.replace('@', '')}.log"
        self.ready.unlink(missing_ok=True)
        self.log = self.log_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(Path(__file__).resolve()),
                "--worker",
                str(root),
                validator,
                str(self.ready),
            ],
            cwd=ROOT,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )
        deadline = time.monotonic() + 25
        while not self.ready.exists() and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        assert self.ready.exists(), (
            f"validator {validator} failed to start: {self.log_path.read_text()}"
        )
        self.port = json.loads(self.ready.read_text())["port"]
        self.send("snapshot")

    def send(self, command: str, **kwargs: Any) -> Any:
        request = {"command": command, **kwargs}
        with socket.create_connection(("127.0.0.1", self.port), timeout=55) as connection:
            connection.settimeout(55)
            stream = connection.makefile("rwb")
            stream.write((json.dumps(request, sort_keys=True) + "\n").encode())
            stream.flush()
            raw = stream.readline()
        assert raw, f"{self.validator}: empty response for {command}"
        response = json.loads(raw)
        assert response["ok"] is True, (
            f"{self.validator} {command}: {response.get('error')}"
        )
        return response["result"]

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.send("stop")
            except (OSError, ValueError, AssertionError):
                self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.log.close()


def _signed(kind: str, signer: str, nonce: int, payload: Json) -> Json:
    _public, secret = deterministic_mldsa_keypair(label=f"p0-03-group:{signer}")
    return sign_tx_envelope_dict(
        tx={
            "tx_type": kind,
            "signer": signer,
            "nonce": nonce,
            "chain_id": bft.CHAIN_ID,
            "network_id": bft.CHAIN_ID,
            "payload": payload,
        },
        privkey=secret.private_bytes_raw().hex(),
    )


@pytest.mark.parametrize("turnout", [3, 4], ids=["below_quorum", "quorum_met"])
def test_socket_separated_production_qc_election_recovery(
    tmp_path: Path, turnout: int
) -> None:
    """Loopback RPC transport; real production proposer/voter/QC/commit entrypoints."""
    pubs, privs = bft._key_material()
    seeded, boundary_id, _hash = bft._install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
        seed_emissary_electorate=True,
    )
    for validator, executor in seeded.items():
        with bft._env(
            bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])
        ):
            executor.mark_clean_shutdown()
    seeded.clear()

    workers: dict[str, _NodeProcess] = {}
    try:
        for validator in bft.VALIDATORS:
            workers[validator] = _NodeProcess(tmp_path, validator)

        votes = [
            workers[validator].send("transition_vote", block_id=boundary_id)
            for validator in bft.VALIDATORS
        ]
        qc0: Json | None = None
        collector = workers[bft.VALIDATORS[0]]
        for vote in votes:
            result = collector.send("receive_vote", vote=vote)
            if isinstance(result, dict):
                qc0 = result
        assert isinstance(qc0, dict)
        assert qc0["block_id"] == boundary_id
        for worker in workers.values():
            worker.send("receive_qc", qc=qc0)

        initial = workers[bft.VALIDATORS[0]].send("snapshot")
        original_group_signers = initial["group_signers"]
        original_treasury_signers = initial["treasury_signers"]
        proposals: dict[int, Json] = {}

        for view in range(1, 10):
            leader = leader_for_view(bft.VALIDATORS, view)
            for worker in workers.values():
                worker.send("set_view", view=view)
            signed: list[Json] = []
            if view == 1:
                signed = [
                    _signed(
                        "GROUP_EMISSARY_ELECTION_CREATE",
                        CREATOR,
                        1,
                        {
                            "group_id": GROUP,
                            "election_id": ELECTION,
                            "seats": 5,
                            "candidates": VOTERS,
                            "start_height": 2,
                            "end_height": 7,
                        },
                    )
                ]
            elif view == 4:
                assert all(w.send("snapshot")["height"] == 2 for w in workers.values())
                signed = [
                    _signed(
                        "GROUP_EMISSARY_BALLOT_CAST",
                        voter,
                        1,
                        {"election_id": ELECTION, "ranking": VOTERS},
                    )
                    for voter in VOTERS[:turnout]
                ]
            elif view == 7:
                assert all(w.send("snapshot")["height"] == 5 for w in workers.values())
                signed = [
                    _signed(
                        "GROUP_EMISSARY_ELECTION_FINALIZE",
                        CREATOR,
                        2,
                        {"group_id": GROUP, "election_id": ELECTION},
                    )
                ]

            for tx in signed:
                admission = workers[leader].send("submit_tx", tx=tx)
                assert admission["ok"] is True, admission
            proposal = workers[leader].send("propose", max_txs=len(signed))
            proposals[view] = proposal
            assert int(proposal["view"]) == view
            if signed:
                receipts = proposal.get("receipts")
                assert isinstance(receipts, list)
                assert all(receipt.get("ok") is True for receipt in receipts)
                user_receipts = [
                    receipt
                    for receipt in receipts
                    if receipt["tx_type"] != "BLOCK_FINALIZE"
                ]
                assert len(user_receipts) == len(signed)
                assert sorted(receipt["tx_type"] for receipt in user_receipts) == sorted(
                    tx["tx_type"] for tx in signed
                )
            follower_votes = [
                workers[validator].send("vote_proposal", proposal=proposal)
                for validator in bft.VALIDATORS
                if validator != leader
            ]
            assert len(follower_votes) == 3
            qc: Json | None = None
            for vote in follower_votes:
                result = workers[leader].send("receive_vote", vote=vote)
                if isinstance(result, dict):
                    qc = result
            assert isinstance(qc, dict)
            assert qc["block_id"] == proposal["block_id"]
            for worker in workers.values():
                worker.send("receive_qc", qc=qc)

            if view in (3, 6, 9):
                snapshots = [worker.send("snapshot") for worker in workers.values()]
                expected_view = view - 2
                expected = proposals[expected_view]
                expected_height = {3: 2, 6: 5, 9: 8}[view]
                assert all(s["height"] == expected_height for s in snapshots)
                assert all(s["tip"] == expected["block_id"] for s in snapshots)
                assert all(s["finalized_block_id"] == expected["block_id"] for s in snapshots)
                assert len({s["state_root"] for s in snapshots}) == 1

        final_snapshots = [w.send("snapshot") for w in workers.values()]
        expected_status = "no_decision" if turnout == 3 else "finalized"
        for state in final_snapshots:
            election = state["election"]
            assert election["status"] == expected_status
            assert election["n_ballots"] == turnout
            assert election["required_votes"] == 4
            if turnout == 3:
                assert election["no_decision_reason"] == "quorum_unmet"
                assert state["group_signers"] == original_group_signers
                assert state["treasury_signers"] == original_treasury_signers
            else:
                assert election["quorum_met"] is True
                assert state["group_signers"] == election["winners"]
                assert state["treasury_signers"] == election["winners"]
                assert state["group_threshold"] == 3
                assert state["treasury_threshold"] == 3

        follower = next(
            validator
            for validator in bft.VALIDATORS
            if validator != leader_for_view(bft.VALIDATORS, 7)
        )
        workers[follower].close()
        del workers[follower]
        workers[follower] = _NodeProcess(tmp_path, follower)
        restarted = workers[follower].send("snapshot")
        assert restarted["state_root"] == final_snapshots[0]["state_root"]
        assert restarted["election"]["status"] == expected_status
        for view, height in ((1, 2), (4, 5), (7, 8)):
            receipt = workers[follower].send("block", height=height)
            assert receipt["block_id"] == proposals[view]["block_id"]
            assert receipt["all_receipts_ok"] is True
            expected_types = {
                1: {"GROUP_EMISSARY_ELECTION_CREATE"},
                4: {"GROUP_EMISSARY_BALLOT_CAST"},
                7: {"GROUP_EMISSARY_ELECTION_FINALIZE"},
            }[view]
            assert expected_types.issubset(set(receipt["tx_types"]))
    finally:
        for worker in workers.values():
            worker.close()


if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--worker":
    _run_worker(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
