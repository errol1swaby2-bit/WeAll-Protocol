#!/usr/bin/env python3
"""Issue #87: four SQLite-backed WeAllExecutor processes exercise signed QC ingress.

The active validator set is DIRECTLY seeded in each process as a test fixture,
NOT authorized by on-chain VALIDATOR_SET_UPDATE. Votes use synthetic block IDs,
NOT production proposals or committed transaction receipts. No authenticated
peer transport, real three-chain finality, or durable restart is claimed.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import multiprocessing as mp
import os
import queue
import tempfile
from pathlib import Path
from typing import Any

from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    quorum_threshold,
    validator_set_hash,
)

ROOT = Path(__file__).resolve().parents[1]
IDS = ("@f1b-v1", "@f1b-v2", "@f1b-v3", "@f1b-v4")
CHAIN_ID = "f1b-four-executor-crypto-fixture"
EPOCH = 19
SET_HASH = validator_set_hash(list(IDS))
TIMEOUT = 75.0
Json = dict[str, Any]


def _worker(identity: str, incoming: Any, outgoing: Any, root: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

    from weall.runtime.executor import WeAllExecutor

    private = MLDSA65PrivateKey.generate()
    pubkey = private.public_key().public_bytes_raw().hex()
    private_hex = private.private_bytes_raw().hex()
    outgoing.put(
        {"event": "ready", "id": identity, "pid": os.getpid(), "pubkey": pubkey}
    )
    executor: WeAllExecutor | None = None
    try:
        while True:
            request = incoming.get()
            if not isinstance(request, dict):
                raise ValueError("command_not_object")
            op = request.get("op")
            if op == "stop":
                return
            if op == "init":
                if executor is not None:
                    raise ValueError("duplicate_initialization")
                registry_keys = request.get("keys")
                if not isinstance(registry_keys, dict):
                    raise ValueError("registry_missing")
                if set(registry_keys) != set(IDS) or registry_keys[identity] != pubkey:
                    raise ValueError("registry_identity_mismatch")
                for key in tuple(os.environ):
                    if key.startswith("WEALL_"):
                        os.environ.pop(key, None)
                os.environ.update(
                    {
                        "WEALL_MODE": "testnet",
                        "WEALL_SIGVERIFY": "1",
                        "WEALL_BFT_ENABLED": "1",
                        "WEALL_UNSAFE_DEV": "0",
                        "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "0",
                        "WEALL_BFT_STRICT_EPOCH_BINDING": "1",
                        "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
                        "WEALL_NET_ENABLED": "0",
                        "WEALL_VALIDATOR_ACCOUNT": identity,
                        "WEALL_NODE_PUBKEY": pubkey,
                        "WEALL_NODE_PRIVKEY": private_hex,
                    }
                )
                db = Path(root) / f"validator-{IDS.index(identity)}.sqlite"
                executor = WeAllExecutor(
                    db_path=str(db),
                    node_id=identity,
                    chain_id=CHAIN_ID,
                    tx_index_path=str(ROOT / "generated" / "tx_index.json"),
                )
                st = executor.state
                st.setdefault("roles", {}).setdefault("validators", {})[
                    "active_set"
                ] = list(IDS)
                consensus = st.setdefault("consensus", {})
                consensus.setdefault("validator_set", {}).update(
                    {"active_set": list(IDS), "epoch": EPOCH, "set_hash": SET_HASH}
                )
                consensus.setdefault("phase", {})[
                    "current"
                ] = CONSENSUS_PHASE_BFT_ACTIVE
                registry = consensus.setdefault("validators", {}).setdefault(
                    "registry", {}
                )
                for signer, pk in registry_keys.items():
                    registry[signer] = {"pubkey": pk, "status": "active"}
                executor._ledger_store.write(st)
                executor.state = executor._ledger_store.read()
                executor._bft.load_from_state(executor.state)
                if executor._active_validators() != sorted(IDS):
                    raise AssertionError("validator_set_readback_failed")
                if executor._current_validator_epoch() != EPOCH:
                    raise AssertionError("epoch_readback_failed")
                if executor._current_validator_set_hash() != SET_HASH:
                    raise AssertionError("set_hash_readback_failed")
                if executor._current_consensus_phase() != CONSENSUS_PHASE_BFT_ACTIVE:
                    raise AssertionError("consensus_phase_not_active")
                if not db.is_file() or db.stat().st_size == 0:
                    raise AssertionError("sqlite_database_missing")
                outgoing.put({"event": "initialized", "id": identity})
                continue
            if executor is None:
                raise ValueError("executor_not_initialized")
            if op == "vote":
                payload = request["block"]
                signed = executor.bft_make_vote_for_block(
                    view=int(payload["view"]),
                    block_id=str(payload["block_id"]),
                    block_hash=str(payload["block_hash"]),
                    parent_id=str(payload["parent_id"]),
                )
                if not isinstance(signed, dict):
                    raise AssertionError("executor_vote_failed")
                outgoing.put({"event": "vote", "value": signed})
            elif op == "receive":
                certificate = executor.bft_on_vote(request["vote"])
                outgoing.put({"event": "receipt", "qc": certificate})
            elif op == "verify":
                valid = executor.bft_verify_qc_json(request["qc"]) is not None
                outgoing.put({"event": "verify", "valid": valid})
            else:
                raise ValueError("unknown_worker_operation")
    except Exception as exc:
        outgoing.put({"event": "error", "type": type(exc).__name__})
    finally:
        private_hex = ""


class Cluster:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ctx = mp.get_context("spawn")
        self.workers: dict[str, Any] = {}
        self.inboxes: dict[str, Any] = {}
        self.outboxes: dict[str, Any] = {}
        self.keys: dict[str, str] = {}
        self.pids: dict[str, int] = {}

    def __enter__(self) -> Cluster:
        try:
            for identity in IDS:
                iq, oq = self.ctx.Queue(), self.ctx.Queue()
                process = self.ctx.Process(
                    target=_worker, args=(identity, iq, oq, str(self.root))
                )
                self.inboxes[identity], self.outboxes[identity] = iq, oq
                self.workers[identity] = process
                process.start()
            for identity in IDS:
                reply = self._read(identity, "ready")
                if reply["id"] != identity:
                    raise AssertionError("wrong_worker_identity")
                self.keys[identity] = str(reply["pubkey"])
                self.pids[identity] = int(reply["pid"])
            if len(set(self.keys.values())) != 4 or len(set(self.pids.values())) != 4:
                raise AssertionError("workers_not_independent")
            for identity in IDS:
                self.call(identity, "init", "initialized", keys=self.keys)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _read(self, identity: str, event: str) -> Json:
        try:
            response = self.outboxes[identity].get(timeout=TIMEOUT)
        except queue.Empty as exc:
            raise TimeoutError(f"worker_timeout:{identity}") from exc
        if not isinstance(response, dict):
            raise AssertionError("invalid_worker_response")
        if response.get("event") == "error":
            raise RuntimeError(f"worker_error:{identity}:{response.get('type')}")
        if response.get("event") != event:
            raise AssertionError("wrong_worker_response")
        return response

    def call(self, identity: str, op: str, event: str, **data: Any) -> Json:
        self.inboxes[identity].put({"op": op, **data})
        return self._read(identity, event)

    def __exit__(self, _t: Any, _v: Any, _tb: Any) -> None:
        for incoming in self.inboxes.values():
            try:
                incoming.put({"op": "stop"})
            except (OSError, ValueError):
                pass
        for process in self.workers.values():
            if process.pid is None:
                continue
            process.join(timeout=2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        for q in (*self.inboxes.values(), *self.outboxes.values()):
            q.close()
            q.join_thread()


def _block(view: int) -> Json:
    identity = f"synthetic-block-{view}"
    return {
        "view": view,
        "block_id": identity,
        "block_hash": hashlib.sha256(f"{CHAIN_ID}|{identity}".encode()).hexdigest(),
        "parent_id": "synthetic-parent",
    }


def run() -> Json:
    if len(IDS) != BFT_MIN_VALIDATORS or quorum_threshold(len(IDS)) != 3:
        raise AssertionError("unexpected_bft_quorum")
    with tempfile.TemporaryDirectory(prefix="weall-f1b-executor-qc-") as td:
        with Cluster(Path(td)) as cluster:
            block = _block(91)
            votes = [
                cluster.call(identity, "vote", "vote", block=block)["value"]
                for identity in IDS[:3]
            ]
            for vote in votes[:2]:
                if cluster.call(IDS[0], "receive", "receipt", vote=vote)["qc"] is not None:
                    raise AssertionError("premature_quorum_certificate")
            qc = cluster.call(IDS[0], "receive", "receipt", vote=votes[2])["qc"]
            if not isinstance(qc, dict):
                raise AssertionError("missing_production_executor_qc")
            for identity in IDS:
                reply = cluster.call(identity, "verify", "verify", qc=qc)
                if reply["valid"] is not True:
                    raise AssertionError("independent_executor_qc_verification_failed")
            for mutation in (
                {"chain_id": "foreign-chain"},
                {"validator_epoch": EPOCH + 1},
                {"validator_set_hash": "f" * 64},
                {"block_hash": "0" * 64},
            ):
                tampered = {**qc, **mutation}
                if cluster.call(IDS[3], "verify", "verify", qc=tampered)["valid"]:
                    raise AssertionError("tampered_qc_accepted")
            forged = copy.deepcopy(qc)
            forged["votes"][0]["sig"] = "00"
            if cluster.call(IDS[3], "verify", "verify", qc=forged)["valid"]:
                raise AssertionError("forged_qc_accepted")

            partition = _block(92)
            partition_votes = [
                cluster.call(identity, "vote", "vote", block=partition)["value"]
                for identity in IDS
            ]
            for vote in partition_votes[:2]:
                if cluster.call(IDS[1], "receive", "receipt", vote=vote)["qc"] is not None:
                    raise AssertionError("left_partition_formed_quorum")
            for vote in partition_votes[2:]:
                if cluster.call(IDS[2], "receive", "receipt", vote=vote)["qc"] is not None:
                    raise AssertionError("right_partition_formed_quorum")
            joined = cluster.call(
                IDS[1], "receive", "receipt", vote=partition_votes[2]
            )["qc"]
            if not isinstance(joined, dict):
                raise AssertionError("rejoined_quorum_missing")
            return {
                "ok": True,
                "scope": "four_sqlite_executor_processes_cryptographic_ingress_only",
                "separate_processes": len(set(cluster.pids.values())),
                "separate_sqlite_databases": len(IDS),
                "signing_api": "WeAllExecutor.bft_make_vote_for_block",
                "aggregation_api": "WeAllExecutor.bft_on_vote",
                "qc_verification_api": "WeAllExecutor.bft_verify_qc_json",
                "strict_epoch_binding": True,
                "signature_verification_enabled": True,
                "qc_less_blocks_allowed": False,
                "quorum_threshold": 3,
                "verified_on_all_four_executors": True,
                "tampered_certificate_variants_rejected": 5,
                "two_plus_two_does_not_form_qc": True,
                "three_vote_quorum_restored": True,
                "validator_set_source": "direct_test_fixture",
                "on_chain_validator_authorization_proven": False,
                "real_proposal_admission_proven": False,
                "live_transport_proven": False,
                "canonical_receipt_finality_proven": False,
                "durable_process_restart_proven": False,
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = run()
    except Exception as exc:
        result = {
            "ok": False,
            "scope": "four_sqlite_executor_processes_cryptographic_ingress_only",
            "error": type(exc).__name__,
            "reason": str(exc)[:140],
        }
    print(json.dumps(result, sort_keys=True, indent=None if args.json else 2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
