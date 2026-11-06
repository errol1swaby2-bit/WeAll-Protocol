#!/usr/bin/env python3
"""Issue #87: authentic ML-DSA votes from four separate OS processes.

This is **not** a multi-validator node, transport, canonical transaction,
quorum-finality, persistence, or public Byzantine-fault-tolerance proof.
Workers use distinct ephemeral signing keys, and the coordinator verifies real
HotStuff votes and QCs with the implementation's cryptographic verifier.
The three linked block identifiers below are deliberately synthetic: their
ancestry tests only the *structural* 3-chain rule, never real block finality.

Never use this script as a substitute for the separately required four-authorized-
validator live network and committed-receipt test in issue #87.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import queue
from contextlib import AbstractContextManager
from typing import Any

from weall.crypto.sig import sign_mldsa
from weall.runtime.bft_hotstuff import (
    BFT_MIN_VALIDATORS,
    BftVote,
    HotStuffBFT,
    QuorumCert,
    canonical_vote_message,
    quorum_threshold,
    validator_set_hash,
    verify_qc,
)

Json = dict[str, Any]
VALIDATORS = ("@issue87-a", "@issue87-b", "@issue87-c", "@issue87-d")
CHAIN_ID = "issue87-four-process-crypto-only"
EPOCH = 17
START_VIEW = 101
TIMEOUT = 20.0


def _worker(signer: str, inbox: Any, outbox: Any) -> None:
    # The signing key is generated in this *child process*, never sent to the
    # coordinator and never written to disk. Public-key fingerprints are safe.
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

    private = MLDSA65PrivateKey.generate()
    public_hex = private.public_key().public_bytes_raw().hex()
    private_hex = private.private_bytes_raw().hex()
    outbox.put({"event": "ready", "signer": signer, "pid": os.getpid(), "pubkey": public_hex})
    try:
        while True:
            msg = inbox.get()
            if not isinstance(msg, dict):
                outbox.put({"event": "error", "reason": "message_not_dict"})
                continue
            if msg.get("event") == "stop":
                return
            if msg.get("event") != "vote":
                outbox.put({"event": "error", "reason": "unknown_command"})
                continue
            body = msg.get("body")
            if not isinstance(body, dict):
                outbox.put({"event": "error", "reason": "missing_vote_body"})
                continue
            # No signature bytes or private key ever enter a persistent log.
            vote_msg = canonical_vote_message(
                chain_id=str(body["chain_id"]),
                view=int(body["view"]),
                block_id=str(body["block_id"]),
                block_hash=str(body["block_hash"]),
                parent_id=str(body["parent_id"]),
                signer=signer,
                validator_epoch=int(body["validator_epoch"]),
                validator_set_hash=str(body["validator_set_hash"]),
            )
            sig = sign_mldsa(message=vote_msg, privkey=private_hex, encoding="hex")
            vote = BftVote(
                chain_id=str(body["chain_id"]),
                view=int(body["view"]),
                block_id=str(body["block_id"]),
                block_hash=str(body["block_hash"]),
                parent_id=str(body["parent_id"]),
                signer=signer,
                pubkey=public_hex,
                sig=sig,
                validator_epoch=int(body["validator_epoch"]),
                validator_set_hash=str(body["validator_set_hash"]),
            )
            outbox.put({"event": "vote", "signer": signer, "vote": vote.to_json()})
    finally:
        private_hex = ""


class FourProcessSigners(AbstractContextManager["FourProcessSigners"]):
    def __init__(self) -> None:
        self.context = mp.get_context("spawn")
        self.processes: dict[str, Any] = {}
        self.inputs: dict[str, Any] = {}
        self.outputs: dict[str, Any] = {}
        self.pubkeys: dict[str, str] = {}
        self.pids: dict[str, int] = {}

    def __enter__(self) -> "FourProcessSigners":
        try:
            for signer in VALIDATORS:
                inbox = self.context.Queue()
                outbox = self.context.Queue()
                process = self.context.Process(
                    target=_worker,
                    args=(signer, inbox, outbox),
                    name=f"issue87-{signer}",
                )
                self.inputs[signer] = inbox
                self.outputs[signer] = outbox
                self.processes[signer] = process
                process.start()
            for signer in VALIDATORS:
                result = self._receive(signer)
                if result.get("event") != "ready" or result.get("signer") != signer:
                    raise RuntimeError(f"worker_ready_failed:{signer}")
                self.pubkeys[signer] = str(result["pubkey"])
                self.pids[signer] = int(result["pid"])
            if len(set(self.pids.values())) != len(VALIDATORS):
                raise RuntimeError("duplicate_process_id")
            if len(set(self.pubkeys.values())) != len(VALIDATORS):
                raise RuntimeError("duplicate_validator_key")
            if any(p.pid != self.pids[s] for s, p in self.processes.items()):
                raise RuntimeError("process_identity_mismatch")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _receive(self, signer: str) -> Json:
        try:
            result = self.outputs[signer].get(timeout=TIMEOUT)
        except queue.Empty as exc:
            raise RuntimeError(f"worker_timeout:{signer}") from exc
        if not isinstance(result, dict):
            raise RuntimeError(f"invalid_worker_reply:{signer}")
        if result.get("event") == "error":
            raise RuntimeError(f"worker_error:{signer}:{result.get('reason')}")
        return result

    def vote(self, signer: str, *, view: int, block_id: str, parent_id: str) -> Json:
        if signer not in self.processes:
            raise RuntimeError("unknown_validator")
        block_hash = hashlib.sha256(
            f"{CHAIN_ID}|{view}|{block_id}|{parent_id}".encode()
        ).hexdigest()
        body = {
            "chain_id": CHAIN_ID,
            "view": view,
            "block_id": block_id,
            "block_hash": block_hash,
            "parent_id": parent_id,
            "validator_epoch": EPOCH,
            "validator_set_hash": validator_set_hash(list(VALIDATORS)),
        }
        self.inputs[signer].put({"event": "vote", "body": body})
        reply = self._receive(signer)
        vote = reply.get("vote")
        if reply.get("event") != "vote" or reply.get("signer") != signer:
            raise RuntimeError("unexpected_worker_reply")
        if not isinstance(vote, dict) or not isinstance(vote.get("sig"), str):
            raise RuntimeError("missing_signed_vote")
        if vote.get("pubkey") != self.pubkeys[signer]:
            raise RuntimeError("worker_public_key_changed")
        return vote

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        for q in self.inputs.values():
            try:
                q.put({"event": "stop"})
            except (OSError, ValueError):
                pass
        for p in self.processes.values():
            if p.pid is None:
                continue
            p.join(timeout=2)
            if p.is_alive():
                p.terminate()
                p.join(timeout=2)
        for q in (*self.inputs.values(), *self.outputs.values()):
            q.close()
            q.join_thread()


def _formed_qc(
    *,
    votes: list[Json],
    public_keys: dict[str, str],
    expect_formed: bool,
) -> QuorumCert | None:
    aggregator = HotStuffBFT(chain_id=CHAIN_ID)
    qc = None
    for vote in votes:
        candidate = aggregator.accept_vote(
            vote_json=vote,
            validators=list(VALIDATORS),
            vpub=public_keys,
        )
        if candidate is not None:
            qc = candidate
    if expect_formed != (qc is not None):
        raise RuntimeError("signed_quorum_expectation_failed")
    if qc is not None and not verify_qc(
        qc=qc, validators=list(VALIDATORS), validator_pubkeys=public_keys
    ):
        raise RuntimeError("cryptographic_qc_verification_failed")
    return qc


def run_rehearsal() -> Json:
    if len(VALIDATORS) != BFT_MIN_VALIDATORS or quorum_threshold(len(VALIDATORS)) != 3:
        raise RuntimeError("unexpected_production_quorum_threshold")

    block_rows: list[Json] = []
    chain_blocks: Json = {}
    structural_finality = HotStuffBFT(chain_id=CHAIN_ID)
    parents = ("", "preflight-block-1", "preflight-block-2")

    with FourProcessSigners() as cluster:
        for offset, parent_id in enumerate(parents):
            index = offset + 1
            block_id = f"preflight-block-{index}"
            view = START_VIEW + offset
            chain_blocks[block_id] = {"height": index, "prev_block_id": parent_id}
            votes = [
                cluster.vote(signer, view=view, block_id=block_id, parent_id=parent_id)
                for signer in VALIDATORS[:3]
            ]
            qc = _formed_qc(votes=votes, public_keys=cluster.pubkeys, expect_formed=True)
            if qc is None:
                raise RuntimeError("quorum_missing")
            finalized = structural_finality.observe_qc(blocks=chain_blocks, qc=qc)
            if index < 3 and finalized is not None:
                raise RuntimeError("structural_finality_advanced_early")
            if index == 3 and finalized != "preflight-block-1":
                raise RuntimeError("three_chain_structural_finality_missing")
            block_rows.append(
                {
                    "block_id": block_id,
                    "view": view,
                    "qc_signers": sorted(str(v["signer"]) for v in qc.votes),
                    "qc_identity_sha256": hashlib.sha256(
                        json.dumps(qc.to_json(), sort_keys=True).encode()
                    ).hexdigest(),
                }
            )

        # A 2+2 delivery partition must not produce any certificate on either side.
        partition_id = "preflight-partition-block"
        partition_view = START_VIEW + 3
        partition_votes = [
            cluster.vote(signer, view=partition_view, block_id=partition_id, parent_id="")
            for signer in VALIDATORS
        ]
        _formed_qc(votes=partition_votes[:2], public_keys=cluster.pubkeys, expect_formed=False)
        _formed_qc(votes=partition_votes[2:], public_keys=cluster.pubkeys, expect_formed=False)
        _formed_qc(votes=partition_votes[:3], public_keys=cluster.pubkeys, expect_formed=True)

        # Duplicate delivery and a forged signature must not create a 3-of-4 QC.
        first, second, third = partition_votes[:3]
        tampered = dict(third, sig="00")
        _formed_qc(
            votes=[first, first, second, tampered],
            public_keys=cluster.pubkeys,
            expect_formed=False,
        )

        public_fingerprints = {
            signer: hashlib.sha256(bytes.fromhex(pubkey)).hexdigest()
            for signer, pubkey in cluster.pubkeys.items()
        }
        return {
            "ok": True,
            "scope": "four_process_mldsa_qc_preflight_not_live_consensus",
            "process_count": len(cluster.pids),
            "distinct_process_ids": len(set(cluster.pids.values())) == 4,
            "validator_count": len(VALIDATORS),
            "distinct_validator_keys": len(set(public_fingerprints.values())) == 4,
            "public_key_sha256": public_fingerprints,
            "quorum_threshold": quorum_threshold(len(VALIDATORS)),
            "linked_cryptographically_verified_qc_count": len(block_rows),
            "synthetic_blocks": block_rows,
            "structural_three_chain_finalized_block": (structural_finality.finalized_block_id),
            "two_plus_two_without_qc": True,
            "three_of_four_after_partition_rejoin": True,
            "duplicate_vote_and_bad_signature_blocked": True,
            "on_chain_validator_authorization_proven": False,
            "production_transport_proven": False,
            "canonical_receipt_finality_proven": False,
            "durable_validator_restarts_proven": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = run_rehearsal()
    except Exception as exc:
        # This script is intentionally non-verbose about secret-bearing internals.
        result = {
            "ok": False,
            "scope": "four_process_cryptographic_preflight",
            "reason": str(exc),
        }
    print(json.dumps(result, sort_keys=True, indent=None if args.json else 2))
    return 0 if result["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
