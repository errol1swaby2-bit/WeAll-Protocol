"""Four-validator election BFT regression across isolated production executors.

The baseline tests run four Python interpreters with separate SQLite stores,
using a localhost RPC controller to relay genuinely signed proposal, vote and
QC artifacts to production NetMeshLoop BFT ingress handlers.

The authenticated TCP test instead operates live NetNode/NetMeshLoop sockets.
Its controller establishes a synthetic transition QC and controls view changes
in the original regression, but never forwards post-transition BFT packets. It
verifies three-view finality, durable leader restart and network convergence.
The autonomous outage regression then keeps the scheduled view-1 leader offline
and requires the three survivors to form a signed timeout certificate, advance
their views, and finalize a three-chain without controller view or vote injection.

These are fixed localhost peers, not autonomous discovery, partition catch-up,
public testnet or constitutional approval. All bootstrap authority, group roles
and keys are synthetic. Signed ballots disclose signer and ranking.
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import test_p0_03_production_composition as bft

from weall.crypto.sig import sign_tx_envelope_dict
from weall.net.messages import BftProposalMsg, BftQcMsg, BftVoteMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
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


class _CaptureBroadcast:
    """Capture actual NetMeshLoop emissions for transport over test-owned TCP.

    This is not a production NetNode handshake or authenticated P2P socket.
    """

    def __init__(self, node: Any, validator: str) -> None:
        self.cfg = SimpleNamespace(
            peer_id=validator,
            chain_id=bft.CHAIN_ID,
            schema_version="1",
            tx_index_hash=node.tx_index_hash(),
        )
        self.messages: list[Any] = []

    def broadcast_message(self, msg: Any, exclude_peer_id: str = "") -> int:
        del exclude_peer_id
        self.messages.append(msg)
        return 1


def _wire_header(node: Any, kind: MsgType) -> WireHeader:
    return WireHeader(
        type=kind,
        chain_id=bft.CHAIN_ID,
        schema_version="1",
        tx_index_hash=node.tx_index_hash(),
    )


def _worker_command(node: Any, request: Json, loop: NetMeshLoop) -> Any:
    command = request["command"]
    if command == "snapshot":
        return _worker_snapshot(node)
    if command == "frontier_debug":
        return {
            "height": int(node.state.get("height") or 0),
            "tip": str(node.state.get("tip") or ""),
            "view": int(node._bft.view),
            "last_proposed_view": int(node._bft.last_proposed_view),
            "last_proposed_block_id": str(node._bft.last_proposed_block_id or ""),
            "timeout_certificate": (
                {
                    "view": int(tc.view),
                    "signers": list(tc.signers),
                    "high_qc_id": str(tc.high_qc_id),
                }
                if (tc := node._bft.best_timeout_certificate()) is not None
                else None
            ),
            "finalized": str(node._bft.finalized_block_id or ""),
            "finalized_view": int(node._bft.finalized_view),
            "high_qc": (
                node._bft.high_qc.to_json()["block_id"] if node._bft.high_qc is not None else None
            ),
            "pending_candidates": sorted(node._pending_candidates),
            "pending_remote": sorted(node._pending_remote_blocks),
            "pending_qcs": sorted(node._pending_missing_qcs),
            "pending_blocks": [
                {
                    "id": block_id,
                    "height": int(block.get("height") or 0),
                    "parent": str(block.get("prev_block_id") or ""),
                }
                for block_id in node._ordered_pending_block_ids()
                for block in [node._bft_pending_block_json(block_id)]
                if isinstance(block, dict)
            ],
        }
    if command == "speculative_parent_debug":
        # Diagnose the same scratch-executor ancestry replay used to justify
        # the next proposal, without mutating a live validator or accepting
        # any unverified block as canonical.
        from weall.runtime import bft_votecheck as votecheck

        qc = node._bft_best_justify_qc_json()
        qc_id = str(qc.get("block_id") or "") if isinstance(qc, dict) else ""
        valid = False
        if isinstance(qc, dict):
            valid = node.bft_verify_qc_json(qc) is not None
        chain = votecheck._speculative_chain_to_parent(node, qc_id) if qc_id else None
        evidence: Json = {
            "canonical_height": int(node.state.get("height") or 0),
            "canonical_tip": str(node.state.get("tip") or ""),
            "view": int(node._bft.view),
            "last_proposed_view": int(node._bft.last_proposed_view),
            "justify_qc_id": qc_id,
            "justify_qc_verified": valid,
            "chain_present": chain is not None,
            "chain": [
                {
                    "block_id": str(block.get("block_id") or ""),
                    "parent": str(block.get("prev_block_id") or ""),
                    "height": int(block.get("height") or 0),
                }
                for block in (chain or [])
            ],
            "steps": [],
        }
        if chain is None:
            return evidence
        slot = node._acquire_spec_exec_slot()
        try:
            clone = node._reset_spec_exec_slot(slot)
            clone.state = copy.deepcopy(node.state)
            clone._ledger_store.write(clone.state)
            clone._bft.load_from_state(clone.state)
            clone._speculative_authenticated_ancestor_replay = True
            for block in chain:
                meta = clone.apply_block(copy.deepcopy(block))
                evidence["steps"].append(
                    {
                        "block_id": str(block.get("block_id") or ""),
                        "ok": bool(meta.ok),
                        "error": str(meta.error or ""),
                        "height_after": int(clone.state.get("height") or 0),
                        "tip_after": str(clone.state.get("tip") or ""),
                    }
                )
                if not meta.ok:
                    break
            evidence["resolved_parent"] = str(clone.state.get("tip") or "") == qc_id
        except Exception as exc:
            evidence["exception"] = f"{type(exc).__name__}:{exc}"
        finally:
            node._release_spec_exec_slot(slot)
        return evidence
    if command == "peer_strike_debug":
        # Synthetic worker-only diagnostics: preserve the real strike/ban
        # policy, but expose why an honest restarted validator was rejected.
        return list(getattr(loop, "_test_strike_events", []))
    if command == "peer_security_writes":
        # This trace is populated by a test-worker-only transparent wrapper
        # around PeerSecurityStore.upsert. Never modifies the store contract.
        return list(getattr(loop, "_test_peer_security_writes", []))
    if command == "peer_host_security":
        # Read the genuine persistent pre-identity transport-host record.
        # New TCP peer records share this key for 127.0.0.1, regardless
        # of their ephemeral source ports. This cannot mutate a security
        # store or reset a strike/ban and is available in test workers only.
        assert loop.node is not None
        key = loop.node._peer_security_transport_key("tcp://127.0.0.1:1")
        store = loop.node._peer_security_store
        saved = store.load(key) if store is not None else None
        return {
            "key": key,
            "saved": (
                {
                    "strikes": int(saved.strikes),
                    "banned_until_ms": int(saved.banned_until_ms),
                    "score": float(saved.score),
                }
                if saved is not None
                else None
            ),
        }
    if command == "peer_status":
        assert loop.node is not None
        return {
            "runtime": loop.runtime_debug(),
            "peers": loop.node.peers_debug(),
            "handshake_context": {
                "chain_id": str(loop.node.cfg.chain_id),
                "schema_version": str(loop.node.cfg.schema_version),
                "tx_index_hash": str(loop.node.cfg.tx_index_hash),
                "validator_epoch": loop.node._handshake_validator_epoch(),
                "validator_set_hash": loop.node._handshake_validator_set_hash(),
                "bft_enabled": bool(loop.node.cfg.bft_enabled),
                "height": int(node.state["height"]),
            },
        }
    if command == "enable_autonomous_bft":
        # Enable normal production tick intervals after the harness has
        # established its synthetic transition QC. No view, vote, proposal or
        # QC is injected by this switch; progression remains network-driven.
        assert loop.node is not None
        assert loop._bft_enabled
        loop._bft_propose_interval_ms = 250
        loop._bft_vote_interval_ms = 250
        loop._bft_timeout_interval_ms = 250
        loop._last_bft_propose_ms = 0
        loop._last_bft_vote_ms = 0
        loop._last_bft_timeout_ms = 0
        return {"enabled": True, "current_view": int(node._bft.view)}
    if command == "start_block_http":
        # Real production read-only state/block route, isolated on localhost.
        # Only the test transport/server lifecycle is supplied by this harness.
        import uvicorn
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        from weall.api.routes_public_parts.state import router as state_router

        port = int(request["port"])
        app = FastAPI()
        app.state.executor = node
        app.include_router(state_router, prefix="/v1")
        fault_lock = threading.Lock()
        fault_state = {"remaining": 0, "rejected": 0, "reads": 0}
        loop._test_block_http_fault_lock = fault_lock
        loop._test_block_http_fault_state = fault_state

        @app.middleware("http")
        async def fail_initial_block_reads(request_http, call_next):
            # Transport fault injection is test-local: only delay block HTTP,
            # never patch the production handler or the consensus verifier.
            if request_http.method == "GET" and request_http.url.path.startswith(
                "/v1/state/block/"
            ):
                with fault_lock:
                    fault_state["reads"] += 1
                    reject = fault_state["remaining"] > 0
                    if reject:
                        fault_state["remaining"] -= 1
                        fault_state["rejected"] += 1
                if reject:
                    return JSONResponse(
                        status_code=503,
                        content={"ok": False, "error": "temporary_test_transport_outage"},
                    )
            return await call_next(request_http)

        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="error",
                access_log=False,
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        loop._test_block_http_server = server
        loop._test_block_http_thread = thread
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started is True
        return {"url": f"http://127.0.0.1:{port}"}
    if command == "configure_block_http_outage":
        # Configure bounded, deterministic HTTP transport failures only after
        # the direct positive/negative raw-route permission probes.
        failures = int(request["failed_requests"])
        assert 0 <= failures <= 2
        with loop._test_block_http_fault_lock:
            state = loop._test_block_http_fault_state
            state["remaining"] = failures
            state["rejected"] = 0
            state["reads"] = 0
        return {"scheduled_failures": failures}
    if command == "block_http_outage_status":
        with loop._test_block_http_fault_lock:
            return dict(loop._test_block_http_fault_state)
    if command == "enable_bft_fetch":
        # Unlock the normal production NetMeshLoop fetch tick only after the
        # returning node has authenticated all surviving TCP identities.
        assert loop.node is not None
        base = str(request["base_url"])
        assert base.startswith("http://127.0.0.1:")
        loop._bft_fetch_sources = [base]
        loop._bft_fetch_enabled = True
        loop._bft_fetch_interval_ms = 100
        loop._bft_fetch_cooldown_ms = 250
        loop._last_bft_fetch_ms = 0
        return {"enabled": True, "sources": len(loop._bft_fetch_sources)}
    if command == "broadcast_proposal":
        loop._broadcast_bft_proposal(request["proposal"])
        return {"broadcast_called": True}
    if command == "export_high_qc":
        qc = node._bft.high_qc
        block_id = str(request["block_id"])
        if qc is None or str(qc.block_id) != block_id:
            return None
        exported = qc.to_json()
        assert node.bft_verify_qc_json(exported) is not None
        return exported
    if command == "rebroadcast_stored_proposal":
        # A survivor retransmits *its own existing signed candidate* through
        # authenticated production TCP. The controller supplies only its ID,
        # not a new proposal body or a replacement signature.
        assert loop.node is not None
        bid = str(request["block_id"])
        proposal = node._bft_pending_block_json(bid)
        assert isinstance(proposal, dict)
        assert str(proposal.get("proposer") or "") == str(node.node_id)
        loop.node.broadcast_message(
            BftProposalMsg(
                header=_wire_header(node, MsgType.BFT_PROPOSAL),
                view=int(proposal["view"]),
                proposer=str(proposal["proposer"]),
                block=proposal,
                justify_qc=proposal.get("justify_qc"),
            )
        )
        return {"broadcast_called": True, "block_id": bid}
    if command == "broadcast_signed_qc":
        assert loop.node is not None
        qcj = request["qc"]
        assert node.bft_verify_qc_json(qcj) is not None
        loop.node.broadcast_message(BftQcMsg(header=_wire_header(node, MsgType.BFT_QC), qc=qcj))
        return {"broadcast_called": True}
    if command == "verify_qc":
        return node.bft_verify_qc_json(request["qc"]) is not None
    if command == "observed_qc_events":
        block_id = str(request["block_id"])
        return [
            event
            for event in node._bft_journal.read_tail(limit=512, strict=True)
            if event.get("event") == "bft_qc_observed"
            and isinstance(event.get("payload"), dict)
            and str(event["payload"].get("block_id") or "") == block_id
        ]
    if command == "fetch_descriptors":
        return node.bft_resolved_pending_fetch_request_descriptors()
    if command == "fetch_debug":
        pending_ids = node._ordered_pending_block_ids()
        speculative = node._bft_speculative_blocks_map()
        from weall.runtime import bft_pending_frontier_impl as frontier_impl

        return {
            "height": int(node.state.get("height") or 0),
            "tip": str(node.state.get("tip") or ""),
            "finalized": str(node._bft.finalized_block_id or ""),
            "high_qc": node._bft.high_qc.to_json().get("block_id")
            if node._bft.high_qc is not None
            else "",
            "fetch_enabled": bool(loop._bft_fetch_enabled),
            "fetch_sources": list(loop._bft_fetch_base_urls()),
            "last_fetch_ms": int(loop._last_bft_fetch_ms),
            "fetch_cooldowns": dict(loop._bft_fetch_cooldowns),
            "source_cooldowns": dict(loop._bft_fetch_source_cooldowns),
            "source_penalty_drops": int(loop._bft_fetch_source_penalty_drops),
            "requests": node.bft_resolved_pending_fetch_request_descriptors(),
            "missing_qcs": [
                {"id": str(k), "hash": str(v.get("block_hash") or "")}
                for k, v in node._pending_missing_qc_entries().items()
                if isinstance(v, dict)
            ],
            "pending_blocks": [
                {
                    "id": bid,
                    "height": int(blk.get("height") or 0),
                    "parent": str(blk.get("prev_block_id") or ""),
                    "hash": str(blk.get("block_hash") or ""),
                }
                for bid in pending_ids
                for blk in [node._bft_pending_block_json(bid)]
                if isinstance(blk, dict)
            ],
            "speculative": [
                {
                    "id": str(bid),
                    "height": int(record.get("height") or 0),
                    "parent": str(record.get("prev_block_id") or ""),
                }
                for bid, record in speculative.items()
                if isinstance(record, dict)
                and int(record.get("height") or 0) > int(node.state.get("height") or 0)
            ][:16],
            "finalized_replay_path": sorted(
                frontier_impl._finalized_replay_path_ids(
                    node, str(node._bft.finalized_block_id or "")
                )
                or []
            ),
            "runtime": loop.runtime_debug(),
        }
    if command == "qc_observation":
        block_id = str(request["block_id"])
        qc = node._bft.high_qc
        if qc is None or str(qc.block_id) != block_id:
            return None
        payload = qc.to_json()
        votes = payload.get("votes")
        assert isinstance(votes, list)
        return {
            "block_id": block_id,
            "view": int(payload["view"]),
            "verified": node.bft_verify_qc_json(payload) is not None,
            "signers": sorted(
                {str(vote.get("signer") or "") for vote in votes if isinstance(vote, dict)}
            ),
        }
    if command == "sent_timeouts":
        view = int(request["view"])
        enqueued: dict[str, Json] = {}
        sent: set[str] = set()
        for event in node._bft_journal.read_tail(limit=512, strict=True):
            body = event.get("payload")
            if not isinstance(body, dict) or body.get("kind") != "timeout":
                continue
            key = str(body.get("key") or "")
            if event.get("event") == "bft_outbound_enqueued":
                timeoutj = body.get("payload")
                if isinstance(timeoutj, dict) and int(timeoutj.get("view", -1)) == view:
                    enqueued[key] = timeoutj
            elif event.get("event") == "bft_outbound_sent":
                sent.add(key)
        return [timeout for key, timeout in enqueued.items() if key in sent]
    if command == "sent_votes":
        block_id = str(request["block_id"])
        # The production BFT outbox deletes obligations after successful send.
        # The checksum-verified journal retains both enqueue and sent events.
        enqueued: dict[str, Json] = {}
        sent: set[str] = set()
        for event in node._bft_journal.read_tail(limit=512, strict=True):
            body = event.get("payload")
            if not isinstance(body, dict) or body.get("kind") != "vote":
                continue
            key = str(body.get("key") or "")
            if event.get("event") == "bft_outbound_enqueued":
                vote = body.get("payload")
                if isinstance(vote, dict) and str(vote.get("block_id")) == block_id:
                    enqueued[key] = vote
            elif event.get("event") == "bft_outbound_sent":
                sent.add(key)
        return [vote for key, vote in enqueued.items() if key in sent]
    if command == "transition_vote":
        assert node.bft_leader_propose(max_txs=0) is None
        boundary = str(request["block_id"])
        choices = [
            entry["payload"]
            for entry in node.bft_pending_outbound_messages()
            if entry.get("kind") == "vote"
            and isinstance(entry.get("payload"), dict)
            and str(entry["payload"].get("block_id")) == boundary
            and int(entry["payload"].get("view", -1)) == 0
        ]
        assert len(choices) == 1
        return choices[0]
    if command == "netmesh_proposal":
        proposal = request["proposal"]
        prior = len(loop.node.messages)
        accepted = loop._on_bft_proposal(
            request["from_validator"],
            BftProposalMsg(
                header=_wire_header(node, MsgType.BFT_PROPOSAL),
                view=int(proposal["view"]),
                proposer=str(request["from_validator"]),
                block=proposal,
                justify_qc=proposal.get("justify_qc"),
            ),
        )
        emitted = loop.node.messages[prior:]
        return {
            "accepted": accepted is True,
            "votes": [m.vote for m in emitted if isinstance(m, BftVoteMsg)],
        }
    if command == "netmesh_vote":
        vote = request["vote"]
        prior = len(loop.node.messages)
        accepted = loop._on_bft_vote(
            request["from_validator"],
            BftVoteMsg(
                header=_wire_header(node, MsgType.BFT_VOTE),
                view=int(vote["view"]),
                vote=vote,
            ),
        )
        emitted = loop.node.messages[prior:]
        return {
            "accepted": accepted is True,
            "qcs": [m.qc for m in emitted if isinstance(m, BftQcMsg)],
        }
    if command == "netmesh_qc":
        accepted = loop._on_bft_qc(
            request["from_validator"],
            BftQcMsg(
                header=_wire_header(node, MsgType.BFT_QC),
                qc=request["qc"],
            ),
        )
        return {"accepted": accepted is True}
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
    if command == "try_propose":
        return node.bft_leader_propose(max_txs=int(request["max_txs"]))
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
            "receipt_signers": [receipt.get("signer") for receipt in block["receipts"]],
        }
    if command == "stop":
        server = getattr(loop, "_test_block_http_server", None)
        if server is not None:
            server.should_exit = True
        node.mark_clean_shutdown()
        return {"stopping": True}
    raise ValueError(f"unknown_command:{command}")


def _run_worker(
    root: Path,
    validator: str,
    ready: Path,
    *,
    mesh_port: int = 0,
    mesh_peers: tuple[int, ...] = (),
) -> None:
    pubs, privs = bft._key_material()
    env = bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])
    if mesh_port:
        env.update(
            {
                "WEALL_NET_TRANSPORT": "tcp",
                "WEALL_NET_REQUIRE_IDENTITY": "1",
                "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT": "1",
                "WEALL_PEER_ID": validator,
                "WEALL_PEERS": ",".join(f"tcp://127.0.0.1:{port}" for port in mesh_peers),
                "WEALL_PEERS_FILE": str(root / f"peers-{validator[1:]}.json"),
                "WEALL_BFT_FETCH_ENABLED": "0",
                "WEALL_STATE_BLOCK_PUBLIC_RAW": "0",
                "WEALL_STATE_RAW_READ_TOKEN": "bounded-bft-http-rehearsal-credential",
                "WEALL_PEER_STATE_RAW_READ_TOKEN": "bounded-bft-http-rehearsal-credential",
            }
        )
    with bft._env(env):
        executor = bft._make_executor(root, validator, node_id=validator)
        assert executor._validator_signing_permitted() is True
        assert executor._active_validators() == bft.VALIDATORS
        loop = NetMeshLoop(
            executor=executor,
            mempool=executor._mempool if mesh_port else object(),
            cfg=NetLoopConfig(
                enabled=bool(mesh_port),
                bind_host="127.0.0.1",
                bind_port=mesh_port or 30303,
                tick_ms=25,
                schema_version="1",
            ),
        )
        if mesh_port:
            # Suppress spontaneous view-driving during this bounded ingress test;
            # only real peer transport and network delivery are autonomous.
            now_ms = int(time.time() * 1000)
            loop._bft_propose_interval_ms = 120_000
            loop._bft_vote_interval_ms = 120_000
            loop._bft_timeout_interval_ms = 120_000
            loop._last_bft_propose_ms = now_ms
            loop._last_bft_vote_ms = now_ms
            loop._last_bft_timeout_ms = now_ms
            from weall.net.node import NetNode
            from weall.net.peer_store import PeerSecurityStore

            # Test-only passive instrumentation of actual durable host writes.
            # Store writes still execute through the unchanged real method.
            writes: list[Json] = []
            original_upsert = PeerSecurityStore.upsert

            def observed_upsert(store, *, peer_id, strikes, banned_until_ms, score):
                value = original_upsert(
                    store,
                    peer_id=peer_id,
                    strikes=strikes,
                    banned_until_ms=banned_until_ms,
                    score=score,
                )
                if str(peer_id).startswith("transport-host:"):
                    caller = sys._getframe(1)
                    origin = sys._getframe(2)
                    writes.append(
                        {
                            "peer_security_key": str(peer_id),
                            "strikes": int(strikes),
                            "banned_until_ms": int(banned_until_ms),
                            "callsite": f"{caller.f_code.co_name}:{caller.f_lineno}",
                            "origin": f"{origin.f_code.co_name}:{origin.f_lineno}",
                        }
                    )
                    if len(writes) > 64:
                        del writes[:-64]
                return value

            PeerSecurityStore.upsert = observed_upsert
            loop._test_peer_security_writes = writes

            # Only the separate test worker installs this bounded tracer.
            # It observes the existing call sites; never reduces strike
            # weights, resets bans, or patches wire/session verification.
            strikes: list[Json] = []
            original_strike = NetNode._strike

            def observed_strike(net_node, rec, weight):
                caller = sys._getframe(1)
                msg = caller.f_locals.get("msg")
                exc = caller.f_locals.get("e")
                strikes.append(
                    {
                        "peer_id": str(rec.peer_id),
                        "weight": int(weight),
                        "callsite": int(caller.f_lineno),
                        "message_type": str(
                            getattr(getattr(msg, "header", None), "type", "") or ""
                        ),
                        "exception_type": type(exc).__name__ if exc is not None else "",
                        "exception_reason": str(exc)[:160] if exc is not None else "",
                        "session_status": str(rec.router.handshake.status),
                    }
                )
                if len(strikes) > 64:
                    del strikes[:-64]
                return original_strike(net_node, rec, weight)

            NetNode._strike = observed_strike
            loop._test_strike_events = strikes
            assert loop.start() is True
        else:
            loop.node = _CaptureBroadcast(executor, validator)
        loop._bft_enabled = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(0.5)
            # The parent polls this path as its readiness signal. Publishing
            # it before write_text closes the file allows a rare empty read.
            # Publish a complete JSON record with a same-directory rename.
            ready_tmp = ready.with_suffix(".json.tmp")
            ready_tmp.write_text(
                json.dumps({"port": listener.getsockname()[1], "pid": os.getpid()}),
                encoding="utf-8",
            )
            ready_tmp.replace(ready)
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
                        result = _worker_command(executor, request, loop)
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
        if mesh_port:
            loop.stop()
            loop.join(timeout=3.0)
            # Persist test-only post-stop observations, because the parent
            # cannot query a process once its RPC listener has exited.
            # No write is made to the node's ledger or security database.
            shutdown_evidence = {
                "strikes": list(getattr(loop, "_test_strike_events", [])),
                "host_writes": list(getattr(loop, "_test_peer_security_writes", [])),
                "host_security": _worker_command(
                    executor, {"command": "peer_host_security"}, loop
                ),
            }
            (root / f"worker-exit-security-{validator.lstrip('@')}.json").write_text(
                json.dumps(shutdown_evidence, sort_keys=True), encoding="utf-8"
            )


class _NodeProcess:
    def __init__(
        self,
        root: Path,
        validator: str,
        *,
        mesh_port: int = 0,
        mesh_peers: tuple[int, ...] = (),
    ) -> None:
        self.validator = validator
        self.ready = root / f"rpc-{validator.replace('@', '')}.json"
        self.log_path = root / f"rpc-{validator.replace('@', '')}.log"
        self.ready.unlink(missing_ok=True)
        self.log = self.log_path.open("w", encoding="utf-8")
        argv = [
            sys.executable,
            "-u",
            str(Path(__file__).resolve()),
            "--worker",
            str(root),
            validator,
            str(self.ready),
        ]
        if mesh_port:
            argv.extend([str(mesh_port), ",".join(str(port) for port in mesh_peers)])
        self.proc = subprocess.Popen(
            argv,
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
        assert response["ok"] is True, f"{self.validator} {command}: {response.get('error')}"
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
@pytest.mark.parametrize("ingress", ["executor", "netmesh"], ids=["direct", "netmesh_handlers"])
def test_socket_separated_production_qc_election_recovery(
    tmp_path: Path, turnout: int, ingress: str
) -> None:
    """Four socket-isolated executors: direct baseline and production network ingress."""
    pubs, privs = bft._key_material()
    seeded, boundary_id, _hash = bft._install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
        seed_emissary_electorate=True,
    )
    for validator, executor in seeded.items():
        with bft._env(bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])):
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
                    receipt for receipt in receipts if receipt["tx_type"] != "BLOCK_FINALIZE"
                ]
                assert len(user_receipts) == len(signed)
                assert sorted(receipt["tx_type"] for receipt in user_receipts) == sorted(
                    tx["tx_type"] for tx in signed
                )
            if ingress == "netmesh":
                follower_votes = []
                for validator in bft.VALIDATORS:
                    if validator == leader:
                        continue
                    response = workers[validator].send(
                        "netmesh_proposal", proposal=proposal, from_validator=leader
                    )
                    assert response["accepted"] is True
                    assert len(response["votes"]) == 1
                    follower_votes.extend(response["votes"])
                # A retransmission cannot create a second vote for the same
                # signed proposal. This is the real NetMeshLoop duplicate path.
                repeat = workers[follower_votes[0]["signer"]].send(
                    "netmesh_proposal", proposal=proposal, from_validator=leader
                )
                assert repeat["accepted"] is True
                assert repeat["votes"] == []
                qc: Json | None = None
                for vote in follower_votes:
                    result = workers[leader].send(
                        "netmesh_vote", vote=vote, from_validator=vote["signer"]
                    )
                    assert result["accepted"] is True
                    if result["qcs"]:
                        assert len(result["qcs"]) == 1
                        qc = result["qcs"][0]
                assert isinstance(qc, dict)
                duplicate_vote = workers[leader].send(
                    "netmesh_vote",
                    vote=follower_votes[-1],
                    from_validator=follower_votes[-1]["signer"],
                )
                assert duplicate_vote["accepted"] is True
                assert duplicate_vote["qcs"] == []
                assert qc["block_id"] == proposal["block_id"]
                delayed = next(v for v in bft.VALIDATORS if v != leader)
                for validator, worker in workers.items():
                    if validator == delayed:
                        continue
                    result = worker.send("netmesh_qc", qc=qc, from_validator=leader)
                    assert result["accepted"] is True
                # Delayed delivery is observable before the withheld process
                # receives the same certified QC; never compare roots until
                # the withheld validator has caught up.
                before_delayed = workers[delayed].send("snapshot")
                result = workers[delayed].send("netmesh_qc", qc=qc, from_validator=leader)
                assert result["accepted"] is True
                delivered = workers[delayed].send("snapshot")
                assert delivered["height"] >= before_delayed["height"]
                for worker in workers.values():
                    again = worker.send("netmesh_qc", qc=qc, from_validator=leader)
                    assert again["accepted"] is True
            else:
                follower_votes = [
                    workers[validator].send("vote_proposal", proposal=proposal)
                    for validator in bft.VALIDATORS
                    if validator != leader
                ]
                assert len(follower_votes) == 3
                qc = None
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


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_canonical_commit_preserves_live_bft_metadata_after_stale_candidate(
    tmp_path: Path,
) -> None:
    """An unchanged validator generation must not load stale BFT signing state.

    Build an otherwise valid candidate first, then advance the local pacemaker
    and signing records as a networking thread may do while the block is pending.
    The canonical commit must preserve the newer live metadata in memory, durable
    SQLite and a fresh restarted executor. State roots exclude local BFT state.
    """
    with bft._env(bft._setup_env()):
        executor = bft._make_executor(tmp_path, "bft-commit-liveness")
        candidate = executor.build_block_candidate(max_txs=0, allow_empty=True, force_ts_ms=1000)
        block, candidate_state, applied_ids, invalid_ids, err = candidate
        assert err == ""
        assert isinstance(block, dict)
        assert isinstance(candidate_state, dict)

        executor._bft.bump_view(9)
        executor._bft.last_voted_view = 8
        executor._bft.last_voted_block_id = "previous-signed-vote"
        executor._bft.last_voted_block_hash = "previous-signed-vote-hash"
        executor._bft.last_proposed_view = 7
        executor._bft.last_proposed_block_id = "previous-signed-proposal"
        executor._bft.last_proposed_block_hash = "previous-signed-proposal-hash"
        executor._persist_bft_state()
        assert int(candidate_state.get("bft", {}).get("view") or 0) < 9

        meta = executor.commit_block_candidate(
            block=block,
            new_state=candidate_state,
            applied_ids=applied_ids,
            invalid_ids=invalid_ids,
        )
        assert meta.ok, meta.error
        assert meta.error == ""
        assert executor._bft.view == 9
        assert executor._bft.last_voted_view == 8
        assert executor._bft.last_voted_block_id == "previous-signed-vote"
        assert executor._bft.last_proposed_view == 7
        assert executor._bft.last_proposed_block_id == "previous-signed-proposal"
        persisted = executor._ledger_store.read()
        assert persisted["bft"]["view"] == 9
        assert persisted["bft"]["last_voted_view"] == 8
        assert persisted["bft"]["last_voted_block_id"] == "previous-signed-vote"
        assert persisted["bft"]["last_proposed_view"] == 7
        assert persisted["bft"]["last_proposed_block_id"] == "previous-signed-proposal"

        restarted = bft._make_executor(tmp_path, "bft-commit-liveness")
        assert restarted.state["height"] == block["height"]
        assert restarted._bft.view == 9
        assert restarted._bft.last_voted_view == 8
        assert restarted._bft.last_voted_block_id == "previous-signed-vote"
        assert restarted._bft.last_proposed_view == 7
        assert restarted._bft.last_proposed_block_id == "previous-signed-proposal"


def test_atomic_bft_state_survives_postcommit_housekeeping_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed block must already contain current local signing history.

    Force a failure at the first post-commit housekeeping hook. The block is
    durable even though the executor fails closed, and its *same transaction*
    ledger snapshot must carry the newest view, vote, and proposal records.
    """
    with bft._env(bft._setup_env()):
        executor = bft._make_executor(tmp_path, "bft-atomic-state")
        candidate = executor.build_block_candidate(max_txs=0, allow_empty=True, force_ts_ms=1000)
        block, candidate_state, applied_ids, invalid_ids, err = candidate
        assert err == ""
        assert isinstance(block, dict)
        assert isinstance(candidate_state, dict)

        executor._bft.bump_view(11)
        executor._bft.last_voted_view = 10
        executor._bft.last_voted_block_id = "atomic-vote"
        executor._bft.last_voted_block_hash = "atomic-vote-hash"
        executor._bft.last_proposed_view = 9
        executor._bft.last_proposed_block_id = "atomic-proposal"
        executor._bft.last_proposed_block_hash = "atomic-proposal-hash"

        def fail_postcommit_cache(_block_id: str, _block_hash: str) -> None:
            raise RuntimeError("injected_postcommit_failure")

        monkeypatch.setattr(executor, "_cache_known_block_hash", fail_postcommit_cache)
        result = executor.commit_block_candidate(
            block=block,
            new_state=candidate_state,
            applied_ids=applied_ids,
            invalid_ids=invalid_ids,
        )
        assert result.ok is True
        assert "post_commit_housekeeping_failed:RuntimeError" in result.error
        assert executor._validator_signing_enabled is False

        # The second BFT persistence write from the previous implementation
        # would never execute in this scenario. Recovery must rely solely on
        # the block's atomic ledger_state transaction.
        persisted = executor._ledger_store.read()
        assert persisted["height"] == block["height"]
        assert persisted["tip"] == block["block_id"]
        assert persisted["bft"]["view"] == 11
        assert persisted["bft"]["last_voted_view"] == 10
        assert persisted["bft"]["last_voted_block_id"] == "atomic-vote"
        assert persisted["bft"]["last_proposed_view"] == 9
        assert persisted["bft"]["last_proposed_block_id"] == "atomic-proposal"


def test_authenticated_tcp_netmesh_delivers_signed_bft_proposal(
    tmp_path: Path,
) -> None:
    """Real TCP peer sessions, independently authenticated in four Python processes.

    The RPC controller seeds the original boundary and chooses the view. It
    never relays proposal/vote/QC network messages. This is static-peer loopback
    transport, not automatic discovery, partition recovery or constitutional
    activation.
    """
    pubs, privs = bft._key_material()
    seeded, boundary_id, _ = bft._install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
        seed_emissary_electorate=True,
        seed_authenticated_validator_keys=True,
    )
    for validator, executor in seeded.items():
        with bft._env(bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])):
            executor.mark_clean_shutdown()
    seeded.clear()

    workers: dict[str, _NodeProcess] = {}
    ports = {validator: _free_tcp_port() for validator in bft.VALIDATORS}
    try:
        for validator in bft.VALIDATORS:
            workers[validator] = _NodeProcess(
                tmp_path,
                validator,
                mesh_port=ports[validator],
                mesh_peers=tuple(port for other, port in ports.items() if other != validator),
            )

        deadline = time.monotonic() + 20
        last_status: dict[str, Json] = {}
        while time.monotonic() < deadline:
            last_status = {
                validator: worker.send("peer_status") for validator, worker in workers.items()
            }

            def connected_identity_set(status: Json) -> set[str]:
                return {
                    str(peer["account_id"])
                    for peer in status["peers"]["peers"]
                    if peer["connected"]
                    and peer["established"]
                    and peer["identity_verified"]
                    and not peer["banned"]
                }

            if all(
                connected_identity_set(last_status[validator])
                >= (set(bft.VALIDATORS) - {validator})
                for validator in bft.VALIDATORS
            ):
                break
            time.sleep(0.1)

        handshake_evidence = {
            validator: {
                "runtime": status["runtime"],
                "counts": status["peers"]["counts"],
                "peers": [
                    {
                        key: peer.get(key)
                        for key in (
                            "peer_id",
                            "connected",
                            "established",
                            "identity_verified",
                            "account_id",
                            "banned",
                            "strikes",
                            "last_error",
                        )
                    }
                    for peer in status["peers"]["peers"]
                    if peer["connected"] or peer["banned"] or peer["strikes"]
                ],
            }
            for validator, status in last_status.items()
        }
        for validator in bft.VALIDATORS:
            status = last_status[validator]
            assert status["runtime"]["thread_alive"] is True, handshake_evidence
            assert status["runtime"]["unhealthy"] is False, handshake_evidence
            assert connected_identity_set(status) >= (set(bft.VALIDATORS) - {validator}), (
                json.dumps(handshake_evidence, sort_keys=True)
            )

        transition_votes = [
            worker.send("transition_vote", block_id=boundary_id) for worker in workers.values()
        ]
        collector = workers[bft.VALIDATORS[0]]
        qc0 = None
        for vote in transition_votes:
            result = collector.send("receive_vote", vote=vote)
            if isinstance(result, dict):
                qc0 = result
        assert isinstance(qc0, dict)
        assert qc0["block_id"] == boundary_id
        for worker in workers.values():
            worker.send("receive_qc", qc=qc0)
            worker.send("set_view", view=1)

        proposals: dict[int, Json] = {}
        for view in (1, 2, 3):
            for worker in workers.values():
                worker.send("set_view", view=view)
            leader = leader_for_view(bft.VALIDATORS, view)
            proposal = workers[leader].send("propose", max_txs=0)
            proposals[view] = proposal
            assert int(proposal["view"]) == view
            assert (
                workers[leader].send("broadcast_proposal", proposal=proposal)["broadcast_called"]
                is True
            )

            # The RPC controller never forwards network votes. They must be
            # emitted after an authenticated TCP proposal reaches each follower.
            deadline = time.monotonic() + 18
            follower_votes: dict[str, Json] = {}
            while time.monotonic() < deadline:
                for validator, worker in workers.items():
                    if validator == leader:
                        continue
                    votes = worker.send("sent_votes", block_id=proposal["block_id"])
                    if len(votes) == 1:
                        follower_votes[validator] = votes[0]
                if len(follower_votes) == 3:
                    break
                time.sleep(0.1)
            expected_followers = set(bft.VALIDATORS) - {leader}
            assert set(follower_votes) == expected_followers, {
                "view": view,
                "received": sorted(follower_votes),
                "expected": sorted(expected_followers),
            }
            assert all(
                vote["signer"] == validator and vote["block_id"] == proposal["block_id"]
                for validator, vote in follower_votes.items()
            )

            # QCs must emerge from production vote handlers and be delivered
            # through peer sockets. Inspect validated QC state on each process;
            # do not inject a QC through RPC as the earlier baseline did.
            qc_observations: dict[str, Json] = {}
            deadline = time.monotonic() + 18
            while time.monotonic() < deadline:
                for validator, worker in workers.items():
                    observation = worker.send("qc_observation", block_id=proposal["block_id"])
                    if isinstance(observation, dict) and observation["verified"]:
                        qc_observations[validator] = observation
                if len(qc_observations) == 4:
                    break
                time.sleep(0.1)
            assert set(qc_observations) == set(bft.VALIDATORS), {
                "view": view,
                "observed": sorted(qc_observations),
            }
            assert all(
                observation["view"] == view
                and len(observation["signers"]) >= 3
                and set(observation["signers"]) <= set(bft.VALIDATORS)
                for observation in qc_observations.values()
            )

        # The certified 3-chain must finalize view 1 on every independent
        # process. The controller drives views, never network messages.
        deadline = time.monotonic() + 8
        snapshots = [worker.send("snapshot") for worker in workers.values()]
        while time.monotonic() < deadline:
            if all(
                snap["height"] == 2 and snap["tip"] == proposals[1]["block_id"]
                for snap in snapshots
            ):
                break
            time.sleep(0.1)
            snapshots = [worker.send("snapshot") for worker in workers.values()]
        frontier = {
            validator: worker.send("frontier_debug") for validator, worker in workers.items()
        }
        assert all(snap["height"] == 2 for snap in snapshots), frontier
        assert all(snap["tip"] == proposals[1]["block_id"] for snap in snapshots), frontier
        assert all(snap["finalized_block_id"] == proposals[1]["block_id"] for snap in snapshots), (
            frontier
        )
        assert len({snap["state_root"] for snap in snapshots}) == 1, frontier

        # Restart the validator selected to lead the *next* view, keeping its
        # exact SQLite store and TCP listening address. This is a real process
        # interruption and network handshake recovery, not controller packet
        # delivery or a replacement in-memory executor.
        next_view = 4
        restarted = leader_for_view(bft.VALIDATORS, next_view)
        prior = workers[restarted].send("snapshot")
        before_initial_restart_host_security = workers[restarted].send("peer_host_security")
        before_initial_restart_strikes = workers[restarted].send("peer_strike_debug")
        workers[restarted].close()
        previous_initial_exit = json.loads(
            (tmp_path / f"worker-exit-security-{restarted.lstrip('@')}.json").read_text(
                encoding="utf-8"
            )
        )
        workers[restarted] = _NodeProcess(
            tmp_path,
            restarted,
            mesh_port=ports[restarted],
            mesh_peers=tuple(port for other, port in ports.items() if other != restarted),
        )
        recovered = workers[restarted].send("snapshot")
        assert recovered["height"] == prior["height"] == 2
        assert recovered["tip"] == prior["tip"] == proposals[1]["block_id"]
        assert recovered["state_root"] == prior["state_root"]
        assert recovered["finalized_block_id"] == prior["finalized_block_id"]

        deadline = time.monotonic() + 20
        restarted_status: Json = {}
        while time.monotonic() < deadline:
            restarted_status = workers[restarted].send("peer_status")
            if connected_identity_set(restarted_status) >= (set(bft.VALIDATORS) - {restarted}):
                break
            time.sleep(0.1)
        assert restarted_status["runtime"]["thread_alive"] is True, restarted_status
        assert restarted_status["runtime"]["unhealthy"] is False, restarted_status
        if connected_identity_set(restarted_status) < (set(bft.VALIDATORS) - {restarted}):
            statuses = {
                validator: worker.send("peer_status") for validator, worker in workers.items()
            }
            evidence = {
                validator: {
                    "handshake_context": status["handshake_context"],
                    "counts": status["peers"]["counts"],
                    "peers": [
                        {
                            key: peer.get(key)
                            for key in (
                                "peer_id",
                                "connected",
                                "established",
                                "identity_verified",
                                "account_id",
                                "banned",
                                "strikes",
                                "last_error",
                            )
                        }
                        for peer in status["peers"]["peers"]
                        if peer["connected"] or peer["banned"] or peer["strikes"]
                    ],
                    # The worker already traces the real production _strike
                    # callsites. Include them on this initial height-2 restart
                    # failure, not only on the later offline-height-3 rejoin.
                    # No authentication, strike, or ban rule is modified.
                    "strike_trace": workers[validator].send("peer_strike_debug"),
                    "current_host_security": workers[validator].send("peer_host_security"),
                }
                for validator, status in statuses.items()
            }
            evidence["before_restart_host_security"] = before_initial_restart_host_security
            evidence["before_restart_strikes"] = before_initial_restart_strikes
            evidence["old_process_shutdown"] = previous_initial_exit
            evidence["new_process_host_writes"] = workers[restarted].send(
                "peer_security_writes"
            )
            pytest.fail(json.dumps(evidence, sort_keys=True))

        for worker in workers.values():
            worker.send("set_view", view=next_view)
        proposal4 = workers[restarted].send("propose", max_txs=0)
        assert int(proposal4["view"]) == next_view
        assert proposal4["prev_block_id"] == proposals[3]["block_id"]
        assert (
            workers[restarted].send("broadcast_proposal", proposal=proposal4)["broadcast_called"]
            is True
        )
        expected_votes = set(bft.VALIDATORS) - {restarted}
        received_votes: set[str] = set()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for validator in expected_votes:
                votes = workers[validator].send("sent_votes", block_id=proposal4["block_id"])
                if len(votes) == 1 and votes[0]["signer"] == validator:
                    received_votes.add(validator)
            if received_votes == expected_votes:
                break
            time.sleep(0.1)
        assert received_votes == expected_votes

        certified: set[str] = set()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for validator, worker in workers.items():
                qc = worker.send("qc_observation", block_id=proposal4["block_id"])
                if isinstance(qc, dict) and qc["verified"] and len(qc["signers"]) >= 3:
                    certified.add(validator)
            if certified == set(bft.VALIDATORS):
                break
            time.sleep(0.1)
        assert certified == set(bft.VALIDATORS)

        # A post-restart QC must advance the next 3-chain commitment on *all*
        # processes. This requires restored speculative ancestry on the
        # restarted proposer and working authenticated network delivery.
        deadline = time.monotonic() + 12
        post_restart = [worker.send("snapshot") for worker in workers.values()]
        while time.monotonic() < deadline:
            if all(
                snap["height"] == 3 and snap["tip"] == proposals[2]["block_id"]
                for snap in post_restart
            ):
                break
            time.sleep(0.1)
            post_restart = [worker.send("snapshot") for worker in workers.values()]
        frontier = {
            validator: worker.send("frontier_debug") for validator, worker in workers.items()
        }
        assert all(snap["height"] == 3 for snap in post_restart), frontier
        assert all(snap["tip"] == proposals[2]["block_id"] for snap in post_restart), frontier
        assert all(
            snap["finalized_block_id"] == proposals[2]["block_id"] for snap in post_restart
        ), frontier
        assert len({snap["state_root"] for snap in post_restart}) == 1, frontier

        # The next three active proposer views must advance consensus without
        # the fourth validator's participation. The controller selects the
        # views, but the production leader signs and counts its own vote;
        # remote signed votes and quorum certificates cross authenticated TCP.
        # We skip view 7 because it belongs to the intentionally offline node.
        offline = leader_for_view(bft.VALIDATORS, 7)
        assert offline not in {leader_for_view(bft.VALIDATORS, view) for view in (5, 6, 8)}
        old_offline = workers.pop(offline)
        offline_before = old_offline.send("snapshot")
        assert offline_before["height"] == 3
        before_offline_stop_host_security = old_offline.send("peer_host_security")
        before_offline_stop_strikes = old_offline.send("peer_strike_debug")
        old_offline.close()
        previous_offline_exit = json.loads(
            (tmp_path / f"worker-exit-security-{offline.lstrip('@')}.json").read_text(
                encoding="utf-8"
            )
        )
        online = set(workers)
        assert len(online) == 3
        surviving_proposals: dict[int, Json] = {}
        certified_view5: Json | None = None
        certified_view8: Json | None = None

        for view in (5, 6, 8):
            for worker in workers.values():
                worker.send("set_view", view=view)
            leader = leader_for_view(bft.VALIDATORS, view)
            assert leader in online
            # The preceding QC/finalized replay can still be pending on the
            # proposed leader at the instant the view changes. A temporary
            # None means no candidate was signed; retry only within a bounded
            # window, and fail with durable frontier evidence if it stays
            # unavailable (exceptions remain hard failures).
            deadline = time.monotonic() + 10
            proposal = workers[leader].send("try_propose", max_txs=0)
            while not isinstance(proposal, dict) and time.monotonic() < deadline:
                time.sleep(0.1)
                proposal = workers[leader].send("try_propose", max_txs=0)
            assert isinstance(proposal, dict), json.dumps(
                {
                    "leader": leader,
                    "view": view,
                    "frontier": workers[leader].send("frontier_debug"),
                    "online": {
                        validator: worker.send("frontier_debug")
                        for validator, worker in workers.items()
                    },
                    "speculative_parent_replay": workers[leader].send("speculative_parent_debug"),
                },
                sort_keys=True,
            )
            surviving_proposals[view] = proposal
            assert proposal["view"] == view
            # No RPC-supplied local vote: the production NetMeshLoop must
            # independently sign, admit and gossip its elected leader's vote.
            assert (
                workers[leader].send("broadcast_proposal", proposal=proposal)["broadcast_called"]
                is True
            )
            local_votes: list[Json] = []
            local_deadline = time.monotonic() + 15
            while time.monotonic() < local_deadline:
                local_votes = workers[leader].send("sent_votes", block_id=proposal["block_id"])
                if len(local_votes) == 1:
                    break
                time.sleep(0.1)
            assert len(local_votes) == 1, {"view": view, "leader": leader, "votes": local_votes}
            assert local_votes[0]["signer"] == leader
            assert local_votes[0]["block_id"] == proposal["block_id"]
            # Re-broadcasting an identical proposal must not sign a second
            # local vote for the same view and block.
            workers[leader].send("broadcast_proposal", proposal=proposal)
            assert workers[leader].send("sent_votes", block_id=proposal["block_id"]) == local_votes

            expected_remote = online - {leader}
            sent: set[str] = set()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                for validator in expected_remote:
                    votes = workers[validator].send("sent_votes", block_id=proposal["block_id"])
                    if len(votes) == 1 and votes[0]["signer"] == validator:
                        sent.add(validator)
                if sent == expected_remote:
                    break
                time.sleep(0.1)
            assert sent == expected_remote, {"view": view, "sent": sorted(sent)}

            qc_proven: set[str] = set()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                for validator, worker in workers.items():
                    qc = worker.send("qc_observation", block_id=proposal["block_id"])
                    if isinstance(qc, dict) and qc["verified"]:
                        assert len(qc["signers"]) >= 3
                        assert set(qc["signers"]) == online
                        qc_proven.add(validator)
                if qc_proven == online:
                    break
                time.sleep(0.1)
            assert qc_proven == online, {
                "view": view,
                "certified": sorted(qc_proven),
            }
            if view in (5, 8):
                captured_qc = workers[leader].send("export_high_qc", block_id=proposal["block_id"])
                assert isinstance(captured_qc, dict)
                assert captured_qc["block_id"] == proposal["block_id"]
                if view == 5:
                    certified_view5 = captured_qc
                else:
                    certified_view8 = captured_qc

        # A certified three-chain formed while one validator was absent must
        # finalize a block *after* that validator's committed height.
        deadline = time.monotonic() + 10
        surviving = [worker.send("snapshot") for worker in workers.values()]
        while time.monotonic() < deadline:
            if all(
                snap["height"] == surviving_proposals[5]["height"]
                and snap["tip"] == surviving_proposals[5]["block_id"]
                for snap in surviving
            ):
                break
            time.sleep(0.1)
            surviving = [worker.send("snapshot") for worker in workers.values()]
        frontier = {
            validator: worker.send("frontier_debug") for validator, worker in workers.items()
        }
        assert all(snap["height"] == surviving_proposals[5]["height"] for snap in surviving), {
            "snapshots": surviving,
            "frontier": frontier,
            "proposed": {
                str(view): {
                    "block_id": proposal["block_id"],
                    "parent": proposal["prev_block_id"],
                    "height": proposal["height"],
                }
                for view, proposal in surviving_proposals.items()
            },
        }
        assert all(snap["tip"] == surviving_proposals[5]["block_id"] for snap in surviving)
        assert len({snap["state_root"] for snap in surviving}) == 1

        # Rejoin the process which never received views 5/6/8. Do not patch
        # its SQLite ledger or deliver a QC directly through the controller.
        # A verified QC from an online validator is retransmitted through the
        # genuine authenticated BFT_QC network message path.
        assert isinstance(certified_view5, dict)
        workers[offline] = _NodeProcess(
            tmp_path,
            offline,
            mesh_port=ports[offline],
            mesh_peers=tuple(port for other, port in ports.items() if other != offline),
        )
        lagging = workers[offline].send("snapshot")
        assert lagging["height"] == offline_before["height"] == 3
        assert lagging["tip"] == offline_before["tip"]
        assert lagging["state_root"] == offline_before["state_root"]

        rejoin_deadline = time.monotonic() + 20
        last_rejoin_status: Json = {}
        while time.monotonic() < rejoin_deadline:
            last_rejoin_status = workers[offline].send("peer_status")
            if connected_identity_set(last_rejoin_status) >= online:
                break
            time.sleep(0.1)
        assert last_rejoin_status["runtime"]["thread_alive"] is True
        assert last_rejoin_status["runtime"]["unhealthy"] is False
        if connected_identity_set(last_rejoin_status) < online:

            def peer_evidence(status: Json) -> Json:
                return {
                    "handshake_context": status["handshake_context"],
                    "runtime": status["runtime"],
                    "counts": status["peers"]["counts"],
                    "peers": [
                        {
                            key: peer.get(key)
                            for key in (
                                "peer_id",
                                "connected",
                                "established",
                                "identity_verified",
                                "account_id",
                                "strikes",
                                "banned",
                                "last_error",
                            )
                        }
                        for peer in status["peers"]["peers"]
                        if peer["connected"] or peer["strikes"] or peer["banned"]
                    ],
                }

            evidence = {
                "lagging": peer_evidence(last_rejoin_status),
                "lagging_strike_trace": workers[offline].send("peer_strike_debug"),
                "persisted_host_after_rejoin": workers[offline].send("peer_host_security"),
                "persisted_host_before_offline_stop": before_offline_stop_host_security,
                "prior_worker_strike_trace": before_offline_stop_strikes,
                "prior_worker_shutdown_security": previous_offline_exit,
                "new_worker_host_writes": workers[offline].send("peer_security_writes"),
                "online": {
                    validator: peer_evidence(worker.send("peer_status"))
                    for validator, worker in workers.items()
                    if validator != offline
                },
                "online_strike_traces": {
                    validator: worker.send("peer_strike_debug")
                    for validator, worker in workers.items()
                    if validator != offline
                },
            }
            pytest.fail(json.dumps(evidence, sort_keys=True))

        source = leader_for_view(bft.VALIDATORS, 5)
        assert source in online
        broadcast = workers[source].send("broadcast_signed_qc", qc=certified_view5)
        assert broadcast["broadcast_called"] is True

        pending: list[Json] = []
        detection_deadline = time.monotonic() + 12
        while time.monotonic() < detection_deadline:
            pending = workers[offline].send("fetch_descriptors")
            if any(
                desc.get("block_id") == certified_view5["block_id"]
                and desc.get("block_hash") == certified_view5["block_hash"]
                and desc.get("reason") == "missing_qc_block"
                for desc in pending
            ):
                break
            time.sleep(0.1)
        assert any(
            desc.get("block_id") == certified_view5["block_id"]
            and desc.get("block_hash") == certified_view5["block_hash"]
            and desc.get("reason") == "missing_qc_block"
            for desc in pending
        ), {
            "pending": pending,
            "offline_frontier": workers[offline].send("frontier_debug"),
            "qc": {"id": certified_view5["block_id"], "view": certified_view5["view"]},
            "verified_at_rejoin": workers[offline].send("verify_qc", qc=certified_view5),
            "qc_observed_events": workers[offline].send(
                "observed_qc_events", block_id=certified_view5["block_id"]
            ),
            "source_peers": workers[source].send("peer_status"),
        }
        # Expose a genuine production raw-block read route from the surviving
        # validator. The credential is harness-local: an unauthenticated request
        # must fail, while the existing fetch client supplies the configured
        # operator header. No test RPC relays or applies any missing block.
        raw_port = _free_tcp_port()
        source_url = workers[source].send("start_block_http", port=raw_port)["url"]
        url = f"{source_url}/v1/state/block/{certified_view5['block_id']}"
        with pytest.raises(HTTPError) as denied:
            urlopen(url, timeout=3)
        assert denied.value.code == 403
        authorized = Request(
            url,
            headers={"X-WeAll-State-Raw-Read-Token": "bounded-bft-http-rehearsal-credential"},
        )
        with urlopen(authorized, timeout=3) as response:
            raw_payload = json.loads(response.read())
        assert raw_payload["ok"] is True
        assert raw_payload["block"]["block_id"] == certified_view5["block_id"]

        assert workers[source].send("configure_block_http_outage", failed_requests=2) == {
            "scheduled_failures": 2
        }
        assert workers[offline].send("enable_bft_fetch", base_url=source_url) == {
            "enabled": True,
            "sources": 1,
        }
        source_snapshot = workers[source].send("snapshot")
        assert source_snapshot["height"] == 6

        # The original view-5 QC plus the fetched committed block at height 6
        # should now re-observe a cached proof and finalize at least height 4.
        # Never manufacture a QC or apply a block through the controller.
        stage_one_deadline = time.monotonic() + 12
        stage_one: Json = {}
        while time.monotonic() < stage_one_deadline:
            stage_one = workers[offline].send("snapshot")
            if stage_one["height"] >= 4:
                break
            time.sleep(0.1)
        assert stage_one["height"] >= 4, {
            "lagging": stage_one,
            "fetch": workers[offline].send("fetch_debug"),
            "http_faults": workers[source].send("block_http_outage_status"),
        }
        outage = workers[source].send("block_http_outage_status")
        assert outage["remaining"] == 0, outage
        assert outage["rejected"] == 2, outage
        assert outage["reads"] >= 3, outage

        # Deliver the surviving quorum's actual signed, not-yet-committed
        # descendants through authenticated TCP. Those bodies establish the
        # ancestry of the real view-8 QC, which can finalize height 6. They
        # remain speculative, never canonical without verified finality.
        assert isinstance(certified_view8, dict)
        for later_view in (6, 8):
            later_leader = leader_for_view(bft.VALIDATORS, later_view)
            original_id = str(surviving_proposals[later_view]["block_id"])
            # These two survivor proposals originate at different peers.
            # TCP delivers each peer's packets in order, but not packets
            # across peer connections. Never deliver view 8 / its QC before
            # the returning process has cached the signed view-6 ancestor.
            cached: Json = {}
            deadline = time.monotonic() + 10
            next_rebroadcast = 0.0
            while time.monotonic() < deadline:
                cached = workers[offline].send("fetch_debug")
                if any(row.get("id") == original_id for row in cached.get("pending_blocks", [])):
                    break
                if time.monotonic() >= next_rebroadcast:
                    result = workers[later_leader].send(
                        "rebroadcast_stored_proposal", block_id=original_id
                    )
                    assert result["broadcast_called"] is True
                    next_rebroadcast = time.monotonic() + 0.75
                time.sleep(0.1)
            assert any(row.get("id") == original_id for row in cached.get("pending_blocks", [])), {
                "missing_signed_view": later_view,
                "missing_signed_block_id": original_id,
                "lagging": cached,
                "survivor": workers[later_leader].send("frontier_debug"),
            }
        source8 = leader_for_view(bft.VALIDATORS, 8)
        assert (
            workers[source8].send("broadcast_signed_qc", qc=certified_view8)["broadcast_called"]
            is True
        )
        catchup_deadline = time.monotonic() + 25
        caught_up: Json = {}
        last_fetch_descriptors: list[Json] = []
        while time.monotonic() < catchup_deadline:
            caught_up = workers[offline].send("snapshot")
            if (
                caught_up["height"] == source_snapshot["height"]
                and caught_up["tip"] == source_snapshot["tip"]
                and caught_up["state_root"] == source_snapshot["state_root"]
            ):
                break
            last_fetch_descriptors = workers[offline].send("fetch_descriptors")
            time.sleep(0.15)
        if not (
            caught_up["height"] == source_snapshot["height"]
            and caught_up["tip"] == source_snapshot["tip"]
            and caught_up["state_root"] == source_snapshot["state_root"]
        ):
            pytest.fail(
                "authenticated_http_catchup_mismatch:"
                + json.dumps(
                    {
                        "lagging": caught_up,
                        "source": source_snapshot,
                        "fetch_descriptors": last_fetch_descriptors,
                        "frontier": workers[offline].send("frontier_debug"),
                        "fetch_debug": workers[offline].send("fetch_debug"),
                        "status": workers[offline].send("peer_status"),
                    },
                    sort_keys=True,
                )
            )
        for height in (4, 5, 6):
            assert (
                workers[offline].send("block", height=height)["block_id"]
                == workers[source].send("block", height=height)["block_id"]
            )
    finally:
        for worker in workers.values():
            worker.close()


def test_authenticated_tcp_three_of_four_autonomous_timeout_and_finality(
    tmp_path: Path,
) -> None:
    """Offline scheduled leader: three real peers timeout and finalize unaided.

    The controller seeds only the synthetic transition QC, then stops the view-1
    leader. It does not set a post-transition view, submit a proposal, forward
    a BFT message, inject a local vote, or install a certificate. All subsequent
    timeout, proposal, vote and QC traffic crosses authenticated NetNode TCP.
    """
    pubs, privs = bft._key_material()
    seeded, boundary_id, _ = bft._install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
        seed_emissary_electorate=True,
        seed_authenticated_validator_keys=True,
    )
    for validator, executor in seeded.items():
        with bft._env(bft._prod_env(validator, pub=pubs[validator], priv=privs[validator])):
            executor.mark_clean_shutdown()
    seeded.clear()

    ports = {validator: _free_tcp_port() for validator in bft.VALIDATORS}
    workers: dict[str, _NodeProcess] = {}
    try:
        for validator in bft.VALIDATORS:
            workers[validator] = _NodeProcess(
                tmp_path,
                validator,
                mesh_port=ports[validator],
                mesh_peers=tuple(port for other, port in ports.items() if other != validator),
            )
        all_validators = set(bft.VALIDATORS)

        def identities(status: Json) -> set[str]:
            return {
                str(peer["account_id"])
                for peer in status["peers"]["peers"]
                if peer["connected"]
                and peer["established"]
                and peer["identity_verified"]
                and not peer["banned"]
            }

        handshake_deadline = time.monotonic() + 20
        peer_states: dict[str, Json] = {}
        while time.monotonic() < handshake_deadline:
            peer_states = {
                validator: worker.send("peer_status") for validator, worker in workers.items()
            }
            if all(
                identities(peer_states[validator]) >= all_validators - {validator}
                for validator in bft.VALIDATORS
            ):
                break
            time.sleep(0.1)
        assert all(
            identities(peer_states[validator]) >= all_validators - {validator}
            for validator in bft.VALIDATORS
        ), peer_states
        assert all(
            status["runtime"]["thread_alive"] and not status["runtime"]["unhealthy"]
            for status in peer_states.values()
        )

        # This is the test-owned synthetic bootstrap boundary ONLY.
        transition_votes = [
            worker.send("transition_vote", block_id=boundary_id) for worker in workers.values()
        ]
        collector = workers[bft.VALIDATORS[0]]
        transition_qc: Json | None = None
        for vote in transition_votes:
            formed = collector.send("receive_vote", vote=vote)
            if isinstance(formed, dict):
                transition_qc = formed
        assert isinstance(transition_qc, dict)
        assert transition_qc["block_id"] == boundary_id
        assert all(worker.send("verify_qc", qc=transition_qc) for worker in workers.values())
        for worker in workers.values():
            worker.send("receive_qc", qc=transition_qc)

        # QC(view=0) must itself advance every validator to view=1.
        # No controller set_view call is allowed in the rest of this test.
        assert all(worker.send("frontier_debug")["view"] == 1 for worker in workers.values())
        offline = leader_for_view(bft.VALIDATORS, 1)
        assert offline not in {leader_for_view(bft.VALIDATORS, view) for view in (2, 3, 4)}
        offline_before = workers[offline].send("snapshot")
        assert offline_before["height"] == 1
        workers.pop(offline).close()
        surviving = all_validators - {offline}
        assert set(workers) == surviving

        # Switch on production network ticks; the controller does not produce
        # further consensus artifacts. A real pacemaker timeout (10s default)
        # is necessary to move past the absent leader's view.
        for worker in workers.values():
            enabled = worker.send("enable_autonomous_bft")
            assert enabled == {"enabled": True, "current_view": 1}

        final_snapshots: dict[str, Json] = {}
        liveness_frontiers: dict[str, Json] = {}
        observed_view1_certificates: dict[str, Json] = {}
        deadline = time.monotonic() + 55
        while time.monotonic() < deadline:
            final_snapshots = {
                validator: worker.send("snapshot") for validator, worker in workers.items()
            }
            liveness_frontiers = {
                validator: worker.send("frontier_debug") for validator, worker in workers.items()
            }
            for validator, frontier in liveness_frontiers.items():
                # A later timeout certificate may replace the latest TC after
                # finality. Retain the first independently verified view-1 TC.
                tc = frontier["timeout_certificate"]
                if isinstance(tc, dict) and tc["view"] == 1 and set(tc["signers"]) == surviving:
                    observed_view1_certificates[validator] = tc
            if len(observed_view1_certificates) == len(surviving) and all(
                final_snapshots[validator]["height"] >= 2
                and liveness_frontiers[validator]["view"] >= 5
                for validator in surviving
            ):
                break
            time.sleep(0.15)

        assert all(snap["height"] == 2 for snap in final_snapshots.values()), {
            "snapshots": final_snapshots,
            "frontiers": liveness_frontiers,
        }
        assert len({snap["tip"] for snap in final_snapshots.values()}) == 1
        assert len({snap["state_root"] for snap in final_snapshots.values()}) == 1
        assert all(snap["finalized_block_id"] == snap["tip"] for snap in final_snapshots.values())
        # All survivors have advanced from view 1 to 2 by independently
        # accepting a three-signer timeout certificate; subsequent views 2-4
        # are justified by the genuinely network-certified proposals.
        assert set(observed_view1_certificates) == surviving, {
            "observed_view1_certificates": observed_view1_certificates,
            "frontiers": liveness_frontiers,
        }
        for validator, frontier in liveness_frontiers.items():
            tc = observed_view1_certificates[validator]
            assert tc["view"] == 1
            assert set(tc["signers"]) == surviving
            assert frontier["view"] >= 5, frontier

        for validator, worker in workers.items():
            timeouts = worker.send("sent_timeouts", view=1)
            assert len(timeouts) == 1, {"validator": validator, "timeouts": timeouts}
            assert timeouts[0]["signer"] == validator
            assert timeouts[0]["view"] == 1
            assert worker.send("peer_status")["runtime"]["unhealthy"] is False

        committed = [worker.send("block", height=2) for worker in workers.values()]
        assert len({block["block_id"] for block in committed}) == 1
        assert all(block["all_receipts_ok"] for block in committed)
        assert committed[0]["block_id"] == next(iter(final_snapshots.values()))["tip"]
        assert offline_before["height"] == 1

        # Restore the genuine stopped process from its unchanged SQLite files.
        # The returning node is deliberately one finalized block behind, and
        # peer authentication must not depend on controller-injected QCs/views.
        # Block fetch remains disabled: identity rejoin is NOT chain recovery.
        workers[offline] = _NodeProcess(
            tmp_path,
            offline,
            mesh_port=ports[offline],
            mesh_peers=tuple(port for other, port in ports.items() if other != offline),
        )
        lagging = workers[offline].send("snapshot")
        assert lagging["height"] == offline_before["height"] == 1
        assert lagging["tip"] == offline_before["tip"]
        assert lagging["state_root"] == offline_before["state_root"]

        rejoin_status: Json = {}
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            rejoin_status = workers[offline].send("peer_status")
            if identities(rejoin_status) >= surviving:
                break
            time.sleep(0.1)
        if identities(rejoin_status) < surviving:
            evidence = {
                "offline_handshake": rejoin_status["handshake_context"],
                "offline_counts": rejoin_status["peers"]["counts"],
                "offline_peers": [
                    {
                        key: peer.get(key)
                        for key in (
                            "peer_id",
                            "connected",
                            "established",
                            "identity_verified",
                            "strikes",
                            "banned",
                            "last_error",
                        )
                    }
                    for peer in rejoin_status["peers"]["peers"]
                    if peer["connected"] or peer["strikes"] or peer["banned"]
                ],
                "survivor_handshakes": {
                    validator: worker.send("peer_status")["handshake_context"]
                    for validator, worker in workers.items()
                    if validator != offline
                },
            }
            pytest.fail(json.dumps(evidence, sort_keys=True))
        assert rejoin_status["runtime"]["thread_alive"] is True
        assert rejoin_status["runtime"]["unhealthy"] is False
        # No speculative state was injected and no missing block fetched.
        assert workers[offline].send("snapshot") == lagging
    finally:
        for worker in workers.values():
            worker.close()


if __name__ == "__main__" and len(sys.argv) in (5, 7) and sys.argv[1] == "--worker":
    mesh_port = int(sys.argv[5]) if len(sys.argv) == 7 else 0
    mesh_peers = tuple(int(part) for part in sys.argv[6].split(",") if part) if mesh_port else ()
    _run_worker(
        Path(sys.argv[2]),
        sys.argv[3],
        Path(sys.argv[4]),
        mesh_port=mesh_port,
        mesh_peers=mesh_peers,
    )
