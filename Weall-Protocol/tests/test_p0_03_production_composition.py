from __future__ import annotations

import contextlib
import copy
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from weall.crypto.sig import sign_signature_for_profile
from weall.crypto.signature_profiles import PQ_MLDSA_V1
from weall.net.messages import BftProposalMsg, MsgType, WireHeader
from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime.bft_hotstuff import (
    CONSENSUS_PHASE_BFT_ACTIVE,
    canonical_proposal_message,
    leader_for_view,
    validator_set_hash,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE, PROTOCOL_VERSION
from weall.runtime.validator_readiness_runner import build_validator_readiness_receipt
from weall.testing.sigtools import deterministic_mldsa_keypair

Json = dict[str, Any]
CHAIN_ID = "p0-03-production-composition"
VALIDATORS = ["@v1", "@v2", "@v3", "@v4"]


@contextlib.contextmanager
def _env(values: dict[str, str]) -> Iterator[None]:
    old = os.environ.copy()
    try:
        for key in list(os.environ):
            if key.startswith("WEALL_"):
                os.environ.pop(key, None)
        os.environ.update({str(k): str(v) for k, v in values.items()})
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def _tx_index_path() -> str:
    return str((Path(__file__).resolve().parents[1] / "generated" / "tx_index.json").resolve())


def _setup_env() -> dict[str, str]:
    return {
        "WEALL_MODE": "testnet",
        "WEALL_SIGVERIFY": "1",
        "WEALL_REQUIRE_VRF": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_NET_LOOP_AUTOSTART": "0",
        "WEALL_MEMPOOL_SELECTION_POLICY": "canonical",
        "WEALL_CHAIN_ID": CHAIN_ID,
    }


def _prod_env(vid: str, *, pub: str, priv: str) -> dict[str, str]:
    return {
        "WEALL_MODE": "prod",
        # This P0 fixture proves production lifecycle/BFT composition with
        # deterministic test keys. A13 independently proves that mainnet
        # cryptographic admission remains closed until ML-DSA is approved.
        "WEALL_CRYPTO_MODE": "closed-testnet",
        "WEALL_NODE_LIFECYCLE_STATE": "production_service",
        "WEALL_SERVICE_ROLES": "node_operator,validator",
        "WEALL_NODE_ROLE": "validator",
        "WEALL_OBSERVER_MODE": "0",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
        "WEALL_BFT_ENABLED": "1",
        "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "0",
        "WEALL_AUTOVOTE": "1",
        "WEALL_SIGVERIFY": "1",
        "WEALL_REQUIRE_VRF": "1",
        "WEALL_UNSAFE_DEV": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
        "WEALL_NET_LOOP_AUTOSTART": "0",
        "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_BOUND_ACCOUNT": vid,
        "WEALL_VALIDATOR_ACCOUNT": vid,
        "WEALL_NODE_ID": vid,
        "WEALL_NODE_PUBKEY": pub,
        "WEALL_NODE_PUBLIC_KEY": pub,
        "WEALL_NODE_PRIVKEY": priv,
        "WEALL_NODE_SIG_PROFILE": PQ_MLDSA_V1,
        "WEALL_CHAIN_ID": CHAIN_ID,
    }


def _paths(root: Path, storage_id: str) -> tuple[Path, Path]:
    safe = storage_id.replace("@", "")
    return root / f"{safe}.sqlite", root / f"{safe}.aux.sqlite"


def _make_executor(
    root: Path,
    storage_id: str,
    *,
    node_id: str | None = None,
) -> WeAllExecutor:
    db, aux = _paths(root, storage_id)
    return WeAllExecutor(
        db_path=str(db),
        aux_db_path=str(aux),
        node_id=str(node_id or storage_id),
        chain_id=CHAIN_ID,
        tx_index_path=_tx_index_path(),
    )


def _key_material() -> tuple[dict[str, str], dict[str, str]]:
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in VALIDATORS:
        pub, sk = deterministic_mldsa_keypair(label=f"p0-03:{vid}")
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    return pubs, privs


def _lifecycle_state(
    ex: WeAllExecutor,
    *,
    pubs: dict[str, str],
    include_transition_bridge: bool,
) -> Json:
    state = copy.deepcopy(ex.read_state())
    state["chain_id"] = CHAIN_ID
    state["height"] = 0
    state["tip"] = ""
    state["tip_hash"] = ""
    state["tip_ts_ms"] = 0
    state["last_block_ts_ms"] = 0
    state["time"] = 0
    state["blocks"] = {}
    state["finalized"] = {"height": 0, "block_id": ""}
    state["system_queue"] = []
    state["bft"] = {}
    state.setdefault("params", {})["chain_id"] = CHAIN_ID
    state["params"]["economics_enabled"] = False

    tx_index_hash = ex.tx_index_hash()
    runtime_hash = PRODUCTION_CONSENSUS_PROFILE.profile_hash()
    accounts = state.setdefault("accounts", {})
    roles = state.setdefault("roles", {})
    node_ops = roles.setdefault("node_operators", {})
    node_ops["active_set"] = list(VALIDATORS)
    node_ops_by_id = node_ops.setdefault("by_id", {})
    role_validators = roles.setdefault("validators", {})
    role_validators["active_set"] = list(VALIDATORS)
    role_validators_by_id = role_validators.setdefault("by_id", {})

    validators_root = state.setdefault("validators", {})
    validator_registry = validators_root.setdefault("registry", {})
    consensus = state.setdefault("consensus", {})
    consensus_validators = consensus.setdefault("validators", {})
    consensus_registry = consensus_validators.setdefault("registry", {})

    for vid in VALIDATORS:
        pub = pubs[vid]
        receipt = build_validator_readiness_receipt(
            account_id=vid,
            node_pubkey=pub,
            bft_pubkey=pub,
            chain_id=CHAIN_ID,
            schema_version="1",
            protocol_version=PROTOCOL_VERSION,
            manifest_hash="55" * 32,
            tx_index_hash=tx_index_hash,
            runtime_profile_hash=runtime_hash,
            readiness_expires_height=10_000,
        )
        accounts[vid] = {
            "nonce": 0,
            "poh_tier": 2,
            "reputation": "10.000",
            "reputation_milli": 10_000,
            "banned": False,
            "locked": False,
            "devices": {
                "by_id": {
                    f"node:{vid}": {
                        "device_id": f"node:{vid}",
                        "device_type": "node",
                        "label": "P0-03 production validator",
                        "pubkey": pub,
                        "active": True,
                        "revoked": False,
                    }
                }
            },
        }
        validator_resp = {
            "opted_in": True,
            "active": True,
            "readiness_status": "verified",
            "reputation_required_milli": 5_000,
            "reputation_actual_milli": 10_000,
            "node_pubkey": pub,
            "bft_pubkey": pub,
            "chain_id": CHAIN_ID,
            "schema_version": "1",
            "protocol_version": PROTOCOL_VERSION,
            "manifest_hash": receipt["manifest_hash"],
            "tx_index_hash": receipt["tx_index_hash"],
            "runtime_profile_hash": receipt["runtime_profile_hash"],
            "readiness_checks": receipt["readiness_checks"],
            "readiness_receipt_hash": receipt["readiness_receipt_hash"],
            "readiness_expires_height": receipt["readiness_expires_height"],
        }
        node_ops_by_id[vid] = {
            "enrolled": True,
            "active": True,
            "status": "active",
            "responsibilities": {
                "validator": validator_resp,
                "storage": {
                    "opted_in": False,
                    "active": False,
                    "declared_capacity_bytes": 0,
                    "proven_capacity_bytes": 0,
                    "allocated_capacity_bytes": 0,
                    "proof_status": "not_requested",
                },
            },
        }
        role_validators_by_id[vid] = {
            "active": True,
            "node_pubkey": pub,
            "readiness_receipt_hash": receipt["readiness_receipt_hash"],
        }
        validator_registry[vid] = {
            "account_id": vid,
            "account": vid,
            "pubkey": pub,
            "status": "active",
            "active": True,
            "sig_profile": PQ_MLDSA_V1,
        }
        consensus_registry[vid] = {
            "account_id": vid,
            "pubkey": pub,
            "status": "active",
            "sig_profile": PQ_MLDSA_V1,
        }

    vhash = validator_set_hash(VALIDATORS)
    validator_set: Json = {
        "epoch": 1,
        "active_set": list(VALIDATORS),
        "set_hash": vhash,
    }
    if include_transition_bridge:
        validator_set["transition_bridge"] = {
            "schema": "weall.validator-set-transition.v1",
            "rule": "new_set_qc_over_canonical_boundary",
            "boundary_height": 1,
            "transition_view": 0,
            "from_validator_epoch": 0,
            "from_validator_set_hash": "",
            "to_validator_epoch": 1,
            "to_validator_set_hash": vhash,
        }
    consensus["validator_set"] = validator_set
    consensus["phase"] = {"current": CONSENSUS_PHASE_BFT_ACTIVE, "history": []}
    consensus["epochs"] = {"current": 1, "events": []}
    return state


def _install_height_zero_prod_node(
    root: Path,
    vid: str,
    *,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> WeAllExecutor:
    with _env(_setup_env()):
        seed = _make_executor(root, f"height-zero-{vid}", node_id=vid)
        seed.state = _lifecycle_state(seed, pubs=pubs, include_transition_bridge=False)
        seed._ledger_store.write(seed.state)
        seed.mark_clean_shutdown()
    with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
        node = _make_executor(root, f"height-zero-{vid}", node_id=vid)
        assert int(node.state.get("height") or 0) == 0
        assert node._current_consensus_phase() == CONSENSUS_PHASE_BFT_ACTIVE
        assert node._active_validators() == VALIDATORS
        assert node._validator_signing_permitted() is True
        return node


def _install_prod_boundary(
    root: Path,
    *,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> tuple[dict[str, WeAllExecutor], str, str]:
    with _env(_setup_env()):
        template_seed = _make_executor(root, "template-seed", node_id="bootstrap-boundary")
        canonical = _lifecycle_state(
            template_seed,
            pubs=pubs,
            include_transition_bridge=True,
        )

    boundary_id = ""
    boundary_hash = ""
    for vid in VALIDATORS:
        with _env(_setup_env()):
            seed = _make_executor(root, vid, node_id="bootstrap-boundary")
            seed.state = copy.deepcopy(canonical)
            seed._ledger_store.write(seed.state)
            block, new_state, applied, invalid, err = seed.build_block_candidate(
                max_txs=0,
                allow_empty=True,
                force_ts_ms=1,
            )
            assert err == ""
            assert isinstance(block, dict)
            assert isinstance(new_state, dict)
            committed = seed.commit_block_candidate(
                block=block,
                new_state=new_state,
                applied_ids=applied,
                invalid_ids=invalid,
            )
            assert committed.ok, committed.error
            if not boundary_id:
                boundary_id = str(block["block_id"])
                boundary_hash = str(block["block_hash"])
            else:
                assert str(block["block_id"]) == boundary_id
                assert str(block["block_hash"]) == boundary_hash
            seed.mark_clean_shutdown()

    assert boundary_id and boundary_hash
    nodes: dict[str, WeAllExecutor] = {}
    for vid in VALIDATORS:
        with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            node = _make_executor(root, vid, node_id=vid)
            assert int(node.state.get("height") or 0) == 1
            assert str(node.state.get("tip") or "") == boundary_id
            assert str(node.state.get("tip_hash") or "") == boundary_hash
            assert node._current_consensus_phase() == CONSENSUS_PHASE_BFT_ACTIVE
            assert node._active_validators() == VALIDATORS
            assert node._validator_signing_permitted() is True
            nodes[vid] = node
    return nodes, boundary_id, boundary_hash


def _form_qc(
    collector: WeAllExecutor,
    collector_id: str,
    votes: list[Json],
    *,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> Json:
    qc: Json | None = None
    with _env(_prod_env(collector_id, pub=pubs[collector_id], priv=privs[collector_id])):
        for vote in votes:
            formed = collector.bft_on_vote(copy.deepcopy(vote))
            if isinstance(formed, dict):
                qc = formed
    assert isinstance(qc, dict) and qc
    return qc


def _broadcast_qc(
    nodes: dict[str, WeAllExecutor],
    qc: Json,
    *,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> None:
    for vid, node in nodes.items():
        with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            node.bft_on_qc(copy.deepcopy(qc))


def _prepare_transition_qc(
    nodes: dict[str, WeAllExecutor],
    *,
    boundary_id: str,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> Json:
    transition_votes: list[Json] = []
    for vid, node in nodes.items():
        with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            assert node.bft_leader_propose(max_txs=0) is None
            pending = node.bft_pending_outbound_messages()
        matches = [
            dict(item["payload"])
            for item in pending
            if str(item.get("kind") or "") == "vote"
            and isinstance(item.get("payload"), dict)
            and str(item["payload"].get("block_id") or "") == boundary_id
            and int(item["payload"].get("view") or 0) == 0
        ]
        assert len(matches) == 1
        transition_votes.append(matches[0])

    collector_id = VALIDATORS[0]
    qc0 = _form_qc(
        nodes[collector_id],
        collector_id,
        transition_votes,
        pubs=pubs,
        privs=privs,
    )
    assert str(qc0["block_id"]) == boundary_id
    assert int(qc0["validator_epoch"]) == 1
    assert str(qc0["validator_set_hash"]) == validator_set_hash(VALIDATORS)
    _broadcast_qc(nodes, qc0, pubs=pubs, privs=privs)
    return qc0


def _propose(
    nodes: dict[str, WeAllExecutor],
    *,
    view: int,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> tuple[str, Json]:
    leader = leader_for_view(VALIDATORS, view)
    for vid, node in nodes.items():
        with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            node.bft_set_view(view)
    with _env(_prod_env(leader, pub=pubs[leader], priv=privs[leader])):
        proposal = nodes[leader].bft_leader_propose(max_txs=0)
    assert isinstance(proposal, dict) and proposal
    return leader, proposal


def _follower_votes(
    nodes: dict[str, WeAllExecutor],
    proposal: Json,
    *,
    leader: str,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> list[Json]:
    votes: list[Json] = []
    for vid, node in nodes.items():
        if vid == leader:
            continue
        with _env(_prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            vote = node.bft_on_proposal(copy.deepcopy(proposal))
        assert isinstance(vote, dict) and vote, f"follower {vid} rejected proposal"
        votes.append(vote)
    assert len(votes) == 3
    return votes


def _signed_wrong_parent(
    node: WeAllExecutor,
    leader: str,
    *,
    view: int,
    justify_qc: Json,
    pubs: dict[str, str],
    privs: dict[str, str],
) -> Json:
    with _env(_prod_env(leader, pub=pubs[leader], priv=privs[leader])):
        block, _st2, _ids, _bad, err = node.build_block_candidate(
            max_txs=0,
            allow_empty=True,
            bft_justify_qc=copy.deepcopy(justify_qc),
            proposer=leader,
            base_state=copy.deepcopy(node.state),
        )
    assert err == "" and isinstance(block, dict)
    epoch = node._current_validator_epoch()
    vhash = node._current_validator_set_hash()
    block["justify_qc"] = copy.deepcopy(justify_qc)
    block["validator_epoch"] = int(epoch)
    block["validator_set_hash"] = vhash
    block["chain_id"] = CHAIN_ID
    block["view"] = int(view)
    block["proposer"] = leader
    block["consensus_phase"] = CONSENSUS_PHASE_BFT_ACTIVE
    msg = canonical_proposal_message(
        chain_id=CHAIN_ID,
        view=int(view),
        block_id=str(block["block_id"]),
        block_hash=str(block["block_hash"]),
        parent_id=str(block.get("prev_block_id") or ""),
        proposer=leader,
        validator_epoch=int(epoch),
        validator_set_hash=vhash,
        justify_qc_id=str(justify_qc.get("block_id") or ""),
        sig_profile=PQ_MLDSA_V1,
    )
    sig = sign_signature_for_profile(
        sig_profile=PQ_MLDSA_V1,
        message=msg,
        privkey=privs[leader],
        encoding="hex",
    )
    block["sig_profile"] = PQ_MLDSA_V1
    block["proposer_pubkey"] = pubs[leader]
    block["proposer_sig_profile"] = PQ_MLDSA_V1
    block["proposer_sig"] = sig
    block["proposer_signature"] = {
        "alg": "ML-DSA",
        "pubkey": pubs[leader],
        "sig_profile": PQ_MLDSA_V1,
        "sig": sig,
    }
    block["signature"] = {
        "alg": "ML-DSA",
        "pubkey": pubs[leader],
        "sig_profile": PQ_MLDSA_V1,
        "sig": sig,
        "role": "bft_proposer_signature",
    }
    return block


def test_prod_bft_active_height_zero_never_uses_qcless_shortcut(tmp_path: Path) -> None:
    pubs, privs = _key_material()
    leader = leader_for_view(VALIDATORS, 0)
    node = _install_height_zero_prod_node(
        tmp_path,
        leader,
        pubs=pubs,
        privs=privs,
    )
    with _env(_prod_env(leader, pub=pubs[leader], priv=privs[leader])):
        node.bft_set_view(0)
        assert node._validator_signing_permitted() is True
        assert node.bft_leader_propose(max_txs=0) is None


def test_four_validator_prod_three_chain_restart_delayed_qc_and_wrong_parent_rejection(
    tmp_path: Path,
) -> None:
    pubs, privs = _key_material()
    nodes, boundary_id, _boundary_hash = _install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
    )

    qc0 = _prepare_transition_qc(
        nodes,
        boundary_id=boundary_id,
        pubs=pubs,
        privs=privs,
    )
    assert str(qc0["block_id"]) == boundary_id

    leader1, b1 = _propose(nodes, view=1, pubs=pubs, privs=privs)
    assert b1["prev_block_id"] == boundary_id
    assert b1["justify_qc"]["block_id"] == boundary_id
    votes1 = _follower_votes(nodes, b1, leader=leader1, pubs=pubs, privs=privs)
    qc1 = _form_qc(nodes[leader1], leader1, votes1, pubs=pubs, privs=privs)
    _broadcast_qc(nodes, qc1, pubs=pubs, privs=privs)
    assert all(str(node.state.get("tip") or "") == boundary_id for node in nodes.values())

    leader2 = leader_for_view(VALIDATORS, 2)
    with _env(_prod_env(leader2, pub=pubs[leader2], priv=privs[leader2])):
        nodes[leader2].mark_clean_shutdown()
        nodes[leader2] = _make_executor(tmp_path, leader2, node_id=leader2)
        assert nodes[leader2]._validator_signing_permitted() is True
        assert nodes[leader2]._bft.high_qc is not None
        assert str(nodes[leader2]._bft.high_qc.block_id) == str(b1["block_id"])

    leader2_actual, b2 = _propose(nodes, view=2, pubs=pubs, privs=privs)
    assert leader2_actual == leader2
    assert b2["prev_block_id"] == b1["block_id"]
    assert b2["justify_qc"]["block_id"] == b1["block_id"]

    wrong = _signed_wrong_parent(
        nodes[leader2],
        leader2,
        view=2,
        justify_qc=qc1,
        pubs=pubs,
        privs=privs,
    )
    assert wrong["prev_block_id"] == boundary_id
    assert wrong["justify_qc"]["block_id"] == b1["block_id"]
    victim = next(v for v in VALIDATORS if v != leader2)
    with _env(_prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        assert nodes[victim].bft_on_proposal(copy.deepcopy(wrong)) is None
    b1_id = str(b1["block_id"])
    assert nodes[victim]._is_conflicted_block_id(b1_id) is False
    assert b1_id in nodes[victim]._bft_speculative_blocks_map()

    votes2 = _follower_votes(nodes, b2, leader=leader2, pubs=pubs, privs=privs)
    qc2 = _form_qc(nodes[leader2], leader2, votes2, pubs=pubs, privs=privs)
    _broadcast_qc(nodes, qc2, pubs=pubs, privs=privs)

    leader3, b3 = _propose(nodes, view=3, pubs=pubs, privs=privs)
    assert b3["prev_block_id"] == b2["block_id"]
    assert b3["justify_qc"]["block_id"] == b2["block_id"]
    votes3 = _follower_votes(nodes, b3, leader=leader3, pubs=pubs, privs=privs)
    qc3 = _form_qc(nodes[leader3], leader3, votes3, pubs=pubs, privs=privs)
    _broadcast_qc(nodes, qc3, pubs=pubs, privs=privs)

    for node in nodes.values():
        assert str(node._bft.finalized_block_id or "") == str(b1["block_id"])
        assert str(node.state.get("tip") or "") == str(b1["block_id"])
        assert int(node.state.get("height") or 0) == 2

    before = {
        vid: (
            int(node._bft.high_qc.view if node._bft.high_qc is not None else -1),
            str(node._bft.finalized_block_id or ""),
            str(node.state.get("tip") or ""),
        )
        for vid, node in nodes.items()
    }
    _broadcast_qc(nodes, qc1, pubs=pubs, privs=privs)
    after = {
        vid: (
            int(node._bft.high_qc.view if node._bft.high_qc is not None else -1),
            str(node._bft.finalized_block_id or ""),
            str(node.state.get("tip") or ""),
        )
        for vid, node in nodes.items()
    }
    assert after == before



def test_prod_bft_proposal_ingress_routes_real_signed_proposal_to_follower(
    tmp_path: Path,
) -> None:
    """A05-F004: exercise the real P2P proposal ingress adapter in prod mode."""

    pubs, privs = _key_material()
    nodes, boundary_id, _boundary_hash = _install_prod_boundary(
        tmp_path,
        pubs=pubs,
        privs=privs,
    )
    _prepare_transition_qc(
        nodes,
        boundary_id=boundary_id,
        pubs=pubs,
        privs=privs,
    )

    leader, proposal = _propose(nodes, view=1, pubs=pubs, privs=privs)
    follower_id = next(vid for vid in VALIDATORS if vid != leader)
    follower = nodes[follower_id]

    with _env(_prod_env(follower_id, pub=pubs[follower_id], priv=privs[follower_id])):
        loop = NetMeshLoop(
            executor=follower,
            mempool=object(),
            cfg=NetLoopConfig(
                enabled=False,
                bind_host="127.0.0.1",
                bind_port=30303,
                tick_ms=25,
                schema_version="1",
            ),
        )
        loop.node = None
        loop._bft_enabled = True
        msg = BftProposalMsg(
            header=WireHeader(
                type=MsgType.BFT_PROPOSAL,
                chain_id=CHAIN_ID,
                schema_version="1",
                tx_index_hash=follower.tx_index_hash(),
            ),
            view=int(proposal["view"]),
            proposer=leader,
            block=copy.deepcopy(proposal),
            justify_qc=copy.deepcopy(proposal["justify_qc"]),
        )

        assert loop._on_bft_proposal(leader, msg) is True

    assert follower.bft_artifact_was_accepted(
        "proposal",
        {
            "view": int(proposal["view"]),
            "proposer": leader,
            "block": proposal,
            "justify_qc": proposal["justify_qc"],
        },
    )
