from __future__ import annotations

import copy
import importlib.util
import tempfile
from pathlib import Path

from weall.runtime.bft_hotstuff import qc_from_json


repo_root = Path(__file__).resolve().parents[1]
test_path = repo_root / "Weall-Protocol/tests/test_p0_03_production_composition.py"
spec = importlib.util.spec_from_file_location("p0diag", test_path)
assert spec is not None and spec.loader is not None
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def qc_summary(qc):
    if qc is None:
        return None
    return {
        "view": int(getattr(qc, "view", -1)),
        "block_id": str(getattr(qc, "block_id", "") or ""),
        "parent_id": str(getattr(qc, "parent_id", "") or ""),
    }


def snapshot(node, label, *, b1_id="", b2_id="", b3_id="", wrong_id=""):
    speculative = node._bft_speculative_blocks_map()
    snap = {
        "label": label,
        "tip": str(node.state.get("tip") or ""),
        "height": int(node.state.get("height") or 0),
        "view": int(getattr(node._bft, "view", -1)),
        "last_voted_view": int(getattr(node._bft, "last_voted_view", -1)),
        "finalized_block_id": str(getattr(node._bft, "finalized_block_id", "") or ""),
        "high_qc": qc_summary(getattr(node._bft, "high_qc", None)),
        "locked_qc": qc_summary(getattr(node._bft, "locked_qc", None)),
        "transition_qc": qc_summary(getattr(node._bft, "validator_transition_qc", None)),
        "pending_remote": list(node._pending_remote_blocks.keys()),
        "pending_candidates": list(node._pending_candidates.keys()),
        "pending_missing_qcs": list(node._pending_missing_qcs.keys()),
        "pending_fetches": list(getattr(node, "_pending_missing_fetches", {}).keys()),
        "conflicted_ids": list(node._conflicted_block_ids.keys()),
        "conflicted_hashes": list(node._conflicted_block_hashes.keys()),
        "spec_has_b1": bool(b1_id and b1_id in speculative),
        "spec_has_b2": bool(b2_id and b2_id in speculative),
        "spec_has_b3": bool(b3_id and b3_id in speculative),
        "spec_has_wrong": bool(wrong_id and wrong_id in speculative),
        "pending_b1": bool(b1_id and isinstance(node._bft_pending_block_json(b1_id), dict)),
        "pending_b2": bool(b2_id and isinstance(node._bft_pending_block_json(b2_id), dict)),
    }
    print("P0DIAG_SNAPSHOT", snap, flush=True)


def direct_checks(node, block, label):
    bid = str(block["block_id"])
    with t._env(t._prod_env(node.node_id, pub=pubs[node.node_id], priv=privs[node.node_id])):
        validation_ok = node._validate_remote_proposal_for_vote(copy.deepcopy(block))
    print(f"P0DIAG_{label}_VOTECHECK", validation_ok, flush=True)
    vote_map = dict(node._bft_speculative_blocks_map())
    vote_map[bid] = {
        "height": int(block.get("height") or 0),
        "prev_block_id": str(block.get("prev_block_id") or ""),
        "block_ts_ms": int(block.get("block_ts_ms") or 0),
        "block_hash": str(block.get("block_hash") or ""),
    }
    justify = qc_from_json(block.get("justify_qc")) if isinstance(block.get("justify_qc"), dict) else None
    can_vote = node._bft.can_vote_for(blocks=vote_map, block_id=bid, justify_qc=justify)
    print(f"P0DIAG_{label}_CAN_VOTE", can_vote, flush=True)
    print(f"P0DIAG_{label}_SIGNING_PERMITTED", node._validator_signing_permitted(), flush=True)


pubs, privs = t._key_material()
with tempfile.TemporaryDirectory(prefix="weall-p0diag-") as td:
    tmp_path = Path(td)
    nodes, boundary_id, _boundary_hash = t._install_prod_boundary(tmp_path, pubs=pubs, privs=privs)
    qc0 = t._prepare_transition_qc(nodes, boundary_id=boundary_id, pubs=pubs, privs=privs)
    assert str(qc0["block_id"]) == boundary_id

    leader1, b1 = t._propose(nodes, view=1, pubs=pubs, privs=privs)
    votes1 = t._follower_votes(nodes, b1, leader=leader1, pubs=pubs, privs=privs)
    qc1 = t._form_qc(nodes[leader1], leader1, votes1, pubs=pubs, privs=privs)
    t._broadcast_qc(nodes, qc1, pubs=pubs, privs=privs)

    leader2 = t.leader_for_view(t.VALIDATORS, 2)
    with t._env(t._prod_env(leader2, pub=pubs[leader2], priv=privs[leader2])):
        nodes[leader2].mark_clean_shutdown()
        nodes[leader2] = t._make_executor(tmp_path, leader2, node_id=leader2)

    leader2_actual, b2 = t._propose(nodes, view=2, pubs=pubs, privs=privs)
    assert leader2_actual == leader2
    wrong = t._signed_wrong_parent(
        nodes[leader2],
        leader2,
        view=2,
        justify_qc=qc1,
        pubs=pubs,
        privs=privs,
    )
    victim = next(v for v in t.VALIDATORS if v != leader2)
    node = nodes[victim]
    b1_id = str(b1["block_id"])
    b2_id = str(b2["block_id"])
    wrong_id = str(wrong["block_id"])
    print(
        "P0DIAG_IDS",
        {
            "victim": victim,
            "leader2": leader2,
            "boundary": boundary_id,
            "b1": b1_id,
            "b2": b2_id,
            "wrong": wrong_id,
            "b2_parent": str(b2.get("prev_block_id") or ""),
            "wrong_parent": str(wrong.get("prev_block_id") or ""),
            "qc1_block": str(qc1.get("block_id") or ""),
        },
        flush=True,
    )

    snapshot(node, "before_wrong", b1_id=b1_id, b2_id=b2_id, wrong_id=wrong_id)
    with t._env(t._prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        wrong_vote = node.bft_on_proposal(copy.deepcopy(wrong))
    print("P0DIAG_WRONG_RESULT", wrong_vote, flush=True)
    snapshot(node, "after_wrong", b1_id=b1_id, b2_id=b2_id, wrong_id=wrong_id)

    direct_checks(node, b2, "B2")
    with t._env(t._prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        b2_vote = node.bft_on_proposal(copy.deepcopy(b2))
    print("P0DIAG_B2_RESULT", b2_vote, flush=True)
    assert isinstance(b2_vote, dict) and b2_vote
    snapshot(node, "after_b2", b1_id=b1_id, b2_id=b2_id, wrong_id=wrong_id)

    votes2 = [b2_vote]
    for vid, other in nodes.items():
        if vid in {leader2, victim}:
            continue
        with t._env(t._prod_env(vid, pub=pubs[vid], priv=privs[vid])):
            vote = other.bft_on_proposal(copy.deepcopy(b2))
        assert isinstance(vote, dict) and vote, f"diagnostic follower {vid} rejected B2"
        votes2.append(vote)
    qc2 = t._form_qc(nodes[leader2], leader2, votes2, pubs=pubs, privs=privs)

    snapshot(node, "before_qc2", b1_id=b1_id, b2_id=b2_id, wrong_id=wrong_id)
    t._broadcast_qc(nodes, qc2, pubs=pubs, privs=privs)
    snapshot(node, "after_qc2", b1_id=b1_id, b2_id=b2_id, wrong_id=wrong_id)

    leader3, b3 = t._propose(nodes, view=3, pubs=pubs, privs=privs)
    b3_id = str(b3["block_id"])
    print(
        "P0DIAG_B3_IDS",
        {
            "leader3": leader3,
            "b3": b3_id,
            "b3_parent": str(b3.get("prev_block_id") or ""),
            "qc2_block": str(qc2.get("block_id") or ""),
            "b3_system_txs": [str(tx.get("type") or "") for tx in (b3.get("system_txs") or []) if isinstance(tx, dict)],
        },
        flush=True,
    )
    assert victim != leader3
    snapshot(node, "before_b3", b1_id=b1_id, b2_id=b2_id, b3_id=b3_id, wrong_id=wrong_id)
    chain = node._speculative_chain_to_parent(b2_id)
    print("P0DIAG_B3_PARENT_CHAIN", None if chain is None else [str(x.get("block_id") or "") for x in chain], flush=True)
    parent_state = node._speculative_parent_state(b2_id)
    print(
        "P0DIAG_B3_PARENT_STATE",
        None if not isinstance(parent_state, dict) else {
            "height": int(parent_state.get("height") or 0),
            "tip": str(parent_state.get("tip") or ""),
            "finalized": str(((parent_state.get("consensus") or {}).get("finality") or {}).get("last_finalized_block_id") or ""),
            "epoch": int((((parent_state.get("consensus") or {}).get("epochs") or {}).get("current")) or 0),
        },
        flush=True,
    )
    direct_checks(node, b3, "B3")
    with t._env(t._prod_env(victim, pub=pubs[victim], priv=privs[victim])):
        b3_vote = node.bft_on_proposal(copy.deepcopy(b3))
    print("P0DIAG_B3_RESULT", b3_vote, flush=True)
    snapshot(node, "after_b3", b1_id=b1_id, b2_id=b2_id, b3_id=b3_id, wrong_id=wrong_id)
