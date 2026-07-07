#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator

from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_BFT_ACTIVE, quorum_threshold
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import build_sample_chain
from weall.testing.sigtools import deterministic_mldsa_keypair

VALIDATORS = ["v1", "v2", "v3", "v4"]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _keys() -> tuple[dict[str, str], dict[str, str]]:
    pubs: dict[str, str] = {}
    privs: dict[str, str] = {}
    for vid in VALIDATORS:
        pub, sk = deterministic_mldsa_keypair(label=f"batch539-{vid}")
        pubs[vid] = pub
        privs[vid] = sk.private_bytes_raw().hex()
    return pubs, privs


@contextlib.contextmanager
def _node_env(validator: str, pubs: dict[str, str], privs: dict[str, str]) -> Iterator[None]:
    old = os.environ.copy()
    os.environ.update(
        {
            "WEALL_MODE": "testnet",
            "WEALL_BFT_ENABLED": "1",
            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",
            "WEALL_AUTOVOTE": "1",
            "WEALL_SIGVERIFY": "0",
            "WEALL_UNSAFE_DEV": "1",
            "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
            "WEALL_NODE_ROLE": "validator",
            "WEALL_PRODUCE_EMPTY_BLOCKS": "1",
            "WEALL_VALIDATOR_ACCOUNT": validator,
            "WEALL_NODE_PUBKEY": pubs[validator],
            "WEALL_NODE_PRIVKEY": privs[validator],
        }
    )
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def _seed_validator_set(ex: WeAllExecutor, pubs: dict[str, str]) -> None:
    st = ex.state
    st.setdefault("roles", {}).setdefault("validators", {})["active_set"] = list(VALIDATORS)
    c = st.setdefault("consensus", {})
    reg = c.setdefault("validators", {}).setdefault("registry", {})
    for vid in VALIDATORS:
        rec = reg.setdefault(vid, {})
        rec["pubkey"] = pubs[vid]
        rec["status"] = "active"
    c.setdefault("validator_set", {})["active_set"] = list(VALIDATORS)
    c["validator_set"]["epoch"] = 7
    c.setdefault("phase", {})["current"] = CONSENSUS_PHASE_BFT_ACTIVE
    c["validator_set"]["set_hash"] = ex._current_validator_set_hash() or ""
    ex._ledger_store.write(st)
    ex.state = ex._ledger_store.read()
    ex._bft.load_from_state(ex.state)


def _make_executor(root: Path, vid: str, pubs: dict[str, str], privs: dict[str, str]) -> WeAllExecutor:
    with _node_env(vid, pubs, privs):
        ex = WeAllExecutor(
            db_path=str(root / f"{vid}.sqlite"),
            node_id=vid,
            chain_id="batch539-production-bft",
            tx_index_path=_tx_index_path(),
        )
    _seed_validator_set(ex, pubs)
    return ex


def run_harness() -> dict[str, Any]:
    pubs, privs = _keys()
    with tempfile.TemporaryDirectory(prefix="weall-b539-production-bft-") as td:
        root = Path(td)
        executors = {vid: _make_executor(root, vid, pubs, privs) for vid in VALIDATORS}
        leader = executors["v1"]

        # Produce a production BFT proposal through WeAllExecutor.bft_leader_propose,
        # which internally builds a real block candidate with block identity,
        # receipts root, state root, mempool policy, BFT epoch, and proposer signature.
        with _node_env("v1", pubs, privs):
            proposal = leader.bft_leader_propose(max_txs=0)
        if not isinstance(proposal, dict):
            raise RuntimeError("proposal_failed")

        votes: list[dict[str, Any]] = []
        for vid in VALIDATORS:
            with _node_env(vid, pubs, privs):
                vote = executors[vid].bft_make_vote_for_block(
                    view=int(proposal.get("view") or 0),
                    block_id=str(proposal.get("block_id") or ""),
                    block_hash=str(proposal.get("block_hash") or ""),
                    parent_id=str(proposal.get("prev_block_id") or ""),
                )
            if isinstance(vote, dict):
                votes.append(vote)

        qc = None
        with _node_env("v1", pubs, privs):
            for vote in votes:
                candidate = leader.bft_handle_vote(vote)
                if candidate is not None:
                    qc = candidate
        if qc is None:
            raise RuntimeError("qc_not_formed")
        qc_json = qc.to_json()

        # Verify the production block builder/commit/replay path with real
        # SQLite-backed WeAllExecutor instances and actual committed blocks.
        # This is intentionally separate from the BFT vote/QC formation above:
        # one proof covers production BFT artifacts, the other covers production
        # block_builder/block_commit/apply_block replay.
        old_env = os.environ.copy()
        try:
            for key in list(os.environ):
                if key.startswith("WEALL_"):
                    os.environ.pop(key, None)
            os.environ["WEALL_MODE"] = "testnet"
            os.environ["WEALL_REQUIRE_VRF"] = "0"
            os.environ["WEALL_PRODUCE_EMPTY_BLOCKS"] = "1"
            os.environ["WEALL_SIGVERIFY"] = "0"
            replay = build_sample_chain(work_dir=str(root / "production-replay"), chain_id_prefix="batch539")
        finally:
            os.environ.clear()
            os.environ.update(old_env)
        source_manifest = replay.get("source_manifest") if isinstance(replay.get("source_manifest"), dict) else {}
        replay_manifest = replay.get("replay_manifest") if isinstance(replay.get("replay_manifest"), dict) else {}
        raw_roots = {
            "source": str(source_manifest.get("computed_state_root") or ""),
            "replay": str(replay_manifest.get("computed_state_root") or ""),
        }
        roots_match = len(set(raw_roots.values())) == 1
        roots = {
            "source": "matched-local-rehearsal-root" if roots_match else raw_roots["source"],
            "replay": "matched-local-rehearsal-root" if roots_match else raw_roots["replay"],
        }
        db_files = {vid: str((root / f"{vid}.sqlite").name) for vid in VALIDATORS}
        return {
            "ok": bool(qc_json) and bool(replay.get("ok")) and roots_match,
            "batch": "539",
            "production_bft_methods_used": [
                "WeAllExecutor.bft_leader_propose",
                "WeAllExecutor.bft_make_vote_for_block",
                "WeAllExecutor.bft_handle_vote",
                "WeAllExecutor.produce_block",
                "WeAllExecutor.get_block_by_height",
                "WeAllExecutor.apply_block",
            ],
            "proof_endpoint_used": False,
            "validator_count": len(VALIDATORS),
            "quorum_threshold": quorum_threshold(len(VALIDATORS)),
            "proposal_block_id": str(proposal.get("block_id") or ""),
            "proposal_block_hash": "volatile-local-rehearsal-block-hash-normalized",
            "vote_count": len(votes),
            "qc_formed": isinstance(qc_json, dict),
            "production_replay": {
                "ok": bool(replay.get("ok")),
                "height": int(source_manifest.get("height") or 0),
                "issues": list(replay.get("issues") or []),
            },
            "state_roots": roots,
            "state_roots_match": roots_match,
            "volatile_fields_normalized": [
                "production_bft_path.proposal_block_hash",
                "production_bft_path.state_roots.source",
                "production_bft_path.state_roots.replay",
            ],
            "db_files_created": db_files,
            "locked_boundaries": {"public_validators": False, "live_economics": False, "automatic_upgrades": False, "production_helpers": False},
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = run_harness()
    if args.json:
        print(json.dumps(out, sort_keys=True, indent=2))
    else:
        print(json.dumps(out, sort_keys=True))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
