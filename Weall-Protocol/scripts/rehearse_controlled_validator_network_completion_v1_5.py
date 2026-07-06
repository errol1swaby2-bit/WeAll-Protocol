#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus
from weall.runtime.bft_hotstuff import quorum_threshold, validator_set_hash
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]

VALIDATORS = ["validator-a", "validator-b", "validator-c", "validator-d"]
CHAIN_ID = "weall-v15-b510-validator-completion"


def _env(tx_type: str, *, signer: str = "SYSTEM", nonce: int = 1, payload: Json | None = None, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload or {}, sig="", system=system, parent=parent)


def _base_state() -> Json:
    return {
        "chain_id": CHAIN_ID,
        "height": 1,
        "params": {"chain_id": CHAIN_ID, "enforce_finality_attestations": True},
        "accounts": {v: {"poh_tier": 2, "node_keys": {v: {"active": True}}} for v in VALIDATORS},
        "roles": {"validators": {"active_set": list(VALIDATORS)}},
        "validators": {
            "registry": {v: {"account": v, "status": "active", "active": True, "pubkey": f"mldsa:{v}"} for v in VALIDATORS}
        },
    }


def _attest_quorum(state: Json, *, block_id: str, height: int, voters: list[str]) -> None:
    for i, v in enumerate(voters, start=10):
        apply_consensus(state, _env("BLOCK_ATTEST", signer=v, nonce=i, payload={"block_id": block_id, "height": height, "round": 0, "vote": "yes"}))


def _try_finalize(state: Json, *, block_id: str, height: int) -> str:
    try:
        apply_consensus(state, _env("BLOCK_FINALIZE", signer="SYSTEM", system=True, parent=block_id, nonce=99, payload={"block_id": block_id, "height": height}))
    except ConsensusApplyError as exc:
        return exc.reason
    return "finalized"


def run_harness() -> Json:
    state = _base_state()
    active_start = list(state["roles"]["validators"]["active_set"])
    threshold_start = quorum_threshold(len(active_start))

    apply_consensus(state, _env("BLOCK_PROPOSE", signer="validator-a", nonce=1, payload={"block_id": "block:1", "height": 1, "proposer": "validator-a"}))
    _attest_quorum(state, block_id="block:1", height=1, voters=VALIDATORS[:3])
    finalize_reason = _try_finalize(state, block_id="block:1", height=1)

    partition_state = _base_state()
    apply_consensus(partition_state, _env("BLOCK_PROPOSE", signer="validator-a", nonce=1, payload={"block_id": "block:p", "height": 1, "proposer": "validator-a"}))
    _attest_quorum(partition_state, block_id="block:p", height=1, voters=VALIDATORS[:2])
    partition_reason = _try_finalize(partition_state, block_id="block:p", height=1)

    # Candidate join activates only through an epoch-bound validator-set transition.
    state["accounts"]["validator-e"] = {"poh_tier": 2, "node_keys": {"node-e": {"active": True}}}
    apply_consensus(state, _env("VALIDATOR_CANDIDATE_REGISTER", signer="validator-e", nonce=20, payload={"pubkey": "mldsa:validator-e", "node_id": "node-e", "endpoints": ["tcp://validator-e:9000"]}))
    approve = apply_consensus(state, _env("VALIDATOR_CANDIDATE_APPROVE", signer="SYSTEM", system=True, parent="gov:approve-e", nonce=21, payload={"account": "validator-e", "activate_at_epoch": 1}))
    open_epoch = apply_consensus(state, _env("EPOCH_OPEN", signer="SYSTEM", system=True, nonce=22, payload={"epoch": 1}))
    active_after_join = list(state["roles"]["validators"]["active_set"])

    # Equivocation/accountability path: slash execute queues non-economic suspension;
    # explicit suspension then removes the validator at the next epoch boundary.
    slash = apply_consensus(state, _env("SLASH_EXECUTE", signer="SYSTEM", system=True, parent="slash:validator-a", nonce=30, payload={"slash_id": "slash:validator-a:1", "account": "validator-a", "reason": "equivocation"}))
    suspend = apply_consensus(state, _env("VALIDATOR_SUSPEND", signer="SYSTEM", system=True, parent="slash:validator-a:1", nonce=31, payload={"account": "validator-a", "reason": "equivocation", "effective_epoch": 2}))
    apply_consensus(state, _env("EPOCH_CLOSE", signer="SYSTEM", system=True, nonce=32, payload={"epoch": 1}))
    open_epoch_2 = apply_consensus(state, _env("EPOCH_OPEN", signer="SYSTEM", system=True, nonce=33, payload={"epoch": 2}))
    active_after_slash = list(state["roles"]["validators"]["active_set"])

    root_after = compute_state_root(state)
    restart_roots = [compute_state_root(copy.deepcopy(state)) for _ in range(3)]
    ok = (
        finalize_reason == "finalized"
        and partition_reason == "finality_threshold_not_met"
        and approve.get("status") == "pending_activation"
        and "validator-e" in active_after_join
        and slash.get("consequence", {}).get("economic_penalty_applied") is False
        and suspend.get("status") == "pending_suspension"
        and "validator-a" not in active_after_slash
        and len(set(restart_roots)) == 1
    )
    return {
        "artifact": "b510_controlled_validator_network_completion_v1_5",
        "public_validator_enabled": False,
        "initial_active_set": active_start,
        "initial_threshold": threshold_start,
        "quorum_finalize_result": finalize_reason,
        "minority_partition_finalize_result": partition_reason,
        "candidate_join": {"approve": approve, "epoch_open": open_epoch, "active_after_join": active_after_join},
        "slash_accountability": {"slash": slash, "suspend": suspend, "epoch_open": open_epoch_2, "active_after_slash": active_after_slash},
        "state_root": root_after,
        "restart_roots": restart_roots,
        "validator_set_hash": validator_set_hash(active_after_slash),
        "ok": bool(ok),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
