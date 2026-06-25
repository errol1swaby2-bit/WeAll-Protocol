#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 mechanics-first implementation register.

This artifact is intentionally different from the public-readiness gap register:
it tracks real executable protocol mechanics, proof harnesses, and activation
boundaries for the M-1 through M-10 implementation batches.
"""

import argparse
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "generated" / "v15_mechanics_gap_register.json"

Json = dict[str, Any]

MECHANICS: list[Json] = [
    {
        "id": "M-01",
        "title": "Public multi-validator BFT proof harness",
        "domain": "consensus/bft",
        "status": "partial_mechanic_proof_missing",
        "locked_features": ["public_validator_promotion", "public_multi_validator_bft"],
        "current_files": [
            "src/weall/runtime/bft_hotstuff.py",
            "src/weall/runtime/bft_journal.py",
            "src/weall/runtime/bft_runtime_adapter.py",
            "src/weall/net/net_loop.py",
            "scripts/bft_adversarial_matrix.py",
            "scripts/bft_consensus_resilience_matrix.py",
        ],
        "missing_mechanics": [
            "four independent validator processes reaching matching finalized height and state root",
            "partition/rejoin convergence proof",
            "equivocation rejection evidence captured from the same harness",
            "observer cannot propose, vote, or validate under rehearsal",
        ],
        "acceptance_tests": [
            "scripts/rehearse_mechanics_m1_m10.sh --bft-local",
            "pytest -q tests/test_batch498_mechanics_m1_m10.py",
        ],
        "do_not_cross": ["do not enable public validators", "do not claim public BFT readiness"],
    },
    {
        "id": "M-02",
        "title": "Fresh-node bootstrap and state sync proof",
        "domain": "state-sync/catchup",
        "status": "implemented_mechanic_needs_fresh_node_proof",
        "current_files": [
            "src/weall/net/state_sync.py",
            "src/weall/runtime/block_replay.py",
            "scripts/devnet_sync_from_peer.sh",
            "scripts/devnet_compare_state_roots.sh",
        ],
        "missing_mechanics": [
            "empty database node catches up from a trusted anchor",
            "invalid snapshot and wrong-chain data are rejected",
            "synced node reaches identical state root and tx index hash",
        ],
        "acceptance_tests": ["scripts/rehearse_mechanics_m1_m10.sh --state-sync-live"],
        "do_not_cross": ["do not copy trusted databases as sync proof"],
    },
    {
        "id": "M-03",
        "title": "Validator accountability mechanics",
        "domain": "validator/slashing",
        "status": "non_economic_accountability_added_stake_slashing_locked",
        "current_files": ["src/weall/runtime/apply/consensus.py"],
        "implemented_in_this_batch": [
            "SLASH_EXECUTE mirrors a deterministic non-economic accountability record into validators.registry[account].accountability",
            "accountability record explicitly marks economic_penalty_applied=false and validator_set_mutation_applied=false",
        ],
        "missing_mechanics": [
            "epoch-bound suspension/removal policy after slash quorum",
            "stake or bond penalty mechanics after economics activation",
        ],
        "acceptance_tests": ["pytest -q tests/test_batch498_mechanics_m1_m10.py::test_m03_slash_execute_records_non_economic_validator_accountability"],
        "do_not_cross": ["do not add stake slashing while economics is locked"],
    },
    {
        "id": "M-04",
        "title": "P2P validator networking adversarial rehearsal",
        "domain": "p2p/network",
        "status": "implemented_components_need_multi_process_adversarial_proof",
        "current_files": [
            "src/weall/net/gossip.py",
            "src/weall/net/handshake.py",
            "src/weall/net/messages.py",
            "src/weall/net/peer_identity.py",
            "src/weall/net/relay.py",
            "src/weall/net/net_loop.py",
        ],
        "missing_mechanics": [
            "validator-only BFT message acceptance proof",
            "mempool gossip convergence under reconnect",
            "duplicate/replayed gossip suppression under load",
            "malicious peer backpressure proof",
        ],
        "acceptance_tests": ["scripts/rehearse_mechanics_m1_m10.sh --network-live"],
        "do_not_cross": ["do not treat relay success as validator-network readiness"],
    },
    {
        "id": "M-05",
        "title": "PoH challenge consequences and reverification mechanics",
        "domain": "poh/identity",
        "status": "initial_consequence_added_reverification_missing",
        "current_files": ["src/weall/runtime/apply/poh.py", "src/weall/runtime/poh/state.py"],
        "implemented_in_this_batch": [
            "upheld POH_CHALLENGE_RESOLVE revokes the target account PoH status using revoke_account_poh_status",
            "dismissed challenges record no consequence",
        ],
        "missing_mechanics": [
            "reverification lifecycle after challenge-upheld revocation",
            "reviewer/juror accountability for bad approvals",
            "duplicate-human detection beyond reused proof commitments",
        ],
        "acceptance_tests": ["pytest -q tests/test_batch498_mechanics_m1_m10.py::test_m05_upheld_poh_challenge_revokes_poh_status"],
        "do_not_cross": ["do not claim full one-human-one-account Sybil resistance"],
    },
    {
        "id": "M-06",
        "title": "Dispute appeal and enforcement completion",
        "domain": "disputes/moderation",
        "status": "partial_mechanic_non_content_enforcement_missing",
        "current_files": ["src/weall/runtime/apply/dispute.py", "src/weall/runtime/apply/content.py"],
        "missing_mechanics": [
            "full appeal panel vote/tally/finalize path",
            "non-content enforcement targets",
            "moderator misconduct appeal path",
            "deterministic remedy/reversal mechanics",
        ],
        "acceptance_tests": ["future: tests/test_dispute_appeal_panel_lifecycle.py"],
        "do_not_cross": ["do not silently enforce unsupported target types"],
    },
    {
        "id": "M-07",
        "title": "Governance execution vectors",
        "domain": "governance/execution",
        "status": "local_vector_pack_added_external_rehearsal_remaining",
        "current_files": [
            "src/weall/runtime/apply/governance.py",
            "scripts/gen_governance_execution_vectors_v1_5.py",
            "generated/governance_execution_vectors_v1_5.json",
        ],
        "implemented_in_this_batch": [
            "machine-readable local vector pack covers every governance action type in DEFAULT_GOV_ACTION_ALLOWLIST",
            "failure vectors capture unsupported action, invalid payload, missing explicit electorate, premature execute, and failed-vote execute rejections",
            "conflicting quorum-change vector proves deterministic same-proposal action ordering and last-write result",
            "GOV_QUORUM_SET and GOV_RULES_SET now validate approved action payloads after stripping deterministic system-queue metadata",
        ],
        "missing_mechanics": [
            "external multi-node governance execution vector replay",
            "cross-client governance vector verification",
            "public beta governance operator transcript capture",
        ],
        "acceptance_tests": [
            "python3 scripts/gen_governance_execution_vectors_v1_5.py --check",
            "pytest -q tests/test_governance_execution_vectors_v1_5_batch597.py",
        ],
        "do_not_cross": ["do not allow governance to bypass locked economics"],
    },
    {
        "id": "M-08",
        "title": "Economics activation blockade and simulation",
        "domain": "tokenomics/economics",
        "status": "locked_mechanic_simulation_added_activation_missing",
        "locked_features": ["live_economics", "balance_transfer", "reward_issuance", "treasury_spend"],
        "current_files": [
            "src/weall/runtime/econ_phase.py",
            "src/weall/runtime/apply/economics.py",
            "src/weall/runtime/apply/rewards.py",
            "src/weall/ledger/issuance.py",
            "scripts/gen_tokenomics_simulation_v1_5.py",
        ],
        "missing_mechanics": [
            "activation go/no-go checklist enforced by runtime preconditions",
            "reward concentration/farming resistance vectors",
            "stake/slash economics after validator proof",
        ],
        "acceptance_tests": [
            "python3 scripts/gen_tokenomics_simulation_v1_5.py --check",
            "pytest -q tests/test_batch498_mechanics_m1_m10.py::test_m08_tokenomics_simulation_artifact_keeps_economics_locked_boundary",
        ],
        "do_not_cross": ["do not enable transfers, tips, rewards, or treasury spend"],
    },
    {
        "id": "M-09",
        "title": "Storage/IPFS durability proof",
        "domain": "storage/media",
        "status": "partial_mechanic_durability_proof_missing",
        "current_files": ["src/weall/runtime/apply/storage.py", "src/weall/storage", "src/weall/ipfs"],
        "missing_mechanics": [
            "multi-node pin durability proof",
            "pin target failure detection and reassignment",
            "restricted identity evidence retention/deletion lifecycle",
            "operator accountability for failed storage duty",
        ],
        "acceptance_tests": ["future: scripts/rehearse_storage_replication.sh"],
        "do_not_cross": ["do not claim media durability from CID recording alone"],
    },
    {
        "id": "M-10",
        "title": "Helper/parallel execution proof corpus",
        "domain": "helper/parallel-execution",
        "status": "locked_or_serial_only_until_proven",
        "current_files": [
            "src/weall/runtime/helper_execution.py",
            "src/weall/runtime/helper_receipts.py",
            "src/weall/runtime/conflict_lanes.py",
            "generated/helper_contract_map.json",
        ],
        "missing_mechanics": [
            "serial-vs-helper equivalence across all helper-eligible txs",
            "deterministic lane assignment across nodes",
            "Byzantine helper-output rejection corpus",
            "crash/restart helper replay proof",
        ],
        "acceptance_tests": ["future: tests/test_helper_serial_equivalence_v15.py"],
        "do_not_cross": ["do not claim production helper execution"],
    },
]


def build_payload() -> Json:
    return {
        "schema": "weall.v1_5.mechanics_gap_register",
        "batch": "M-01-through-M-10",
        "truth_boundaries": {
            "public_validators_enabled": False,
            "live_economics_enabled": False,
            "automatic_protocol_upgrade_apply_enabled": False,
            "production_helper_execution_claimed": False,
        },
        "mechanics": MECHANICS,
    }


def write_if_changed(path: Path, data: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    data = json.dumps(build_payload(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not out.exists():
            raise SystemExit(f"missing generated mechanics register: {out}")
        current = out.read_text(encoding="utf-8")
        if current != data:
            raise SystemExit(f"stale generated mechanics register: {out}")
        return 0
    write_if_changed(out, data)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
