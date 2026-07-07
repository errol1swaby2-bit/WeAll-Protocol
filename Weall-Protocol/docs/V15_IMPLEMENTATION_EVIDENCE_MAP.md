# WeAll v1.5 implementation evidence map

Status: public-readiness evidence map, not a public launch claim.

This document synchronizes the v1.5 implementation evidence after the first two alignment batches and the public-readiness guardrail batch.

## Resolved alignment drift

| Area | Current evidence | Status | Truth boundary |
|---|---|---|---|
| Epoch issuance tokenomics | `src/weall/ledger/issuance.py`, `src/weall/ledger/tokenomics.py`, `src/weall/runtime/apply/rewards.py`, `tests/test_real_tokenomics_policy.py`, `tests/test_reward_issuance_invariants.py`, `tests/test_v15_epoch_issuance_scheduler.py` | Resolved as locked implementation | Live economics is still disabled unless the existing governance activation path proves activation and future legal/economic gates are satisfied. |
| Runtime block timing | `configs/prod.chain.json`, `configs/testnet.chain.json`, `src/weall/runtime/chain_config.py`, `tests/test_v15_runtime_config_alignment.py` | Resolved | 20-second runtime timing does not prove public multi-validator BFT. |
| API contract inventory | `generated/api_contract_map_v1_5.json`, `scripts/gen_api_contract_map.py`, `specs/api_contracts/v1_5_route_metadata.json`, `tests/test_api_contract_map_v15.py` | Hardened audit artifact | Sensitive session, PoH, WebRTC, relay, and observer routes now require explicit metadata; runtime route tests remain authoritative. |
| Failure-code registry | `generated/failure_code_registry_v1_5.json`, `scripts/gen_failure_code_registry_v1_5.py` | New reviewer artifact | Source-derived registry only; exact route responses remain governed by runtime tests. |
| State-root vector pack | `generated/state_root_vectors_v1_5.json`, `scripts/gen_state_root_vectors_v1_5.py` | Expanded reviewer artifact | Vectors document canonicalization and representative domain fixtures; they do not prove public BFT readiness. |
| Tokenomics simulation | `generated/tokenomics_simulation_v1_5.json`, `scripts/gen_tokenomics_simulation_v1_5.py` | Expanded locked-economics artifact | Live economics, rewards, treasury spend, transfers, and fee markets remain disabled. |
| Public validator preflight matrix | `generated/public_validator_bft_preflight_matrix_v1_5.json`, `scripts/gen_public_validator_bft_preflight_matrix_v1_5.py` | New preflight artifact | This is a plan/checklist, not proof that public validators are ready. |
| Launch-disabled matrix | `src/weall/runtime/launch_matrix.py`, `generated/launch_disabled_matrix_v1_5.json`, `docs/LAUNCH_DISABLED_FEATURE_MATRIX.md` | New guardrail | Matrix prevents overclaims and drift; apply/admission code remains authority. |
| Protocol upgrade truth boundary | `src/weall/runtime/apply/protocol.py`, `docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md` | Hardened record-only status | No automatic patch/application/migration/rollback exists yet. |
| Legal/compliance posture | `docs/legal/*` | Draft pack added | Non-lawyer, counsel-review-pending posture only. |
| Public validator/BFT proof | `docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md` | Proof plan added | Public multi-validator BFT readiness is not claimed. |
| Batch 582-586 proof pack | `generated/b582_b586_readiness_truth_and_proof_v1_5.json`, `scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py`, `tests/test_readiness_truth_and_proof.py` | New audit-truth/proof artifact | Refreshes gap-register truth, PoH operator route metadata, storage durability rehearsal, anti-Sybil review lifecycle proof, and helper equivalence corpus while preserving all public-beta/live-economics/public-validator/helper-production prohibitions. |
| Batch 587-594 testnet mechanism completion | `generated/b587_b594_testnet_mechanism_completion_v1_5.json`, `generated/api_response_vectors_v1_5.json`, `src/weall/runtime/testnet_capabilities.py`, `scripts/rehearse_protocol_upgrade_signed_staging_b589_v1_5.py`, `scripts/rehearse_external_multimachine_validator_harness_b590_v1_5.py`, `scripts/rehearse_multimachine_storage_ipfs_durability_b591_v1_5.py`, `scripts/rehearse_reviewer_accountability_appeal_b592_v1_5.py`, `scripts/rehearse_helper_block_path_adversarial_b593_v1_5.py`, `scripts/rehearse_locked_economics_adversarial_expansion_b594_v1_5.py`, `tests/test_testnet_mechanism_coverage.py` | New controlled-testnet mechanism pack | Completes the remaining controlled-testnet mechanism scaffolds and gates, but public beta readiness still requires external go-gate evidence; no live economics, public validator readiness, automatic upgrades, production helper execution, or legal/compliance approval is claimed. |
| Batch 595 controlled-testnet go-gate evidence manifest | `generated/controlled_testnet_go_gate_v1_5.json`, `scripts/run_controlled_testnet_go_gate_v1_5.py`, `tests/test_controlled_testnet_go_gate.py` | New final go-gate manifest/runner | Captures the deterministic controlled-testnet go-gate evidence surface and commands for full pytest, artifact freshness, validator/storage/capability snapshots, while still keeping public beta, live economics, public validators, automatic upgrades, and production helpers unclaimed. |

## Remaining P0/P1 gaps

The machine-readable register is `generated/v15_implementation_gap_register.json`.

Priority remaining gates:

1. Run `scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked` and attach the runtime report to the controlled testnet evidence bundle.
2. Compare the API response vector pack against broader live TestClient/OpenAPI schemas and external route transcripts before public beta.
3. Capture frontend/API release evidence showing launch-matrix capability flags block every high-risk public claim surface.
4. Extend signed protocol-upgrade staging into deterministic migration/rollback vectors and multi-node staged-rollout rehearsal before enabling any upgrade execution.
5. Complete counsel review of legal/compliance docs before public token/governance claims.
6. Run the external multi-machine validator harness with independent operators, real network transport, churn, equivocation, partition/rejoin, restart/replay, cold state sync, and incident evidence.
7. Validate the existing state-root vector pack across external machines/cross-implementation fixtures before public beta.
8. Run external locked-economics review covering reward farming, concentration, wallet/read-model posture, treasury capture, and governance go/no-go evidence before any live economics activation.
9. Run storage/IPFS durability against real multi-machine operator daemons before public decentralized media claims.
10. Extend reviewer accountability and anti-Sybil appeal hardening into live reviewer operations without claiming complete Sybil resistance.
11. Run helper block-path adversarial rehearsals through real multi-node proposal/replay paths while keeping production helper execution disabled.

## Claims allowed from this evidence map

Allowed:

- private/local rehearsal implementation;
- external-observer readiness work in progress;
- locked tokenomics with v1.5 epoch issuance policy;
- 20-second runtime block timing alignment;
- public-readiness evidence/gap artifacts added.

Not allowed yet:

- public mainnet readiness;
- public multi-validator BFT readiness;
- live economics;
- automatic protocol upgrades;
- legal/compliance approval;
- production helper execution;
- complete public beta readiness.
