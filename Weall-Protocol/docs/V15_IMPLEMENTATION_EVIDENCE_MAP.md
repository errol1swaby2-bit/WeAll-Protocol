# WeAll v1.5 implementation evidence map

Status: public-readiness evidence map, not a public launch claim.

This document synchronizes the v1.5 implementation evidence after the first two alignment batches and the public-readiness guardrail batch.

## Resolved alignment drift

| Area | Current evidence | Status | Truth boundary |
|---|---|---|---|
| Epoch issuance tokenomics | `src/weall/ledger/issuance.py`, `src/weall/ledger/tokenomics.py`, `src/weall/runtime/apply/rewards.py`, `tests/test_batch481_real_tokenomics_policy.py`, `tests/test_batch485_reward_issuance_invariants.py`, `tests/test_batch491_v15_epoch_issuance_scheduler.py` | Resolved as locked implementation | Live economics is still disabled unless the existing governance activation path proves activation and future legal/economic gates are satisfied. |
| Runtime block timing | `configs/prod.chain.json`, `configs/testnet.chain.json`, `src/weall/runtime/chain_config.py`, `tests/test_batch493_v15_runtime_config_alignment.py` | Resolved | 20-second runtime timing does not prove public multi-validator BFT. |
| API contract inventory | `generated/api_contract_map_v1_5.json`, `scripts/gen_api_contract_map.py`, `specs/api_contracts/v1_5_route_metadata.json`, `tests/test_batch494_api_contract_map_v15.py` | Hardened audit artifact | Sensitive session, PoH, WebRTC, relay, and observer routes now require explicit metadata; runtime route tests remain authoritative. |
| Failure-code registry | `generated/failure_code_registry_v1_5.json`, `scripts/gen_failure_code_registry_v1_5.py` | New reviewer artifact | Source-derived registry only; exact route responses remain governed by runtime tests. |
| State-root vector pack | `generated/state_root_vectors_v1_5.json`, `scripts/gen_state_root_vectors_v1_5.py` | Expanded reviewer artifact | Vectors document canonicalization and representative domain fixtures; they do not prove public BFT readiness. |
| Tokenomics simulation | `generated/tokenomics_simulation_v1_5.json`, `scripts/gen_tokenomics_simulation_v1_5.py` | Expanded locked-economics artifact | Live economics, rewards, treasury spend, transfers, and fee markets remain disabled. |
| Public validator preflight matrix | `generated/public_validator_bft_preflight_matrix_v1_5.json`, `scripts/gen_public_validator_bft_preflight_matrix_v1_5.py` | New preflight artifact | This is a plan/checklist, not proof that public validators are ready. |
| Launch-disabled matrix | `src/weall/runtime/launch_matrix.py`, `generated/launch_disabled_matrix_v1_5.json`, `docs/LAUNCH_DISABLED_FEATURE_MATRIX.md` | New guardrail | Matrix prevents overclaims and drift; apply/admission code remains authority. |
| Protocol upgrade truth boundary | `src/weall/runtime/apply/protocol.py`, `docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md` | Hardened record-only status | No automatic patch/application/migration/rollback exists yet. |
| Legal/compliance posture | `docs/legal/*` | Draft pack added | Non-lawyer, counsel-review-pending posture only. |
| Public validator/BFT proof | `docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md` | Proof plan added | Public multi-validator BFT readiness is not claimed. |

## Remaining P0/P1 gaps

The machine-readable register is `generated/v15_implementation_gap_register.json`.

Priority remaining gates:

1. Generate route-level response/schema vectors from live TestClient responses for the remaining public surfaces.
2. Wire launch-matrix capability flags into all relevant public read models.
3. Build signed protocol-upgrade artifact manifest, migration-vector, staged-rollout, and rollback tests before enabling any upgrade delivery.
4. Complete counsel review of legal/compliance docs before public token/governance claims.
5. Run public validator/BFT adversarial proof with multiple external processes, churn, equivocation, partition/rejoin, restart/replay, cold state sync, and incident evidence.
6. Expand state-root vectors into external cross-implementation fixtures before public beta.
7. Expand economics simulation from locked policy checks into adversarial reward-farming and concentration analysis before any live economics activation.

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
