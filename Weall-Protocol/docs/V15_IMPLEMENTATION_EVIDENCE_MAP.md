# WeAll v1.5 implementation evidence map

Status: public-readiness evidence map, not a public launch claim.

This document synchronizes the v1.5 implementation evidence after the first two alignment batches and the public-readiness guardrail batch.

## Resolved alignment drift

| Area | Current evidence | Status | Truth boundary |
|---|---|---|---|
| Epoch issuance tokenomics | `src/weall/ledger/issuance.py`, `src/weall/ledger/tokenomics.py`, `src/weall/runtime/apply/rewards.py`, `tests/test_batch481_real_tokenomics_policy.py`, `tests/test_batch485_reward_issuance_invariants.py`, `tests/test_batch491_v15_epoch_issuance_scheduler.py` | Resolved as locked implementation | Live economics is still disabled unless the existing governance activation path proves activation and future legal/economic gates are satisfied. |
| Runtime block timing | `configs/prod.chain.json`, `configs/testnet.chain.json`, `src/weall/runtime/chain_config.py`, `tests/test_batch493_v15_runtime_config_alignment.py` | Resolved | 20-second runtime timing does not prove public multi-validator BFT. |
| API contract inventory | `generated/api_contract_map_v1_5.json`, `scripts/gen_api_contract_map.py`, `tests/test_batch494_api_contract_map_v15.py` | New audit artifact | Static inventory only; runtime route tests remain authoritative. |
| Launch-disabled matrix | `src/weall/runtime/launch_matrix.py`, `generated/launch_disabled_matrix_v1_5.json`, `docs/LAUNCH_DISABLED_FEATURE_MATRIX.md` | New guardrail | Matrix prevents overclaims and drift; apply/admission code remains authority. |
| Protocol upgrade truth boundary | `src/weall/runtime/apply/protocol.py`, `docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md` | Hardened record-only status | No automatic patch/application/migration/rollback exists yet. |
| Legal/compliance posture | `docs/legal/*` | Draft pack added | Non-lawyer, counsel-review-pending posture only. |
| Public validator/BFT proof | `docs/public_validator/PUBLIC_VALIDATOR_BFT_PROOF_PLAN.md` | Proof plan added | Public multi-validator BFT readiness is not claimed. |

## Remaining P0/P1 gaps

The machine-readable register is `generated/v15_implementation_gap_register.json`.

Priority remaining gates:

1. Generate route-level response/error schema vectors from live TestClient responses.
2. Wire launch-matrix capability flags into all relevant public read models.
3. Build signed protocol-upgrade artifact manifest, migration-vector, staged-rollout, and rollback tests before enabling any upgrade delivery.
4. Complete counsel review of legal/compliance docs before public token/governance claims.
5. Run public validator/BFT adversarial proof with multiple external processes, churn, equivocation, partition/rejoin, restart/replay, cold state sync, and incident evidence.
6. Add deterministic state-root vector pack for public reviewers.
7. Add economics simulation pack before any live economics activation.

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
