# PR #48 — seven-contract transaction semantic review matrix

**Status: review packet only; NO ACCEPTANCE, SIGN-OFF, INDEPENDENT AUDIT, OR ACTIVATION AUTHORIZATION.**

PR: https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/48

## Review scope and standard

The compiler-derived read-only candidate report (`scripts/report_pending_tx_semantic_reviews.py`) identifies seven changed transaction contracts whose current material differs from their accepted semantic-review digests. This matrix makes the decisions and missing evidence explicit. It is *not* permission to regenerate accepted digests or mark the draft ready.

Review the current source and per-transaction candidate material, then independently verify runtime effects, canonical admission/queue binding, historical replay, source-balance conservation, invalid-input rejection, and authority boundaries. A passing direct-applier unit test establishes only the tested local transition.

| Candidate transaction | Changed contract requiring adjudication | Focused evidence (test module) | Critical unresolved question |
| --- | --- | --- | --- |
| `ACCOUNT_REGISTER` | Activated pool ID cannot be human-registered; legacy replay remains unactivated | `test_human_cannot_register_reserved_system_fee_pool_id`, genesis/version tests | Can any recovery, key rotation, legacy registration, migration, or alternative creation path assign human authority to this reserved ID? |
| `BALANCE_TRANSFER` | Activated ordinary transfers cannot spend from or target pool; native transfer fees can credit the verified canonical sink | `test_user_cannot_spend_from_or_transfer_into_fee_reward_pool`, `test_fee_bearing_transfer_funds_pool_without_extra_issuance` | Have all aliases, debit/fee combinations, signer checks, and historical legacy payloads been covered, including chain activation at a height? |
| `FEE_PAY` | Activated fee-reserve cannot be fee payer; incoming payments validate its strict unkeyed system account | `test_real_fee_payment_funds_fee_only_reward_without_issuance`, `test_untrusted_fee_pool_cannot_receive_fees` | Is an arbitrary user-selected alternate fee destination permitted by the normative fee policy, and can it be misrepresented as protocol revenue elsewhere? |
| `BLOCK_REWARD_DISTRIBUTE` | Activated funding whitelist, fee-reserve identity check, internal funding accounts excluded from recipients, exact credits/debits, stricter row and funding-account validation | `test_fee_only_epoch_mints_zero_and_pays_from_existing_supply`, `test_reward_distribution_rejects_unaccounted_excess_debit_without_mutation`, strict-row tests | Prove minted-source lineage, queued epoch cutoff, double-spend resistance, exact previous balance, proposer/follower equal results and restart/replay including malformed inputs |
| `CREATOR_REWARD_ALLOCATE` | Activated fee-reserve cannot be a source or recipient; aggregate existing-source debit checks, non-coercing amount validation and preflight atomicity | `test_secondary_reward_allocators_cannot_move_activated_fee_pool`, `test_activated_secondary_allocation_is_atomic_on_aggregate_insufficiency`, additional atomicity tests | What source-funding authority allows a system creator allocator to debit non-reserve accounts, and which process proves the system payload was authorized? |
| `TREASURY_REWARD_ALLOCATE` | Same activated reserve and atomic funding boundaries as creator allocator | Shared parameterized secondary-allocation tests | Is treasury allocation restricted to correctly authorized treasury sources and governed allocation decisions, beyond being system-attributed? |
| `FORFEITURE_APPLY` | Activated reserve cannot be burned/forfeited by this other value path | `test_forfeiture_cannot_burn_activated_fee_pool` | Who authorizes forfeiture of any other account; do forfeited coins obey final accounting/burn/recycle policy, and can other mutation paths evade the reserve guard? |

## Evidence already established — bounded

- An earlier source/test diagnostic run, [Backend CI #37861729728](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37861729728), recorded **70 focused tests passed in 8.21 seconds**, plus changed-file Ruff, dependency audit, and canonical lint. These tests preceded the later strict `BLOCK_REWARD_DISTRIBUTE` row-validation change.
- Read-only candidate generation reported each of the seven current candidate digests differs from the accepted digest in that earlier run.
- The compiler gate remains deliberately red on the first stale review record (`ACCOUNT_REGISTER`). This is **not** a full backend suite, historical network replay, external audit, or approval.
- The separately executed newer strict distribution tests and their results, if any, must be documented by an exact source/test commit and workflow evidence. Do not retroactively attribute their results to the earlier 70-test run.

## Required decision procedure for each of seven entries

1. Examine compiler-derived `material_for_review`, the exact code diff, existing canonical specification, activation constraints, all callers and cross-domain value mutation paths.
2. Determine **ACCEPT / REVISE / REJECT** with explicit rationale, exact commits, tests, historical-compatibility consequences, and responsible human reviewer identity. A candidate hash alone is not acceptance.
3. Independently reproduce relevant tests and compare canonical proposer/follower/restart history on old and activated ledgers; validate account balance delta and issuance delta for the same transactions.
4. Only after a real authorized acceptance, use the repository's prescribed review procedure to update that specific accepted digest, disposition, reviewer and timestamp **truthfully**. Preserve gate failures for remaining unresolved candidates.
5. Keep independent review and production activation separate from a maintainer's semantic acceptance. They are still unsatisfied.

## Explicit unclosed cross-contract risks

- Unknown or malformed contract version/sink combinations currently do not satisfy `fee_reward_pool_contract_enabled`; a governed migration must guarantee transition safety and prevent post-activation downgrade or partial configuration. This draft does **not** establish that protocol-wide invariant.
- The scheduler's local/dev legacy 20% allocation and treasury remainder fallback are deliberately not final constitutional economics. Canonical production/public-testnet chain IDs remain guarded.
- Direct-apply balance-conservation assertions do not verify executed block rollback, authenticated system issuance, complete state-root commitment, duplicate/replay handling, or BFT multi-node restart behavior.
- Group dissolution liabilities/claims/proceeds integration and formal full-supply accounting are not implemented here.
- No declaration in this review packet supersedes `specs/v2/source/semantic_reviews.json`, the existing compiler gate, or the normative specification.
