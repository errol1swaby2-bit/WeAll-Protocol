# PR #48 — seven-contract transaction semantic review matrix

**Status: review packet only; NO ACCEPTANCE, SIGN-OFF, INDEPENDENT AUDIT, OR ACTIVATION AUTHORIZATION.**

PR: https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/48

## Review scope and standard

The compiler-derived read-only candidate report (`scripts/report_pending_tx_semantic_reviews.py`) identifies seven changed transaction contracts whose current material differs from their accepted semantic-review digests. This matrix makes the decisions and missing evidence explicit. It is *not* permission to regenerate accepted digests or mark the draft ready.

Review the current source and per-transaction candidate material, then independently verify runtime effects, canonical admission/queue binding, historical replay, source-balance conservation, invalid-input rejection, and authority boundaries. A passing direct-applier unit test establishes only the tested local transition.

| Candidate transaction | Changed contract requiring adjudication | Focused evidence (test module) | Critical unresolved question |
| --- | --- | --- | --- |
| `ACCOUNT_REGISTER` | Activated pool ID cannot be human-registered; legacy replay remains unactivated | `test_human_cannot_register_reserved_system_fee_pool_id`, genesis/version tests | Can any recovery, key rotation, legacy registration, migration, or alternative creation path assign human authority to this reserved ID? |
| `BALANCE_TRANSFER` | Activated ordinary transfers cannot spend from or target pool; native transfer fees credit the canonical sink. Activated amounts, fee policy and account balances now reject lossy numeric coercion | `test_fee_bearing_transfer_funds_pool_without_extra_issuance`, `test_activated_balance_transfer_rejects_invalid_account_balance`, `test_activated_balance_transfer_rejects_invalid_fee_policy`, amount/legacy tests | Have all aliases, debit/fee combinations, signer checks and historical legacy payloads been covered across a governed activation-height migration? |
| `FEE_PAY` | Activated fee-reserve cannot be payer, incoming fees require strict pool ownership; positive payments now require signer, non-self destination, exact integer amount and valid existing balances | `test_real_fee_payment_funds_fee_only_reward_without_issuance`, `test_activated_fee_payment_rejects_coerced_amount_without_account_changes`, `test_activated_fee_payment_rejects_self_destination_without_fake_receipt`, payer/sink/legacy tests | Is an alternate user-selected fee destination permitted by normative policy, and can fee receipts from such destinations mislead any external accounting? |
| `BLOCK_REWARD_DISTRIBUTE` | Activated funding whitelist, fee-reserve identity check, internal funding accounts excluded from recipients, exact credits/debits, strict rows, funding **and recipient** balance validation | `test_fee_only_epoch_mints_zero_and_pays_from_existing_supply`, `test_activated_reward_distribution_rejects_invalid_recipient_balances`, `test_fee_only_reward_queue_emission_and_binding_survive_snapshot_replay`, queue-tamper/recovery tests | Prove minted-source lineage, queued epoch cutoff, double-spend resistance, proposer/follower archival replay and crash/restart including malformed inputs |
| `CREATOR_REWARD_ALLOCATE` | Activated fee-reserve cannot be a source or recipient; aggregate existing-source debit checks, non-coercing amount validation and preflight atomicity | `test_secondary_reward_allocators_cannot_move_activated_fee_pool`, `test_activated_secondary_allocation_is_atomic_on_aggregate_insufficiency`, additional atomicity tests | What source-funding authority allows a system creator allocator to debit non-reserve accounts, and which process proves the system payload was authorized? |
| `TREASURY_REWARD_ALLOCATE` | Same activated reserve and atomic funding boundaries as creator allocator | Shared parameterized secondary-allocation tests | Is treasury allocation restricted to correctly authorized treasury sources and governed allocation decisions, beyond being system-attributed? |
| `FORFEITURE_APPLY` | Activated reserve cannot be burned/forfeited by this other value path | `test_forfeiture_cannot_burn_activated_fee_pool` | Who authorizes forfeiture of any other account; do forfeited coins obey final accounting/burn/recycle policy, and can other mutation paths evade the reserve guard? |

## Evidence already established — bounded

- An earlier source/test diagnostic run, [Backend CI #37861729728](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37861729728), recorded **70 focused tests passed in 8.21 seconds**, plus changed-file Ruff, dependency audit, and canonical lint. These tests preceded the later strict `BLOCK_REWARD_DISTRIBUTE` row-validation change.
- Latest source/test diagnostic [Backend CI #37868678896](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37868678896) on commit `7119d87ebfe565a988daa47da69d53b3da060834`: **103 focused tests passed in 10.44 seconds**, including activated recipient-balance rejection and queue-bound copied-state replay. Ruff, dependency audit, and canon lint passed. Full Backend CI still fails at the intentionally unaccepted `ACCOUNT_REGISTER` review binding. All seven review candidates remain pending; no approvals were asserted.
- Latest activated economics audit diagnostic [Backend CI #37869370863](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37869370863) on exact source/test commit `404019cb5eb566736b8dcafbb06caf0da6bdb141`: **137 focused tests passed in 9.28 seconds**, with Ruff, dependency audit and canon lint passing. New tests cover fee payer and transfer recipient monetary input/balance integrity, signer/self-payment restrictions and unactivated replay. The original workflow has been restored and all seven accepted review digests remain stale; full backend CI remains red at the existing review gate.
- Read-only candidate generation reported each of the seven current candidate digests differs from the accepted digest in that earlier run.
- The compiler gate remains deliberately red on the first stale review record (`ACCOUNT_REGISTER`). This is **not** a full backend suite, historical network replay, external audit, or approval.
- Strict-row and queue/replay diagnostic results are separately documented above by their respective exact source/test commits; do not retroactively attribute later tests to the earlier 70-test diagnostic.

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
