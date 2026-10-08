# Fee-backed reward epoch implementation — draft handoff (2026-10-08)

Status: **DRAFT; LOCAL/DEV COMPATIBILITY PATH ONLY; NOT PRODUCTION-READY**.

Related: [PR #48](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/48), [Issue #47](https://github.com/errol1swaby2-bit/WeAll-Protocol/issues/47).

Base: `main` at `111066c475a7f4b60317419bbfa30f9122cd7932`. This document describes the draft PR implementation; it is **not** a change to the full-scope v2 normative specification or an independent audit.

## Purpose and boundaries

The intended lifecycle uses the *same* five-bucket reward distribution for newly issued epoch subsidy and already-existing protocol fee revenue, including after subsidy exhaustion. Validly settled dissolved-group treasury proceeds should become fee-equivalent revenue in the **future** final architecture, after dissolution obligations and claims are resolved.

This draft only demonstrates source-backed **fee-only and mixed subsidy/fee reward epochs** on noncanonical local/dev chain IDs. The existing production/public-testnet chain guard `FINAL_REWARD_ALLOCATION_REQUIRED_CHAIN_IDS` is **unchanged**: the legacy fallback allocation remains disallowed on `weall-prod` and `weall-testnet-v1`.

## Implemented

1. Dedicated internal `FEE_REWARD_POOL_ACCOUNT_ID` constant (`FEE_REWARD_POOL`).
2. When `params.fee_sink_account` explicitly equals that account ID, the nonproduction epoch scheduler reads the pool's existing nonnegative integer balance. An absent or malformed configured pool fails closed.
3. The scheduler continues emitting a zero-amount `BLOCK_REWARD_MINT` lineage receipt with positive fee revenue and zero subsidy. The actual reward distribution debits the fee pool; minting remains exactly zero.
4. With both sources present, minted subsidy is debited from `MINT_POOL` and fee revenue from `FEE_REWARD_POOL`, without treating fee receipts themselves as spendable funding.
5. Ordinary `BALANCE_TRANSFER` into or out of the reserved pool and `FEE_PAY` originating there are rejected. Direct `FEE_PAY` into the reserved pool requires explicit canonical fee-sink configuration.
6. `BLOCK_REWARD_DISTRIBUTE` rejects debits exceeding explicit payout credits. The existing opposite-direction check and atomic preflight remain in place.
7. `ACCOUNT_REGISTER` refuses the reserved fee-pool ID; fee collection and reward scheduling require an account marked `account_type=system` and `system_role=fee_reward_pool` with no human key/recovery/session authority and a nonnegative integer balance.
8. `BLOCK_REWARD_DISTRIBUTE` allows funding debits only from explicitly recognized internal reward sources, verifies canonical fee-pool configuration and authority, and prevents credits back into internal funding pools.

The reserved pool must be *provisioned and authority-protected* by an independently reviewed activation/genesis procedure before any production deployment. This draft intentionally does **not** invent a production migration, reserve key policy, or new economic-governance authority.

## CI evidence and limitations

The temporary diagnostic step on commit `f4f135f4da7e1604223542f6abff66eb0f6d478e`, GitHub Actions [Backend CI run #37846555276](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37846555276), executed:

```
pytest -q tests/test_fee_backed_reward_epochs.py \
  tests/test_v15_epoch_issuance_scheduler.py \
  tests/test_reward_issuance_invariants.py \
  tests/test_p1_a10_reward_scheduler_scope.py
```

Initial phase: **33 passed** on Backend CI #37846555276. After the fee-pool authority hardening and additional adversarial tests, [Backend CI #37849761283](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37849761283) confirmed **44 passed** in the same focused matrix; Ruff changed-file checks and canonical lint also passed. The temporary workflow diagnostic was removed afterward. This does **not** establish full backend-suite, multi-node replay, or production readiness.

The v2 spec compiler rejects stale semantic-review digests. After the reserved-identity change, the earliest rejected binding is `ACCOUNT_REGISTER`; the previously established `BLOCK_REWARD_DISTRIBUTE` change and touched `FEE_PAY`/`BALANCE_TRANSFER` behaviors also require fresh contract review. The compiler checks rows in order. This is a **required semantic evidence reconciliation**, not a reason to relax the validator. No review digest was silently changed, no maintainer approval was impersonated, and `independent_review` was not represented as true.

## Explicit future requirements / risk register

- Replace legacy local 20% bucket fallback with the full accepted-work, public-goods, active-group, common-control, reserve, and rotating-remainder contracts before production activation.
- The draft now rejects direct registration of the fee-pool ID, refuses key-bearing/mistyped pools, limits reward debit sources, and prohibits internal-pool payout recipients. **Still pending:** prove deterministic genesis/migration provisioning, activation-height-gated historical replay compatibility for the reserved-ID change, and that every other account/balance mutation path preserves internal-account authority. Audit **all** balance-changing transaction types, not just `FEE_PAY` and `BALANCE_TRANSFER`.
- Bind distributable fees to settled sources, a deterministic epoch cutoff, deduplication, and exact conservation. Handle queued distributions, process restart, competing block proposals, and proposer/follower replay.
- Implement automatic last-member voluntary group dissolution, liability and claim settlement, claim-window finality, and once-only routing of **unencumbered** proceeds into the canonical fee-equivalent revenue pool.
- Reconcile `GRP-206`, `ECO-102`, `ECO-113`, and `ECO-114` with the decided unified subsidy/fee distribution architecture through the appropriate normative and governance process.
- Review the use of a zero-amount `BLOCK_REWARD_MINT` as the required parent of `BLOCK_REWARD_DISTRIBUTE` in the fee-only era; validate canonical transaction ancestry and replay behavior.
- Perform explicit maintainer semantic-contract review and update evidence bindings using the repository's prescribed process, **without claiming an independent review that has not occurred**.
- Run complete backend and web CI, relevant invariant and property suites, deterministic multi-node/restart tests, launch-guard tests, and economic supply-conservation vectors at an exact commit.

## Reviewer decision

**Do not merge or activate** on the basis of the current draft alone. The review must explicitly approve (or reject) the transaction-semantic changes, reconcile v2 contract evidence, and prove the final reward recipient/economic activation gates.
