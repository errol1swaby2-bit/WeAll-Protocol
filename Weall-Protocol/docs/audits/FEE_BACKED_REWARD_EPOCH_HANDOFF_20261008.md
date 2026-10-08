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

The reserved pool must be *provisioned and authority-protected* by an independently reviewed activation/genesis procedure before any production deployment. This draft intentionally does **not** invent a production migration, reserve key policy, or new economic-governance authority.

## CI evidence and limitations

The temporary diagnostic step on commit `f4f135f4da7e1604223542f6abff66eb0f6d478e`, GitHub Actions [Backend CI run #37846555276](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37846555276), executed:

```
pytest -q tests/test_fee_backed_reward_epochs.py \
  tests/test_v15_epoch_issuance_scheduler.py \
  tests/test_reward_issuance_invariants.py \
  tests/test_p1_a10_reward_scheduler_scope.py
```

Result: **33 passed**, Ruff changed-file checks passed, and canonical lint passed. The temporary workflow diagnostic was removed afterward. This does **not** establish full backend-suite, multi-node replay, or production readiness.

The v2 spec compiler fails with `transaction semantic-review digest is stale: BLOCK_REWARD_DISTRIBUTE`. This is a **required semantic evidence reconciliation**, not a reason to relax the validator. The compiler checks rows in order; other touched transaction handlers (`FEE_PAY`, `BALANCE_TRANSFER`) may also require semantic-review reconciliation after the first failure is resolved. No review digest was silently changed, no maintainer approval was impersonated, and `independent_review` was not represented as true.

## Explicit future requirements / risk register

- Replace legacy local 20% bucket fallback with the full accepted-work, public-goods, active-group, common-control, reserve, and rotating-remainder contracts before production activation.
- Prove the canonical internal fee pool is provisioned, account-ID-squatting-resistant, inaccessible to human-key authority, and exclusively debited by versioned authorized reward settlement. Audit **all** balance-changing transaction types, not just `FEE_PAY` and `BALANCE_TRANSFER`.
- Bind distributable fees to settled sources, a deterministic epoch cutoff, deduplication, and exact conservation. Handle queued distributions, process restart, competing block proposals, and proposer/follower replay.
- Implement automatic last-member voluntary group dissolution, liability and claim settlement, claim-window finality, and once-only routing of **unencumbered** proceeds into the canonical fee-equivalent revenue pool.
- Reconcile `GRP-206`, `ECO-102`, `ECO-113`, and `ECO-114` with the decided unified subsidy/fee distribution architecture through the appropriate normative and governance process.
- Review the use of a zero-amount `BLOCK_REWARD_MINT` as the required parent of `BLOCK_REWARD_DISTRIBUTE` in the fee-only era; validate canonical transaction ancestry and replay behavior.
- Perform explicit maintainer semantic-contract review and update evidence bindings using the repository's prescribed process, **without claiming an independent review that has not occurred**.
- Run complete backend and web CI, relevant invariant and property suites, deterministic multi-node/restart tests, launch-guard tests, and economic supply-conservation vectors at an exact commit.

## Reviewer decision

**Do not merge or activate** on the basis of the current draft alone. The review must explicitly approve (or reject) the transaction-semantic changes, reconcile v2 contract evidence, and prove the final reward recipient/economic activation gates.
