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
9. **Fresh local genesis only:** an explicit `WEALL_MODE=dev` and `WEALL_LOCAL_FEE_REWARD_POOL_GENESIS=1` opt-in provisions `FEE_REWARD_POOL` with zero initial balance and no user authority. Genesis commits `fee_sink_account=FEE_REWARD_POOL` and `fee_reward_pool_contract_version=1`. Pinned production/public-testnet chain IDs refuse the opt-in.
10. Authority enforcement and fee-backed scheduling require an exact integer contract version `1` plus the canonical fee sink. Unactivated chains retain their prior account-registration, fee-credit, and reward-transaction replay behavior. This is intentionally **not an in-place state migration**, and it does not activate production allocation.

The reserved pool must be *provisioned and authority-protected* by an independently reviewed activation/genesis procedure before any production deployment. This draft intentionally does **not** invent a production migration, reserve key policy, or new economic-governance authority.

## CI evidence and limitations

The temporary diagnostic step on commit `f4f135f4da7e1604223542f6abff66eb0f6d478e`, GitHub Actions [Backend CI run #37846555276](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37846555276), executed:

```
pytest -q tests/test_fee_backed_reward_epochs.py \
  tests/test_v15_epoch_issuance_scheduler.py \
  tests/test_reward_issuance_invariants.py \
  tests/test_p1_a10_reward_scheduler_scope.py
```

Initial phase: **33 passed** on Backend CI #37846555276. After the fee-pool authority hardening and additional adversarial tests, [Backend CI #37849761283](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37849761283) confirmed **44 passed** in the same focused matrix; Ruff changed-file checks and canonical lint also passed. Following the versioned local genesis and replay-compatibility changes, [Backend CI #37851640027](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37851640027) confirmed **51 passed in 1.82 seconds**, with Ruff changed-file checks and canonical lint also passing. The backend job itself remained red at the unchanged semantic-review digest gate. The temporary workflow diagnostic was removed afterward. This does **not** establish full backend-suite, multi-node replay, or production readiness.

The v2 spec compiler rejects stale semantic-review digests. After the reserved-identity change, the earliest rejected binding is `ACCOUNT_REGISTER`; the previously established `BLOCK_REWARD_DISTRIBUTE` change and touched `FEE_PAY`/`BALANCE_TRANSFER` behaviors also require fresh contract review. The compiler checks rows in order. This is a **required semantic evidence reconciliation**, not a reason to relax the validator. No review digest was silently changed, no maintainer approval was impersonated, and `independent_review` was not represented as true.

## Pending transaction-semantic adjudication

Use the read-only compiler-derived candidate inventory:

```bash
cd Weall-Protocol
python scripts/report_pending_tx_semantic_reviews.py --output /tmp/weall-semantic-review-candidates.json
```

The command uses the *same source scanners, review material, and digest algorithm*
as the v2 compiler. It does not change the accepted review inventory or assert
that a maintainer has approved any candidate. The test
`tests/test_pending_tx_semantic_review_report.py` checks deterministic output
and non-mutation of `semantic_reviews.json`.

CI evidence: [Backend CI run #37857805624](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37857805624) passed **52 focused tests in 10.62 seconds**, including the deterministic diagnostic and the fee-reward tests. Ruff and canonical lint passed. The report confirmed **four candidate digests differ from the accepted records** (`ACCOUNT_REGISTER`, `BALANCE_TRANSFER`, `BLOCK_REWARD_DISTRIBUTE`, `FEE_PAY`). The unchanged compiler correctly failed on the first stale accepted record, `ACCOUNT_REGISTER`. The temporary diagnostic CI step was removed afterward. No new maintainer review acceptance or independent attestation was asserted.

The four transaction contracts requiring a new explicit adjudication are:

| Transaction | Change to review | Security and compatibility evidence required |
| --- | --- | --- |
| `ACCOUNT_REGISTER` | New activated-chain restriction on a reserved protocol revenue account ID | Prove identity collision is impossible under a valid local genesis, and pre-activation history remains replayable |
| `BALANCE_TRANSFER` | Activated-chain block on ordinary incoming/outgoing transfers for the internal revenue pool | Verify current fee transfer paths and unactivated replay, including all fee aliases and economic-lock states |
| `FEE_PAY` | Activated-chain prohibition on fee-pool spending and validation of internal destination ownership | Verify actual debit/credit conservation and transaction attribution, not mere receipt labels |
| `BLOCK_REWARD_DISTRIBUTE` | Source whitelist, internal-recipient prohibition, exact debit accounting after activation, pool-identity checks | Verify no arbitrary user debits, no fee double spend, parent lineage, proposer/follower deterministic replay and source reserve accounting |

**Adjudication process:** The maintainer should review each material row, related
runtime change, targeted regression evidence, and full scope implications.
If accepted, update the corresponding review entry with a newly derived
digest, a truthful reviewer and timestamp, and an explicit description of what
was reviewed. Do not carry forward the prior `reviewer`, `reviewed_at`, or
`disposition` as an assertion that the new material has already been accepted.
An independent review remains a separate unfulfilled launch gate. If a candidate
is rejected or requires changes, keep the compiler rejection and revise the
code or specification; do not adjust the digest to force a green check.

## Explicit future requirements / risk register

- Replace legacy local 20% bucket fallback with the full accepted-work, public-goods, active-group, common-control, reserve, and rotating-remainder contracts before production activation.
- The draft has deterministic **fresh local genesis** provisioning, state-committed v1 activation, an unkeyed strict account profile, new reward authority boundaries, and tests covering unactivated legacy behavior. **Still pending:** governed activation/migration for existing chains, consensus-height cutover and old-block replay across multi-node historical fixtures, and a complete authority audit of every other account/balance mutation path. Audit **all** balance-changing transaction types, not just `FEE_PAY` and `BALANCE_TRANSFER`.
- Bind distributable fees to settled sources, a deterministic epoch cutoff, deduplication, and exact conservation. Handle queued distributions, process restart, competing block proposals, and proposer/follower replay.
- Implement automatic last-member voluntary group dissolution, liability and claim settlement, claim-window finality, and once-only routing of **unencumbered** proceeds into the canonical fee-equivalent revenue pool.
- Reconcile `GRP-206`, `ECO-102`, `ECO-113`, and `ECO-114` with the decided unified subsidy/fee distribution architecture through the appropriate normative and governance process.
- Review the use of a zero-amount `BLOCK_REWARD_MINT` as the required parent of `BLOCK_REWARD_DISTRIBUTE` in the fee-only era; validate canonical transaction ancestry and replay behavior.
- Perform explicit maintainer semantic-contract review and update evidence bindings using the repository's prescribed process, **without claiming an independent review that has not occurred**.
- Run complete backend and web CI, relevant invariant and property suites, deterministic multi-node/restart tests, launch-guard tests, and economic supply-conservation vectors at an exact commit.

## Reviewer decision

**Do not merge or activate** on the basis of the current draft alone. The review must explicitly approve (or reject) the transaction-semantic changes, reconcile v2 contract evidence, and prove the final reward recipient/economic activation gates.
