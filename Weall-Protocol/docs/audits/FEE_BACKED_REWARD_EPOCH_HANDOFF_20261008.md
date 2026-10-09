# Fee-backed reward epoch implementation — draft handoff (2026-10-08)

Status: **DRAFT; LOCAL/DEV COMPATIBILITY PATH ONLY; NOT PRODUCTION-READY**.

Related: [PR #48](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/48). Issue #47 concerns a separate group-scope governance architecture and is **not** fee-reward issue closure.

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

## Epoch funding and replay focused verification

The four additional cases in `tests/test_fee_backed_reward_epochs.py` cover:

- A genuine fee-bearing `BALANCE_TRANSFER` deposits its fee into the state-committed internal pool without changing issuance or losing total balance.
- A user fee receipt sent to an arbitrary noncanonical account does not become reward revenue merely by being labeled a fee.
- A fee arriving after an epoch's payout has been queued remains available for the next issuance epoch rather than silently altering the prior reward commitment.
- Two independently copied ledger states process identical fee-only mint and distribution transitions to equal resulting states, balances, and monetary-policy records.

[Backend CI run #37858947707](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37858947707) verified **56 focused tests passed in 10.80 seconds**, Ruff checks passed, and canonical lint passed. The temporary CI testing step was removed afterward. The unchanged v2 compiler correctly rejects the still-unapproved `ACCOUNT_REGISTER` semantic digest, so this is not a green full-backend CI result.

These fixtures are a *single-process deterministic dual-state replay check*, **not** a full network, BFT, crash/restart, reorganization, or archival-history replay proof. An exact-commit multi-node test and a formal review of every value-moving path remain required before activation.

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

## Secondary reward-path reserve containment (additional draft remediation)

Source review identified other balance-changing reward transaction handlers that
could move the activated `FEE_REWARD_POOL` without the canonical
`BLOCK_REWARD_DISTRIBUTE` source checks:

- `CREATOR_REWARD_ALLOCATE` and `TREASURY_REWARD_ALLOCATE` use the
  shared `_apply_transfers_and_debits` path, which formerly allowed
  fee-reserve credits or debits.
- `FORFEITURE_APPLY` could debit the same reserve without distributing
  the proceeds through the fee-backed epoch mechanism.

These paths now fail closed for the reserved account **only when the exact
state-committed v1 contract is enabled**. The shared allocation path checks
both directions before any account-balance changes. Unactivated legacy
histories retain the prior behavior. Six new focused test cases cover the
secondary paths and the historical compatibility behavior.

**Exact-commit diagnostic:** [Backend CI run #37860903825](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37860903825)
on diagnostic commit `a2a08d43cbfc337fe47aa850375e1b342ff71e45`
passed **62 focused tests in 8.36 seconds**, including the six new
cases. The run also passed changed-file Ruff, dependency audit, and
canonical lint. Its unchanged generated-artifact phase rejected
`ACCOUNT_REGISTER` because the old transaction-semantic review digest
is stale. This does not validate the full backend suite, prove network
replay, or approve contract semantics. Both temporary CI diagnostic steps
were removed in commit `b36de3c2d3aa729951b8ead388a9314ea9e9858d`;
the permanent `.github/workflows/backend-ci.yml` blob was restored
bit-for-bit to its prediagnostic SHA `e1090406588e1ecf148382f227263f5fdd43573c`.

**Additional semantic-review obligations:** This source change affects
`CREATOR_REWARD_ALLOCATE`, `TREASURY_REWARD_ALLOCATE`, and
`FORFEITURE_APPLY`, in addition to the four previously enumerated contract
candidates. Their accepted semantic-review digests must be re-evaluated using
the read-only compiler-derived scanner. This is **not** an acceptance or
independent sign-off. The earlier four-candidate diagnostic and 56-test run
predate this additional change; they cannot be cited as validation of it.
The full runtime and multi-node checks remain pending.

## Activated secondary allocation atomicity and seven-contract review inventory

An additional source audit found that the shared `_apply_transfers_and_debits`
handler credited recipients before completing debit/funding checks, allowing
partially changed account balances on failed direct handler invocation. Both
`CREATOR_REWARD_ALLOCATE` and `TREASURY_REWARD_ALLOCATE` use this handler.
The new **activated v1 only** branch now:

- Validates recipient/source account existence, positive exact-integer
  amounts, and nonnegative integer account balances before any account write.
- Aggregates repeated debits per source so they cannot overdraw the same
  pre-existing balance in parts.
- Requires sum of recipient credits to equal sum of funding debits.
- Refuses to use incoming credits in the same allocation as available
  pre-existing debit funding.
- Applies only the resulting deterministic net balances after all checks pass;
  the internal fee reserve remains excluded by the prior two-way guard.
- Leaves the legacy unactivated processing path unchanged.

Eight parameterized tests cover the two allocation types against aggregate
insufficiency, unequal funding, valid conserved transfers, and boolean amounts.
These are direct-handler state tests, not a network consensus proof; source
review and further execution/rollback tests remain necessary.

The **read-only** `report_pending_tx_semantic_reviews.py` now includes all
seven affected transaction contracts, with deterministic/non-mutation testing:

`ACCOUNT_REGISTER`, `BALANCE_TRANSFER`, `BLOCK_REWARD_DISTRIBUTE`,
`CREATOR_REWARD_ALLOCATE`, `FEE_PAY`, `FORFEITURE_APPLY`,
`TREASURY_REWARD_ALLOCATE`.

GitHub Actions [Backend CI diagnostic #37861729728](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37861729728)
at exact source/test diagnostic commit
`909892e7bdca4a782f79a5b367e94eade364ed78` reported:

- **70 focused tests passed in 8.21 seconds**, including the eight new
  parameterized atomicity and strict-amount cases.
- Changed-file Ruff, dependency audit, and canonical lint passed.
- Compiler-derived candidates **differ from accepted digests for all seven
  transaction types** and remain `PENDING_MAINTAINER_REVIEW`.
- The generated-artifact phase still correctly rejects the existing
  `ACCOUNT_REGISTER` stale accepted digest. Backend CI is **not green**.

The temporary CI step was removed in commit
`5730e5f119de0a960e51c6c7f9e05b61d490a575`; the checked-in backend CI
workflow returned to its exact original blob
`e1090406588e1ecf148382f227263f5fdd43573c`.

The candidate inventory is diagnostic only. **None of these seven changes
has been accepted, signed off independently, or promoted to the normative
production activation contract.** Do not alter accepted hashes just to pass
CI. Remaining release blockers include full backend and multi-node validation,
formal conservation review, final reward allocation policy, and governed
migration/replay planning.

## Activated distribution strict decoding and seven-contract review packet

Further source audit found that `BLOCK_REWARD_DISTRIBUTE` previously used
permissive row parsing: malformed or non-positive rows could be discarded, and
booleans/floats/number strings could be coerced to integer coin amounts.
Those rules do not provide an unambiguous amount contract for an activated
fee-backed epoch.

With the exact state-committed v1 fee-pool contract enabled, the applier now
requires explicit nonempty debit and credit row lists, string account IDs,
**positive exact-integer** amounts, and existing, valid nonnegative-integer
funding balances. An absent funding account is rejected before mutation,
instead of being implicitly created during failed preflight. The normalized
funding whitelist, strict fee-reserve identity, and equal-debits/credits
checks continue to apply. Unactivated chain replay retains the old decoding.

Thirteen additional focused tests cover malformed credits/debits, fractions,
booleans, string amounts, empty/missing lists, missing mint funding,
malformed mint balance and a specific legacy fractional-row case.

**Exact diagnostic evidence:** [Backend CI #37868004651](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37868004651)
on source/test/temporary-workflow commit
`68313a582aeccda6c215ef58a02580a927c2d92c` recorded
**83 focused tests passed in 11.27 seconds**, with successful
changed-file Ruff, dependency audit and canonical lint. The same run
printed all seven compiler-derived semantic candidates as
`PENDING_MAINTAINER_REVIEW` with changed digests.

The workflow's final status was **cancelled/superseded** by subsequent PR
documentation changes; its generated-artifact phase log still recorded the
existing stale `ACCOUNT_REGISTER` digest failure. This is **not** a
green full backend job, full suite, or network consensus test. The temporary
diagnostic step was removed in commit
`82c302b48846ed94a76bb05c7cb636f0a6790cd4`, restoring the
original CI workflow blob `e1090406588e1ecf148382f227263f5fdd43573c`.

The separate
[seven-contract review matrix](FEE_REWARD_EIGHT_CONTRACT_REVIEW_MATRIX_20261008.md)
maps every changed transaction to the tested boundary and the outstanding
authority, conservation and replay questions. Its contents are diagnostic
review preparation, **not** maintainer acceptance or independent sign-off.
Full end-to-end validation, governed activation-height migrations, and
final production reward allocation remain unclosed.

## Payout recipient integrity and queue-bound snapshot replay

A further source review found a remaining strictness mismatch on the
**activated** `BLOCK_REWARD_DISTRIBUTE` path: debit-account balances
had exact nonnegative-integer validation, but the existing recipient balance
was still converted via `_as_int`. A malformed recipient balance could thus
be truncated or defaulted, undermining total-supply conservation even when
the explicitly listed funding debits equal new payout credits.

The activated v1 handler now preflights recipient account balances as
exact nonnegative integers **before** mutating any funding account. Existing
unactivated-chain semantics remain unchanged. Five parameterized tests cover
boolean, string, fractional, negative and missing recipient balances; they
assert failure with no account-balance writes.

Three additional tests exercise the **actual system queue and binding helpers**
rather than only direct-applier synthetic reward envelopes:

- A fee-only issuance-boundary emission creates the zero-subsidy mint and
  fee-backed distribution, passes canonical queue binding, and can be
  applied identically to two independently copied ledger snapshots without
  changing issued supply or losing existing-supply fees.
- An attempt to change the emitted fee amount without matching the queued
  payload is rejected by the system queue binding check.
- Persisted un-emitted reward queue items already due at committed height
  fail the queue recovery integrity check, rather than silently skipping
  the reward epoch.

**Verified diagnostic run:** [Backend CI #37868678896](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37868678896)
at exact code/test/temporary-workflow commit
`7119d87ebfe565a988daa47da69d53b3da060834` recorded
**103 focused tests passed in 10.44 seconds**, including the eight new
cases and existing queue-security test modules. Changed-file Ruff,
dependency audit, and canonical lint passed. The read-only compiler-derived
report confirmed all seven changed semantic candidates still differ from
accepted records. The backend job **failed at the existing stale
`ACCOUNT_REGISTER` semantic-review digest**, not at these focused tests.

The temporary diagnostic workflow step was removed in
`3dcf3fcd7c68fe831aadf011430177a74128467c`;
the permanent workflow was restored bit-for-bit to original blob
`e1090406588e1ecf148382f227263f5fdd43573c`.

**Limits:** These are in-process queued-envelope validation and
deterministic copied-snapshot replay tests. They do *not* prove a real
network of independently starting BFT validators, proposer/follower
historical-chain sync, archival replay across an activation-height
migration, crash/journal rollback under process failure, or a normative
production reward allocation. None of the seven changed semantic
contracts has been accepted or independently audited.

## Strict activated fee/transfer monetary inputs and balances

Source review found that `FEE_PAY` and `BALANCE_TRANSFER` still relied on
permissive `_as_int` conversions in activated v1 fee-pool states. These can
silently truncate fractional amounts, turn booleans into coin amounts, or
coerce malformed payer/recipient balances. `FEE_PAY` also permitted a
positive self-directed payment: it left the source balance unchanged while
recording a positive fee receipt. Without an explicit signer, direct fee
handling could use a payload-provided source account.

The new **activated v1 only** checks:

- `FEE_PAY`: require a nonempty signer; require an exact integer amount
  (zero remains permitted for preexisting zero-fee receipt compatibility);
  reject positive self-destination payments; require existing payer and
  recipient balances to be exact nonnegative integers **before** writing
  either balance. The already-enforced canonical pool identity remains
  required when fees are deposited into that pool.
- `BALANCE_TRANSFER`: require an exact positive integer amount; if
  `transfer_fee_int` is configured, require a nonnegative exact integer
  policy value; validate existing payer/recipient/fee-sink balances before
  debit/credit writes. The activated fee-pool destination/source ban and
  separate sink ownership checks remain enforced.
- **Unactivated chains retain their historical amount conversion behavior.**
  This PR does not retroactively change legacy replay semantics.

34 additional focused cases in `tests/test_fee_backed_reward_epochs.py`
cover coerced amount types, malformed payer/sink balances, invalid policy
fees, a forged self-pay fee receipt, missing signer and unactivated replay
compatibility. This is still a bounded direct-handler check, **not** a proof
that every consensus path or wallet schema enforces the same input boundary.

[Backend CI diagnostic #37869370863](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37869370863)
on exact source/test/temporary-workflow commit
`404019cb5eb566736b8dcafbb06caf0da6bdb141` reported
**137 focused tests passed in 9.28 seconds**, with changed-file Ruff,
dependency audit and canon lint successful. The read-only compiler-derived
inventory still reported **all seven** transaction semantic review digests
stale. The full backend job remains **red** at the unchanged
`ACCOUNT_REGISTER` review acceptance gate, not because the focused tests
failed. No semantic-review digest or review approval was changed.

Temporary CI instrumentation was removed in commit
`81ef02f29ea1ec75acaa9604716e6fbec455ac4a`. The committed
`.github/workflows/backend-ci.yml` blob returned to the exact baseline
`e1090406588e1ecf148382f227263f5fdd43573c`.

**Still open:** Positive `FEE_PAY` with an explicitly chosen alternate
noncanonical recipient is accepted by the current contract, but those
receipts do *not* fund the fee pool. Whether such use should be prohibited
or be differentiated in canonical admission/accounting is a normative
policy question and has not been silently changed here. Full value-moving
path review, independently witnessed supply accounting, historical
activation-height replay, and final production allocation remain pending.

## Activated mint integrity and corrected eight-contract review scope

The minted-supply code path also needed explicit activated-contract controls.
Previously, the scheduler used permissive integer coercion of `issued`, allowing
a malformed counter to be interpreted as zero. The `BLOCK_REWARD_MINT`
applier could also normalize malformed `amount` and issuance-policy fields,
or implicitly create/coerce the mint funding pool after already recording
issuance. These are independent risks to recorded monetary conservation.

The new **activated v1 only** behavior:

- The scheduler refuses missing monetary-policy records, invalid exact-integer
  `issued` counters, out-of-range counters, and noncanonical `max_supply`
  fields **before** enqueueing reward-mint or reward-distribution work.
- The mint applier requires an exact nonnegative-integer amount; for a new
  positive mint it validates the existing exact-integer monetary-policy
  counter/cap and the pre-existing mint-pool account/balance before writing
  issuance records or adding supply.
- Zero-subsidy fee-only epochs remain valid without a positive mint-pool
  credit, and historical unactivated chains retain prior amount coercion.
- Direct-handler checks are not substitute evidence for authenticated
  consensus queue ancestry, reorg handling, rollback safety, final governed
  production reward allocation, or independent economic review.

[Backend CI diagnostic #37870208267](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37870208267)
at exact source/test/temporary-CI head
`59863c1d62c458f1549a7ad40f8d7c68fbf5f947` reported
**165 focused tests passed in 11.24 seconds**, including 28 additional
malformed-issuance/policy/mint-pool and legacy-replay cases. Changed-file
Ruff, dependency audit, and canon lint passed. The main Backend CI job still
fails the deliberately unchanged first stale semantic-review acceptance
digest `ACCOUNT_REGISTER`. The temporary diagnostic step was removed in
commit `792997c0d8ecf5e7e127c800491f7940c4cea782` and baseline workflow
blob `e1090406588e1ecf148382f227263f5fdd43573c` was restored.

**Review inventory correction:** The previous chronological evidence sections
reported seven changed transaction contracts. Explicit activated
`BLOCK_REWARD_MINT` behavior also requires semantic adjudication. We added
it to the *read-only* compiler-derived candidate reporter, without changing
accepted review records. [Backend CI inventory #37870513713](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37870513713)
at `b6385ed7cc1e3a971e41025ba5e2965054db79ab` recorded
**132 focused tests passed in 9.86 seconds** and **eight** differing
candidate digests, all `PENDING_MAINTAINER_REVIEW`.
The original workflow was again restored in
`455b0b7ffe54935c273f99cb2d97a720a133d956`.
The corrected current review scope is **eight**:
`ACCOUNT_REGISTER`, `BALANCE_TRANSFER`, `BLOCK_REWARD_DISTRIBUTE`,
`BLOCK_REWARD_MINT`, `CREATOR_REWARD_ALLOCATE`, `FEE_PAY`,
`FORFEITURE_APPLY`, and `TREASURY_REWARD_ALLOCATE`.

See the [current eight-contract review matrix](FEE_REWARD_EIGHT_CONTRACT_REVIEW_MATRIX_20261008.md).
No candidate has been accepted or independently signed off. Do not cosmetically
update accepted digests or merge/activate this draft.

## Activated duplicate reward replay identity

A replay audit found that an existing `block_id` caused
`BLOCK_REWARD_MINT` or `BLOCK_REWARD_DISTRIBUTE` to return a successful
deduplication receipt without comparing the new payload against the original
committed transaction. On activated fee-pool states, this could present a
misleading receipt for a different amount, epoch, or recipient/funding plan
despite no additional balance movement.

The activated mint and distribution handlers now reject a reused ID with a
different recorded payload using
`reward_mint_duplicate_payload_mismatch` or
`reward_distribution_duplicate_payload_mismatch`. Exact duplicate payloads
still dedupe without re-minting/re-distributing; unactivated historical
ledgers retain their existing behavior.

At the formatted diagnostic source/test commit
`b4a787cdde154ad583e42b7f7c675fcadf34c0c6`,
[Backend CI #37871383594](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/37871383594)
reported **176 focused tests passed in 11.54 seconds**, including 11 new
parameterized/individual duplicate-replay cases. Changed-file Ruff,
dependency audit and canon lint passed. The eight compiler-derived semantic
candidates **still differ** from accepted records; full backend CI remains
red on the deliberately unchanged first `ACCOUNT_REGISTER` accepted
review digest. The temporary workflow diagnostic was removed in
`951f50215074522e60773313d95b559828a4d42c`, restoring the exact
permanent workflow blob
`e1090406588e1ecf148382f227263f5fdd43573c`.

**Still pending:** transaction queue authentication, complete BFT historical
replay, restart/reorg behavior, per-epoch unique settlement authority and
cross-contract source/finality review. These direct-applier checks alone
do not certify those properties.

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
