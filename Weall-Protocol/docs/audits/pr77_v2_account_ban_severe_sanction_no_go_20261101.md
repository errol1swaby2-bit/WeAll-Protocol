# PR #77 — V2 ACCOUNT_BAN interim severe-sanction no-go

**Status: BLOCKED, not a V2 semantic acceptance, public-beta authorization, or merge approval.**

## Authority and scope

The v2.0 **First Draft** specification (Section 32, `DSP-210`, `SAN-005` and related severe-sanction rules) describes a 25-juror panel with **20 approvals**, followed by a newly sampled appeal panel and completion of the automatic appeal before enforcement; it also describes a limited waiver after delivery of the full reasoned outcome. Those are **target** conditions, not a claim that this repository implements them.

The canonical transaction `TX-0904 / ACCOUNT_BAN` is system-only, receipt-only, with declared `DISPUTE_RESOLVE` parent. The legacy reputation applier previously required the SYSTEM flag but did not independently prove authenticated dispute/appeal authorization. The ordinary dispute action filter already rejects `ACCOUNT_BAN` (Stage 23), so a full authorized producer still needs to be designed.

## Interim change

`src/weall/runtime/apply/reputation.py::_apply_account_ban` now rejects `ACCOUNT_BAN` when **replayable** `meta.constitutional_clock.enabled` is true, with:

- code: `forbidden`
- reason: `severe_sanction_authorization_unimplemented`

The rejection happens before a receipt can mutate the ban or account state. A claimed SYSTEM signer, forged panel counts, asserted appeal finality, or asserted appeal waiver do **not** satisfy the missing authorization contract.

For compatibility, when the constitutional clock is **disabled**, the previous legacy receipt semantics are unchanged. This is **not** proof that legacy-mode SYSTEM receipt provenance is safe: gate activation, historical replay migration, and all alternate entry paths must be separately adjudicated. The interim guard cannot authorize a valid severe sanction; it intentionally blocks such sanctions in constitutional-clock mode.

## Bounded tests and evidence

`tests/test_pr77_severe_sanction_clock_no_go.py` includes:

- Six synthetic refusal tests (three payload forms, each through bounded rollback and deepcopy) asserting rejection, no state mutation, and unchanged candidate state root.
- Two synthetic legacy-mode tests checking the existing account-ban behavior.
- Other prior dispute/receipt tests remain in `test_stage23_account_ban_severe_sanction_no_go.py` and `test_pr73_account_ban_atomic_duplicate.py`.

These tests do **not** prove BFT consensus, network provenance, preserved-chain replay, or constitutional enforcement. They assert only bounded behavior of selected application paths.

The PR77-specific V1.5 evidence refresh GitHub Actions run `41317562729` passed and generated a bot commit `805109867f6e8aa8efc6e40bdf111c7504d87c67` containing only the allowed V1.5 derivatives and test formatting. The V2 review digest was **not** changed.

## Explicit unresolved requirements

1. Determine the authoritative severe-sanction decision record, eligibility, vote finality, fresh juror sampling, appeal quorum, and waiver evidence required by the specification.
2. Implement and verify an authenticated deterministic SYSTEM receipt producer, parent binding, and replay-safe enforcement verifier.
3. Distinguish legacy replay from future activation; establish migration and compatibility with historically valid states before enabling any new consensus rule on a shared network.
4. Reconcile the `TX-0904` semantic-review digest after substantive maintainer adjudication. The compiler is intentionally still expected to report a stale review.
5. Run complete backend, multisystem and clean-clone two-node validation, independent security review where required, and close remaining public-beta blockers.

**Do not merge or launch based on the no-go safeguard.** It is an interim defense, not a substitute for the constitutional producer or complete authorization lifecycle.


## Source-to-queue authority trace (November 1, 2026; not semantic signoff)

The real block path has a deterministic SYSTEM queue boundary. A node's
`system_tx_emitter` emits a `TxEnvelope(system=True)` with the canonical
`_system_queue_id`, `_due_height`, and parent reference from a queue item.
`validate_system_tx_queue_binding` matches that receipt against the
canonical queue's type, hash-bound payload, signer, parent, phase, due
height, and emission height. The block builder and follower replay each
call this validator; the public admission entrypoint prohibits SYSTEM
traffic. These are **execution provenance** constraints.

But `enqueue_system_tx` is deliberately a general internal scheduler:
its queue ID commits to the queued fields, **not to a constitutional
judgment**. A test can enqueue an `ACCOUNT_BAN` with a synthetic parent
reference and receive an exactly queue-bound emitted envelope. The
queue signature/hash does not by itself establish a source-backed
`DISPUTE_RESOLVE`, 25 independently eligible jurors, 20 recorded
approvals, a fresh appeal panel, valid appeal finality, or a lawful
post-outcome waiver.

The default governance action allowlist does not include
`ACCOUNT_BAN`, and ordinary dispute enforcement explicitly rejects
ban actions. Neither fact is proof that every possible future dynamic
configuration or direct internal producer is safe. A legitimate
constitutional severe-sanction producer remains **unverified**.

New source-bound regression
`tests/test_pr77_account_ban_queue_provenance.py` checks:
- An intact, actually emitted `ACCOUNT_BAN` matches both the direct
  queue and the validated lookup-cache binding path, but the applier
  rejects the receipt in constitutional-clock mode without changing
  state or state root, under both bounded rollback and deepcopy.
- Changed `_system_queue_id`, target account, synthetic appeal proof,
  due height, parent, signer or transaction type cannot match the
  existing scheduled item; wrong phase/height also fail binding.
- Legacy-clock behavior is observed only as compatibility evidence,
  not as proof of lawful severe-sanction provenance.
- The real `WeAllExecutor.build_block_candidate` path is exercised
  against the deliberately injected queue entry; its result must be
  adjudicated from CI rather than inferred from applier-only tests.
- The V2 `ACCOUNT_BAN` prior archived semantic digest remains verified,
  and its two changed reviewed fields remain `failure_codes` and
  `state_reads`. The exact new rejection reasons are
  `conflicting_receipt:duplicate_ban_receipt_conflict` and
  `forbidden:severe_sanction_authorization_unimplemented`.

**No AUTHORITY transition is implemented.** The queue-source trace
does not make an arbitrary `SYSTEM` flag a cryptographic credential.
Do not enable severe bans, approve the new semantic digest, modify
historical state, or assert a two-node replay from a synthetic
single-node queue fixture. Independent replay of authentic old blocks
and signed, queue-bound severe case material is still required.
