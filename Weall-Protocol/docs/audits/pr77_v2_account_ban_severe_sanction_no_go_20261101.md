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


## Completed synthetic 25/20 initial + fresh 25/20 appeal: still NO AUTHORITY (2026-11-01)

**Verified on the current PR77 draft; no production activation or semantic
review signoff.** New executable regression
`tests/test_pr77_complete_severe_appeal_no_authority.py` extends the
earlier split initial-vote and fresh-appeal safety tests with one
continuous in-memory constitutional-clock story:

1. Seed 25 distinct initial jurors, five substitutes, 20 affirmative
   initial final-ballot nullifiers, a claimed S4 account case, and an
   explicitly enabled **synthetic controlled-testnet** ballot profile.
   Such fixture fields do **not** independently authenticate a real
   case, jury, cryptographic ballot, signed source receipt, or chain.
2. Run the **real** `DISPUTE_RESOLVE` domain handler with a 20/25
   initial result, and the default-off experimental automatic severe
   appeal assignment switched on only in this synthetic state.
3. Verify a new 25-member appeal panel and five substitutes, disjoint
   from the original 30 identities. Execute 20 actual
   `DISPUTE_JUROR_ACCEPT` and 20 `DISPUTE_VOTE_SUBMIT` domain
   calls and observe `appeal_vote_counts={"uphold":20}` and
   `stage="appeal_resolved"`. These calls are not signed public
   transaction admission or BFT consensus evidence.
4. Run `tick_dispute_lifecycle` and confirm **no** queued
   `DISPUTE_FINAL_RECEIPT` or `ACCOUNT_BAN`, including with
   user-asserted waiver material.
5. Submit a forged final-receipt-shaped `SYSTEM` envelope claiming
   an `ACCOUNT_BAN` action. The dispute applier rejects it with
   `forbidden:severe_sanction_automatic_appeal_unimplemented`,
   without changing the state.
6. Submit a direct synthetic `SYSTEM ACCOUNT_BAN` with a case ID,
   apparent 20+20 tallies, appeal panel commitment, waiver assertion,
   and queue ID string. Both bounded-rollback and reference deepcopy
   domain execution reject
   `forbidden:severe_sanction_authorization_unimplemented`.
   The target remains unbanned and the state root is preserved.

**Additional real `DISPUTE_OPEN` boundary:** A distinct three-case
regression supplies client-claimed `severity="severe"`,
`sanction_class="S4"`, or nested `rules` class/severity on an
otherwise accepted account-targeted `DISPUTE_OPEN`. The resulting
canonical dispute record contains no `severity`, `sanction_class`
or `rules` classification. The existing opener does not promote
untrusted caller labels into source-backed severe authority.
**However, there is still no positive, authenticated canonical
severe-case classification producer**. A synthetic fixture can set
an S4 field, but that is not proof that an actual submitted case can
legitimately reach this class. This gap must be resolved before
enabling any severe sanction.

[Focused GitHub Actions run 41381332705](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41381332705)
**PASS** at test source commit
`e10f7befa67edb18a6ab64af98b0e683262cd32b`:
the new eight tests passed, along with the five existing workflow
suites (**38 + 4 + 6 + 13 + 10 tests**, plus four subtests), strict
Ruff lint and format. No protocol default, canonical receipt
applier, disputed review digest, or historical state was modified.

### Source-backed producer implementation order — STILL BLOCKED

The next actual producer cannot safely be created merely by
`enqueue_system_tx("ACCOUNT_BAN")`. At minimum, the separately
reviewed and **versioned** design must specify and prove:

- **Case origin and classification:** an authenticated, non-spoofable
  severe/S4 account-target decision bound to the exact case, account,
  evidence, opening transaction and applicable constitutional version.
  The current `DISPUTE_OPEN` does not produce it.
- **Initial jury and ballots:** verifiable 25-person assignment,
  identity uniqueness, conflicts, eligibility, panel commitment, at
  least 20 genuine affirmative juror ballots, and deterministic
  finality—not merely read-model counts or claimed nullifiers.
- **Automatic appeal:** exactly one properly initiated,
  non-overlapping fresh 25-member panel; valid 20-vote result; and
  the constitutional waiver exception only if separately authenticated
  *after* the full reasoned outcome is provided. The default-off
  experimental panel transition is not the complete producer.
- **Final decision/authorization:** a deterministic, idempotent final
  authority record tying decision, appeal, target, reasoned outcome,
  deadlines, restoration/restitution and predecessor receipt.
  `DISPUTE_FINAL_RECEIPT` is presently held for recognized severe
  cases, even after a synthetic appeal has finished.
- **Queue and execution trust:** an actual authorized producer must
  bind its source certificate to the `SYSTEM` queue item, parent,
  payload and exact finalized height, with the same check repeated
  by followers at `ACCOUNT_BAN` execution. Queue hash binding
  alone does not prove the source decision.
- **Reputation and replay:** separately adjudicate the already known
  alternate reputation-floor automatic exclusion, discordant
  reinstatement/ban index, pre-activation ledgers, receipt roots,
  historical V2 semantic digests and independently operated nodes.
  A green negative regression is **not** a claim that all alternative
  paths are non-excluding.

**Disposition:** this round increases source-bound *negative*
evidence for the complete synthetic case and identifies a concrete
authentic-classification prerequisite. It neither implements nor
authorizes the severe-sanction producer. Keep all 15 V2 semantic
review approvals pending, retain constitutional-clock ban rejection,
preserve historical compatibility, leave PR77 Draft/unmerged and
release **NO-GO**.
