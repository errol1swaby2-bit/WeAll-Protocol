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
