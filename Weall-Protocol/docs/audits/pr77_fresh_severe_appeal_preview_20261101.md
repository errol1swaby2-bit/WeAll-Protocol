# PR77: Deterministic fresh severe-appeal preview — NO GO

This implementation deliberately **does not** enqueue any SYSTEM transaction,
assign active jurors, amend dispute state, or authorize an ACCOUNT_BAN.
It computes a review-only, repeatable candidate panel using the existing
`select_dispute_panel` algorithm on an independent deep copy of state.

## S4 panel-size inconsistency

Before this change, `_dispute_panel_size` looked only at severity, so an
S4 account case whose severity field was absent or labeled "low" could
silently receive a 7-member instead of 25-member panel. The narrow
sizing fix reuses the existing severe-account guard predicate to require
25 jurors for explicit S4/severe/critical account cases, regardless of
an inconsistent outer severity label. This changes panel sizing for
these cases and requires separate semantic and historical replay review.

## Candidate prerequisites

The read-only preview requires clock/strict mode, an explicit account-severe
classification, 25 distinct initial jurors with five distinct substitutes,
a declared initial assignment, observed >=20 affirmative votes, a recorded
upheld resolution, and an eligible fresh review pool large enough for
25 new jurors plus five substitutes. Initial jurors and substitutes are
excluded when calling the existing deterministic selector.

All votes, commitments and severity signals remain **unverified read-model
observations**. A plausible preview never becomes authorization.
Every preview explicitly returns `may_enqueue_account_ban=false` and
`may_finalize_severe_sanction=false`.

## Missing canonical authorization

- `DISPUTE_OPEN` still cannot authenticate a severe sanction category.
- Stored tally fields are not independently authenticated approval proof.
- No automatic appeal is scheduled, recorded or voted.
- No valid waiver, SYSTEM receipt producer, or replay-compatible activation exists.
- V2 `TX-0904 / ACCOUNT_BAN` and `DISPUTE_OPEN` semantic reviews remain stale.
- PR77 stays Draft, with public-beta readiness blocked and no merge authorization.

The preview is a building block for the eventual automatic appeal scheduler,
not a substitute for the constitutional lifecycle.

## Exact GitHub test evidence

- Source/panel sizing and candidate preview commit: `4dc9e08f39363ab5bf1c40c99735918679b69728`.
- Import correction: `3815815c1fc93d38469d17d6203a55bdfa29bd06`.
- Bounded V1.5 evidence/format workflow: `41321551870`, **PASS**.
- This run passed Ruff lint and formatting, **69 focused tests**, the V1.5
  derived-artifact checks, and release-hygiene checks. It generated bot
  commit `c917ccf52c2517822d80425aaa00f83c40a8a783`, limited to
  Ruff formatting of the two new candidate/test files and three
  source-bound V1.5 proof artifacts.
- The public-beta blocker report still lists **8 open blockers**.
- Neither the V2 semantic attestation nor the explicit account-ban
  constitutional-clock deny was changed by this work.

### Semantics explicitly not yet authorized

S4 panel sizing is a source/consensus behavior change for explicitly marked
account cases. This preview cannot distinguish a legitimate from a forged
initial vote tally or sanction-class marker. A real automatic appeal must
originate from an authenticated first-stage decision, persist a distinct
deterministic juror assignment, allow actual juror ballots, verify 20 approvals,
and produce a queue-bound final receipt. None of those transitions is
implemented here.

PR #77 remains Draft. Full backend/clean-clone and replay compatibility
validation, V2 semantic adjudication, and remaining readiness blockers
must be resolved independently before merge or launch.
