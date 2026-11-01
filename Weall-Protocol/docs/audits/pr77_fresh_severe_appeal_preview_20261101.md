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
