# PR77 — Strict severe initial decision 20/25 gate (interim)

**Scope:** Runtime defensive gate for already-explicit S4/severe/critical account
cases with the constitutional clock enabled. This does **not** add canonical
severe case admission or the constitutionally required fresh automatic appeal.

The ordinary BFT `quorum_threshold(25)` alone may permit resolution below the
20 affirmative jurors required for a severe sanction. Both automatic
DISPUTE_VOTE_SUBMIT-triggered resolution and directly supplied SYSTEM
DISPUTE_RESOLVE are now held until an internally consistent strict
25-panel / 5-substitute read model shows at least 20 affirmative votes.

Required observations: distinct panel and substitutes, assigned initial
panel, exact nonnegative integer counts, 20 yes, matching voted-juror IDs,
matching deterministic finalized round-one ballot nullifiers with no legacy
attributable-vote migration. The direct receipt must claim a report-upheld
outcome consistent with the initial read model.

**Limitations:** This verifies only consistency of already-stored read models.
It does not cryptographically authenticate the original ballots, validate
the source of a severe label, or authorize any SYSTEM producer. An S4 case
with 20 opposing votes or a split vote is conservatively held pending the
complete constitutional decision process. Explicit severe cases in
non-strict constitutional-clock mode remain blocked, while legacy-clock
state retains compatibility behavior.

On success the initial decision may only enter the existing appeal window.
The earlier independent fresh-appeal and ACCOUNT_BAN finalization guards
remain in force; no ban receipt is emitted or enforced. Source-bound V1.5
derivatives and stale V2 review digests require separate validation.
