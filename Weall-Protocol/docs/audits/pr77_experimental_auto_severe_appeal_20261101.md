# PR77 experimental automatic severe appeal: NOT ACTIVATED

## Implementation

A default-off *replicated-state opt-in* named
`params.experimental_severe_auto_appeal_v0 is True` enables a
prototype that selects and assigns a fresh 25-juror plus five-substitute
panel as part of an existing initial SYSTEM `DISPUTE_RESOLVE`
transition. The case must be explicitly severe/S4, in strict
constitutional-clock mode, and already pass the previous 20/25 strict
first-stage ballot-record consistency guard. The deterministic existing
panel selector excludes the original 25+5, and checks 60 distinct
normalized identities before writing an appeal assignment record.

If the fresh pool is insufficient, the initial case is kept in the
appeal window and an explicit blocker is recorded. Duplicate SYSTEM
resolution or subsequent manual appeal cannot replace an automatically
assigned panel. The existing severe-appeal 20/25 voting rule remains.

## Not a constitutional authorization

This prototype does not authenticate the client's severe classification
or independently verify the original ballots. The SYSTEM queue reference
is recorded as an observation, not validated BFT lineage or permission.
No new SYSTEM transaction type is registered. This is **not** a
production-activated automatic appeal and the switch must remain off on
shared chains until consensus activation, historical replay, semantic,
and independent authority review are completed.

The fresh-appeal stage cannot enqueue `DISPUTE_FINAL_RECEIPT` for
severe account cases and cannot execute `ACCOUNT_BAN` in
constitutional-clock mode. Appeal waiver, finality provenance and
sanction restoration remain unimplemented. Eight public-beta blockers
remain open. Do not merge or launch PR #77 based on this prototype.
