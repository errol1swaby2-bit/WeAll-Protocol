# PR77 — deterministic timeout juror replenishment, experiment only

The project already queues `DISPUTE_JUROR_TIMEOUT` after an **accepted**
juror's vote deadline but previously had no replacement path; an
**unanswered initial assignment** had no response deadline at all.

This experimental feature fills those gaps **only on a replicated-state,
default-OFF feature flag** `params.experimental_severe_juror_replenishment_v0
is True` and for explicitly classified S4/severe account cases in strict
constitutional-clock mode. Neither shared-chain consensus activation nor
canonical severe classification is approved.

On each deterministic block height, the scheduler replaces an assigned,
non-responding juror only after the configured response window (default
45 blocks, exact integer 1..10080). Accepted jurors must first receive
a canonical `DISPUTE_JUROR_TIMEOUT` SYSTEM receipt and a resulting
`timed_out` status; late votes are never erased by the scheduler.
Declined and withdrawn no-vote jurors are also replaceable.

An eligible FIFO substitute takes the vacant panel seat only when a new
eligible reviewer can refill the reserve. Every selection excludes the
original appeal roster, current panel/substitutes, replaced identities,
and known case conflicts. The replacement history forms a deterministic
hash chain and preserves the initial selection commitment. For the
experimental fresh appeal the 25+5 current panel remains disjoint from
the original 25+5; for initial panels it keeps 25 jurors and 5 substitutes.
The required severe-sanction approval threshold remains 20. If safe
replenishment is impossible, no roster mutation occurs.

This implementation **does not** prove canonical juror eligibility,
cryptographically authenticate the prior ballot/receipt evidence,
authorize appeal finalization, assign constitutional sanctions, waive
appeals, or execute ACCOUNT_BAN. The safety path must be replay-audited,
reviewed against the V2 specification, tested on separate nodes, and
subject to a proper activation decision. Public-beta blockers and stale
V2 semantics remain unresolved. Do not merge PR77 or launch.
