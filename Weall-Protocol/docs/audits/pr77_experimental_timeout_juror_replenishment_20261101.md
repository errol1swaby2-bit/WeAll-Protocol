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

## GitHub implementation and test checkpoint

- Primary feature commit: `dfbfb1bf9c33e7afd482f2f9bd9dfff15fb3f617`.
- Dedicated timeout/replenishment workflow `41330070295`: **PASS,
  59 focused tests**. These exercise both the initial and fresh-appeal
  panels, deadline boundaries, substitute promotion, reserve refill,
  blocked candidate pools, preserved voted jurors, deterministic
  replay-shaped identical state, and the default-off switch.
- Bounded artifact and formatting workflow `41330250777`:
  **PASS, 120 focused tests**, Ruff lint/format, V1.5 regeneration,
  artifact currentness and release hygiene.
- Bounded bot commit `3e33b07cf969dbece2c0b3707bdc1d32e3a29875`
  has only the three regenerated V1.5 proof JSON files and
  Ruff formatting of the new module and tests.
- Public-beta evidence continues to list **8 open blockers**.

### Safety / implementation boundaries

Accepted nonvoters are not displaced by a scheduler's speculative
timeout: the existing canonical SYSTEM timeout receipt must first set
`timed_out` in state. The new response timeout for jurors who never
accept only records an unpenalized `replaced_no_response`; it does
not invent a reputation sanction. At each replacement, an eligible
substitute is promoted only when an external eligible reviewer can
restore the full reserve. An incomplete pool leaves the roster intact.

This remains an EXPERIMENTAL replicated-state algorithm with a
separate default-off switch, not a production-active consensus rule.
The original severe-sanction category and ballots still lack
independent source authentication, the replacement hash chain has
not undergone multi-node replay adjudication, and actual juror
notifications/delivery require separate workflow verification.
The 20/25 requirement and terminal severe-ban no-go are preserved.

Do not merge or enable on shared networks, or approve the stale
V2 `DISPUTE_OPEN`/`ACCOUNT_BAN` semantic attestations merely
to green CI.


## Adversarial promotion-boundary audit (2026-11-01)

A read of the existing implementation found the deterministic no-response
replacement, accepted-juror canonical SYSTEM timeout receipt, FIFO reserve
promotion, eligible reviewer backfill, and hashed replacement history were
**already implemented** and covered by the original 120-test checkpoint.
No alternative scheduler, selection algorithm, or transaction type was added.

A narrow conflict-of-interest gap was identified: the reserve juror chosen for
promotion was rechecked for **role eligibility**, but not rechecked against the
current dispute conflict set. A juror could become a reporter, party, target
owner, or rule-defined conflict after the original assignment and still be
promoted. The existing authoritative `_dispute_conflict_account_ids` function
is now reused at promotion time. The guard also refuses promotion of a
historically retired or already journaled/assigned juror, without changing
the deterministic newcomer selection algorithm. Unsafe reserves cause the
existing fail-closed no-mutation outcome.

This does not address the wider undecided rollout question: the current
prototype operates only on explicitly classified severe/S4 account cases,
and remains default OFF. General 7/15-person dispute panel replenishment,
independent case-class authentication, BFT replay/activation, actual delivery
notifications, and final sanction authority remain outside this change.
