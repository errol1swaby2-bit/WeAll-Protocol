# PR77 phase-1 content report → dispute pipeline integration

**Status: BOUNDED SYNTHETIC EXECUTOR/REPLAY TEST PASSED; WHOLE SUBSYSTEM NOT CERTIFIED.** Not final protocol, user-facing
E2E, global PoH, independent BFT, S4 case classification, or testnet evidence.

## Why this check exists

The frontend's public content/feed reporting action submits `CONTENT_FLAG`;
the content domain enqueues `CONTENT_ESCALATE_TO_DISPUTE`; the escalation
invokes dispute opening, assigns only conflict-eligible opt-in reviewers, and
enqueues a receipt. Direct applier/emitter tests did not alone prove this chain
survives signed external submission, canonical block admission, system queue,
durable state, and independent fresh-executor replay within one code revision.

This bounded regression exercises two separately signed accounts: the genesis
author and a registered, controlled-*local-bootstrap* reporter. It submits
`ACCOUNT_REGISTER`, explicit local `POH_BOOTSTRAP_TIER2_GRANT`,
`CONTENT_POST_CREATE`, and `CONTENT_FLAG` through `WeAllExecutor.submit_tx`,
builds blocks with `produce_block`, and requires the system escalation's
**successful block receipt**, resulting dispute, correct target and reporter
attribution, exclusion of parties from juror assignments, absence of account
bans, and exact source/fresh-replay manifest equivalence.

## Exact limitations

- `WEALL_POH_BOOTSTRAP_OPEN=1` under local developer mode is a controlled
  fixture shortcut and **not** proof of unique human identity or real PoH
  issuance. This mode must never be silently used to claim real testnet PoH.
- A second executor on the same runner is not a separate operator, BFT finality
  authority, third-party node or full network topology.
- Direct account-target signed `DISPUTE_OPEN` has a separate synthetic
  end-to-end regression. The current frontend's ordinary public report action
  exposes `CONTENT_FLAG`; whether to expose other dispute targets in the
  participant UI is a product/constitutional scope decision, not something
  this test guesses or activates.
- Generated/severe-sanction and semantic-review gates remain unchanged. No
  `ACCOUNT_BAN` authority, no constitutional S4 classification or appeal is
  implied.
- Phase 1 requires a full subsystem inventory and additional integrated flows.
  This is just one representative path, not a completeness certification.

**Original baseline result:** Verified separately below. Later reviewer lifecycle
extensions have their own exact-commit CI and do not supersede the original
baseline evidence or establish broader release authority.


## Height-advancement diagnostic during CI

The expanded audit-receipt assertion initially failed because the fixture called
`produce_block()` **without** `allow_empty=True` after all signed user
transactions had been committed. On a chain with no automatic empty-block
production, this returns `ok=True` without advancing height; the
`FLAG_ESCALATION_RECEIPT` remained correctly queued for the next height.
No evidence was found of an early return in the content applier.
The integration fixture now explicitly advances the controlled local
block clock with `allow_empty=True` and asserts the new height for each
rehearsal step. This does not change the production block-loop policy.
Receipt-commit evidence remains subject to the next exact-head CI result.


## Verified exact-commit CI result

The enhanced test passed on commit `d1de0733283b6097c47f45f8841502ae9ecacfbf`
in [PR77 phase1 content-to-dispute CI run #41502322410](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41502322410):
pinned Ruff lint PASS, pinned Ruff format PASS and **1 integration test PASS**.
The run exercises source and scratch executor histories against the same
software revision and explicit synthetic test-only genesis parameters.

| Integrated boundary | What the regression actually confirms |
| --- | --- |
| Account identity and signatures | Two independently signed accounts; real account registration and explicit local PoH bootstrap transaction accepted and committed |
| User content creation and reporting | Signed `CONTENT_POST_CREATE` and `CONTENT_FLAG` accepted with successful persisted block receipts |
| System escalation and case identity | A successful canonical `CONTENT_ESCALATE_TO_DISPUTE` system receipt creates the account-attributed report and links the moderation target |
| Responsibility/party conflict | Target author and reporter excluded from any assigned review panel; unassigned case remains visible without inventing jurors |
| Follow-up audit | A successful `FLAG_ESCALATION_RECEIPT` is committed after explicitly producing a next-height block |
| Determinism | A fresh executor replays the persisted blocks with matching per-height commitments and final dispute state |
| Safety posture | Neither participating account was banned by escalation; no constitutional severe-sanction authority inferred |

This result is not a completed client UI journey, independent multi-node
HotStuff/BFT finality, adversarial network partition test, cryptographic audit,
real-human PoH, completed appeal pipeline or full review of every content and
dispute transaction type. Frontend reporting currently submits `CONTENT_FLAG`;
the separate account-target `DISPUTE_OPEN` fixture is not proof that an
account-target reporting screen exists.

**Unresolved phase-1 follow-ups:** trace assigned juror opt-in + accept/vote
through real block admission and restart; exercise failed/retry and duplicate
escalation across block boundaries; verify public dispute read-model and
frontend reconciliation under asynchronous inclusion; account for
constitutional-clock/empty-block scheduling in operator configuration; test
independent node convergence and failure/partition recovery in phase 2.
These are work items, not implied PASS results.


## 2026-11-02 — Signed reviewer responsibility, acceptance and ballot continuation (candidate)

The same end-to-end test now **attempts** a third account's actual signed
registration, controlled-local PoH bootstrap, separate opt-in to
`content_review` and `dispute_review`, automatic reassignment of the
unassigned content case, `DISPUTE_JUROR_ACCEPT` and a `DISPUTE_VOTE_SUBMIT`
"no" ballot, including persisted ballot admission receipts and full
fresh-executor replay. Its status remains **UNVERIFIED until pinned CI**.

The runtime currently requires `dispute_review` consent for dispute accept
and vote even when `content_review` opt-in assigned the content review case.
This is a **potential participant-journey architecture/UX mismatch**.
The integration fixture does not bypass consent; it makes both explicit
so the combined path can be observed and the product contract can later be
adjudicated in the dedicated architecture/documentation phase. No new
constitutional authority or severe-sanction completion is claimed.


### Exact two-lane consent behavior — tested on a persisted pre-state

To avoid silently widening reviewer authority, the expanded fixture also
extracts the **actual committed state** after `content_review` assignment
but before `dispute_review` opt-in. On a deep-copied state it invokes the
domain accept operation with the third account's real signed envelope and
requires `reviewer_responsibility_not_active` **without mutation**, then
performs the second explicit opt-in through the canonical executor and proves
accept/vote/replay afterward. This negative check is domain-level, while the
positive sequence uses actual admission and persisted blocks. It is not proof
that a standalone content-review permission ought to be insufficient under
the final product design. That policy/UX decision remains open for
specification reconciliation.


## Signed third-reviewer continuation — exact-head verified

The upgraded local-only integration fixture **PASSED** on
`cb59e10144533fab0f6395adca15f148e70be896`:
[PR77 phase-1 content/dispute workflow #41504204822](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41504204822)
(pinned Ruff lint PASS, pinned Ruff format PASS, **1 focused end-to-end
executor/replay test PASS**). This extends the older green baseline without
claiming additional real-world identities or an independent validator.

The same committed chain now includes a third independently signed account:
`ACCOUNT_REGISTER`, explicit synthetic
`POH_BOOTSTRAP_TIER2_GRANT`, `REVIEWER_LANE_OPT_IN` for
`content_review`, case reassignment out of `unassigned`, separate
`REVIEWER_LANE_OPT_IN` for `dispute_review`,
`DISPUTE_JUROR_ACCEPT`, and `DISPUTE_VOTE_SUBMIT` ("no"). The exact
persisted account/dispute/juror state, attendance, deattributed ballot-admission
receipt, and entire recorded transaction history replay identically in a fresh
executor. The original target owner/reporter do not become reviewers and none
of the three synthetic accounts is banned.

**Important unresolved design/UX mismatch:** the implementation requires
two separate reviewer-lane opt-ins to complete one content-report review.
`content_review` alone assigns the report, while `dispute_review` is also
needed for `DISPUTE_JUROR_ACCEPT` and voting. A mutation-free negative
regression confirms the current domain gate rejects the content-only reviewer
with `reviewer_responsibility_not_active`. This proves existing behavior,
**not** that two consents are the constitutionally correct final design. It
requires explicit architecture/product adjudication; this pass did not widen
authority or silently merge the lanes.

Remaining outside this evidence: actual independent-human verification,
25+5 constitutional panels and 20-vote severe adjudication, appeal/automatic
fresh panel, real browser/API UX, cross-machine quorum and BFT finality,
restarts, independent external review and final clean-genesis protocol run.
This is not a production or public testnet launch gate closure.
