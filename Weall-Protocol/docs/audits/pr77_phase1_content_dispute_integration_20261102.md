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


## Duplicate-ballot executor boundary (new candidate)

Extended the controlled local-source/scratch-replay integration fixture with a
**second distinct correctly signed** `DISPUTE_VOTE_SUBMIT` from the same juror
after the first ballot had finalized, using the next canonical account nonce.
The test demands one canonical **failed** block receipt
(`dispute_ballot_already_final`), no additional recorded vote or ballot receipt,
no case-state or reputation modification, expected nonce progression, and
matching fresh-executor replay of the rejected transaction itself.

This new assertion must **not** be marked verified until the exact-head
pinned CI has passed. It is unrelated to changing sealed-ballot profile
activation, 25-member juries, or severe sanction authority.


### Duplicate-ballot CI diagnostic: scheduled finality is not ballot mutation

Initial focused workflow [#41506003529](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41506003529)
confirmed a **failed signed duplicate ballot block receipt** with reason
`dispute_ballot_already_final`. The test then wrongly treated the already
queued `DISPUTE_FINAL_RECEIPT` transition (`resolved` →
`finalized`) as mutation caused by the rejected ballot. This is a *fixture
comparison error*, not evidence that duplicate voting changed the result.
The revised test first commits the expected final receipt in a separate
explicitly height-advancing empty block, demands its successful canonical
receipt and `finalized` case stage, **then** submits the signed duplicate
and compares finalized-case and ballot/reputation evidence before/after.
Status: pending revised exact-head CI. No production runtime changed.


## Local fallback reassignment: report-party conflict and retry (new candidate)

An inspection of `runtime/apply/roles.py::_assign_unassigned_content_reviews_to_juror`
found that the non-strict single-reviewer reassignment branch excluded the
target owner but **not the reporter**. This allowed a reporter who opted into
`content_review` after their report was opened to receive their own case.
The same branch treated a prior
`target_owner_cannot_review_own_content` blocked reason as permanently
non-retryable, so a later unrelated reviewer could not clear the case.

The focused patch adds reporter exclusion using the same normalized account
matching already used for target owners, emits explicit
`reporter_cannot_review_own_report` blocked state, and makes these two
conflict-specific reasons retryable **only when a later reviewer without
those conflicts opts in**. It leaves strict constitutional panel selection,
account authority, severe sanctions and ballot profiles unchanged.

Regressions: an actual signed reporter opt-in following a committed flag
must not assign its own case; a subsequent independent eligible signer must
still assign and complete it. Two direct role-flow tests separately cover
reporter and target-owner conflict followed by legitimate reviewer opt-in.
**Status pending exact-head CI; no release or independent consensus claim.**


## Reporter self-review: initial panel and direct accept/vote boundary (candidate)

The initial content escalation selected a legacy/local panel without explicitly
excluding the reporter, although comments promised that reporters never review
their own reports. The shared strict panel selector already excludes material
conflicts; the local selector excluded only the content owner. This patch
explicitly passes reporter identity in `exclude_ids` to the shared selector.

The dispute acceptance/voting boundary now separately rejects a
`reported_by`, `flagged_by` or `reporter` identity with
`juror_conflict_reporter`, even if a legacy state has stale assignment or
both exact reviewer-lane consents. The signed fixture tests this rule against
a copy of the real committed state, without mutation. Unit tests check
prior-opt-in reporters cannot be selected on initial escalation while a
distinct opted-in participant may be selected. A legacy test that had
explicitly expected a reporter to adjudicate their own report has been
rewritten to test an independent reporter instead.

**Pending exact-head CI.** The patch does not ratify historical semantic
digests, grant severe sanctions, or claim full constitutional finality.


## Reporter alias regression and adjacent suite (candidate)

The initial-selection reporter exclusion now uses the existing account identity
variant helper, protecting `@account` and `account` aliases. New
parameterized unit coverage tests both. Focused CI includes previously existing
reviewer-selection, dispute assignment, strict juror gating, vote acceptance,
and review-outcome suites in addition to the signed executor/replay path.
**Status pending pinned CI; no release authority claimed.**


### Adjacent legacy test corrected (pending rerun)

Expanded CI [#41507682922](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41507682922)
ran **21 passed, 1 failed**. The failure was a contradictory old test
`test_content_review_selection_requires_exact_content_review_lane_not_generic_juror`:
it defined the opted-in reviewer as the case's own `reported_by`/
`flagged_by` but expected that reviewer to receive the case. The
test's intent is to prove explicit per-lane selection, not reporter self-review.
The fixture now names a separate reporter and asserts the reporter stays
excluded while the independent content reviewer receives assignment.
The previous failure is retained in this audit; the revised test awaits CI.


## 2026-11-02 — confirmed integrated safety boundary

**Verified code head:** `2240c2d4bf10604df8e565f003946f60e12a46af`.
[Focused phase-1 CI run #41507955308](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41507955308):
**22 passed**, Ruff lint PASS, Ruff format PASS (six checked files).

The regression set includes signed two-party content report and a third signed
reviewer, report escalation + audit receipt, opt-in and final signed ballot,
later reporter opt-in exclusion, a distinct signer subsequently receiving the
unassigned case, negative reporter acceptance even with both active lanes,
duplicate signed ballot rejection with failed canonical receipt, system
finalization in a separate block, and fresh executor replay of the full chain.
Neighboring review assignment, juror strict-gate, acceptance API, review outcome
and content-review UI contract tests also passed. Alias tests cover both
`@account` and `account` for reporter conflict.

**Implementation corrections in this review branch:**
1. `runtime/apply/roles.py` now excludes reporters from local fallback review
   reassignment and allows later independent reviewers to recover a case
   blocked by an earlier reporter/owner conflict.
2. `runtime/apply/content.py` explicitly excludes reporter identity variants
   at initial panel selection even under legacy/local selection.
3. `runtime/apply/dispute.py` independently blocks reporter juror accept/vote
   despite active lane consent or a stale historical assignment.

**Historical consistency caution:** these reviewer conflict checks change
local/legacy consensus-observable behavior and supersede fixtures that
expected reporter self-review. The clean-genesis replacement plan means old
development-chain replay is not the testnet release gate, but divergence from
older semantics remains transparently documented and must be addressed in the
architecture/documentation reconciliation stage. No legacy evidence is
misrepresented as refreshed by this focused synthetic run.

**Open/unproven:** full cross-revision compatibility, strict M3 7/15/25 plus
substitutes under adversarial concurrency, completed appeal and fresh appeal
panels, deattributed production ballot activation, frontend exact-lane UI
and receipt reconciliation, restart under independent operators, verified
real-human PoH and two-machine BFT finality. Severe sanction authority
(`ACCOUNT_BAN`) and V2 review digest signoff remain gated. Full testnet
rehearsal and evidence regeneration have not begun.


## 2026-11-02 — strict appeal fresh-panel failure atomicity (candidate)

In `runtime/apply/dispute.py::_apply_dispute_appeal` an appeal was appended
to the live case's existing `appeals` list **before** strict
`select_dispute_panel` verified sufficient fresh reviewers. When a
7+2 strict ordinary appeal had only eight fresh unconflicted reviewers,
the applier raised `insufficient_fresh_appeal_panel` but left the
appellant's appeal recorded in caller-visible state. The surrounding
canonical rollback machinery may undo changes on executor failure, but direct
domain callers and future alternate integrations must not depend on that.

The focused patch delays adding the appeal until after a successful strict
panel completeness decision. Synthetic direct-domain tests require: failed
8-of-9 available fresh pool leaves case and queue byte-for-byte equivalent;
9-of-9 available produces a deterministic fresh 7+2 panel disjoint from
original 7+2, records exactly one authorized appeal; an unauthorized or
duplicate appellant and an expired window each fail without mutation.

These tests **do not** prove real-human PoH, independent BFT, or strict
public ballot activation. Because a strict insufficient-pool attempt is
rejected (not durably recorded), the product policy for preserving appellant
rights when the pool is depleted remains an architectural decision and
possible lifecycle gap; this patch does not create automatic panel or extend
constitutional deadlines. **Pending pinned CI.**


## Signed local appeal and independent fresh reviewer (candidate)

After the previous signed report, review, final receipt and rejected duplicate
vote, a fourth independent signed account opts into `dispute_review`.
The original content author submits a real signed `DISPUTE_APPEAL` through
`WeAllExecutor.submit_tx` on the local-development/legacy profile, and a
fresh executor replays the entire augmented chain. The test demands a fresh
reviewer and excludes the original panel juror, original reporter and content
author.

Inspection revealed the non-strict appeal selector excluded original jurors
and substitutes but not `reported_by`/`flagged_by`. A reporter who already
had dispute-review consent could therefore be reselected on appeal, making
acceptance impossible under the explicit reporter-recusal guard. The patch
now excludes resolved reporter IDs from legacy/local fresh-panel selection;
strict constitutional profiles retain all existing material-conflict checks.
**Pending exact-head CI.** Legacy/local mode does not impose the production
constitutional appeal window, so this exercise is not strict-clock signed
appeal or 7/15/25 panel evidence.


## 2026-11-02 — pinned appeal/fresh-panel test completion

The strict fresh-panel atomicity patch and signed local fresh-reviewer appeal
were both run in [focused GitHub Actions #41510157854](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41510157854)
against implementation commit `b76184752ce4b1b53f32b6ace149a51ce5beeb44`:
**40 passed**, Ruff lint PASS, Ruff format PASS. The prior strict-only focused
run [#41509851966](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41509851966)
also passed 40 tests before the local signed-appeal extension.

The strict constitutional-clock fixture (synthetic direct-domain, not
production identity or independently finalized consensus) verifies that a
7-member review plus 2 substitutes receives a completely fresh disjoint
7+2 appeal panel *only* with nine eligible additional reviewers, and that
an eight-member fresh pool fails without writing an appeal record or panel
state. A duplicate appeal, unrelated appellant, or expired deadline fails
without mutation.

The separate signed executor fixture (legacy/local-dev, **not** strict-clock
appeal-window coverage) verifies the real signed content author files
`DISPUTE_APPEAL`, a newly opted-in independent reviewer forms a fresh
appeal panel, prior reviewer and original reporter are excluded, and a
separate scratch executor reproduces the complete chain. A safety correction
was necessary because the non-strict appeal selector previously excluded
original jurors/substitutes but could select the original reporter. Explicit
reporter exclusion now prevents a conflict from entering that panel;
no severity or sanction authority changed.

**Open governance/product issue:** a strict appeal can be rejected when
the independent pool lacks sufficient fresh humans, leaving the legitimate
appellant no durable appeal record and the original appeal deadline
unchanged. This test proves atomic rejection, **not** a fair mechanism for
preserving appeal rights during pool shortages. Policy for suspending
finalization, durable appeal intent, and deterministic roster replenishment
requires architecture/constitutional review before implementation.
No automatic severe fresh-panel scheme or `ACCOUNT_BAN` authority is
activated. Real PoH, browser-signed appeal UI, validator-operated BFT and
new-genesis all-subsystem evidence remain unproven.

## 2026-11-02 — recorded appeals wait for a full fresh constitutional panel

**Product decision applied to the draft PR77 branch:** a valid, on-time
appeal survives a shortage of unconflicted jurors. The previous strict
`DISPUTE_APPEAL` failure `insufficient_fresh_appeal_panel` is replaced
by successful admission with persisted stage `appeal_pending_panel`.
Original jurors, substitutes, reporter identities and material-conflict
identities remain excluded. The prior complete constitutional 7/15/25-person
panel plus substitutes and original quorum are **not reduced**.

During pending, the state retains the appeal signer, signed transaction
nonce, filing height, and the original panel and substitute snapshot. It
records the incomplete panel status, required panel size, required substitute
count and available reviewer count. No active appeal jury is installed.
The constitutional block-height scheduler deterministically retries from
replicated `dispute_review` eligibility on each produced block; once a
complete fresh panel is available, the case enters `appeal_review` and
records the assignment height without changing its original filing height.
An existing appeal never expires just because panel formation takes longer
than the original filing window. The final-receipt applier independently
rejects stale `DISPUTE_FINAL_RECEIPT` while
`appeal_pending_panel` persists, before writing any receipt.

**Pinned validation:** implementation/test head
`e4138676b54557b1cbe1aa309fd70700cd5c982c`,
[phase-1 focused workflow #41519892377](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41519892377):
**43 tests passed**, Ruff lint PASS, Ruff format PASS. Strict synthetic
domain tests check shortage (8 candidates when 9 are required), durable
filing, deadline-crossing hold, rejected direct forged/stale receipt with
no state changes, duplicate filing rejection, independence of initial and
appeal jurors, and exact state parity across two independent state copies
when a ninth fresh reviewer later becomes eligible. Existing local-dev
signed executor + fresh-executor replay evidence remains separately covered
by the same workflow, but it does **not** demonstrate signed strict-clock
pending appeal processing across independent validators.

**Semantic provenance:** the V2 material review now registers a change in
appeal state writes and removal of the old
`insufficient_fresh_appeal_panel` rejection code. The regression checks
that the current digest differs from the previously accepted digest, rather
than treating old signoff as automatically applicable to new code. New
human ratification and protocol documentation reconciliation remain required.

**Remaining barriers:** browser/API read-model and reviewer-eligibility
presentation for the new pending stage, explicit canonical strict-clock
signed transaction and persisted restart/replay proof, independent
two-node BFT concurrency and partition testing, complete panel signing/
privacy activation, time-of-height eligibility and adversarial reviewer
entry/exit, and all severe-sanction authority gates. No `ACCOUNT_BAN`
authority is enabled. PR77 remains Draft and testnet/public release NO-GO.

## 2026-11-02 — pending appellate panel public/API and frontend contract (candidate)

The dispute API now exposes `appeal_panel_readiness` as aggregate canonical
read-model status: pending/held, filed and assignment block heights, required
panel and substitutes, eligible candidate count and shortage reason. Raw
appeal payloads stay redacted and `appeal_total` is the canonical count;
the frontend does not attempt to render a redacted `appeals` list.

The affected owner's appeal eligibility is read from backend block height and
prior filing (with account-alias normalization). A recorded appeal is not
offered as a second filing, and an expired window is not presented as open.
Reviewer work queues exclude `appeal_pending_panel` cases with no assigned
juror. Queue and detail pages show the held-pending state, reviewer shortage
and the fact that the original filing deadline is not an appeal-decision
deadline. No raw juror mappings or appeal reasons were added to the UI.
**Pending exact-head CI.**

The state transition remains a constitutional semantic deviation requiring
independent review; API/frontend visibility is not end-to-end BFT proof.
