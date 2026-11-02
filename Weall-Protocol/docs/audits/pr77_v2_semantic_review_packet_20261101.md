# PR77 V2 semantic decision packet — NOT a review approval

The V2 compiler correctly fails closed for 15 stale semantic-review digests.
The generator `scripts/pr77_v2_semantic_review_packet.py` constructs
a source-bound, inspectable per-TX comparison. It records the historical
approved digest, compiled-matrix material digest, current material digest,
implementation source paths, all changed material fields, and recorded
review provenance, and writes a standalone JSON review packet.

The packet is deliberately **read-only**: it never edits
`specs/v2/source/semantic_reviews.json`, never invents a reviewer,
and never claims independent semantic adjudication.

The output also detects whether the previously generated V2 matrix
actually hashes to the recorded review digest. Failure of this binding
means an authoritative review cannot infer original accepted material
from that matrix without retrieving the actual earlier approved revision.

The 15 outstanding TX types remain split into source attribution
(`DISPUTE_OPEN`), dispute decisions, finality, account ban authority,
and versioned roles/reviewer eligibility. Category labels are
triage labels, **not approval decisions**. The prior audit is
`docs/audits/pr77_ci_semantic_adjudication_queue_20261101.md`.

The companion test and CI require the expected 15-review inventory,
a 236-TX unique register, no unregistered state IDs, and zero newly stale
contracts beyond those 15. A drift change fails rather than refreshing
semantic approvals.

**Closure** requires actual prior-vs-current semantics and runtime
regressions per transaction, explicit authorized human signoff for
the changed digest, pinned old-ledger replay, and clean checkout V2
derivatives. No public-testnet or Mainnet authorization.

## Expanded versioned role/reviewer runtime comparison

The existing Issue #72 independent reference comparison already spans
version absent/v1/v2, eligible and restricted accounts, and seven of the
nine stale role/reviewer TX types. The new regression rows include
`ROLE_JUROR_REINSTATE` and `REVIEWER_LANE_OPT_OUT`.

Additional full-dispatch checks assert v1 legacy reinstatement vs explicit
v2 canonical-event disqualification, exact rollback of rejected
reinstatement, and reviewer-duty withdrawal even when the member is
ineligible to activate a juror role. These tests confirm **current-version
policy** only; they do not accept nine source-review digests or prove
replay compatibility with old blocks. Runtime review must still inspect
source attribution and registered failure codes separately.


## DISPUTE_VOTE_SUBMIT: first source/runtime cross-bound review (2026-11-01)

**Disposition: REVIEW EVIDENCE COMPLETE FOR THIS NARROW GUARD; THE REVIEW IS NOT ACCEPTED.**

The previously accepted `DISPUTE_VOTE_SUBMIT` material remains anchored by its archived generated digest, and the current implementation source attribution is unchanged. The only `tx_review_material` delta is `failure_codes`: added `forbidden:severe_appeal_fresh_panel_unverified`, removed none. The hardening is in `_apply_dispute_vote_submit` at the start of severe appeal voting: a constitutional-clock, explicitly severe account appeal must have both the strict ballot profile and the structurally verified fresh appeal panel before reaching vote/account/reputation mutations.

The pre-existing `tests/test_pr77_severe_appeal_twenty_vote_guard.py` exercises the exposed executable behavior: seven malformed second-panel fields reject without state mutation; 17 ordinary votes cannot finalize a 20-vote severe appeal; the 20th structurally valid vote reaches only `appeal_resolved` and does **not** emit an `ACCOUNT_BAN` or `DISPUTE_FINAL_RECEIPT`; legacy-clock voting retains its current compatibility behavior. The associated new packet regression requires that this be the **sole V2 field and rejection-code change** for `DISPUTE_VOTE_SUBMIT`. Dedicated V2 packet CI now executes the existing runtime guard tests alongside all 15 diff checks.

**Limit:** these are synthetic current-runtime tests. A structurally correct panel does not authenticate ballot signatures, an automatically selected independent appeal, valid SYSTEM queue provenance, or historical replay across versions. Adding this rejection changes replay-observable behavior under the constitutional clock; it must be explicitly reviewed with real old-height evidence. The accepted digest in `semantic_reviews.json` has **not** been replaced; no reviewer/waiver/activation authority is inferred.


## DISPUTE_RESOLVE / DISPUTE_APPEAL: source-bound adjudication evidence (2026-11-01)

**Disposition: EXECUTION CHARACTERIZED; V2 REVIEW STILL UNAPPROVED.**

The new `tests/test_pr77_dispute_resolve_appeal_semantic_adjudication.py` pins both rows to their previously accepted V2 digests and confirms each has precisely two changed review-material fields: `failure_codes` and `state_reads`. The compiler's `implementation_source` remains identical to its accepted review in both cases; no current digest has been accepted.

| Transaction | Added rejection reasons | Removed reasons |
| --- | --- | --- |
| `DISPUTE_RESOLVE` | `conflict:automatic_severe_appeal_already_assigned`, `forbidden:severe_sanction_initial_outcome_mismatch`, `forbidden:severe_sanction_initial_twenty_votes_unverified` | None |
| `DISPUTE_APPEAL` | `conflict:automatic_severe_appeal_already_assigned` | None |

The direct-applier regressions prove the following current synthetic cases: fewer than twenty structurally accepted first-panel yes votes cannot resolve a severe account case; a SYSTEM-labeled resolution whose outcome contradicts those votes is denied; an existing automatic panel record blocks duplicate experimental resolution; an existing automatic panel record also blocks manual replacement even after the experimental selection flag is disabled. Each of these denials is asserted to leave the entire supplied test state unchanged. Legacy-clock resolution is separately checked to preserve its historical local behavior. A resolution outside the experimental path remains appealable and does not emit ban/final receipt merely from stored vote metadata.

**Important distinction:** The synthetic `TxEnvelope(system=True)` is not evidence of an authenticated SYSTEM queue producer, valid cryptographic ballot signatures, panel provenance or consensus scheduler finality. Nor does a source-observed `state_reads` change prove historical replay equivalence. The experimental automatic-appeal flag remains a test-only behavior; this review does not establish lawful automatic appeal, quorum, sanction authority or public network eligibility.

The strict `PR77 V2 decision packet (no semantic approval)` run [41373403927](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41373403927) passed **252 tests**, Ruff lint and format, and reported **15 still-stale TX reviews**, zero newly stale TXs, zero missing state stable IDs, zero archived approval digest mismatches, zero packet integrity blockers, and **no altered approvals**.

**Next blockers:** real queue-bound signed receipts, pinned historical ledger replay across legacy and activated profiles, constitutional adjudication of severe cases and separate authorized maintainer/independent reviewer acceptance of both current V2 digests. The compiler must remain fail closed until those requirements are satisfied.


## DISPUTE_FINAL_RECEIPT: version-sensitive finality/no-bypass adjudication (2026-11-01)

**Disposition: READ/EXECUTION EVIDENCE ONLY; NO SEVERE SANCTION AUTHORIZATION.**

The exact accepted V2 `DISPUTE_FINAL_RECEIPT` archive digest still binds to the same `implementation_source` as the current scanner. Exactly two semantic-review material fields have drifted: `failure_codes` and `state_reads`. The sole added rejection is `forbidden:severe_sanction_automatic_appeal_unimplemented`, with no removed failure reasons.

The existing `tests/test_pr77_severe_account_finality_no_go.py` directly verifies that under the constitutional clock an explicitly severe account case or incoming unclassified `ACCOUNT_BAN` cannot finalize, while ordinary content/lock cases retain their distinct path and legacy-clock behavior remains separate. The new regression adds an **already-present final-receipt ID** to the case, then attempts an identical `DISPUTE_FINAL_RECEIPT` under constitutional clock: the severe hold must reject before the deduplication shortcut, without any mutation. An equivalent legacy-clock duplicate must continue to return `deduped=True` and leave state unchanged.

This is an important provenance boundary: an untrusted duplicate marker is neither approval of an appeal nor authority for an account ban. These are synthetic applier tests; the real authenticated queue, committee evidence, old-height replay roots and chain-committed activation are not yet proven.

The approved semantic review record remains untouched. A completed source/effect review, genuine replay fixtures and separate authorized approval are required before adopting a new V2 digest, releasing, or enabling severe sanction finality.
