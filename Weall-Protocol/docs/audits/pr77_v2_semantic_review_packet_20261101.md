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
