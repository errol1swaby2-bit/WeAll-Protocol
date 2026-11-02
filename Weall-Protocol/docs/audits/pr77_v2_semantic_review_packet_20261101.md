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
