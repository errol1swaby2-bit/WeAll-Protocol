# PR #93 — A03: public read availability and legacy scoped-comment parity

**Input exact source head**: `233d7bcf967ef61896967d3e5252b527b7e7393f`. **Classification**: source-level P0 privacy/read-contract hardening. Not a V2 review acceptance or independent network approval.

## Source-level failure modes corrected

1. The shared historical `_snapshot(request)` helper swallows missing executor/read failures as an empty dictionary. For the anonymous public-lobby route this previously caused an indistinguishable HTTP 200 / empty thread. The new `_required_public_lobby_snapshot` returns **503 `public_lobby_state_unavailable`** when the executor is missing, cannot read, raises, or returns non-object state. A genuinely valid empty dictionary remains a legitimate 200 / empty thread. This is deliberately scoped to `GET /v1/public-lobby/comments`; no speculative global availability-policy rewrite was made.
2. The authenticated legacy `/v1/content/{content_id}/scoped` route used `_viewer_can_read_comment`, whose owner shortcut returned true before checking private visibility, deletion or adjudicated content hiding. This contradicted its own *public-only* route docstring and the ordinary public detail route. The scoped endpoint now uses exactly the public visibility predicate, and the backwards-compatible helper no longer grants owner bypass.
3. The ordinary public comment predicate previously checked parent visibility but omitted direct moderation/dispute visibility of the comment itself. It now checks `_content_target_hidden_by_review` for the comment's canonical identity. At public detail, scoped detail, lobby list, thread list, and comment counts, the known state-map index is passed explicitly to avoid an alias covering up a moderation target. This does not change the underlying consensus adjudication rule or visibility status stored on-chain.

## Tests and evidence boundary

Added regressions exercise unavailable/malformed/throwing snapshots, normal and legitimately empty snapshots, private comments by authenticated owners, directly moderated ordinary comments, deleted comments, legacy index aliases and normal visible public comments. The existing separate M4.2 positive Tier-0 rehearsal still needs an exact-head rerun after the source modification.

The broader public-lobby whole-state scan remains potentially expensive; a 50-result output cap does not bound total scan cost. The V2 route semantic review is still missing an accepted record, and 20 transaction semantic reviews remain stale. The independent Genesis/PoH/BFT/legal/capture-safety release gates remain **NO-GO**.

Because source changed, the B528/B534/B567 deterministic completion proofs must be rerun and refreshed **only if** the full source-bound harness reports non-freshness equivalence and leaves every locked boundary disabled. Neither this document nor a passing local regression confers release authorization.
