# PR #93 — A03 deterministic bounded public-lobby scan (interim NO-GO)

**Input PR #93 source head:** `9b51be9e040b0a587849a04d4184c6c68a5529f4`.
**Status:** bounded-scan interim safeguard, **not** a production-scale indexed read model or constitutional semantic-review approval.

## Scope

The old `GET /v1/public-lobby/comments` implementation sorted every record in the global comment map, checked moderation and dispute visibility for all qualifying comments, collected all matching visible records, then sorted the entire visible list and returned at most 50. The page-size limit did **not** bound read CPU cost or collection memory; dispute visibility also repeatedly scanned `disputes_by_id`.

This change preserves the existing canonical descending `(created_nonce, comment_id)` cursor identity, the same visible content fields, the 1–50 page limit, public-only moderation checks, and the exact original synthetic lobby surface and canonical map-key gates. It sorts only matching candidates once, invokes the potentially expensive full visibility predicate until it finds **limit+1** visible records, and refuses workloads exceeding conservative, deterministic bounds.

The fixed source-level safeguards are:
- At most **10,000** global in-memory comment rows.
- At most **2,048** direct dispute records and **4,096** dispute-target-index records.
- At most **512** per-page full visibility evaluations.
- At most **4,096** characters in an encoded pagination cursor prior to base64 decoding.

If these checks are exceeded, the endpoint returns an explicit HTTP **503** with `public_lobby_read_budget_exceeded`. It must never respond HTTP 200 with a partial page when moderation hides enough newer records that the scan budget would be exhausted. A malformed oversized cursor is HTTP 400 `invalid_cursor`.

## Material limitations

This is **not** a durable efficient index. The executor still materializes the full state snapshot before route-level guards run. A bounded scan of up to 10,000 global comments occurs for each request, with in-memory sorting of matched candidate rows. The 503 threshold means that high-adoption or dispute-heavy nodes will have an unavailable lobby until a source-authenticated committed-state read index and replay/restart consistency have been implemented and reviewed. Raising these caps without independent load evidence is not a production solution.

No on-chain state shape, consensus dispatch rule, reputation authority, validator/helper activation, economic flag, PoH issuing authority, or accepted V2 semantic-review digest is changed by this patch.

## Tests and validation

Added regressions cover output parity and deterministic same-nonce pagination (existing tests), 1,800 candidate comments with only `limit+1` deep visibility checks, deliberate global-budget overload, visibility suppression across more than 512 newest candidate rows (HTTP 503 rather than dishonest omission), dispute inventory cap, and oversized cursor rejection. The existing two-real-account M4.2 rehearsal and B528/B534/B567 full-harness source-bound proofs must pass on the exact implementation commit. **No claim of passing CI is made by this document before its run.**

The public-lobby route is still missing an accepted V2 route review; 20 transaction reviews remain stale. Reviewer Readiness, Backend CI, public Genesis and public beta remain NO-GO.

## Next-stage scalable architecture

A production replacement requires a durable per-thread read index rooted in validated, committed block/state history; atomic updates and replay/restart reconstruction; deterministic moderated pagination; total-work bounds; and a transition audit that compares indexed output with the existing canonical scan on synthetic and adversarial histories. It must avoid an unversioned process-local cache being mistaken for independently finalized consensus state.
