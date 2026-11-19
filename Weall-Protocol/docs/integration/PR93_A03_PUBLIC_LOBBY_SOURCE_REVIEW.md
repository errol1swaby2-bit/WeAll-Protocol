# PR #93 — A03 public-lobby source-bound semantic findings (review only)

**Implementation source head:** `dae0aa45c6f43145c933c95501cf8f528325a7e0` (PR #93).
**Disposition:** targeted source and test repair; **V2 route semantic review not accepted**. All constitutional and public-network release gates remain NO-GO.

## Source-derived API behavior

- `GET /v1/public-lobby/comments` is a public projection (no account session requirement). The query requires a `public-lobby:` prefix and enforces a 2,048-byte maximum thread identifier. Its page size is clamped to 1–50 items.
- The handler uses committed executor state through `_snapshot`, filters synthetic-lobby comments by their explicit surface and thread, then checks deletion, visibility, moderation and dispute-based suppression using `_comment_visible`.
- Results are ordered by `(created_nonce, comment_id)` descending. The cursor binds these two fields, including equal nonces belonging to independent accounts.
- The pre-change read implementation could treat a legacy `id` alias as the content identity in visibility checks while falling back to the *dictionary index* for the public-lobby list. A malformed indexed record with no matching `comment_id` could therefore disagree with moderation keyed by the index. This is a source-consistency finding; no remote exploitation or compromised consensus state has been established.
- This increment requires an explicit `comment_id` exactly matching the state index for synthetic public-lobby records in the listing and content-detail read surfaces. Other historical comment surfaces retain compatibility. Tests cover missing and mismatched IDs and an index-key moderation record.

## Independent browser rehearsal finding

At exact head `dae0aa45c6f43145c933c95501cf8f528325a7e0`, [M4.2 GitHub Actions](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43943362855) failed a legitimate anonymous GET with HTTP **429**, not a consensus or authorization failure. The rate middleware in `src/weall/api/security.py` applies an IP-keyed in-memory token bucket. All localhost browsers and background polling share a source IP, so a burst can exhaust the default read bucket (12 requests/sec, burst 40).

The browser regression now retries **only** the idempotent anonymous GET on the server's exact `rate_limited` envelope, capped at eight attempts with 1.25-second spacing. Any other status fails normally, and canonical signed transactions/receipts are never retried by this change. This demonstrates liveness under documented throttling; it does not disable or relax rate limits.

## Not closed by this increment

1. The public-lobby handler still scans the full comment map and evaluates moderation/dispute histories while returning a bounded page. The page-size cap is **not** a bounded total CPU/database cost. Production-scale indexing and adversarial scan limits remain open performance/DoS review topics.
2. `_snapshot` currently returns empty state on read failures. A `200` empty-thread result can therefore be ambiguous with temporarily unavailable chain state. A fail-closed, observable state-unavailable read contract remains to be specified.
3. The V2 AST-derived route row is still missing its accepted semantic review. The pending transaction semantic drift also remains unresolved. No digest, approval record, stable ID, consensus state, genesis manifest, or activation authority is changed.
4. Existing `/v1/content/{content_id}/scoped` legacy owner-visibility branches and moderation suppression require separate source-level parity review; restricting malformed public-lobby index identities here does not resolve every historical content visibility behavior.
5. A passing local two-account test does **not** establish independently verified BFT finality, external reviewer independence, Tier-2 PoH issuance, or public launch readiness.

## Reproduction and acceptance

`python -m pytest -q tests/test_public_lobby_comment_read_model.py` should demonstrate canonical-map-key suppression for the added malformed fixtures. `M4.2 social read and eligibility boundaries` must validate independent signed Tier-0 submissions and publicly readable canonical records on the exact PR head, while retaining explicit BFT/PoH/Genesis no-proof markers.

This document is evidence for future named reviewer adjudication, **not that adjudication**.
