# v1.5 Completion Mechanics Batch 517-521

This batch continues the v1.5 implementation path by prioritizing executable mechanics over additional truth-gating.

## Scope

- **517 — Real validator network rehearsal:** adds a deterministic private validator rehearsal covering quorum finality, restart stability, partition rejection, rejoin catch-up, and observer non-authority.
- **518 — Fresh-node replay sync:** adds a replay-oriented fresh-node sync rehearsal that verifies contiguous block/delta replay and state-root equality without relying on snapshot copy alone.
- **519 — Identity/dispute safety completion:** adds PoH reviewer accountability when an upheld challenge invalidates a previously approved account, and adds a deterministic dispute target/action registry with unsupported enforcement rejection records.
- **520 — Economics/storage activation-complete but locked:** adds opt-in economics activation precondition enforcement and storage retrieval availability proof on successful pin confirmation.
- **521 — Integrated lifecycle proof:** adds an integrated proof artifact tying validator rehearsal, replay sync, locked-boundary preservation, and feed-ranking review together.

## Feed ranking review

The existing public feed was safe and deterministic, but not a complete ranking system. Its default behavior remains unchanged: public posts are filtered by visibility/moderation/tag/author and sorted by `created_at_nonce` descending.

This batch adds optional deterministic ranking modes:

- `rank=recency` / default: existing recency order.
- `rank=engagement`: state-derived reaction/comment weighted order.
- `rank=balanced`: recency plus bounded reaction/comment weighting.

The ranking is intentionally not personalized and does not use wall-clock time, randomness, floating point, locale-specific behavior, or client-local state. It is suitable for deterministic public/read-model ranking, but it is not yet a full production discovery/recommendation system.

Remaining feed-ranking gaps:

- No personalized ranking.
- No explicit reputation/quality weighting.
- No anti-brigading/downranking model beyond moderation labels and visibility.
- Ranked pagination still uses the legacy nonce/id cursor shape for compatibility; recency remains the safest default for external clients.

## Safety boundaries preserved

This batch does **not** enable:

- public validators,
- live economics,
- automatic software upgrades,
- production helper execution.

## Verification

Run:

```bash
PYTHONPATH=src bash scripts/rehearse_b517_b521.sh
```

Expected:

```text
[mechanics] OK: Batches 517-521 completion mechanics gate passed
```

Recommended targeted regression:

```bash
PYTHONPATH=src pytest -q \
  tests/test_batch517_521_completion_mechanics.py \
  tests/test_batch510_515_completion_mechanics.py \
  tests/test_batch505_509_mechanics.py \
  tests/test_batch341_344_four_gate_hardening.py \
  tests/test_ipfs_replication_assignment.py \
  tests/test_storage_revalidation_and_accounting_batch304.py \
  tests/test_feed_persists_order_after_restart_api.py \
  tests/test_batch355_media_viewport_observer_proxy.py \
  tests/test_batch447_local_rehearsal_qol_regressions.py
```
