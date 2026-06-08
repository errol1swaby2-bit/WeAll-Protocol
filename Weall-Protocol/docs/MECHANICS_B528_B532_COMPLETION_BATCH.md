# WeAll v1.5 Mechanics Batch 528-532

This batch addresses the remaining implementation gaps identified after the 523-527 audit while preserving locked safety boundaries.

## Included mechanics

- 528: local TCP subprocess validator rehearsal with durable per-node state files.
- 529: SQLite-backed fresh-node replay sync with receipt-root and corrupt-block rejection.
- 530: API-assisted full lifecycle journey covering session/feed read routes plus runtime state transitions across PoH, content, groups, messaging, dispute, storage, economics lock, and protocol-upgrade record-only boundaries.
- 531: PoH reviewer accountability and dispute juror inactivity eligibility consequences.
- 532: economics activation precondition expansion and storage retrieval confirmation proof while keeping live economics locked.
- Production social feed ranking: deterministic public ranking mode using bounded reputation weighting, anti-brigading unique-reaction caps, safety penalties, freshness, and author-frequency dampening.

## Truth boundary

This is still a local/private completion rehearsal. It does not enable public validators, live economics, automatic software upgrades, or production helper execution.

The production feed ranking is a deterministic public ranking system, not a personalized recommendation engine. It avoids wall-clock randomness, floating-point scoring, private profile surveillance, and nondeterministic client state.
