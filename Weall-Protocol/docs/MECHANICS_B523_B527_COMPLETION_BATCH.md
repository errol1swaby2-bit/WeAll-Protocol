# WeAll v1.5 mechanics completion batch 523-527

This batch converts several remaining v1.5 proof gaps into stronger executable mechanics while preserving locked public boundaries.

## Implemented

- **523 — Process-isolated validator rehearsal:** `scripts/rehearse_real_validator_network_v1_5.py` now uses local multiprocessing workers with explicit proposal/vote/commit/snapshot/sync messages instead of a single in-memory dictionary-only simulation. It remains a private local rehearsal and does not enable public validator promotion.
- **524 — Durable fresh-node replay sync:** `scripts/rehearse_fresh_node_replay_sync_v1_5.py` writes committed block records to a durable JSON block store, validates parent/hash continuity, replays deltas, resumes interrupted sync, and rejects corrupt blocks.
- **525 — Full lifecycle journey:** `scripts/rehearse_v15_full_lifecycle.py` now exercises concrete content, dispute, storage, locked-economics rejection, and protocol-upgrade record-only paths in addition to validator and replay-sync harnesses.
- **526 — Feed ranking correctness:** `/v1/feed` preserves legacy recency cursors but ranked modes now use score/nonce/id cursors, preventing old high-engagement posts from corrupting later ranked pages.
- **527 — Sensitive route metadata:** API contract sidecar metadata now explicitly describes session-aware PoH/session/relay/observer/feed routes instead of leaving them under generic static heuristics.

## Still not claimed

- Public validator readiness.
- Live economics.
- Automatic protocol software upgrades.
- Production helper execution.
- Personalized/reputation-weighted recommendation ranking.

## Reviewer boundary

The validator harness now uses separate local processes, but it is still a local private rehearsal, not a public multi-machine validator network.
