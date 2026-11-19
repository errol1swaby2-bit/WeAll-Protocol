# IHD-1 — second durable observer process and canonical receipt replay

**Candidate date:** 2026-11-14. **Branch:** `feature/pr91-ihd1-two-process-sync-20261114`. **Base:** draft PR #91. **Status:** unmerged integration rehearsal; passing evidence requires a successful exact-head GitHub Actions job.

## The critical distinction

The previous J01/J02/J18 test established a **single** controlled-devnet block producer with real browser key generation, ML-DSA-65 signing, signed `ACCOUNT_REGISTER` and `PROFILE_UPDATE`, committed application receipts, recovery in a new browser profile, public observation in an unsigned third profile, and surviving source-node restart.

This increment deliberately adds a **second backend process with its own SQLite database and node ID**. It does not create a second validator, confer real-world independence, enable public network roles, or show autonomous authenticated P2P gossip.

The second process pulls a source-provided trusted **delta state-sync response** over a **loopback operator-controlled HTTP route** and applies it through the existing executor/sync validation path. The source is frozen at a committed height after the signed browser actions so that exact-height state-root comparison is meaningful.

## Required positive evidence

1. Both source and observer APIs boot in separate OS processes with distinct SQLite file inodes. Their genesis/chain identity is pinned using `devnet_join_anchor.py`.
2. The source persists its original account and profile transaction receipts after a true backend process restart.
3. The observer starts with an empty durable DB, requests bounded trusted delta blocks from the source via `devnet_sync_from_peer.sh`, and applies them with the devnet-only state-sync API.
4. Both processes report the **same** chain ID, exact height, tip hash, state root, schema version, transaction-index hash, and profile hash, verified through `devnet_compare_state_roots.sh` (which also enforces valid controlled-devnet chain manifest status).
5. The observer independently serves the original **successful apply** receipts with identical tx ID, block ID and height and the same canonical account signing key digest, Tier-0 status, account nonce and committed profile via `verify_ihd1_receipts_after_restart.py`.
6. The observer is stopped and restarted without resetting its own DB. Both receipt and state-root checks must pass again.

The CI workflow fails closed if any check fails. The source and observer receive no private PoH evidence and no production Genesis signing material. All HTTP endpoints bind to `127.0.0.1`; dev-only state-sync operator controls are enabled only for this isolated job.

## Not established by this test

**No:** independent physical PCs, distinct verified node signing keys, production validator status, authenticated TCP mesh adjacency, autonomous gossip or scheduler, validator quorum certificates, independent network consensus finality, live PoH uniqueness, IPFS durability, Cloudflare deployment, public testnet authority, or release approval.

The existing two-PC network capture/compare helper and reviewer LAN runbooks remain the appropriate later evidence procedure. Do not reinterpret two separate local OS processes as independent hosts or validators.

**NO-GO:** Existing PR #81/#82/#88/#89/#90/#91 review state, generated-artifact and semantic-review gates, PoH approval, ballot privacy, locked economics and constitutional release conditions are unchanged.
