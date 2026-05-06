# Validator Responsibility Production Runbook

## Purpose
This runbook is for active Node Operators who have opted into validator responsibility on a public WeAll network. Validator-set epochs and proposal authentication are consensus-critical. Baseline Node Operator status alone does not grant validator authority.

## Preflight
- Verify repository commit hash and release tag.
- Verify `generated/tx_index.json` hash matches the release manifest.
- Verify tx canon artifacts are synchronized: `python3 -S scripts/check_tx_canon_artifacts.py`.
- Verify secret/release hygiene: `bash scripts/secret_guard.sh` and `bash scripts/verify_release_tree.sh`.
- Verify production profile hash matches the release profile hash.
- Verify chain ID from genesis config.
- Verify the account has active baseline Node Operator status.
- Verify validator responsibility is active or the account is in the active validator set according to chain state.
- Verify the registered node public key matches the local node key before enabling signing.
- Verify local node clock is synchronized with NTP.
- Verify database path is on reliable local storage.

## Required secrets
- `WEALL_VALIDATOR_ACCOUNT` or `WEALL_BOUND_ACCOUNT`
- `WEALL_NODE_PUBKEY`
- `WEALL_NODE_PRIVKEY_FILE`

Store the node key outside shell history and outside the repo. The node key must be separate from the account recovery key.

## Startup checklist
1. Clone the exact tagged release.
2. Create a fresh virtual environment.
3. Install locked dependencies only.
4. Verify `generated/tx_index.json` exists and matches the published hash.
5. Start the node in observer mode first.
6. Confirm `/v1/status` and consensus diagnostics are healthy.
7. Only then enable validator signing with `WEALL_BFT_ENABLED=1` after validator responsibility/readiness is active in chain state.
8. Never combine observer mode with validator signing.

## Safety invariants
A validator must not sign if any of the following are true:
- local chain ID differs from the network chain ID
- local tx index hash differs from the release hash
- local account does not have active validator responsibility or is not in the active validator set
- proposal view leader does not match the local validator when proposing
- validator epoch in inbound proposals differs from local state
- validator-set hash in inbound proposals differs from local state
- local tx payload profile limits differ from the release profile
- validator signing is enabled while BFT is disabled
- observer/onboarding mode is enabled while validator signing is enabled

## Crash recovery
After a crash:
1. Restart in observer mode.
2. Inspect the latest committed height and finalized block ID.
3. Inspect any `bft_pending_fetch` entries.
4. Confirm the node catches up to the latest height.
5. Re-enable validator signing only after catch-up and after validator responsibility/readiness still evaluates active.

## Stalled consensus checklist
- Check active validator set and validator epoch.
- Check the current view and last progress timestamp.
- Check whether a pending QC exists for a block the node does not have.
- Check whether the local validator believes it is the current leader.
- Check peer connectivity and timeout emission.

## Upgrade procedure
- Never mix binaries from different protocol releases on the same validator-responsibility node.
- Upgrade only at an announced epoch boundary.
- Stop signing before the upgrade.
- Confirm post-upgrade validator epoch and set hash match peers before resuming validator responsibility.

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **225 transaction types**, canon version **1.24.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, no required Cloudflare, no required SMTP, and no required DNS are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

