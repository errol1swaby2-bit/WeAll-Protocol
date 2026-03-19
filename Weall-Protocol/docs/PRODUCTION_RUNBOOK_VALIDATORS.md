# Independent Validator Production Runbook

## Purpose
This runbook is for independent validator operators running a public WeAll network.
It assumes validator-set epochs and proposal authentication are consensus-critical.

## Preflight
- Verify repository commit hash and release tag.
- Verify `generated/tx_index.json` hash matches the release manifest.
- Verify chain ID from genesis config.
- Verify validator account and validator pubkey have been registered on-chain before enabling signing.
- Verify local node clock is synchronized with NTP.
- Verify database path is on reliable local storage.

## Required secrets
- `WEALL_VALIDATOR_ACCOUNT`
- `WEALL_NODE_PUBKEY`
- `WEALL_NODE_PRIVKEY`

Store keys outside shell history and outside the repo.

## Startup checklist
1. Clone the exact tagged release.
2. Create a fresh virtual environment.
3. Install locked dependencies only.
4. Verify `generated/tx_index.json` exists and matches the published hash.
5. Start the node in observer mode first.
6. Confirm `/v1/status` and consensus diagnostics are healthy.
7. Only then enable validator signing.

## Safety invariants
A validator must not sign if any of the following are true:
- local chain ID differs from the network chain ID
- local tx index hash differs from the release hash
- local validator account is not in the active validator set
- proposal view leader does not match the local validator when proposing
- validator epoch in inbound proposals differs from local state
- validator-set hash in inbound proposals differs from local state

## Crash recovery
After a crash:
1. Restart in observer mode.
2. Inspect the latest committed height and finalized block ID.
3. Inspect any `bft_pending_fetch` entries.
4. Confirm the node catches up to the latest height.
5. Re-enable validator signing only after catch-up.

## Stalled consensus checklist
- Check active validator set and validator epoch.
- Check the current view and last progress timestamp.
- Check whether a pending QC exists for a block the node does not have.
- Check whether the local validator believes it is the current leader.
- Check peer connectivity and timeout emission.

## Upgrade procedure
- Never mix binaries from different protocol releases on the same validator.
- Upgrade only at an announced epoch boundary.
- Stop signing before the upgrade.
- Confirm post-upgrade validator epoch and set hash match peers before resuming.
