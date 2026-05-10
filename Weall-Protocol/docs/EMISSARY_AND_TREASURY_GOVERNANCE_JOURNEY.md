# Emissary and Treasury Governance Journey

This document locks the current production interpretation of emissary authority, treasury signer sync, and proposal-voted treasury spending.

## Authority split

WeAll separates three concepts:

1. **Human verification** — Tier 0, Tier 1, Tier 2
2. **Responsibility/role authority** — emissary, signer, juror, node operator, validator, GovExecutor
3. **Value movement** — treasury wallets and account balances

An emissary is not created by frontend display or local node config. Emissary authority comes from chain state.

## Global emissary lifecycle

The global protocol emissary flow is:

1. `ROLE_EMISSARY_NOMINATE`
   - user-origin
   - Tier2+ eligibility
   - creates nomination record
   - nominator auto-votes for the candidate

2. `ROLE_EMISSARY_VOTE`
   - user-origin
   - Tier2+ eligibility
   - records support for an existing or target nomination

3. `ROLE_EMISSARY_SEAT`
   - SYSTEM/GovExecutor path
   - account must exist
   - account must be Tier2+
   - account must not be banned or locked
   - role eligibility must not be revoked
   - reputation minimum, when configured, must be satisfied
   - activates the emissary in chain state

4. `ROLE_EMISSARY_REMOVE`
   - SYSTEM/GovExecutor path
   - deactivates the emissary
   - removes the account from the seated emissary set
   - resynchronizes the protocol treasury signer snapshot

The nomination/vote surface is evidence of community support. Seating/removal of protocol-level authority remains a governed SYSTEM path.

## Protocol treasury signer sync

The protocol treasury policy lives at:

```text
roles.treasuries_by_id.TREASURY_PROTOCOL
```

When the treasury is configured with:

```json
{
  "require_emissary_signers": true,
  "auto_sync_emissaries": true
}
```

then `ROLE_EMISSARY_SEAT` and `ROLE_EMISSARY_REMOVE` keep the signer snapshot aligned with seated emissaries.

Hardening rule:

- fewer than 2 seated emissaries makes the treasury inert
- signer list is cleared when the seated set falls below quorum
- threshold remains 2 so spending cannot accidentally become single-signer
- removed emissaries must not remain in the signer snapshot

## Group emissary election lifecycle

The group-level election flow is:

1. `GROUP_EMISSARY_ELECTION_CREATE`
   - created by group signer authority
   - stores candidates, voter snapshot, seat count, start/end height
   - seat count is normalized to at least 5

2. `GROUP_EMISSARY_BALLOT_CAST`
   - Tier1+ voter action
   - voter must be in the election snapshot
   - ranking must reference valid candidates

3. `GROUP_EMISSARY_ELECTION_FINALIZE`
   - group signer action
   - valid only after the election end height
   - computes deterministic STV winners
   - fills to at least 5 winners from remaining candidates if needed
   - updates group emissaries
   - aligns group signer set to elected emissaries
   - sets group treasury signer threshold to majority

## Proposal-voted treasury spend decision

This batch chooses the explicit governance-execution path:

- `TREASURY_SPEND_EXECUTE` is now an allowed governance executable action
- `GROUP_TREASURY_SPEND_EXECUTE` is now an allowed governance executable action
- governance approval only queues the execution SYSTEM tx
- treasury/group apply layers still enforce all spend safety checks

Those safety checks include:

- economics unlock and activation
- spend exists
- spend is not already executed/cancelled/expired
- timelock is satisfied
- signer snapshot has enough signatures
- signers are still valid where emissary signer validation is required
- treasury wallet exists
- recipient account exists
- treasury balance is sufficient

## Genesis economics lock rule for treasury execution

Treasury execution moves value, even when the transaction belongs to the Groups domain. Governance therefore treats both of these as economic/value movement actions during the Genesis lock:

```text
TREASURY_SPEND_EXECUTE
GROUP_TREASURY_SPEND_EXECUTE
```

Before economics unlock, proposals containing either action are rejected as `economic_actions_locked`.

## Tests

The hardening batch adds coverage for:

- global emissary nomination/vote/seating/removal
- protocol treasury signer sync after emissary seating
- clearing stale protocol treasury signers after emissary removal below quorum
- group emissary election finalization
- group signer and group treasury signer synchronization
- governance allowlisting for proposal-voted treasury spend execution after unlock
- governance rejection of treasury value movement during the Genesis economics lock
