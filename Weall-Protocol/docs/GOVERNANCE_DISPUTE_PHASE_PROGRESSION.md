# Governance and dispute phase progression

WeAll is a pre-public-testnet protocol implementation under active hardening.

This document defines the reviewer-facing model for governance and dispute phase progression. It is not a production constitutional-governance readiness claim and does not claim public multi-validator BFT or mainnet readiness.

## Canonical rule

A governance or dispute phase can advance by either route:

1. **Block-height deadline**: the current chain height reaches or passes the phase deadline.
2. **Phase quorum**: enough eligible participants from the phase-open snapshot have acted.

The first deterministic route satisfied advances the phase. If the block-height deadline and quorum are both satisfied at the same height, the transition reason is `block_height_and_quorum`.

## Phase-open eligible snapshot

At phase open, the protocol records a deterministic denominator:

- `eligible_snapshot_height`
- `eligible_snapshot_root`
- `eligible_count`
- `quorum_policy_id`
- `quorum_bps`
- `quorum_required`

That denominator is fixed for the current phase. New users joining, users becoming newly eligible, or users becoming inactive do not silently move the quorum target while the phase is open. A new denominator is computed only when the next phase opens, or through an explicit deterministic emergency-resnapshot rule if such a rule is later added.

The snapshot is based on protocol state. Frontend sessions, peer connectivity, browser visibility, or currently-online users are never quorum authority.

## Governance phases

Governance phase status is exposed through:

- `GET /v1/gov/proposals/{proposal_id}/phase-status`
- `GET /v1/governance/{proposal_id}/phase-status`

The status response includes:

- current phase;
- phase open height;
- deadline height;
- blocks remaining;
- eligible snapshot height and root;
- eligible count;
- quorum required;
- participation count;
- whether quorum is reached;
- whether the deadline is reached;
- whether a transition is allowed;
- transition reason;
- next phase or next step;
- blocking reasons.

For governance, the denominator should represent eligible governance voters for that proposal or stage. It must not be reconstructed from current voters only, and it must not be inferred from the number of currently connected users.

## Dispute phases

Dispute phase status is exposed through:

- `GET /v1/disputes/{dispute_id}/phase-status`

For disputes, the denominator is phase-specific. Juror-review and voting phases use the assigned or eligible juror snapshot for that phase, not the entire global userbase. Once recorded, the saved juror snapshot is treated as the denominator for the phase. It is not re-filtered on every read in a way that shrinks quorum mid-phase.

## Small-network behavior

Controlled devnets and early testnet rehearsals may have small populations. The phase-status surface therefore reports small-network blockers when quorum would otherwise be satisfied by a population too small to imply public governance legitimacy.

The block-height route remains available even when the quorum route is blocked or weak. The UI and docs must not present small-network quorum as proof of production-grade governance legitimacy.

## User walkthrough

When a user opens a proposal or dispute, the UI should answer five questions:

1. What phase is this in?
2. What action can I take?
3. Does the phase end at a block height, by quorum, or either?
4. How many eligible participants were counted at phase open?
5. Has the phase advanced by quorum, block height, or both?

Reviewer-friendly labels include:

- “Voting open”
- “Ends at block 12,340 or when quorum is reached”
- “Quorum progress: 7 / 12 eligible participants”
- “Phase advanced by quorum”
- “Phase advanced by block-height deadline”
- “Phase advanced by block-height deadline and quorum”
- “Waiting for more eligible votes”
- “You are not eligible to vote in this phase”
- “You already voted”
- “Next phase: tally review”
- “Finalization available”

The UI should not show “passed” or “failed” before finalization. It should not show “quorum pending” unless backend phase status provides quorum state. It should not call the denominator “active users” when the actual source is a phase-open eligible snapshot.

## Reviewer evidence to capture

For each governance or dispute flow rehearsal, capture:

- object ID;
- phase-status response at phase open;
- eligible count and snapshot root;
- votes/actions submitted;
- phase-status response before transition;
- transition reason;
- finalization state;
- any small-network blocker reason.
