# Reputation progression and anti-farming

WeAll is a pre-public-testnet protocol implementation under active hardening.

This document describes the current reviewer-facing reputation progression model. It is not a claim of production-grade Sybil resistance, final economics, public mainnet readiness, or production constitutional-governance readiness.

## Canonical rule

A legitimate newer user should have a bounded, non-spammy path toward adequate civic participation reputation. Repetitive low-value activity must not allow unlimited reputation farming. Reputation gains and losses must be deterministic, capped where appropriate, and tied to protocol-visible actions.

## Source-of-truth surfaces

Reputation status is exposed through:

- `GET /v1/accounts/{account_id}/reputation-status`
- `GET /v1/accounts/{account_id}/reputation-progression-status`
- `GET /v1/reputation/action-map`

The progression response reports:

- account ID;
- tier;
- unrestricted status;
- total reputation in milli-units;
- reputation by domain;
- next relevant thresholds;
- meaningful actions available without spam;
- actions recently counted;
- actions capped or on cooldown;
- active penalties;
- eligibility summary;
- next step;
- blocking reasons.

## Reputation action map

The action map summarizes every currently registered reputation event with:

- action or event code;
- transaction type or source flow;
- affected reputation bucket;
- positive or negative direction;
- amount;
- duplicate/cooldown/cap posture;
- self-farming risk;
- collusive farming risk;
- spam risk;
- affected governance, dispute, juror, node, validator, or storage readiness.

The map is a reviewability artifact. It does not mean the reputation matrix is final.

## New-user progression

A quiet legitimate new user should not need to spam posts or comments. The intended path is:

1. create an account;
2. complete verification where required;
3. keep the account unrestricted;
4. participate in eligible governance or dispute actions when available;
5. complete assigned civic responsibilities responsibly;
6. avoid duplicate, harmful, or frivolous actions.

A civic participant can progress by voting when eligible, contributing meaningful public evidence or comments where appropriate, and completing assigned duties. A node operator can progress from Tier 2 through node-key registration and baseline enrollment. Validator authority uses a single deterministic readiness threshold: `VALIDATOR_REPUTATION_REQUIRED_MILLI = 3000`. Once Tier 2, unrestricted status, baseline node-operator active status, validator opt-in, verified readiness, matching registered node key, and the reputation threshold are all true, the protocol records active validator authority deterministically. Storage readiness remains separately blocked by capacity-proof requirements.

## Anti-farming posture

The current hardening posture includes deterministic source-key dedupe and capped content-related reputation accrual windows. The UI must not tell users to “earn reputation by posting more.” Instead, it should explain meaningful actions, capped actions, and blockers.

Examples of safer labels:

- “Reputation progress”
- “Meaningful actions available”
- “Daily/epoch reputation cap reached”
- “This action does not increase reputation again”
- “Validator readiness blocked by reputation threshold”
- “Storage readiness blocked by capacity proof”

## What does not count as legitimacy proof

The following must not be treated as production-grade legitimacy proof:

- frontend-visible activity;
- online status;
- repeated low-value content;
- duplicate votes;
- self-confirmation;
- small controlled-devnet quorum;
- validator/storage opt-in without the required readiness, reputation, node-key, and capacity-proof gates.

## Reviewer evidence to capture

For reputation rehearsals, capture:

- the account’s reputation-progression status before actions;
- the action map entry for each action tested;
- the submitted transactions or protocol events;
- capped/on-cooldown evidence for repeated low-value actions;
- eligibility changes, if any;
- blocker states for governance, dispute, validator, or storage readiness, including deterministic validator activation once all gates are satisfied.

Any remaining farming, collusion, or Sybil-resistance gaps should remain documented as public-readiness hardening work, not silently closed.
