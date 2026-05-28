# WeAll Locked Tokenomics / Economics Model

Status: locked Genesis model for production-oriented rehearsal. This is not live public economics.

## Design posture

During the Genesis Constitutional Phase, economics must remain locked unless governance activation rules are satisfied. The lock is a safety feature, not an incomplete UI detail.

## Locked by default

The following must remain unavailable while economics are locked:

- WeCoin transfers;
- rewards;
- treasury spend;
- group treasury spend;
- validator/role compensation;
- protocol fees on economic transfers.

## Permanently fee-free civic/social/governance surfaces

These flows must not become pay-to-participate anti-spam mechanisms:

- account onboarding;
- Proof-of-Humanity;
- posting and group participation where protocol gates allow it;
- reports/reviews/appeals;
- governance proposals/votes during the constitutional phase;
- node/observer onboarding documentation flows.

## Activation target

Future economics activation must be explicit, auditable, and governance-controlled:

1. economics lock period is satisfied;
2. `ECONOMICS_ACTIVATION` proposal path is used;
3. activation receipts are visible;
4. wallet/treasury UI changes from locked to active only after chain state proves activation;
5. civic/social/governance actions remain fee-free after activation.

## Reviewer-ready status

A reviewer should be able to inspect `/v1/status` and see that economics are locked unless activation rules are satisfied. The UI must not show live balances, fees, rewards, or treasury spending as usable before activation.

## Batch 457 implementation surface

Batch 457 adds a concrete read model and user-facing Economics surface for the locked Genesis economics model.

- `/v1/economics/status` exposes activation status, fee-free civic protections, wallet balance visibility, treasury counts, and transfer/treasury/reward lock state.
- `/v1/wallet/{account}` exposes the same safe read model scoped to one account.
- The frontend Economics page shows WeCoin/treasury status without providing any activation or transfer controls.

This is an implementation step, not an activation step. Transfers, rewards, and treasury spending remain disabled until the existing `ECONOMICS_ACTIVATION` and governance/system rules are satisfied.

## Batch 458-461 implementation surface

The locked tokenomics model now has reviewer-facing API surfaces for activation
readiness, transfer preview, and treasury status:

- `/v1/economics/activation/readiness`
- `/v1/economics/transfer/preview`
- `/v1/treasury/status`

These routes do not activate economics and do not submit transfers. They expose
why transfers, rewards, and treasury spends are locked until the governance/system
activation path satisfies the Genesis economic lock and fee-free civic-rights
constraints.
