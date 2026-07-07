# Real WeAll Tokenomics Implementation

Status: canonical locked tokenomics model. This document describes implemented protocol mechanics, not a live public token launch.

## Core unit

- Name: WeCoin
- Symbol: WCN
- Precision: 8 decimals
- Atomic unit: 1 WCN = 100,000,000 atomic units

## Supply

- Maximum supply: 21,000,000 WCN
- Supply cap is enforced by the reward and issuance model.
- Genesis production state does not activate public economics.
- Circulating account balances are observable as account balances, but transfers remain locked until activation.

## Emission

WeCoin issuance is epoch-based, not per-block.

- Target block interval: 20 seconds
- Issuance epoch length: 10 minutes
- Blocks per issuance epoch at the target interval: 30 blocks
- Initial epoch issuance: 100 WCN per issuance epoch
- Halving interval: 105,120 issuance epochs, approximately two years
- Maximum supply: 21,000,000 WCN
- Issuance is capped by remaining unissued supply and stops exactly at the cap
- Duplicate issuance for the same issuance epoch is invalid

The legacy system transaction names `BLOCK_REWARD_MINT` and `BLOCK_REWARD_DISTRIBUTE` are retained for wire/contract compatibility, but their v1.5 payloads represent a single issuance epoch rather than a per-block reward.

## Reward split

When economics is eventually activated, each epoch issuance/reward allocation is modeled as five equal 20% buckets:

1. validators
2. node operators
3. jurors and community reviewers
4. creators
5. treasury

Any unavailable recipient bucket or integer remainder must flow to treasury or accounting policy rather than minting extra supply.

## Locked Genesis economics

Economics are real protocol mechanics, but production Genesis launches with economics locked.

Locked actions include:

- WeCoin transfers
- fee payments
- fee policy activation
- epoch issuance mint and distribution
- creator rewards
- treasury reward allocations
- treasury spend execution
- group treasury spend execution

Activation requires:

1. the Genesis economic lock to expire;
2. canonical governance or system execution of `ECONOMICS_ACTIVATION`;
3. continued enforcement that civic, social, governance, PoH, and review participation remains fee-free.

## Fee-free civic invariant

The following action classes remain fee-free and must not become pay-to-participate mechanics:

- account onboarding
- Proof-of-Humanity
- posting
- comments
- reactions
- group participation
- governance proposals
- governance votes
- reports
- reviews
- appeals
- observer onboarding
- peer onboarding

## API surface

`/v1/economics/status` exposes the canonical tokenomics read model under `tokenomics`.

The read model reports the epoch-based issuance cadence, 30-block epoch size at the 20-second target interval, initial 100 WCN epoch issuance, 105,120-epoch halving interval, hard cap, remaining supply, and locked activation state.

This is a read model. It does not activate economics or mutate balances.
