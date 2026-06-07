# Tokenomics Testnet Flow Audit

Status: implemented locked-tokenomics flow with activated-state tests.

## Flow covered

This batch covers:

1. epoch issuance minting
2. reward/issuance distribution conservation
3. supply-cap enforcement
4. activated user-to-user balance transfer
5. content tipping as transfer metadata
6. tip indexing by content and creator
7. locked-economics rejection before activation
8. wallet balance-known UX guard

## Truth boundary

This does not activate public economics.

Economics remain locked until:

1. the Genesis economic lock is satisfied;
2. `ECONOMICS_ACTIVATION` is applied through the canonical governance/system path;
3. fee-free civic/social/governance/PoH/review invariants remain enforced.

## Canonical transfer payload

The frontend and backend now share the canonical payload shape:

- `from_account_id`
- `to_account_id`
- `amount`
- `memo`
- `purpose`

Legacy aliases such as `to`, `target`, and `account` remain accepted for compatibility.

If `from_account_id` is present, it must match the transaction signer.

## Tipping

Tipping is implemented as a `BALANCE_TRANSFER` with:

- `purpose = content_tip`
- `content_id = <content id>`

The backend indexes tips under:

- `economics.tips_by_content_id`
- `economics.tips_by_creator`

This makes content tips auditable without adding a new token transfer type.

## Epoch issuance

WeCoin issuance is epoch-based, not per-block. One issuance epoch is 10 minutes. At the 20-second target block interval, one issuance epoch equals 30 blocks.

`BLOCK_REWARD_MINT` is retained as the legacy system transaction name, but its v1.5 payload represents a single issuance epoch. It validates the supply cap before mutating reward state and records the issuance epoch so a second mint for the same epoch is invalid.

`BLOCK_REWARD_DISTRIBUTE` must debit a funding source such as `MINT_POOL` and credit recipients with equal debit/credit totals.

Exact replay by the same block/epoch id is deduped and must not inflate supply or double-credit recipients. A different mint for an already-issued epoch is rejected.
