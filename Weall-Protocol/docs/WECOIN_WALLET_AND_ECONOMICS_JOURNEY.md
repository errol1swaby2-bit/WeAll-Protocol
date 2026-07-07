# WeCoin Wallet and Economics Journey

This runbook documents the production-safe WeCoin journey after the Genesis economics lock hardening.

## Launch posture

Production Genesis starts with economics disabled:

- `params.economics_enabled = false`
- `params.economic_unlock_time = genesis_time + 90 days`
- civic, social, governance, identity, PoH, and networking actions remain fee-free
- anti-spam must come from PoH/session/rate-limit gates, not pay-to-progress fees

A node must treat value movement as disabled until both conditions are true:

1. the chain time has reached `economic_unlock_time`
2. governance has executed `ECONOMICS_ACTIVATION`

## Account wallet model

The current MVP wallet ledger stores ordinary WeCoin balances on account records:

```json
{
  "accounts": {
    "@alice": { "balance": 100 },
    "@bob": { "balance": 0 }
  }
}
```

The transfer transaction is:

```text
BALANCE_TRANSFER
```

Production transfer requirements:

- sender account exists
- recipient account exists
- sender is at least Tier 1 / async verified human
- sender is not banned or locked
- account nonce is valid
- tx signature is valid in production mode
- economics lock has expired
- economics has been activated by governance
- amount is a positive integer
- sender balance is sufficient

The state transition is deterministic:

```text
sender.balance -= amount
recipient.balance += amount
```

No recipient account may be created implicitly by a transfer.

## Governance activation journey

The intended activation path is:

1. a valid governance proposal includes an `ECONOMICS_ACTIVATION` action
2. the executable proposal uses an explicit validator electorate in production
3. the proposal receives enough valid votes
4. `GOV_TALLY_PUBLISH` records the passed outcome
5. `GOV_EXECUTE` enqueues the `ECONOMICS_ACTIVATION` SYSTEM transaction
6. follower replay validates the SYSTEM tx against the scheduler queue binding
7. `ECONOMICS_ACTIVATION` sets `params.economics_enabled = true`
8. account-to-account transfers, approved treasury spends, and rewards may execute only after this point

## Fee-free civic invariant

Even after activation, governance must not use fee policy as the anti-spam gate for civic/social/governance actions.

The following classes must remain fee-free in production policy:

- account registration and account safety actions
- PoH onboarding actions
- social/content/community participation gates that are intended to be PoH-gated
- governance votes/proposals where the protocol design says participation is human-gated
- peer advertisement and observer onboarding primitives

Positive fees for those classes are rejected by the economics apply layer.

## Rewards and treasury before activation

The following must fail before economics activation:

- `BALANCE_TRANSFER`
- epoch issuance and reward distribution
- creator rewards
- treasury reward allocations
- protocol treasury spend execution
- group treasury spend execution
- positive fee activation for civic/social/governance actions

## Tests

The hardening batch adds coverage for:

- Genesis economics lock still blocks treasury value movement proposals before unlock
- governance can allow proposal-voted treasury spend execution only after the economics unlock
- rewards stay disabled before activation
- existing WeCoin account-to-account balance tests remain green
- existing fee-free civic/social/governance invariant tests remain green
