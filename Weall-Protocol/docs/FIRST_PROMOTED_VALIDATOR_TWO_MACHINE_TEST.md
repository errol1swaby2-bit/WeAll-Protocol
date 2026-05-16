# First Promoted Validator Two-Machine Test

This is the first safe target for proving the complete journey:

```text
genesis node
-> external observer node
-> signed onboarding
-> account/device/peer/PoH case
-> native/live verification or auditable bootstrap Tier2
-> node-operator activation
-> validator readiness verification
-> validator activation and validator-set update
-> reboot second machine as validator
-> local validator live gate
```

## Machine A: genesis

1. Boot genesis in production posture.
2. Build and publish the public observer bundle.
3. Keep `/v1/chain/identity`, `/v1/status`, `/v1/status/consensus`, and `/v1/accounts/{account}/operator-status` reachable to Machine B.
4. Commit the required system/governance authority transactions only through the real protocol path.

## Machine B: observer then validator

1. Run `scripts/external_observer_onboarding_smoke.sh`.
2. Run `scripts/rehearse_external_observer_two_machine.sh`.
3. Run `scripts/external_observer_live_gate.sh`.
4. Complete the required PoH/role/readiness/activation path through protocol authority.
5. Run `scripts/promoted_validator_preflight.sh`.
6. Run `scripts/reboot_promoted_observer_as_validator.sh`.
7. Run `scripts/promoted_validator_live_gate.sh` after boot.

## Hard failure conditions

The test fails if any of these happen:

- observer mode and BFT/signing are enabled together;
- validator signing is enabled without active validator authority;
- chain ID, tx-index hash, manifest hash, or validator set hash mismatches;
- peer advertisement is not bound to the registered node key;
- local validator status is not active after reboot;
- local signing is not allowed by consensus state;
- the validator set has fewer than two active validators for the two-machine test.

## Required evidence to save

Save these outputs for the audit trail:

```text
external observer live gate JSONL results
promoted validator preflight JSON report
post-boot /v1/status/operator
post-boot /v1/status/consensus
post-boot promoted validator live gate output
```
