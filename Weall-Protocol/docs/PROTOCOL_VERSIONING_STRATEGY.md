# Protocol State and Versioning Strategy

## Principles
1. Consensus validity must never depend on undocumented local environment flags.
2. Consensus messages must carry enough metadata to be self-verifying.
3. Validator-set transitions must be epoch-bound.
4. Replay on a fresh machine must produce identical results.

## Required versioned surfaces
- chain ID
- protocol version
- tx canon index hash
- validator epoch
- validator-set hash
- state schema version

## Consensus message contract
Every proposal, vote, timeout, and QC should carry:
- `chain_id`
- `view`
- `validator_epoch`
- `validator_set_hash`
- signer/proposer identity and signature

## Activation rules
- protocol version changes activate only at explicit on-chain boundaries
- validator-set changes activate only at committed epoch boundaries
- old-epoch messages remain valid only for the epoch that produced them

## Operator compatibility rules
A validator must fail closed if:
- protocol version is unsupported
- tx index hash mismatches
- chain ID mismatches
- validator epoch/hash mismatch is detected in live consensus
