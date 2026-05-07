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
- production consensus profile hash
- consensus-affecting tx payload limits

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


## Current production profile snapshot

Current audited production profile:

- protocol version: `2026.03-prod.6`
- protocol profile hash: `7f014fb5ff451081b56cc1bd818a820cf7460c00be854adfb6118f082032a991`
- transaction canon: `230 tx types, version 1.25.0`

The production profile includes tx payload limits. Public validators must not
change these through local environment drift; mismatched values are startup or
handshake failures, not local policy differences.

## Public validator posture

Production observer nodes may remain read-only. Public validator service or
validator signing posture requires BFT enabled, active validator authority,
matching profile hash, matching tx index hash, matching chain ID, and epoch/set
hash compatibility before signing.

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **230 transaction types**, canon version **1.25.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, no required Cloudflare, no required SMTP, and no required DNS are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

