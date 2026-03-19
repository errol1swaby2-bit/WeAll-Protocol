# Consensus Governance Surface

This document freezes the consensus-adjacent surfaces that may and may not change through governance.

## Not governance-controlled at runtime

The following properties are pinned by the production consensus profile and must not be changed by in-protocol governance without a coordinated software upgrade:

- consensus algorithm (`hotstuff_bft`)
- validator normalization rule (`sort_and_dedup`)
- leader selection rule (`deterministic_round_robin_sorted_validator_set`)
- quorum rule (`ceil(2n/3)`)
- finality rule (`hotstuff_three_chain`)
- signature verification required in production
- trusted-anchor requirement in production networking
- profile-match requirement during handshake
- strict validator epoch / set-hash binding for BFT traffic
- monotonic block timestamp requirement
- startup clock sanity requirement

These rules are frozen by `src/weall/runtime/protocol_profile.py` and consensus helpers in `src/weall/runtime/bft_hotstuff.py`.

## Governance-controlled parameters allowed at runtime

Only explicitly whitelisted parameter updates are allowed through governance/system execution.

Current allowed runtime parameter paths are defined in `src/weall/runtime/param_policy.py`:

- `params.poh.tier2_n_jurors`
- `params.poh.tier2_min_total_reviews`
- `params.poh.tier2_pass_threshold`
- `params.poh.tier2_fail_max`
- `params.poh.tier3_n_jurors`
- `params.poh.tier3_interacting_jurors`
- `params.poh.tier3_pass_threshold`
- `params.economics.transfer_fee_bps`
- `params.treasury.timelock_blocks`
- `treasury.params.timelock_blocks`

Anything not present in that whitelist must be rejected.

## Validator-set transitions

Validator-set membership may change only through deterministic state transitions that update the persisted validator epoch and validator set hash together.

Operational rule:

- validator epoch and validator set hash are consensus-binding metadata
- stale epoch messages must be rejected
- nodes must not infer a different hash encoding from the same logical validator set

## Economics lock

Genesis economics remain disabled until the constitutional lock expires and a valid `ECONOMICS_ACTIVATION` flow completes.

Governance must not be able to reinterpret already-finalized blocks or retroactively relax the production consensus profile.
