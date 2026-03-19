# WeAll Protocol Runtime Consensus Profile Snapshot - 2026.03-prod.4

Repository snapshot date: 2026-03-17
Protocol version: `2026.03-prod.4`
Protocol profile hash: `a24247787464e1e7dc062615fd8bc3b5f3a30433d415efcfdb9ae77730ecfc37`
Transaction canon index: `1.22.1`

## Enforced production posture

- sigverify_required = true
- legacy_sig_domain_allowed = false
- qc_less_blocks_allowed = false
- unsafe_autocommit_allowed = false
- trusted_anchor_required = true
- proposal_requires_justify_qc = true
- handshake_requires_profile_match = true
- handshake_requires_validator_epoch_match_for_bft = true
- monotonic_block_timestamps_required = true
- startup_clock_sanity_required = true
- max_block_future_drift_ms = 120000
- clock_skew_warn_ms = 30000
- startup_clock_hard_fail_ms = 86400000
- vrf_required = false
- timestamp_rule = `chain_time_floor_plus_wall_clock_future_guard`
- reputation_scale = 1000

## Spec-sync release note

This snapshot supersedes the earlier `2026.03-prod.3` authoritative spec artifact.

The production-readiness P0 determinism fixes reflected in this build are:

- PoH scheduler thresholds on the consensus-critical execution path are no longer sourced from node-local environment variables.
- Consensus-critical reputation thresholds use integer milli-units rather than floating-point comparisons.
- Independent validators should compare both `protocol_version` and `protocol_profile_hash` before signing.

## Operator check

Before enabling signing, validators should verify:

- chain_id matches the intended network
- tx_index_hash matches peers
- schema_version matches peers
- protocol_version matches peers
- protocol_profile_hash matches peers
- validator_epoch matches peers when BFT is enabled
- validator_set_hash matches peers when BFT is enabled
