# WeAll Protocol Runtime Consensus Profile Snapshot - 2026.03-prod.6

Repository snapshot date: 2026-05-02
Protocol version: `2026.03-prod.6`
Protocol profile hash: `a155300bfec3f3339b49cbe80e61223ec1be1cbed695114cd4438d10075f4eb6`
Transaction canon index: `1.25.0`
Transaction canon count: `233`

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
- startup_clock_sanity_required = false
- max_block_future_drift_ms = 120000
- clock_skew_warn_ms = 30000
- startup_clock_hard_fail_ms = 86400000
- max_block_time_advance_ms = 60000
- vrf_required = true
- timestamp_rule = `chain_time_successor_only`
- reputation_scale = 1000

## Pinned tx payload limits

These limits are production consensus-profile values. Public validators must not
change them through local environment drift.

| Field | Value |
|---|---:|
| max_tx_payload_bytes | 65536 |
| max_tx_payload_depth | 20 |
| max_tx_payload_list_len | 2000 |
| max_tx_payload_dict_keys | 2000 |
| max_tx_payload_str_len | 65536 |
| max_tx_payload_nodes | 50000 |

## Production safety deltas reflected in this snapshot

- Native two-tier PoH is the required identity path: Tier 1 async, Tier 2 live.
- Email, SMTP, DNS, named hosting providers, CAPTCHA, phone, OAuth, KYC, app-store identity,
  and third-party AI scoring are not required PoH authorities.
- Public validator service/signing posture requires BFT enabled.
- Validator signing and observer mode cannot be mixed.
- Production tx payload limits are profile-pinned.
- Public snapshots and unauthenticated account reads redact private/session/device/evidence internals.
- Release-tree verification rejects local runtime DBs, devnet state, helper lanes,
  demo bootstrap secret/result artifacts, and generated JSON secret artifacts.

## Operator check

Before enabling signing, validators should verify:

- chain_id matches the intended network
- tx_index_hash matches peers
- schema_version matches peers
- protocol_version matches peers
- protocol_profile_hash matches peers
- validator_epoch matches peers when BFT is enabled
- validator_set_hash matches peers when BFT is enabled
- `WEALL_BFT_ENABLED=1` before validator service/signing is enabled

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **236 transaction types**, canon version **1.25.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, SMTP, DNS, or named hosting provider is part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

Current tx canon checkpoint: 234 tx types, version 1.25.0.
