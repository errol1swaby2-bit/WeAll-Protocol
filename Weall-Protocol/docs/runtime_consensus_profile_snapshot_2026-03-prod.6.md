# WeAll Protocol Runtime Consensus Profile Snapshot - 2026.03-prod.6

Status: **HISTORICAL SNAPSHOT**.

This file records repository/runtime state as of 2026-05-02 for protocol `2026.03-prod.6`. It is not a current transaction-canon or release-readiness authority. For current transaction-canon facts, read `generated/tx_index.json`; for current readiness, read the generated release/readiness artifacts.

Repository snapshot date: 2026-05-02
Protocol version: `2026.03-prod.6`
Protocol profile hash: `0932c0ad1161d39c152e2e24d3dda3a0455567d49a386263cb1d5c6ca1f9ed25`
Transaction canon index: `1.25.0`
Transaction canon count: `233`

## Enforced production posture

- state_root_commitment_version = `weall.state-root.v2`
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

These limits are production consensus-profile values from this historical snapshot. They are retained as evidence of that profile and must not be treated as the current runtime profile without a fresh current-authority check.

| Field | Value |
|---|---:|
| max_tx_payload_bytes | 65536 |
| max_tx_payload_depth | 20 |
| max_tx_payload_list_len | 2000 |
| max_tx_payload_dict_keys | 2000 |
| max_tx_payload_str_len | 65536 |
| max_tx_payload_nodes | 50000 |

## Production safety deltas reflected in this snapshot

- Native two-tier PoH was the required identity path: Tier 1 async, Tier 2 live.
- Email, SMTP, DNS, named hosting providers, CAPTCHA, phone, OAuth, KYC, app-store identity,
  and third-party AI scoring were not required PoH authorities.
- Public validator service/signing posture required BFT enabled.
- Validator signing and observer mode could not be mixed.
- Production tx payload limits were profile-pinned.
- Public snapshots and unauthenticated account reads redacted sensitive session/device/evidence internals.
- Release-tree verification rejected local runtime DBs, devnet state, helper lanes,
  demo bootstrap secret/result artifacts, and generated JSON secret artifacts.

## Historical operator check

For this snapshot, validators were expected to verify:

- chain_id matched the intended network
- tx_index_hash matched peers
- schema_version matched peers
- protocol_version matched peers
- protocol_profile_hash matched peers
- state_root_commitment_version was `weall.state-root.v2`
- validator_epoch matched peers when BFT was enabled
- validator_set_hash matched peers when BFT was enabled
- `WEALL_BFT_ENABLED=1` before validator service/signing was enabled
