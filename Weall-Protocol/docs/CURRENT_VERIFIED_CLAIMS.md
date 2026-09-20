# Current Verified Claims

> GENERATED FILE — do not edit by hand.
> Regenerate with `python scripts/gen_current_verified_claims.py`.

This artifact summarizes bounded claims supported by canonical repository artifacts.
It is intentionally commit-agnostic: final exact-commit binding is established by the
clean-checkout audit after the review-prep changes are committed.

It does **not** claim public beta readiness, mainnet readiness, completed external
cryptographic review, or a current scalar TPS measurement.

## Claim register

| Claim ID | Type | Status | Current claim | Evidence |
| --- | --- | --- | --- | --- |
| `READINESS-001` | readiness | `PROVEN_GENERATED_CURRENT` | Public beta readiness is not currently claimed. | `generated/public_beta_blocker_report_v1_5.json`<br>`generated/release_evidence_manifest_v1_5.json` |
| `READINESS-002` | readiness | `PROVEN_GENERATED_CURRENT` | Mainnet readiness is not currently claimed. | `generated/public_beta_blocker_report_v1_5.json`<br>`generated/release_evidence_manifest_v1_5.json` |
| `READINESS-003` | readiness | `SUPPORTED_BUT_QUALIFICATION_REQUIRED` | The current reviewer framing is pre-public-testnet / active hardening, not public beta or mainnet. | `docs/reviewer/CURRENT_READINESS_STATEMENT.md`<br>`docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`<br>`generated/public_beta_blocker_report_v1_5.json` |
| `TX-CANON-001` | structural_count | `PROVEN_GENERATED_CURRENT` | The canonical transaction index count and version are generated facts. | `generated/tx_index.json` |
| `BOUNDARY-AUTOMATIC_PROTOCOL_UPGRADES` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `automatic_protocol_upgrades` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-LEGAL_COMPLIANCE_READY` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `legal_compliance_ready` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-LIVE_ECONOMICS` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `live_economics` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-MAINNET_READY` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `mainnet_ready` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PRODUCTION_HELPER_EXECUTION` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `production_helper_execution` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PUBLIC_BETA_READY` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `public_beta_ready` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PUBLIC_DECENTRALIZED_MEDIA_DURABILITY` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `public_decentralized_media_durability` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PUBLIC_MULTI_VALIDATOR_BFT` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `public_multi_validator_bft` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PUBLIC_STORAGE_PROVIDER_MARKET` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `public_storage_provider_market` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `BOUNDARY-PUBLIC_VALIDATOR_ENABLED` | claim_boundary | `PROVEN_GENERATED_CURRENT` | Release claim boundary `public_validator_enabled` is not claimed/enabled. | `generated/release_evidence_manifest_v1_5.json` |
| `EXTERNAL-VALIDATION-001` | external_validation | `EXTERNAL_VALIDATION_REQUIRED` | Open release blockers still require external evidence before stronger public launch claims are allowed. | `generated/public_beta_blocker_report_v1_5.json` |
| `CRYPTO-REVIEW-001` | cryptography | `EXTERNAL_VALIDATION_REQUIRED` | Completed production cryptographic audit and production post-quantum security are not currently claimed. | `generated/public_beta_blocker_report_v1_5.json`<br>`docs/reviewer/CURRENT_READINESS_STATEMENT.md` |
| `PERFORMANCE-001` | performance | `NOT_CURRENTLY_MEASURABLE` | No scalar TPS value is asserted as a current verified performance claim by this manifest. | `scripts/check_public_claim_freshness.py` |
| `V2-DERIVATIVE-001` | generated_derivative_boundary | `SUPPORTED_BUT_QUALIFICATION_REQUIRED` | V2 structural counts and derivative fingerprints are intentionally not duplicated into this claims manifest. | `generated/v2/spec_compilation_manifest.json`<br>`scripts/compile_v2_spec.py` |
| `TEST-EVIDENCE-001` | testing | `SUPPORTED_BUT_QUALIFICATION_REQUIRED` | Volatile pytest pass counts are intentionally not stored as a durable current claim in this tracked manifest. | `.github/workflows/backend-ci.yml`<br>`scripts/check_v2_spec_clean_checkout.py` |

## Canonical generated snapshot

- Transaction types: **236** (generated tx canon version `1.25.0`).
- Public beta readiness: **not claimed**.
- Mainnet readiness: **not claimed**.
- Remaining external-evidence blocker IDs: `AUD-618-P0-001, AUD-618-P0-002, AUD-618-P0-003, AUD-633-P0-004, AUD-618-P1-003, AUD-618-P1-004, AUD-618-P1-005, AUD-628-P1-001`.

V2 structural counts are intentionally not copied here. Their canonical source is
`generated/v2/spec_compilation_manifest.json`, verified independently by
`python scripts/compile_v2_spec.py --check`.

## Performance boundary

Historical TPS measurements are not treated as current verified performance evidence.
No scalar TPS value should be promoted to a current claim without a fresh exact-subject
benchmark recording workload, crypto/signature behavior, persistence, network/consensus
scope, topology, hardware, OS/runtime, duration, repetitions, latency distribution,
throughput distribution, error rate, and resource utilization.

## External validation boundary

Internal repository evidence is not a substitute for independent cryptographic, legal,
operator, storage, cross-machine, or other external evidence required by open launch gates.
