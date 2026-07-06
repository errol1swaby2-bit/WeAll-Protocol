# Pass 33 PQ signing transition evidence

WeAll is a pre-public-testnet protocol implementation under active hardening.

This evidence bundle records the Pass 33 transition work from classical-only ML-DSA assumptions toward profile-aware post-quantum signing gates. The patch does **not** claim quantum-proof security, production post-quantum security, completed production cryptographic audit, public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, or public beta readiness.

## Result boundary

Real ML-DSA was not implemented in this exported sandbox because no reproducible pinned ML-DSA backend was available. The patch therefore adds fail-closed scaffolding, a signature-profile registry, canonical profile-aware signing context, testnet-mode rejection of missing/unknown/disallowed profiles, generated crypto posture artifacts, and a new public-beta blocker for real ML-DSA integration and external cryptographic review.

## Key outputs

- `artifacts/crypto_inventory_v1_5.json`
- `artifacts/signature_profile_registry_v1_5.json`
- `artifacts/quantum_resistance_readiness_v1_5.json`
- `artifacts/public_beta_blocker_report_v1_5.json`
- `transcripts/targeted_crypto_tests.txt`
- `transcripts/affected_readiness_tests.txt`
- `transcripts/check_v15_artifacts.txt`
- `transcripts/check_reviewer_truth_boundaries.txt`

## Important not-run / failed gates

- Full `pytest -q` was attempted with a bounded timeout and did not complete in this sandbox export.
- `check_release_hygiene_v1_5.py` failed in the raw uploaded archive because the uploaded export did not include a `.git` directory, so `git check-ignore` could not validate ignored runtime paths. A reconstructed git checkout transcript is included for `git status --short` and `git diff --check`.
