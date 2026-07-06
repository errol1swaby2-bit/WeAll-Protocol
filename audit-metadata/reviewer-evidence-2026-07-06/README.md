# Reviewer evidence bundle — 2026-07-06

This bundle is commit-bound evidence for NLnet / public-testnet reviewer readiness hardening.

Commit under review: `514871321519837ac33278fc634523e1c8202686`

Current reviewer-facing claim preserved by this patch:

> WeAll is a pre-public-testnet protocol implementation under active hardening.

This bundle records commands actually run in this sandbox. It does not claim public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, production encrypted/private messaging, or first external observer readiness.

## What was run

| Transcript | Result | Purpose |
| --- | --- | --- |
| `transcripts/00_commit_environment.txt` | recorded | Commit hash, git status, timestamp, Python, Node, npm, kernel summary. |
| `transcripts/01_git_patch_checks.txt` | passed | `git status --short`, `git diff --check HEAD~1..HEAD`, and patch stat. |
| `transcripts/02_generated_artifact_consistency.txt` | passed | Generated artifact checks for public beta blocker report, release evidence manifest, public-only audit, protocol upgrade plan, helper topology plan, tx index, v1.5 public readiness artifacts, and reviewer truth boundaries. |
| `transcripts/03_backend_targeted_pytest.txt` | passed | 87 targeted backend/doc/protocol tests for public-only posture, direct-message quarantine, protocol upgrade record-only semantics, helper posture, observer authority, reviewer traceability, release truth sync, and public-readiness artifacts. |
| `transcripts/03b_observer_capture_script_checks.txt` | passed | Executable and non-authority/non-closure checks for observer/replay/storage capture scripts. |
| `transcripts/04_frontend_source_checks.txt` | passed | Reviewer-critical frontend source checks, accessibility source check, public-only source check, and rendered civic-loop source rehearsal check. |
| `transcripts/05_npm_typecheck.txt` | failed honestly | `npm run typecheck` was attempted and failed because this sandbox does not have installed React/JSX dependencies. No typecheck pass is claimed. |
| `transcripts/06_release_hygiene.txt` | passed | Release hygiene checker after fixing required executable bits. |

## What was not run

- Remote two-machine signed observer proof was not run. Reason: this sandbox does not include a second remote machine, public endpoint, operator identity secrets, or network conditions required to produce fresh remote signed observer evidence.
- First external observer readiness was not claimed. The runbook path is documented in `Weall-Protocol/docs/testnet/OBSERVER_PROOF_POSTURE_AND_CAPTURE.md`.
- Long-running public observer boot evidence was not captured in this bundle. Reason: it requires a node launch/evidence session rather than a static patch validation pass.
- Full Playwright/browser E2E was not run. Reason: frontend dependencies/browser/backend service were not installed/running in this sandbox. Source-level deterministic checks were run instead.
- Full `pytest -q` completion is not claimed from this bundle. Targeted backend coverage was run and passed; full-suite completion should be captured in a clean local checkout or CI environment with enough time budget.

## Claim boundaries

- Public beta readiness remains false in `generated/public_beta_blocker_report_v1_5.json`.
- Public mainnet readiness remains false.
- Public multi-validator BFT readiness remains false.
- Live economics remains false.
- Production helper execution remains false/gated.
- Protocol upgrade execution remains record-only unless explicit migration code/tests are added.
- Private/direct/encrypted messaging remains out of scope for the NLnet public-testnet claim.
- First external observer readiness remains blocked until a fresh remote/signed observer run is captured.
