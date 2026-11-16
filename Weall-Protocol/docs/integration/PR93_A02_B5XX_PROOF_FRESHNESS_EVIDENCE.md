# PR #93 — A02: B5xx deterministic proof freshness reconciliation

**Status:** Evidence freshness repair, not runtime semantics approval or launch authorization.
**Input source commit:** `9370b7a13d3423b1877eff5867095c607dbffcdb` (PR #93 exact head).
**CI runner:** GitHub Actions [PR93 B5xx full-harness proof freshness diagnostic](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43937402843), successful job `133545529023`.

The CI workflow checked out the source commit in a clean runner environment, executed the existing B528, B534, and B567 generators (including their existing live harnesses), and emitted canonical regenerated public JSON in machine-readable Base64 log markers. The workflow compared each regenerated object against the tracked artifact **excluding `freshness`**; no other key changed. It then executed all three generators in `--check` mode after regeneration and passed.

The corresponding artifact files in this commit are **exactly the decoded byte sequences** emitted by the above CI job. Their B5xx provenance and their source digest are recorded below. Source files in `src/weall/` and the three generator scripts and their source-input harness scripts are unchanged by this commit. A01 test formatting was corrected within the same commit to address the Ruff failure recorded by Backend CI run `43937402816`.

| Artifact | Previous source digest | Regenerated source digest |
| --- | --- | --- |
| `b528_b532_completion_proof_v1_5` | `a602b821879d80b445f6cfb273142d3189f0455bd037879facc48cd89ba8b1de` | `024845510829fdc97150dd4f2c0a960d30d330da71edb66da2559efbc816d175` |
| `b534_b538_completion_proof_v1_5` | `ff8a633458a4760d85d302afadb014a5df3718d93a58079c53e867eba0eef7f6` | `3d2e8c03e7f8f3297861529554cab88e9321dfd969abf2276a114ec5e7da4093` |
| `b567_b571_autonomous_mechanics_proof_v1_5` | `1b70cf77608ed057542fdfa065c21658ba751c0b995c4b753c642a7169983e6e` | `2778f5e9774e63fd41cef78b17b3ef20b96cd833b5397329425fa3bc22d63da6` |

## Strict boundaries

- Generator `ok=true` means the bounded existing proof harness passed. It does **not** prove independent operator control, BFT production finality, PoH/human-authority legitimacy, constitutional approval, or launch readiness.
- All existing locked `public_validators`, `live_economics`, `automatic_upgrades`, and `production_helpers` flags remain false in the artifacts that declare them.
- This change does **not** update V2 semantic-review digests or grant approval to the added public-lobby route.
- The branch remains DRAFT/NO-GO until exact-head Backend CI, Reviewer Readiness and A01–A20 P1 gates pass and the remaining constitutional and independent external-evidence gates are met.
- A fresh GitHub Actions run on the new commit must verify `--check` without regenerating proofs during its ordinary release checks. The original diagnostic had already proven the refreshed files, but no claim is made that the new commit's CI is green before its run completes.
