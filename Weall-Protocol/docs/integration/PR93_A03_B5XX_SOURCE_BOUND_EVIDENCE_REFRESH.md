# PR #93 — A03 live proof freshness after public-lobby read hardening

**Input commit**: `0409b02b48633672ebf1755de5b5d52de45a920c` (the exact source commit whose Python content read paths changed).
**Source-bound execution**: [PR93 B5xx full-harness proof diagnostic, run 43949131659](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43949131659), successful job `133586617939`.
**Independent M4.2 proof scope**: [run 43949131569](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43949131569), including signed Tier-0 public-lobby read behavior; no independent BFT finality or PoH/Genesis authorization.

The proof job regenerated the existing B528, B534 and B567 JSON using its unmodified source generator scripts and full bounded rehearsal harnesses on the pinned exact source commit. Compared to the preceding tracked JSON, the only changed top-level key in each artifact was `freshness`. All non-freshness proof fields and protected activation flags remain unchanged, and the three `--check` validations succeeded after regeneration.

These three files are committed as the exact byte contents of the source-bound generator's logged Base64 evidence outputs. No consensus source, signing authority, release gate, legal gate, production helper, stake/economic setting, constitutional permission, or accepted semantic-review record is modified by this evidence-only commit.

| Proof | Previous source digest | Regenerated exact-source digest |
| --- | --- | --- |
| `b528_b532_completion_proof_v1_5` | `024845510829fdc97150dd4f2c0a960d30d330da71edb66da2559efbc816d175` | `d67682b0913a3e501651a1aa12886947ba284878a891ae8209cb99a01059ea4b` |
| `b534_b538_completion_proof_v1_5` | `3d2e8c03e7f8f3297861529554cab88e9321dfd969abf2276a114ec5e7da4093` | `c2d1c2f579e05ec8e213786a30eea92895982de911c33f3fdaafbba8246f0af7` |
| `b567_b571_autonomous_mechanics_proof_v1_5` | `2778f5e9774e63fd41cef78b17b3ef20b96cd833b5397329425fa3bc22d63da6` | `b747da0bfbff11924d4c18698ba53e77f7a3504065b2668e438eedee00ac457e` |

## Deliberate fail-closed boundary

The relevant PR still has 20 stale V2 transaction semantics and a missing accepted `GET /v1/public-lobby/comments` route review, so Backend CI and Reviewer Readiness must remain **NO-GO** until those independent semantic contracts are adjudicated. A generated proof's `ok=true` only confirms the tested bounded harness, **not** public launch or independently verified BFT finality.

The source-derived public-lobby review also identified unresolved whole-state scan cost, unavailable-executor ambiguity and legacy scoped-read parity questions, documented in `PR93_A03_PUBLIC_LOBBY_SOURCE_REVIEW.md`. This freshness update closes none of those independent review decisions.

Exact-head release checks and the M4.2 browser rehearsal should be rerun for the resulting proof-only commit. Do not claim they passed before successful exact-head run evidence exists.
