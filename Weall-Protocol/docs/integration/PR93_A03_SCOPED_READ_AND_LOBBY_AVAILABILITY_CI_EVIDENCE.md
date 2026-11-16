# PR #93 — A03 public-only scoped content and lobby availability proof

**Pinned implementation input commit**: `790f6168bd006d6f16dfde07c6fd687c9143ee9b`.
**Read-model and browser validation**: [M4.2 full CI run 43957625806](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43957625806) — both jobs successful, including 13 Python read-model/provider regressions, two independent signed Tier-0 controlled-node browser journeys, and their explicit no-proof authority markers.
**Source-bound proof validation**: [PR93 B5xx full-harness diagnostic run 43957625367](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43957625367), job `133616381669` succeeded, with `--check` after regeneration.

The implementation now separates missing/malformed/failing public-lobby state from genuine zero-comment state (HTTP 503 versus 200), closes the authenticated scoped-comment owner bypass, and checks direct moderation/dispute suppression for ordinary comments in public and scoped detail paths, counts and threads. These are **API projection changes**, not new consensus penalties or voting rules. Scope details and explicit open issues are documented in `PR93_A03_PUBLIC_READ_FAIL_CLOSED_AND_SCOPED_PARITY.md`.

This evidence-only commit copies the exact Base64-decoded JSON bytes emitted by the pinned-source full-harness CI diagnostic. Each differs from the previous checked-in artifact only in `freshness.input_digest_sha256` and has an unchanged `ok=true` and unchanged explicit locked boundaries.

| Artifact | Previous digest | Regenerated digest |
| --- | --- | --- |
| `b528_b532_completion_proof_v1_5` | `d67682b0913a3e501651a1aa12886947ba284878a891ae8209cb99a01059ea4b` | `7a3638c1768df84e1f26c4ff5fe757da79d542a27619a23da762c4e46ccd0711` |
| `b534_b538_completion_proof_v1_5` | `c2d1c2f579e05ec8e213786a30eea92895982de911c33f3fdaafbba8246f0af7` | `882c9cb69e9d24622b1a22ad0fb341d42ed3512a1d509ab97c39696c4e70d4a7` |
| `b567_b571_autonomous_mechanics_proof_v1_5` | `b747da0bfbff11924d4c18698ba53e77f7a3504065b2668e438eedee00ac457e` | `5fc421926d6e68618945cb2d5e0175124cc59edeb53937138f1b11e0c0f39e91` |

## Release gate deliberately remains NO-GO

- No prior signed acceptance, semantic review, constitutional witness or independent operator approval was regenerated or asserted.
- The V2 compiler still has a missing public-lobby route acceptance and approximately 20 stale TX semantic contracts. Automatic digest acceptance is prohibited.
- The B5xx artifacts do not claim independent BFT finality, publicly activated PoH, deployed production helpers, or a live economy. Protected flags stay false.
- This is an exact-source diagnostic result, not a claim that the **new evidence-only commit** itself has passed all exact-head GitHub release checks. A new run is required.
- Public-lobby pagination currently scans a complete comment-map snapshot; its scale and DoS performance remain a separate P0 review item.

