# PR #93 — A03 bounded lobby read evidence freshness

**Implementation and test input head:** `0a62aa86915101d0a20c5097ef21ebcb1ce14f6b` (the exact source commit, following a test-only Ruff style adjustment).
**CI source proof:** [PR93 B5xx full-harness diagnostic run 43960352973](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43960352973), successful job `133625773609`.
**M4.2 two-user regression:** [run 43960353224](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43960353224), both jobs successful. The public-lobby read model suite passed **17** cases with the pinned Ruff checker; signed Tier-0 negative and positive real-stack browser scenarios passed independently.

The three generated evidence files in this commit are the exact decoded JSON contents emitted by the full-harness diagnostic, which ran on the pinned input source commit. The previous JSON and regenerated JSON are identical except for their **freshness** records. All existing `ok=true` results and locked activation boundaries remain unchanged.

| Proof | Prior source digest | Source-bound refreshed digest |
| --- | --- | --- |
| `b528_b532_completion_proof_v1_5` | `7a3638c1768df84e1f26c4ff5fe757da79d542a27619a23da762c4e46ccd0711` | `f7555f2a065ec7eca6629e31aee1af1b49aa4da4468ab4e62edb8a8d4b32e49f` |
| `b534_b538_completion_proof_v1_5` | `882c9cb69e9d24622b1a22ad0fb341d42ed3512a1d509ab97c39696c4e70d4a7` | `82404be9b86eba9f28f3b748c5bf5ee713747badb3e8a706f259a16e74014553` |
| `b567_b571_autonomous_mechanics_proof_v1_5` | `5fc421926d6e68618945cb2d5e0175124cc59edeb53937138f1b11e0c0f39e91` | `2eec6a16edf5263f38818745be661a252ff61edbe3e92eb2c353f5ab65b88175` |

The bounded lobby read patch retains existing canonical pagination, but performs only the first `limit+1` full visibility checks on healthy pages. It rejects work exceeding the explicit global scan, dispute history, cursor length, or visibility check budgets with HTTP 503/400, rather than misreporting truncated pages as final. This is **not** a durable indexed read, and a node beyond any interim 503 limit remains non-operational on this endpoint until an authenticated committed-state index exists.

**NO-GO remains:** the strict V2 compiler still requires a semantic review for the registered public-lobby route plus adjudication of ~20 stale transaction contracts. Nothing in this artifact restores independent BFT finality, production helper activation, real PoH Tier-2, independent operator approval, genesis acceptance, public beta access, or live economic policy. These are review-only and test-only changes without release authority.

This evidence-only update itself requires fresh exact-head CI; do not infer green CI for the resulting commit from successful runs on its parent.
