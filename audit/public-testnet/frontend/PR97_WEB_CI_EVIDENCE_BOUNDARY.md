# Phase 12 — PR #97 current CI and browser-test coverage boundary

**PR:** [https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97) · **head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` · **base `main`:** `6d3d69234415d294936d99e819367cff589ced3d`.

## Version equivalence

Connected GitHub comparison in Phase 11 showed PR #97 four commits ahead with eight additions/changes, all under `audit/public-testnet/` and `.github/workflows/`; **no `web/` file changed**. Phase 12's comparison to live `main` returned `identical` at canonical `6d3d69234415d294936d99e819367cff589ced3d`. Therefore PR #97's successful existing frontend jobs test the same **source tree** inspected here, but note that test environment and backend fixtures differ from each planned acceptance case.

## Existing PR checks (historical, not rerun)

| Workflow | Run | Outcome | Scope note |
|---|---|---|---|
| Web CI | [44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) | SUCCESS | Four completed successful frontend jobs; selected browser smoke/functional tests, typecheck, dependency checks |
| Backend CI | [44799230934](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230934) | FAILURE | Overall PR cannot be called ready |
| Reviewer Readiness Gate | [44799230972](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230972) | FAILURE | External review/release gate unclosed |
| Repository-wide change coverage candidate | [44799230878](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230878) | FAILURE | Audit/coverage approval unclosed |
| Public Testnet Audit (diagnostic only) | [44799231043](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799231043) | SUCCESS | Diagnostic success is not launch authorization |

From the prior exact-head CI inspection, Web CI jobs included production deployment/Chromium smoke, compiled browser custody isolation, theme import/export and contrast, active deliberations, and frontend dependency security. The test runner at `web/playwright.config.ts` is configured for **Desktop Chrome**, not an explicit 320px/390px/mobile screen-reader matrix.

## Not established by these tests

- The source-only accessibility checker asserts the presence of the skip-link text and target, **not** activation and hash-route preservation (B01).
- The rendered deliberation test exercises proposal discussion and private ballot presentation, **not** a canceled reviewer `prompt()` and zero signing attempts (B03).
- No inspected existing Web CI step establishes the `unknown` tx-status post-composer continuation branch, draft preservation, and exact receipt outcome together (B06).
- A successful TypeScript build, CSP test, or theme contrast check cannot be substituted for mobile focus, real keyboard interactions, reviewer authorization cancellation, live-room media permission, or conditional post transaction states.

## Test execution record

Phase 12: no PR checkout, CI rerun, browser launch against the actual frontend, signed action or network write. Do not ascribe `PASS` to any of the 233 audit case IDs on this basis. Source grades (E0) and existing CI evidence (E1) remain separate fields from runtime test results (E2/E3).
