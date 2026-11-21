# WeAll public-testnet review — combined backend and frontend audit index

**Audit-only, draft PR #97.** The implementation baseline remains [`6d3d69234415d294936d99e819367cff589ced3d`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d). This is **one pull request with two separate audit tracks**; it is not a release candidate, defect-remediation patch, or authorization to deploy.

## Start here

| Track | Primary evidence | Finding system | Status |
| --- | --- | --- | --- |
| Backend, protocol, consensus and public-testnet safety | [Living complete backend audit](FULL_REPORT.md) and [immutable backend evidence archive](evidence/WeAll_Master_Audit_Reaudit_Through_R1A.zip) | **TN-001–TN-081** (21 provisional P0; 60 provisional P1), plus 8 separate cross-domain candidates | **81 open; 0 formally closed.** Source and diagnostic evidence vary by finding. |
| Web frontend, UX, navigation, onboarding, civic interfaces and accessibility | [Full frontend Phase 1–12 ledger](frontend/FRONTEND_MASTER_LEDGER_PHASES1-12.md) and [finding index](frontend/FINDINGS_INDEX_FE001-FE064.md) | **FE-001–FE-064** (mixed severities, some candidates/program dependencies) | **64 documented; 0 closed by this audit.** Source rechecks do not constitute browser reproductions. |
| Frontend acceptance | [233-case execution register](frontend/ACCEPTANCE_233_CASES.csv), [14-journey matrix](frontend/JOURNEY_COMPLETENESS_MATRIX.md), [prioritized browser handoff](frontend/PRIORITIZED_ACCEPTANCE_HANDOFF.md) | Existing test case IDs **R2/R3/R4, P5–P11**, unchanged | **233 planned cases: none executed by the frontend audit.** Earlier CI is separately scoped. |

See [frontend/README.md](frontend/README.md) for the frontend source, test and provenance files now included in this PR.

## Related findings — coordination, not duplicate closure

| Backend audit area | Relevant frontend findings | Shared acceptance boundary |
| --- | --- | --- |
| TN-007 / TN-008 — deployment and independent acceptance | FE-001, FE-024–FE-028, FE-043–FE-050, FE-056 | Real browser, mobile, keyboard, screen-reader and multi-account evidence; successful Web CI alone is not completeness. |
| TN-015 / TN-053 / TN-054 / TN-055 — sessions and credentials | FE-017–FE-023, FE-030, FE-058, FE-059, FE-062 | Credentials, account and node provenance, revocation/recovery, and no cross-account leakage. |
| TN-016 / TN-017 / TN-018 — human verification and role eligibility | FE-002, FE-029, FE-032, FE-037–FE-039 | Canonical eligibility governs actual authorization; frontend labels and prompts must match it. |
| TN-019 / TN-021 / TN-022 / TN-023 / TN-066–TN-072 — ballots/governance | FE-033–FE-036, FE-039, FE-043, FE-063 | Frozen electorate, redaction, vote options, tally and truthful eligibility presentation. |
| TN-025 / TN-026 / TN-030 / TN-058 / TN-059 — media and evidence | FE-031, FE-032, FE-047, FE-048, FE-052, FE-055 | Confidential access, provenance, publication accessibility and failed media states; one test never proves the other track. |
| TN-061–TN-065 / TN-081 — transaction/observer truth | FE-013, FE-022, FE-035, FE-041, FE-042, FE-051, FE-057, FE-064 | Submitted, accepted, included, finalized, rejected and unknown are distinct; origin node matters. |

**No crosswalk entry means “same defect,” “fixed,” “tested,” or “closed.”** A case may require independent backend and frontend fixtures and separate acceptance reports. FE- and TN-numbered findings must retain their native severity, evidence level, original text and closure requirements.

## Current evidence and release posture

- Protocol implementation and `web/` source were **not changed to combine the audits**. The frontend findings document the pinned implementation baseline; adding documentation does not validate runtime behavior.
- Existing PR #97 [Web CI run 44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) passed its selected jobs; other PR checks failed. Do not infer 233 frontend-case PASS outcomes from that.
- Backend R1B/R1C helper diagnostics include reproduced test- or merge-boundary failures; they do not prove production canonical ledger exploitation or authorize a patch.
- Independent test results, remediation, release gates and branch protection remain unchanged by this documentation.
- **Public participatory testnet: NO-GO. PR remains draft and unmerged.**

## Archive provenance

The earlier complete frontend Phase 1–12 source ZIP (`WeAll_Frontend_ReadOnly_Audit_Phases1-12_2026-11-20.zip`) contains **82 historical members**, SHA-256 `1b7e637ebd47f7ffc34a67de0ba6cc4e88ac8bf14d8b19d7814bfdb86862a99b`. Its complete original archive binary is **not committed in this GitHub tree**; the full master findings and 233-case CSV were imported as Git-tracked reviewable text, with additional key matrices and runbooks. Do not describe this as an exact binary-archive replacement.
