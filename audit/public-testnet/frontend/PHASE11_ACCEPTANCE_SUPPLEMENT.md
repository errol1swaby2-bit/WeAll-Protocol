# Phase 11 acceptance supplement — nine unexecuted FE-002–FE-010 specifications

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

**Why this exists:** the Phase 1 source report documents FE-002 through FE-010 but no original numbered acceptance matrix directly cites those IDs. These nine new proposed cases repair traceability without claiming source changes, running tests, or closing findings. The original work order remains authoritative for intent and scope.

| Case ID | Finding | Scenario | Fixture | Expected outcome | Evidence needed | Status |
|---|---|---|---|---|---|---|
| P11-01 | FE-002 | Tier1 group membership request and separate Tier2 creation gate | Mock Tier1 account, signed membership request, backend authorization | Frontend shows Tier1 request eligibility without suggesting group creation is Tier1; canonical backend guards remain | E2 browser+API fixture | NOT RUN |
| P11-02 | FE-003 | Feed/Groups/Decisions GET error versus successful empty response | 503, timeout and a successful zero-item response, isolated by surface | Error/stale/empty indicators remain mutually distinguishable; no failure represented as zero records | E2 browser+network faults | NOT RUN |
| P11-03 | FE-004 | Delayed Feed request must not overwrite a newer filter/sort | Return initial scope/sort response after fast second request | Only latest selected request updates visible results, counts and sorting state | E2 browser delayed fixture | NOT RUN |
| P11-04 | FE-005 | Bounded group/decision lists report their limits | Server offers 251 groups or 201 decisions; first result bounded | UI says bounded sample, correctly reports more records or unknown total; never declares complete without evidence | E2 browser+pagination fixture | NOT RUN |
| P11-05 | FE-006 | Group directory discovery follows intended v1.6 search and paging contract | Seed multiple names and >one backend page; use keyboard and mobile | Search, result context, pagination or explicit documented missing-capability disposition; no silent omissions | E2 browser+spec comparison | NOT RUN |
| P11-06 | FE-007 | Task-focused civic hierarchy and technical-copy comprehension | Anonymous and verified test personas at 320/390/1440px | Primary action, current status and next step can be identified without reading unrelated protocol detail; document observations, do not assume PASS | E3 moderated UX+assistive review | NOT RUN |
| P11-07 | FE-008 | Account-dependent directory state refresh after identity switch | Mounted directory; account A→B with changed membership/roles | No stale account A controls or membership badge under B; previous responses isolated | E2 two-account browser | NOT RUN |
| P11-08 | FE-009 | Composite-page decomposition and behavioral parity | Inspect component ownership and run focus/route/state tests after any future extraction | Engineering boundary review documented; no regression to signer/journal/recorder stability; mark architectural debt separately | E0 architectural review + future E2 | NOT RUN |
| P11-09 | FE-010 | v1.6 status requirements to frontend implementation traceability | Compare original v1.6 status checklist with exact source and per-feature tests | For every target record implemented/evidence, deferred/blocker, owner and acceptance criteria; no unsupported completion claim | E0 documentation+source parity | NOT RUN |

**Execution boundaries:** FE-009 and FE-010 require an engineering/documentation parity review as well as behavioral regressions, not a claim of an exploit; FE-007 requires human observation rather than an arbitrary accessibility pass. Preserve all original severity/evidence distinctions.
