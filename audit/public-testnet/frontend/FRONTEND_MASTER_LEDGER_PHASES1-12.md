# WeAll Frontend — Complete Master Findings Ledger (Phases 1–4)

**Snapshot recorded by source audits:** `6d3d69234415d294936d99e819367cff589ced3d` (`main`, audited 2026-11-20).
**Reconciliation basis:** four user-supplied Phase 1–4 ZIP archives, read directly and checked for FE IDs and test IDs.
**Current disposition:** historical read-only source-review evidence; this consolidation does not verify current GitHub HEAD, execute tests, close any finding, authorize a merge, or change public-testnet NO-GO.

## Why this replaces the earlier cumulative ledger

The earlier Phase 4 cumulative file listed FE-001–FE-028 in short rows but omitted their explanatory evidence, linked source paths, remedial boundaries, acceptance scenarios, safety constraints and source uncertainty. It also retained an inaccurate “Phases 1–3” heading. This master includes **all 28 full original findings**, preserving their wording; then supplies the four **unaltered complete source reports**, all linked regression plans, source index, and execution runbook as appendices. Repetitions in the appendices are intentional audit-traceability, not separate findings.

## Reconciliation summary

| Original source | FE IDs | Total | Source status |
|---|---|---:|---|
| Phase 1 | FE-001–FE-010 | 10 | Read-only source inspection; runtime testing not executed |
| Phase 2 | FE-011–FE-016 | 6 | Read-only source inspection; runtime testing not executed |
| Phase 3 | FE-017–FE-023 | 7 | Read-only source inspection; runtime testing not executed |
| Phase 4 | FE-024–FE-028 | 5 | Read-only source inspection; rendered/browser acceptance not executed |
| **Total** | **FE-001–FE-028** | **28** | **No closure verdict derived from aggregation** |

## Interpretation and evidence limits

- **P1/P2/P3 and “candidate/investigation/backlog” are retained exactly as each phase classified them.** They are frontend audit triage, not final production-release blocker severities.
- **Confirmed source discrepancy** is not proof of exploitation or a reproduced browser failure.
- **Planned tests** are not passing results; R2-01–R2-20, R3-01–R3-21 and R4-01–R4-20 are preserved below and unexecuted in their source audits.
- Some cases test multiple findings, and some cases protect existing safeguards rather than testing a new FE defect.
- This is a faithful merger of *the documents as supplied*. It does not silently correct any historical conclusions or update them against a later repository revision.

## All 28 findings — navigable crosswalk

| Finding | Phase | Original priority | Original evidence classification | Acceptance references |
|---|---:|---|---|---|
| [FE-001 — Public Feed incorrectly disabled in five-tab navigation](#fe-001) | 1 | P1 | Confirmed source discrepancy | R4-10 |
| [FE-002 — Directory overstates the PoH requirement for joining groups](#fe-002) | 1 | P1 | Confirmed source discrepancy | Phase 1 work order (narrative regression criteria) |
| [FE-003 — API errors can coexist with “empty directory / no decisions” messages](#fe-003) | 1 | P1/P2 | Source-supported UX defect | Phase 1 work order (narrative regression criteria) |
| [FE-004 — Feed may display a stale response after scope or sorting changes](#fe-004) | 1 | P1 candidate | Reproduction required | Phase 1 work order (narrative regression criteria) |
| [FE-005 — Directory and decision-count language does not clearly communicate result bounds](#fe-005) | 1 | P2 | Source-supported UX limitation | Phase 1 work order (narrative regression criteria) |
| [FE-006 — Group directory discovery is less capable than the intended product contract](#fe-006) | 1 | P2 | Product gap | Phase 1 work order (narrative regression criteria) |
| [FE-007 — Core civic pages remain heavy with technical/context copy](#fe-007) | 1 | P2 | Product-design review | Phase 1 work order (narrative regression criteria) |
| [FE-008 — Some account-dependent directory data is initialized only on mount](#fe-008) | 1 | P2 candidate | Reproduction required | Phase 1 work order (narrative regression criteria) |
| [FE-009 — Large composite screens need bounded presentation refactoring](#fe-009) | 1 | P2 | Maintainability/product enhancement | Phase 1 work order (narrative regression criteria) |
| [FE-010 — Existing status documents flag unfinished v1.6 task delivery](#fe-010) | 1 | Program-level dependency | Documented gap, not a new defect | Phase 1 work order (narrative regression criteria) |
| [FE-011 — Reviewer queues suppress service failures](#fe-011) | 2 | P1 | Confirmed source-level state conflation; browser impact not yet demonstrated | R2-01, R2-02, R2-03, R2-04 |
| [FE-012 — Reviewer readiness assumes signer availability on several pages](#fe-012) | 2 | P1/P2 | Confirmed preflight discrepancy; backend bypass not alleged | R2-05, R2-06 |
| [FE-013 — Transaction activity history is not scoped to account](#fe-013) | 2 | P2 | Confirmed local history attribution gap | R2-15, R2-16 |
| [FE-014 — Provisional bootstrap “assigned” status can overstate reviewer authority](#fe-014) | 2 | P1 | Confirmed provisional-vs-canonical label conflation; intentional bootstrap mechanism must be preserved safely | R2-07, R2-08, R2-09, R2-10 |
| [FE-015 — Reports “Open / unresolved” counter disagrees with backend stages](#fe-015) | 2 | P2 | Confirmed inconsistent classification logic | R2-11, R2-12 |
| [FE-016 — “Assigned to me” matches past/terminal juror statuses](#fe-016) | 2 | P2 | Confirmed filter/label mismatch; may include declined/completed assignments | R2-13, R2-14 |
| [FE-017 — Selected-account identity has two disconnected sources](#fe-017) | 3 | P1 | Confirmed code-level contract divergence; impact to reproduce | R3-01, R3-02, R4-11 |
| [FE-018 — In-flight account reads are not guarded against account or node switches](#fe-018) | 3 | P1 | Confirmed async race structure; visible manifestation untested | R3-02, R3-03, R3-04, R3-05 |
| [FE-019 — Mounted pages and development Settings can retain old API targets](#fe-019) | 3 | P1/P2 | Confirmed source-level stale-target paths; browser outcomes untested | R3-06, R3-07, R3-08, R3-09, R4-12 |
| [FE-020 — Chain ID cache is global rather than tied to the selected node](#fe-020) | 3 | P2 | Confirmed cache/fallback behavior; backend rejection expected | R3-10, R3-11, R3-12 |
| [FE-021 — Missing tab-scoped session bearer may be displayed as active](#fe-021) | 3 | P2 | Confirmed conditional UI-truth gap; normal fresh-tab safeguard already present | R3-13, R3-14, R3-15, R4-13 |
| [FE-022 — Finality monitoring can follow a different node than the submitted action](#fe-022) | 3 | P2 | Confirmed provenance ambiguity; effect depends on timing and node sync | R3-16, R3-17, R3-18, R4-14 |
| [FE-023 — Session teardown can clear coordination state while an operation is still pending](#fe-023) | 3 | P1 investigation | Source-level race candidate; requires controlled reproduction | R3-19, R3-20, R3-21, R4-15 |
| [FE-024 — Skip-to-content anchor changes hash route (P1, confirmed source defect)](#fe-024) | 4 | P1 | Confirmed source defect | R4-01, R4-02 |
| [FE-025 — Duplicate top-level headings (P2, source-confirmed hierarchy inconsistency)](#fe-025) | 4 | P2 | Confirmed heading duplication; accessibility impact requires rendered review | R4-03, R4-04 |
| [FE-026 — Route-change focus is not explicitly managed (P2 candidate)](#fe-026) | 4 | P2 candidate | Source gap; browser reproduction required | R4-05, R4-06 |
| [FE-027 — Breadcrumb accessible-label semantics (P3, source confirmed)](#fe-027) | 4 | P3 | Confirmed semantics defect; screen-reader impact to verify | R4-07 |
| [FE-028 — Feed sort active state only conveyed visually (P2, confirmed source gap)](#fe-028) | 4 | P2 | Confirmed missing active-state semantics | R4-08, R4-09 |

## Detailed findings — complete original section text

Each record below reproduces its **entire finding section verbatim** from the uploaded phase report. The small identifying lines above each excerpt are additional indexing information, not a reinterpretation of the audit.

## Phase 1 — detailed findings

<a id="fe-001"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P1. **Planned linked tests:** R4-10.

### FE-001 — Public Feed incorrectly disabled in five-tab navigation
**Priority:** P1 · **Evidence:** Confirmed source discrepancy  
**Files:** [`web/src/components/PrimaryNavigation.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx), [`web/src/App.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx), [`web/src/lib/router.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts)

Five-tab navigation declares `{label: "Feed", href: "/feed", sessionOnly: true}`, then disables any `sessionOnly` destination for an unsigned visitor. The application router, however, explicitly renders `<Feed />` without authentication at `/feed`, and route metadata marks Feed public. `AppShell` renders that navigation even on public routes. This makes the first-time visitor's most important public destination appear unavailable from the primary navigation, despite being a supported public read route.

**Required behavior:** Keep public Feed navigation enabled for unsigned users while preserving backend-checked eligibility for reactions, replies, posts and other signed mutations. Verify public Feed accessibility from a fresh anonymous browser as well as logged-in navigation.

---

<a id="fe-002"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P1. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-002 — Directory overstates the PoH requirement for joining groups
**Priority:** P1 · **Evidence:** Confirmed source discrepancy  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Group.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx), [`web/src/lib/gates.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/gates.ts)

`Groups.tsx` sets both creation and membership preflights to `requireTier: 2` and labels membership “Complete live verification to join.” `Group.tsx` sets group membership request preflight to `requireTier: 1` with a comment that `GROUP_MEMBERSHIP_REQUEST` is canonically Tier 1+. This is a guidance/presentation mismatch, not evidence of backend authorization bypass. Backend authority must be checked against the current canonical transaction index, not inferred from UI-only gate logic.

**Required behavior:** Retain the higher tier for group creation if dictated by canonical rules, but derive **join/request membership** messaging from the correct transaction action's tier. Test an eligible Tier 1 account, a Tier 0 account, an unavailable account state, and a restricted account.

---

<a id="fe-003"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P1/P2. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-003 — API errors can coexist with “empty directory / no decisions” messages
**Priority:** P1/P2 · **Evidence:** Source-supported UX defect  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx), [`web/src/components/FeedView.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx)

In Groups, `refreshGroups()` catches failures and sets both `err` and an empty `groups` array, while the render condition `groups.length === 0` shows “No groups are visible yet.” The loading branch likewise initially starts with zero groups. In Decisions, `load()` catches errors and sets empty items; `filtered.length === 0` can show a no-decisions message even when loading failed. FeedView similarly clears items on non-append errors, then shows an empty-state panel alongside an inline error.

**Required behavior:** Explicit **idle/loading/ready-empty/ready-data/error** states. Never imply a complete empty canonical collection when the request has failed or is still loading. Allow retry without silently overwriting a known-good list unless the UI clearly marks data stale.

---

<a id="fe-004"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P1 candidate. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-004 — Feed may display a stale response after scope or sorting changes
**Priority:** P1 candidate · **Evidence:** Reproduction required  
**File:** [`web/src/components/FeedView.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx)

`loadPage()` asynchronously requests a page using the current `scope`, `filters` and `sort`, then directly writes `items`, `rankingInfo`, and `nextCursor`. The effect runs again when scope/sort changes, but no request generation ID, abort signal, or superseded-response check is apparent in this loading path. When a user switches global feed ↔ “My posts” rapidly, or changes ranking during network delay, an older response could arrive last and replace the newer view. Do not report this as an observed production failure without a controlled latency test.

**Required behavior:** Add a request epoch/cancellation contract; bind response to the requested scope and ranking; ensure append pagination cannot mix old and new cursors; test out-of-order backend responses.

---

<a id="fe-005"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P2. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-005 — Directory and decision-count language does not clearly communicate result bounds
**Priority:** P2 · **Evidence:** Source-supported UX limitation  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx), [`web/src/pages/Group.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx)

The Groups directory requests at most 250 records and displays “Visible groups {groups.length}”; it offers neither search nor a next-page affordance. The Decisions hub requests 200 proposals and displays “Total {items.length}” and client-derived vote/result counts. Group-specific Decisions already acknowledge they filter a bounded first 200 records and do **not** prove complete history. The global list's “Total” label is especially easy to misread as an authoritative network-wide total.

**Required behavior:** Label counts as “Returned,” “In this view,” or “Showing N”; use authoritative total only if one is returned and validated. Add server-backed search/pagination when canonical API support is available; do not implement client-only unlimited historical-count claims.

---

<a id="fe-006"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P2. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-006 — Group directory discovery is less capable than the intended product contract
**Priority:** P2 · **Evidence:** Product gap  
**Files:** `Groups.tsx`; [`web/docs/FRONTEND_V16_PRODUCT_SPEC.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/FRONTEND_V16_PRODUCT_SPEC.md)

The v1.6 target calls for searchable/filterable public groups with clear membership previews. The current directory presents the first bounded list as click-to-open cards, with no search/filter control and no explicit pagination. This is not a backend authorization flaw, but it is a material discovery limitation once communities begin to grow.

**Required behavior:** Start with accessible client filtering over the returned bounded set **only if clearly labeled as such**. Design a cursor-backed API integration separately, once backend contract, sort order, and denial cases are reviewed.

---

<a id="fe-007"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P2. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-007 — Core civic pages remain heavy with technical/context copy
**Priority:** P2 · **Evidence:** Product-design review  
**Files:** `web/src/pages/Feed.tsx`; `web/src/pages/Groups.tsx`; `web/src/pages/Proposals.tsx`; `web/src/components/AppShell.tsx`

The application shell renders its own title/subtitle, mode pill, contract note, and route-summary strip. Feed, Groups and Decisions then introduce another hero title, account/verification panels, boundary explanations, context text, statistics and action panels. This improves reviewer transparency but risks burying actual posts, groups and decisions below operational guidance. The proposed v1.6 contract favors one primary object and one clear next action per page. The UX impact requires screenshots, viewport measurements and accessibility review.

**Required behavior:** Preserve legal/security/authority truth, but move repeated technical explanations to contextual details or the optional information drawer. Give the visible list/content first-screen priority; test desktop/mobile before removing any important eligibility text.

---

<a id="fe-008"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P2 candidate. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-008 — Some account-dependent directory data is initialized only on mount
**Priority:** P2 candidate · **Evidence:** Reproduction required  
**File:** `web/src/pages/Groups.tsx`

The Groups directory calls `refreshGroups()` and `loadAccountState()` in an effect with an empty dependency array, yet derives `acct` from the current session. If authentication/account changes while that component remains mounted, the displayed account preflight and account state could be stale until a manual refresh or remount. This may be mitigated by the current navigation lifecycle; validate the actual browser sequence before calling it a defect.

**Required behavior:** Verify account-switch and session-recovery transitions while remaining on Groups. Add appropriate reactive dependencies/revalidation without creating polling loops or unsigned mutations.

---

<a id="fe-009"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** P2. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-009 — Large composite screens need bounded presentation refactoring
**Priority:** P2 · **Evidence:** Maintainability/product enhancement  
**Files:** `web/src/pages/Group.tsx` (~1,128 lines), `web/src/pages/Proposal.tsx` (~1,181 lines), `web/src/pages/ProposalCreate.tsx` (~534 lines), `web/src/components/FeedView.tsx` (~724 lines)

These pages already contain significant scope, status, access, timeline and action logic. Refactor **presentation** into focused components only after regression coverage is pinned. Do not move canonical acceptance, role checks, signer/nonce/session contracts or scope decisions into new unverified client-only authority pathways. Group election and treasury surfaces have known current-state/read-only limitations documented in main.

---

<a id="fe-010"></a>

**Original source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` → `01_MAIN_FRONTEND_AUDIT.md`. **Original priority:** Program-level dependency. **Planned linked tests:** Not assigned numbered R-cases in original Phase 1 work order.

### FE-010 — Existing status documents flag unfinished v1.6 task delivery
**Priority:** Program-level dependency · **Evidence:** Documented gap, not a new defect  
**Files:** [`web/docs/FRONTEND_V16_IMPLEMENTATION_STATUS.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/FRONTEND_V16_IMPLEMENTATION_STATUS.md), [`web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md)

The design spec is explicitly a **target**, not proof that 103 contemplated destinations exist. Status documents name incomplete PoH journey splitting, authorized profile/banner media flows, full group governance indexes/mandates, independent reviewer task workspaces, richer accessibility/visual regressions and real multi-account/browser acceptance. Some documents refer to earlier draft PR baselines, so they should be treated as historical tracking context rather than exact-head CI evidence.

---

## Phase 2 — detailed findings

<a id="fe-011"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P1. **Planned linked tests:** R2-01, R2-02, R2-03, R2-04.

### FE-011 — Reviewer queues suppress service failures
**P1 — source-confirmed.**

`web/src/pages/JurorDashboard.tsx` lines 307–348 has a `Promise.all` across independent review authorities, but individual requests catch errors and substitute empty arrays or null reviewer state:

- `pohAsyncJurorCases(...).catch(() => ({ cases: [] }))`
- `pohLiveAssigned(...).catch(() => ({ cases: [] }))`
- `pohLiveSessions(...).catch(() => ({ sessions: [] }))`
- `disputesCurrent(...).catch(() => ({ items: [] }))`
- `disputes(...).catch(() => ({ items: [], unavailable: true }))`
- `accountReviewerStatus(...).catch(() => ({ reviewer: null }))`

Only the fallback disputes list marks itself unavailable. Failed PoH assignment calls and current dispute queue calls lose their error provenance. Users can see zero cases rather than “assignment service unavailable.” This is a high-priority UX truth issue because an absent assignment and a temporarily unreadable queue are different states, especially for time-limited juror duties.

**Safer contract:** Load lane results independently with `{status: 'ready'|'unavailable', data, source, error}` and explicit freshness markers. A failed lane should never display “no assigned cases” as an authoritative fact. Do not allow action control merely because the cached queue included an item; fetch fresh case/role/assignment state before signing. Never expose protected PoH evidence before reviewer-specific backend acceptance.

**Evidence:** [JurorDashboard.tsx lines 307–349](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx#L307-L349), [backend current queue](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L766).

**Required reproduction:** Mock individual timeout/401/403/500 responses for each lane, including one failed lane while others succeed. Confirm a retry updates only the affected lane without silently turning unavailable into empty or clearing other verified queues.

---

<a id="fe-012"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P1/P2. **Planned linked tests:** R2-05, R2-06.

### FE-012 — Reviewer readiness assumes signer availability on several pages
**P1/P2 — source-confirmed preflight mismatch.**

`web/src/pages/Disputes.tsx` lines 93–99, `DisputeDetail.tsx` lines 87–93, `DisputeReview.tsx` lines 58–64 and `JurorDashboard.tsx` lines 287–293 call `checkGates` with `canSign: true` instead of deriving real local-key/session readiness. `checkGates` treats this value as the device signing preflight. In the **public** Reports and Report Detail routes, a session/account with missing key can therefore see a positive readiness cue despite not being able to sign. The protected Review Center / Review Action routes have additional outer app guards, which reduce but do not cure the inconsistent shared contract.

This is not evidence the backend will admit an unsigned action. The intended fix is device-state truth, not lower tier requirements.

**Safer contract:** Use canonical effective tier from account read model, actual local `getKeypair` availability, live session posture, and the appropriate case assignment. Maintain a `state unknown` status if the backend cannot be reached. Regenerate the gate if the session or account changes.

**Evidence:** [Disputes.tsx lines 93–99](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L93-L99), [DisputeDetail.tsx lines 87–93](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/DisputeDetail.tsx#L87-L93), [gate helper](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/gates.ts#L30-L87).

**Required reproduction:** Separate cases for signed-in Tier 2 with no local signer, expired node session, revoked/suspended tier, and fully capable user. Verify public report pages remain readable in all these states.

---

<a id="fe-013"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R2-15, R2-16.

### FE-013 — Transaction activity history is not scoped to account
**P2 — source-confirmed.**

`web/src/pages/TransactionsPage.tsx` uses global localStorage keys (`weall_tx_activity_v3`, then v2/v1), deserializes the first populated record list and displays all entries without filtering to the current account. `TxHistoryItem` has no account identity field; `account` is only obtained separately for the header. Switching between accounts within a browser may therefore display one account's local signing attempts while a different account is shown as current.

The underlying protocol transactions are publicly inspectable; this finding is primarily **attribution and multi-account UX**, not a claim of secret signing material leakage. It may nonetheless expose browser-local activity titles or errors to the next person using a shared browser.

**Safer contract:** Record explicit account, chain ID, node identity, and tx ID where known in new history entries; filter or visibly label mixed-account history. Retain unknown-attribution legacy entries separately rather than silently assigning them to the current user. Do not silently discard pending historical tx IDs during schema migration. Validate `local_state_synced` and successful apply receipts as today.

**Evidence:** [TransactionsPage.tsx lines 12–63](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L12-L63), [rendered current-account label and history](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L220-L451).

**Required reproduction:** Account A sends tx; switch to B in same browser without clearing storage; demonstrate how history is attributed. Also test legacy v1/v2/v3 records and unknown pending outcomes.

---

<a id="fe-014"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P1. **Planned linked tests:** R2-07, R2-08, R2-09, R2-10.

### FE-014 — Provisional bootstrap “assigned” status can overstate reviewer authority
**P1 — source-confirmed UI/protocol evidence mismatch.**

`web/src/lib/disputeSurface.ts` lines 39–54 contains an intentional controlled-bootstrap exception. For SYSTEM-opened disputes with certain low-vote-count conditions, it returns `{ account, juror: account, status: 'assigned', source: 'bootstrap_single_reviewer_fallback' }` even without an explicit viewer assignment. This is consumed by Reports and reviewer routing.

The **backend** is stricter. `GET /v1/disputes/current` returns only authenticated, canonically assigned juror records, and signed `DISPUTE_JUROR_ACCEPT` may materialize a bootstrap assignment only after recomputing the caller's eligibility in canonical state (including active reviewer-lane requirements and conflicts). It can reject the claimant. Thus the UI preflight may say `assigned` even when the final action is not permitted.

**Important nuance:** The fallback is intentionally present and tested by source assertions; removing it without preserving legitimate controlled-bootstrap acceptability could break rehearsals. The finding is principally that **provisional acceptance opportunity** and **confirmed assignment** must be separate statuses. The UI should not manufacture the latter.

**Safer contract:** Represent `potential_bootstrap_accept` separately and require authoritative case/eligibility read before displaying “Assigned to you.” Use the backend `/disputes/current` or exact-case self status as the source of confirmed assignment. Keep the signed backend checks. Do not grant vote or evidence access from speculative UI state.

**Evidence:** [disputeSurface.ts lines 25–55](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/disputeSurface.ts#L25-L55), [backend current queue](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L770), [backend accept recomputation](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/dispute.py#L2107-L2134), [existing source assertion](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/tests/test_live_request_sync_and_dispute_bootstrap.py#L29-L40).

**Required reproduction:** SYSTEM `open`/`juror_review` with no explicit assignment, 0/1 required votes, unrelated account, conflicted reporter/author, and genuinely active unconflicted reviewer. Check that the first three are not advertised as canonically assigned, while legitimate bootstrap review remains possible through fresh authority checks.

---

<a id="fe-015"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R2-11, R2-12.

### FE-015 — Reports “Open / unresolved” counter disagrees with backend stages
**P2 — confirmed classification mismatch.**

`Disputes.tsx` line 165 derives `openCount` with `items.filter((item) => !String(item?.resolved || '')).length`. The backend `GET /v1/disputes?include_summary=true` uses `_is_active_stage(stage)` to calculate `summary.active` and `summary.resolved` and explicitly returns those counts. It can classify stage `finalized`, `resolved`, `closed`, `dismissed`, or `expired` as inactive without relying on the `resolved` flag. Backend normalization also defaults absent `resolved` fields to false. A terminal-stage record with `resolved: false` can consequently be counted as open by the browser.

**Safer contract:** Consume authoritative summary counts with status/availability checks; distinguish whole-node summary from the bounded 200-item list; if deriving view-specific counts, use the same canonical stages with a clearly labeled subset. Avoid a “0 open” claim on unavailable results.

**Evidence:** [Disputes.tsx lines 110–166](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L110-L166), [backend `_is_active_stage`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L32-L36), [backend summary](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L650-L698).

**Required reproduction:** Feed a `stage: 'finalized', resolved: false` record; compare backend `summary.active` with UI. Test capped pages, filtered views, missing summary and endpoint failure.

---

<a id="fe-016"></a>

**Original source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` → `01_PHASE2_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R2-13, R2-14.

### FE-016 — “Assigned to me” matches past/terminal juror statuses
**P2 — confirmed filter/label mismatch.**

`Disputes.tsx` line 147 uses `jurorStatus !== 'unassigned'` for the `assigned` filter, and line 163 applies the same rule to `assignedCount`. `disputeJurorStatus` simply returns the stored juror status; statuses can include `declined`, `withdrawn`, `timed_out`, `completed`, and other terminal states. Those cases can appear as active “Assigned to me” work. The backend `/disputes/current` defines a separate, narrower current-work set.

**Safer contract:** Label history as “Previously involved,” and use a canonical active-assignment predicate for “Needs my action.” Keep public report history readable. Test declined, withdrawn, timed out, accepted, assigned, completed and unavailable.

**Evidence:** [Disputes.tsx lines 139–166](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L139-L166), [disputeSurface.ts lines 58–60](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/disputeSurface.ts#L58-L60), [backend current work filter](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L774).

---

## Phase 3 — detailed findings

<a id="fe-017"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P1. **Planned linked tests:** R3-01, R3-02, R4-11.

### FE-017 — Selected-account identity has two disconnected sources

**Priority:** P1  
**Classification:** Confirmed code-level contract divergence; impact to reproduce  
**Acceptance cases:** R3-01,R3-02,R3-03.

**Evidence:** AccountProvider obtains selected account with getAccount(), which reads weall.account; normal setSession() persists weall_session_v1 but does not update weall.account. The separate key is explicitly set in devBootstrap and fixture code. This can leave shared UI account state missing or attributed to a stale account after ordinary onboarding or switching.

**Remediation boundary:** Derive account context from getSession() (or a single typed session source), not an independent legacy selected-account key. Use a data identity of account + API base + chain identity. Keep signed actions separately gated.

**Exact-main source references:** [`web/src/context/AccountContext.tsx` L2–90](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L2-L90); [`web/src/api/weall.ts` L153–172](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L153-L172); [`web/src/auth/session.ts` L329–363](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L329-L363); [`web/src/lib/devBootstrap.ts` L1–170](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/devBootstrap.ts#L1-L170)

---

<a id="fe-018"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P1. **Planned linked tests:** R3-02, R3-03, R3-04, R3-05.

### FE-018 — In-flight account reads are not guarded against account or node switches

**Priority:** P1  
**Classification:** Confirmed async race structure; visible manifestation untested  
**Acceptance cases:** R3-02,R3-03,R3-04,R3-05.

**Evidence:** AccountProvider coalesces every refresh behind one refreshInFlight promise without checking the requested account/base. A later refresh for B waits for A and returns; A may then call setState(A) after the active account changes. Reads after a node switch can likewise land against an obsolete context.

**Remediation boundary:** Assign a monotonically increasing context generation, snapshot account/base/chain before each fetch, and only commit results if the generation and identity still match. On context change invalidate stale results and initiate new fetch. Preserve unavailable as unknown, not an empty verified account.

**Exact-main source references:** [`web/src/context/AccountContext.tsx` L57–132](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L57-L132); [`web/src/lib/revalidation.ts` L20–95](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/revalidation.ts#L20-L95)

---

<a id="fe-019"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P1/P2. **Planned linked tests:** R3-06, R3-07, R3-08, R3-09, R4-12.

### FE-019 — Mounted pages and development Settings can retain old API targets

**Priority:** P1/P2  
**Classification:** Confirmed source-level stale-target paths; browser outcomes untested  
**Acceptance cases:** R3-06,R3-07,R3-08,R3-09.

**Evidence:** Several page components memoize getApiBaseUrl() with an empty dependency array, so their active API calls may remain on node A after switching to B. In the non-public-testnet Settings branch, setApiBaseUrl() is called directly, whereas switchToNode() additionally emits the node-base change event. Existing mounted components are not guaranteed to remount when this happens.

**Remediation boundary:** Centralize selected node as reactive state. Emit a typed change notification for all selection paths, increment a node epoch, invalidate page caches, and use a stable per-operation base for signed transactions. Do not bypass public-testnet compatibility and recognition checks.

**Exact-main source references:** [`web/src/pages/Settings.tsx` L131–177](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Settings.tsx#L131-L177); [`web/src/lib/nodeConnectionManager.ts` L515–532](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/nodeConnectionManager.ts#L515-L532); [`web/src/api/weall.ts` L125–150](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L125-L150); [`web/src/pages/SessionDevicesPage.tsx` L47–86](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L47-L86); [`web/src/pages/Disputes.tsx` L80–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L80-L120)

---

<a id="fe-020"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R3-10, R3-11, R3-12.

### FE-020 — Chain ID cache is global rather than tied to the selected node

**Priority:** P2  
**Classification:** Confirmed cache/fallback behavior; backend rejection expected  
**Acceptance cases:** R3-10,R3-11,R3-12.

**Evidence:** getChainId() stores one global value for 60 seconds without a cache key for the selected API base. Normal submitSignedTx()/submitSignedTxInSequence() call resolveChainId(), which falls back to an environment value or literal testnet when the chain-status read fails. In controlled/development switching, an operation sent to B may be signed using a chain ID learned from A. This is not evidence that B would accept a cross-chain transaction. Journal-bound registration/login operations have stricter fresh expectedChainId handling and must remain so.

**Remediation boundary:** Key chain identity by verified node+chain commitments and invalidate on node changes. For new signed mutations, use a verified matching chain identity or fail closed, with explicit retry guidance rather than silent fallback. Keep existing journal-bound exact-ID safety.

**Exact-main source references:** [`web/src/lib/chain.ts` L1–37](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/chain.ts#L1-L37); [`web/src/auth/session.ts` L1080–1130](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1080-L1130); [`web/src/auth/session.ts` L1141–1180](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1141-L1180); [`web/src/lib/browserNodeTransition.ts` L60–117](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeTransition.ts#L60-L117)

---

<a id="fe-021"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R3-13, R3-14, R3-15, R4-13.

### FE-021 — Missing tab-scoped session bearer may be displayed as active

**Priority:** P2  
**Classification:** Confirmed conditional UI-truth gap; normal fresh-tab safeguard already present  
**Acceptance cases:** R3-13,R3-14,R3-15.

**Evidence:** readStoredSessionUnsafe reads persistent account metadata but bearer from tab-scoped sessionStorage. getSessionHealth() checks expiry and local signer, but when bearer is absent may still return active or expiring_soon. App.readyForApp checks that a signer exists and the status is not node_unverified; AppShell only locks writes for degraded SessionHealth. getAuthHeaders() correctly returns no auth headers when bearer is absent. In a controlled state where the tab retains a valid local signer but loses its tab-scoped bearer, the shell may display write-ready even though authenticated headers cannot be supplied. A normal newly opened independent tab usually lacks BOTH signer seed and bearer, so it is already blocked by the missing-local-signer gate. This does not demonstrate a practical authentication bypass.

**Remediation boundary:** Add explicit missing_session_bearer/recovery status; make protected-action readiness require active verified session with bearer and local signer, not just metadata. Keep anonymous public reads available. Keep bearer in sessionStorage (do not move it to localStorage).

**Exact-main source references:** [`web/src/auth/keys.ts` L261–322](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/keys.ts#L261-L322); [`web/src/auth/session.ts` L140–307](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L140-L307); [`web/src/auth/session.ts` L458–471](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L458-L471); [`web/src/App.tsx` L185–205](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L185-L205); [`web/src/components/AppShell.tsx` L85–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L85-L120); [`web/tests/e2e/production_browser_storage_isolation.spec.ts` L1–80](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/production_browser_storage_isolation.spec.ts#L1-L80)

---

<a id="fe-022"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R3-16, R3-17, R3-18, R4-14.

### FE-022 — Finality monitoring can follow a different node than the submitted action

**Priority:** P2  
**Classification:** Confirmed provenance ambiguity; effect depends on timing and node sync  
**Acceptance cases:** R3-16,R3-17,R3-18.

**Evidence:** TxQueueProvider chooses args.finality.base || getApiBaseUrl() when monitoring begins, after the asynchronous task returns. Callers such as Group.tsx provide the original base to submitSignedTx() but do not always pass it into finality. If the active node changes while the action submits, finality may be checked against the newly selected node instead. Same-chain synchronized observers can give valid receipts, but the provenance of this specific operation becomes ambiguous and missing receipts can look like a submission problem.

**Remediation boundary:** Record the submission node, chain commitment, account and tx ID in an immutable action descriptor. Prefer status from the origin, permit separately labeled verified same-chain observer checks, and never treat unavailable as rejected or safe to retry. Preserve read-model reconciliation as nonterminal.

**Exact-main source references:** [`web/src/components/TxQueueProvider.tsx` L305–365](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L305-L365); [`web/src/components/TxQueueProvider.tsx` L445–482](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L445-L482); [`web/src/pages/Group.tsx` L290–342](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L290-L342); [`web/src/lib/status.ts` L49–143](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/status.ts#L49-L143)

---

<a id="fe-023"></a>

**Original source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` → `01_PHASE3_AUDIT_FINDINGS.md`. **Original priority:** P1 investigation. **Planned linked tests:** R3-19, R3-20, R3-21, R4-15.

### FE-023 — Session teardown can clear coordination state while an operation is still pending

**Priority:** P1 investigation  
**Classification:** Source-level race candidate; requires controlled reproduction  
**Acceptance cases:** R3-19,R3-20,R3-21.

**Evidence:** endSession() directly clears the account nonce reservation, signer lock, signer pending counts, and queued promise map, without awaiting an active runSignerSerialized task. It is called by local-only clear-session and expiry cleanup as well as after logout. Ordinary revoke-on-logout serializes its signed revocation, which mitigates the usual logout route, but direct teardown during another action is not shown to cancel that action. The precise duplicated nonce, late dispatch or user-visible outcome requires a race test; no exploit is claimed.

**Remediation boundary:** Introduce operation-lifecycle ownership and safe cancellation/no-new-work gate on session teardown; do not clear an in-flight lock until its owning task has completed or unequivocally aborted. Reconcile uncertain submissions before nonce reuse. Do not weaken canonical nonce or signer isolation.

**Exact-main source references:** [`web/src/auth/session.ts` L310–395](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L310-L395); [`web/src/auth/session.ts` L475–575](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L475-L575); [`web/src/auth/session.ts` L878–920](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L878-L920); [`web/src/auth/session.ts` L1490–1525](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1490-L1525); [`web/src/pages/SessionDevicesPage.tsx` L208–217](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L208-L217)

---

## Phase 4 — detailed findings

<a id="fe-024"></a>

**Original source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` → `01_PHASE4_FINDINGS.md`. **Original priority:** P1. **Planned linked tests:** R4-01, R4-02.

### FE-024 — Skip-to-content anchor changes hash route (P1, confirmed source defect)

- In [`AppShell.tsx` L203](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L203), the skip link has `href="#app-shell-content"`.
- [`router.ts` L916–922](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts#L916) interprets the URL fragment as the client-side path. `#/feed` becomes `#app-shell-content`, which `currentHashPath()` normalizes to `/app-shell-content`.
- The unknown path falls back to `/login` in [`matchRoute()`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts#L895). The application listens to `hashchange` in [`App.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L206).
- **Impact:** using keyboard skip navigation can navigate away rather than focus the content. This is a source-confirmed route collision, not a completed browser reproduction.
- **Fix boundary:** avoid changing `window.location.hash`. Attach a click handler that calls `preventDefault()`, then focus/scroll the existing `#app-shell-content` node; preserve browser keyboard semantics and skip visibility. Alternatively use a route-safe strategy that does not rewrite the SPA fragment.
- **Acceptance:** R4-01 and R4-02; focus moves to main and `#/feed` / `#/decisions` stays unchanged.

---

<a id="fe-025"></a>

**Original source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` → `01_PHASE4_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R4-03, R4-04.

### FE-025 — Duplicate top-level headings (P2, source-confirmed hierarchy inconsistency)

- Shell renders `<h1 className="appShellTitle">` in [`AppShell.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L263).
- Groups renders its own `<h1>` in [`Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx#L112) and Decisions renders another in [`Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx#L237).
- **Impact:** competing page titles and redundant screen-reader heading choices. Multiple H1s do **not automatically prove a WCAG failure**, so classify as design/semantic consistency rather than a formal conformance defect.
- **Fix boundary:** establish one top-level page title per route; keep visible hero titles as properly subordinate H2 or derive the shell title from the page. Preserve visual presentation.
- **Acceptance:** R4-03/R4-04; check exact heading hierarchy in the rendered accessibility tree.

---

<a id="fe-026"></a>

**Original source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` → `01_PHASE4_FINDINGS.md`. **Original priority:** P2 candidate. **Planned linked tests:** R4-05, R4-06.

### FE-026 — Route-change focus is not explicitly managed (P2 candidate)

- The shell's main element is focusable (`tabIndex={-1}`) but there is no route-change focus effect in [`AppShell.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L309). Focus movement exists for the context drawer and menu return but not page navigation.
- A navigation control may retain keyboard focus while the route content changes. This may impair assistive-technology orientation, **but requires browser reproduction**; do not mark as WCAG noncompliance yet.
- **Fix boundary:** on a real route transition, focus the newly relevant main heading or main content without stealing focus during a PoH recording or other persistent guided journey. Respect reduced motion and modal state.
- **Acceptance:** R4-05/R4-06, including the guided PoH continuity exception.

---

<a id="fe-027"></a>

**Original source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` → `01_PHASE4_FINDINGS.md`. **Original priority:** P3. **Planned linked tests:** R4-07.

### FE-027 — Breadcrumb accessible-label semantics (P3, source confirmed)

- [`AppShell.tsx` L266](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L266) applies `aria-label="Breadcrumbs"` to a plain `div`, not a semantic breadcrumb navigation landmark.
- **Fix boundary:** prefer `<nav aria-label="Breadcrumbs">` with a suitable list/link structure and `aria-current="page"` for the terminal crumb. Preserve route-dependent URLs and role boundaries.
- **Acceptance:** R4-07.

---

<a id="fe-028"></a>

**Original source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` → `01_PHASE4_FINDINGS.md`. **Original priority:** P2. **Planned linked tests:** R4-08, R4-09.

### FE-028 — Feed sort active state only conveyed visually (P2, confirmed source gap)

- [`FeedView.tsx` L585–588](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx#L585) switches `btnPrimary` CSS for Newest, Balanced, and Production sorting, but does not expose `aria-pressed`, a checked radio, or other programmatic state of the currently selected option.
- **Fix boundary:** add a proper single-choice sort control pattern (radio group or pressed toggle semantics), while retaining canonical backend ordering and its existing label distinctions.
- **Acceptance:** R4-08/R4-09, including keyboard-only sort changes and screen-reader state.

---


## Unabridged original source reports (verbatim, with all context and nonfinding safeguards)

The four complete reports follow unchanged. Their executive summaries, evidence grades, safety constraints, sequencing, additional watchpoints, test limitations, and release nonclaims are preserved even where these are not individual FE findings.


## Source Report — Phase 1
**Source:** `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip` / `01_MAIN_FRONTEND_AUDIT.md`

<!-- BEGIN UNALTERED SOURCE REPORT -->

# WeAll Protocol — Frontend Source Audit, Phase 1

**Prepared:** 2026-11-20  
**Repository:** https://github.com/errol1swaby2-bit/WeAll-Protocol  
**Scope:** Read-only source audit of Feed, Groups and Decisions, their route shell, UI eligibility preflight, selected backend contracts and test inventory.  
**Frozen target:** `main` = `6d3d69234415d294936d99e819367cff589ced3d` (confirmed by GitHub compare: identical, 0 ahead / 0 behind).  
**Status:** Preliminary source-backed audit, not a full rendered UX audit, independent operator rehearsal, CI execution, security approval or public-testnet release authorization.

## 1. Verdict

The frontend contains substantial real application architecture: React routes, public social/group/governance read views, locally signed mutation flows, API reconciliation, group-scope checks and many targeted regression scripts. It is **not** reasonable to describe it as merely a mockup. On the other hand, the available evidence does not justify describing the visitor experience as complete or the protocol as public-beta ready.

The first development increment should prioritize truthful navigation and eligibility, safe asynchronous list rendering, and less visually crowded user journeys, **before** screenshot capture for the P2P Foundation Wiki.

### Evidence grades

- **Confirmed source discrepancy** — compared actual paths/code with another relevant code path or its canonical contract. Still requires a regression test after correction.
- **Source-supported UX defect** — actual code renders inconsistent/misleading states; its user impact may vary by network and browser.
- **Reproduction required** — source admits a plausible failure, but it has not been demonstrated in a running browser.
- **Product gap / enhancement** — improvement or known incomplete work, not automatically a bug.

## 2. Triage findings

### FE-001 — Public Feed incorrectly disabled in five-tab navigation
**Priority:** P1 · **Evidence:** Confirmed source discrepancy  
**Files:** [`web/src/components/PrimaryNavigation.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx), [`web/src/App.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx), [`web/src/lib/router.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts)

Five-tab navigation declares `{label: "Feed", href: "/feed", sessionOnly: true}`, then disables any `sessionOnly` destination for an unsigned visitor. The application router, however, explicitly renders `<Feed />` without authentication at `/feed`, and route metadata marks Feed public. `AppShell` renders that navigation even on public routes. This makes the first-time visitor's most important public destination appear unavailable from the primary navigation, despite being a supported public read route.

**Required behavior:** Keep public Feed navigation enabled for unsigned users while preserving backend-checked eligibility for reactions, replies, posts and other signed mutations. Verify public Feed accessibility from a fresh anonymous browser as well as logged-in navigation.

### FE-002 — Directory overstates the PoH requirement for joining groups
**Priority:** P1 · **Evidence:** Confirmed source discrepancy  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Group.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx), [`web/src/lib/gates.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/gates.ts)

`Groups.tsx` sets both creation and membership preflights to `requireTier: 2` and labels membership “Complete live verification to join.” `Group.tsx` sets group membership request preflight to `requireTier: 1` with a comment that `GROUP_MEMBERSHIP_REQUEST` is canonically Tier 1+. This is a guidance/presentation mismatch, not evidence of backend authorization bypass. Backend authority must be checked against the current canonical transaction index, not inferred from UI-only gate logic.

**Required behavior:** Retain the higher tier for group creation if dictated by canonical rules, but derive **join/request membership** messaging from the correct transaction action's tier. Test an eligible Tier 1 account, a Tier 0 account, an unavailable account state, and a restricted account.

### FE-003 — API errors can coexist with “empty directory / no decisions” messages
**Priority:** P1/P2 · **Evidence:** Source-supported UX defect  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx), [`web/src/components/FeedView.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx)

In Groups, `refreshGroups()` catches failures and sets both `err` and an empty `groups` array, while the render condition `groups.length === 0` shows “No groups are visible yet.” The loading branch likewise initially starts with zero groups. In Decisions, `load()` catches errors and sets empty items; `filtered.length === 0` can show a no-decisions message even when loading failed. FeedView similarly clears items on non-append errors, then shows an empty-state panel alongside an inline error.

**Required behavior:** Explicit **idle/loading/ready-empty/ready-data/error** states. Never imply a complete empty canonical collection when the request has failed or is still loading. Allow retry without silently overwriting a known-good list unless the UI clearly marks data stale.

### FE-004 — Feed may display a stale response after scope or sorting changes
**Priority:** P1 candidate · **Evidence:** Reproduction required  
**File:** [`web/src/components/FeedView.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx)

`loadPage()` asynchronously requests a page using the current `scope`, `filters` and `sort`, then directly writes `items`, `rankingInfo`, and `nextCursor`. The effect runs again when scope/sort changes, but no request generation ID, abort signal, or superseded-response check is apparent in this loading path. When a user switches global feed ↔ “My posts” rapidly, or changes ranking during network delay, an older response could arrive last and replace the newer view. Do not report this as an observed production failure without a controlled latency test.

**Required behavior:** Add a request epoch/cancellation contract; bind response to the requested scope and ranking; ensure append pagination cannot mix old and new cursors; test out-of-order backend responses.

### FE-005 — Directory and decision-count language does not clearly communicate result bounds
**Priority:** P2 · **Evidence:** Source-supported UX limitation  
**Files:** [`web/src/pages/Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx), [`web/src/pages/Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx), [`web/src/pages/Group.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx)

The Groups directory requests at most 250 records and displays “Visible groups {groups.length}”; it offers neither search nor a next-page affordance. The Decisions hub requests 200 proposals and displays “Total {items.length}” and client-derived vote/result counts. Group-specific Decisions already acknowledge they filter a bounded first 200 records and do **not** prove complete history. The global list's “Total” label is especially easy to misread as an authoritative network-wide total.

**Required behavior:** Label counts as “Returned,” “In this view,” or “Showing N”; use authoritative total only if one is returned and validated. Add server-backed search/pagination when canonical API support is available; do not implement client-only unlimited historical-count claims.

### FE-006 — Group directory discovery is less capable than the intended product contract
**Priority:** P2 · **Evidence:** Product gap  
**Files:** `Groups.tsx`; [`web/docs/FRONTEND_V16_PRODUCT_SPEC.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/FRONTEND_V16_PRODUCT_SPEC.md)

The v1.6 target calls for searchable/filterable public groups with clear membership previews. The current directory presents the first bounded list as click-to-open cards, with no search/filter control and no explicit pagination. This is not a backend authorization flaw, but it is a material discovery limitation once communities begin to grow.

**Required behavior:** Start with accessible client filtering over the returned bounded set **only if clearly labeled as such**. Design a cursor-backed API integration separately, once backend contract, sort order, and denial cases are reviewed.

### FE-007 — Core civic pages remain heavy with technical/context copy
**Priority:** P2 · **Evidence:** Product-design review  
**Files:** `web/src/pages/Feed.tsx`; `web/src/pages/Groups.tsx`; `web/src/pages/Proposals.tsx`; `web/src/components/AppShell.tsx`

The application shell renders its own title/subtitle, mode pill, contract note, and route-summary strip. Feed, Groups and Decisions then introduce another hero title, account/verification panels, boundary explanations, context text, statistics and action panels. This improves reviewer transparency but risks burying actual posts, groups and decisions below operational guidance. The proposed v1.6 contract favors one primary object and one clear next action per page. The UX impact requires screenshots, viewport measurements and accessibility review.

**Required behavior:** Preserve legal/security/authority truth, but move repeated technical explanations to contextual details or the optional information drawer. Give the visible list/content first-screen priority; test desktop/mobile before removing any important eligibility text.

### FE-008 — Some account-dependent directory data is initialized only on mount
**Priority:** P2 candidate · **Evidence:** Reproduction required  
**File:** `web/src/pages/Groups.tsx`

The Groups directory calls `refreshGroups()` and `loadAccountState()` in an effect with an empty dependency array, yet derives `acct` from the current session. If authentication/account changes while that component remains mounted, the displayed account preflight and account state could be stale until a manual refresh or remount. This may be mitigated by the current navigation lifecycle; validate the actual browser sequence before calling it a defect.

**Required behavior:** Verify account-switch and session-recovery transitions while remaining on Groups. Add appropriate reactive dependencies/revalidation without creating polling loops or unsigned mutations.

### FE-009 — Large composite screens need bounded presentation refactoring
**Priority:** P2 · **Evidence:** Maintainability/product enhancement  
**Files:** `web/src/pages/Group.tsx` (~1,128 lines), `web/src/pages/Proposal.tsx` (~1,181 lines), `web/src/pages/ProposalCreate.tsx` (~534 lines), `web/src/components/FeedView.tsx` (~724 lines)

These pages already contain significant scope, status, access, timeline and action logic. Refactor **presentation** into focused components only after regression coverage is pinned. Do not move canonical acceptance, role checks, signer/nonce/session contracts or scope decisions into new unverified client-only authority pathways. Group election and treasury surfaces have known current-state/read-only limitations documented in main.

### FE-010 — Existing status documents flag unfinished v1.6 task delivery
**Priority:** Program-level dependency · **Evidence:** Documented gap, not a new defect  
**Files:** [`web/docs/FRONTEND_V16_IMPLEMENTATION_STATUS.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/FRONTEND_V16_IMPLEMENTATION_STATUS.md), [`web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/docs/IHD1_JOURNEY_CLOSURE_MATRIX_20261114.md)

The design spec is explicitly a **target**, not proof that 103 contemplated destinations exist. Status documents name incomplete PoH journey splitting, authorized profile/banner media flows, full group governance indexes/mandates, independent reviewer task workspaces, richer accessibility/visual regressions and real multi-account/browser acceptance. Some documents refer to earlier draft PR baselines, so they should be treated as historical tracking context rather than exact-head CI evidence.

## 3. Existing source-backed strengths worth preserving

1. **Anonymous read architecture:** `/feed`, `/groups`, `/decisions` and `/reports` render public reading paths in `App.tsx`. Browser convenience must not override public protocol visibility.
2. **Separated authoring routes:** post, group and decision creation have dedicated routes rather than inline unlimited mutations inside list views.
3. **Signed mutation discipline:** group joining and creating, and decision creation and voting, use `submitSignedTx` or the queue/finality machinery; UX should clearly distinguish submitted from included/finalized.
4. **Canonical scoped governance:** group decision creation verifies group scope/context; group read pages avoid assuming their capped index is comprehensive.
5. **Account state:** `GET /v1/accounts/{account}` supplies `effective_poh_tier()` in its returned `poh_tier` field, so do **not** misdiagnose the frontend's consumption of `poh_tier` as necessarily reading stale legacy state.
6. **Public-only policy:** group posts and decisions are publicly readable; membership can gate actions but must not gate reading.
7. **Human verification safety boundary:** production human-authority advancement remains scope-closed pending uniqueness/reviewer entropy work. UI improvements must not simulate or silently award verification.
8. **Native test inventory:** current `web/package.json` includes TypeScript typechecks, focused source-level checks, source contract tests, Playwright rendered tests, account custody/PoH and governance test entrypoints. **Presence is not a passing exact-head run.**

## 4. Risk matrix and suggested ownership

| Item | Category | Priority | Work boundary |
|---|---|---|---|
| FE-001 Feed tab access | Public usability | P1 | Frontend only; keep feed signed writes gated |
| FE-002 join tier text/gate | UI/protocol contract | P1 | Verify canonical subject gate; no backend weakening |
| FE-003 error vs empty states | Correctness / trust | P1/P2 | Frontend only; retry & stale labeling |
| FE-004 stale feed responses | Data consistency | P1 candidate | Frontend async, controlled latency tests |
| FE-005 bounded totals | Transparency | P2 | Frontend labels now; API totals later |
| FE-006 group discovery | Product | P2 | Source-aware bounded filtering then API pagination |
| FE-007 page density | Design / accessibility | P2 | Presentation only; rendered before/after review |
| FE-008 account freshness | React state | P2 candidate | Account lifecycle tests |
| FE-009 composite page refactor | Maintainability | P2 | No authority or consensus change |
| FE-010 v1.6 target gaps | Program | Backlog | Separate deliverables and external gates |

## 5. Validation limits and what was NOT done

- **No code changes, commits, PRs or branch modifications.**
- Did **not** clone/build the full repository locally: direct Git/network access from the working container is unavailable. GitHub connector delivered exact source files, not an executable full checkout.
- No `npm ci`, `npm run typecheck`, browser/Playwright runs, API availability checks, real user account test, two-node rehearsal, WCAG audit, visual regression, or latest GitHub workflow result was executed in this audit.
- GitHub commit status endpoints returned no associated statuses/workflow runs for the queried commit; that is **not** proof CI is green or failing.
- No assertion that a P2P Wiki screenshot is ready, or that live public beta is approved. External testnet and crypto gates remain open per `Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md`.

## 6. First remediation tranche recommendation

**Tranche F-UX-01 — Public access, join eligibility, honest loading.** Fix FE-001, FE-002 and FE-003 first, with targeted regressions and a narrow review diff. These are user-visible and can be addressed without inventing a new protocol feature. Test anonymous Feed navigation, Tier 0/Tier 1/Tier 2 group request copy, signed-action gating, unavailable endpoint/error-state handling, and successful empty collection states. Re-run the existing shell, public social, group, source accessibility, focused contract checks and browser acceptance tests at the exact new head.

**Tranche F-UX-02 — Feed consistency.** Reproduce FE-004 using delayed/reordered requests before editing. If confirmed, implement stale-response suppression and pagination epoch binding with deterministic out-of-order regression tests.

**Tranche F-UX-03 — Discoverability and visual hierarchy.** FE-005/006/007, after real screenshots of the unpolished frontend can be used for private comparison. Remove duplication without hiding constitutional limitations or audit evidence; ensure public pages still clearly distinguish current status and technical aspirations.

**Tranche F-UX-04 — Governance/group scaling.** Work against the documented bounded APIs and scope protections; do not claim historical completeness, executable treasury/mandates or automatic upgrades.

---

**Decision for this audit:** First code change should be limited to FE-001 + FE-002 + FE-003, with no cryptographic, consensus, eligibility, transaction-schema or production-configuration changes. Capture P2P Wiki images only after this tranche and subsequent visual acceptance are complete.

<!-- END UNALTERED SOURCE REPORT -->

---

## Source Report — Phase 2
**Source:** `WeAll_Frontend_Audit_Phase2_MAIN_2026-11-20.zip` / `01_PHASE2_AUDIT_FINDINGS.md`

<!-- BEGIN UNALTERED SOURCE REPORT -->

# WeAll Protocol — Frontend Audit, Phase 2: Identity, Review, Disputes & Transactions

**Date:** 2026-11-20  
**Mode:** Strictly read-only source review  
**Repository:** https://github.com/errol1swaby2-bit/WeAll-Protocol  
**Target:** `main` at `6d3d69234415d294936d99e819367cff589ced3d`  
**Relation to previous audit:** Continues `WeAll_Frontend_Main_Phase1_Audit_2026-11-20.zip`; findings begin at FE-011, without reissuing FE-001 through FE-010.  
**Release posture:** No public-beta, mainnet, independent-browser, real validator, or independent security certification claimed.

## 1. Executive summary

Source review identified five distinct cross-page/cross-domain defects or material UX inconsistencies and one additional report-filter discrepancy. Two matter directly to operational accountability: reviewer endpoint failure being represented as an empty queue, and provisional bootstrap eligibility being rendered as a canonical assignment. Backend authorization remains authoritative; these findings do **not** prove unauthorized reviewer action or consensus invalidity.

| ID | Source-review finding | Priority | Classification |
|---|---|---|---|
| FE-011 | Reviewer API failures silently converted to empty cases | **P1** | Confirmed source-level state conflation; browser impact not yet demonstrated |
| FE-012 | Review/report eligibility sometimes hardcodes `canSign: true` | **P1/P2** | Confirmed preflight discrepancy; backend bypass not alleged |
| FE-013 | Stored transaction activity is not account-scoped | **P2** | Confirmed local history attribution gap |
| FE-014 | Bootstrap dispute fallback presents speculative assignment as `assigned` | **P1** | Confirmed provisional-vs-canonical label conflation; intentional bootstrap mechanism must be preserved safely |
| FE-015 | Reports open count uses `resolved` flag, but backend summary uses `stage` | **P2** | Confirmed inconsistent classification logic |
| FE-016 | “Assigned to me” includes any juror status except `unassigned` | **P2** | Confirmed filter/label mismatch; may include declined/completed assignments |

No code was modified, no branch created, and no tests were executed by this review.

## 2. Findings

### FE-011 — Reviewer queues suppress service failures
**P1 — source-confirmed.**

`web/src/pages/JurorDashboard.tsx` lines 307–348 has a `Promise.all` across independent review authorities, but individual requests catch errors and substitute empty arrays or null reviewer state:

- `pohAsyncJurorCases(...).catch(() => ({ cases: [] }))`
- `pohLiveAssigned(...).catch(() => ({ cases: [] }))`
- `pohLiveSessions(...).catch(() => ({ sessions: [] }))`
- `disputesCurrent(...).catch(() => ({ items: [] }))`
- `disputes(...).catch(() => ({ items: [], unavailable: true }))`
- `accountReviewerStatus(...).catch(() => ({ reviewer: null }))`

Only the fallback disputes list marks itself unavailable. Failed PoH assignment calls and current dispute queue calls lose their error provenance. Users can see zero cases rather than “assignment service unavailable.” This is a high-priority UX truth issue because an absent assignment and a temporarily unreadable queue are different states, especially for time-limited juror duties.

**Safer contract:** Load lane results independently with `{status: 'ready'|'unavailable', data, source, error}` and explicit freshness markers. A failed lane should never display “no assigned cases” as an authoritative fact. Do not allow action control merely because the cached queue included an item; fetch fresh case/role/assignment state before signing. Never expose protected PoH evidence before reviewer-specific backend acceptance.

**Evidence:** [JurorDashboard.tsx lines 307–349](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx#L307-L349), [backend current queue](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L766).

**Required reproduction:** Mock individual timeout/401/403/500 responses for each lane, including one failed lane while others succeed. Confirm a retry updates only the affected lane without silently turning unavailable into empty or clearing other verified queues.

### FE-012 — Reviewer readiness assumes signer availability on several pages
**P1/P2 — source-confirmed preflight mismatch.**

`web/src/pages/Disputes.tsx` lines 93–99, `DisputeDetail.tsx` lines 87–93, `DisputeReview.tsx` lines 58–64 and `JurorDashboard.tsx` lines 287–293 call `checkGates` with `canSign: true` instead of deriving real local-key/session readiness. `checkGates` treats this value as the device signing preflight. In the **public** Reports and Report Detail routes, a session/account with missing key can therefore see a positive readiness cue despite not being able to sign. The protected Review Center / Review Action routes have additional outer app guards, which reduce but do not cure the inconsistent shared contract.

This is not evidence the backend will admit an unsigned action. The intended fix is device-state truth, not lower tier requirements.

**Safer contract:** Use canonical effective tier from account read model, actual local `getKeypair` availability, live session posture, and the appropriate case assignment. Maintain a `state unknown` status if the backend cannot be reached. Regenerate the gate if the session or account changes.

**Evidence:** [Disputes.tsx lines 93–99](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L93-L99), [DisputeDetail.tsx lines 87–93](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/DisputeDetail.tsx#L87-L93), [gate helper](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/gates.ts#L30-L87).

**Required reproduction:** Separate cases for signed-in Tier 2 with no local signer, expired node session, revoked/suspended tier, and fully capable user. Verify public report pages remain readable in all these states.

### FE-013 — Transaction activity history is not scoped to account
**P2 — source-confirmed.**

`web/src/pages/TransactionsPage.tsx` uses global localStorage keys (`weall_tx_activity_v3`, then v2/v1), deserializes the first populated record list and displays all entries without filtering to the current account. `TxHistoryItem` has no account identity field; `account` is only obtained separately for the header. Switching between accounts within a browser may therefore display one account's local signing attempts while a different account is shown as current.

The underlying protocol transactions are publicly inspectable; this finding is primarily **attribution and multi-account UX**, not a claim of secret signing material leakage. It may nonetheless expose browser-local activity titles or errors to the next person using a shared browser.

**Safer contract:** Record explicit account, chain ID, node identity, and tx ID where known in new history entries; filter or visibly label mixed-account history. Retain unknown-attribution legacy entries separately rather than silently assigning them to the current user. Do not silently discard pending historical tx IDs during schema migration. Validate `local_state_synced` and successful apply receipts as today.

**Evidence:** [TransactionsPage.tsx lines 12–63](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L12-L63), [rendered current-account label and history](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L220-L451).

**Required reproduction:** Account A sends tx; switch to B in same browser without clearing storage; demonstrate how history is attributed. Also test legacy v1/v2/v3 records and unknown pending outcomes.

### FE-014 — Provisional bootstrap “assigned” status can overstate reviewer authority
**P1 — source-confirmed UI/protocol evidence mismatch.**

`web/src/lib/disputeSurface.ts` lines 39–54 contains an intentional controlled-bootstrap exception. For SYSTEM-opened disputes with certain low-vote-count conditions, it returns `{ account, juror: account, status: 'assigned', source: 'bootstrap_single_reviewer_fallback' }` even without an explicit viewer assignment. This is consumed by Reports and reviewer routing.

The **backend** is stricter. `GET /v1/disputes/current` returns only authenticated, canonically assigned juror records, and signed `DISPUTE_JUROR_ACCEPT` may materialize a bootstrap assignment only after recomputing the caller's eligibility in canonical state (including active reviewer-lane requirements and conflicts). It can reject the claimant. Thus the UI preflight may say `assigned` even when the final action is not permitted.

**Important nuance:** The fallback is intentionally present and tested by source assertions; removing it without preserving legitimate controlled-bootstrap acceptability could break rehearsals. The finding is principally that **provisional acceptance opportunity** and **confirmed assignment** must be separate statuses. The UI should not manufacture the latter.

**Safer contract:** Represent `potential_bootstrap_accept` separately and require authoritative case/eligibility read before displaying “Assigned to you.” Use the backend `/disputes/current` or exact-case self status as the source of confirmed assignment. Keep the signed backend checks. Do not grant vote or evidence access from speculative UI state.

**Evidence:** [disputeSurface.ts lines 25–55](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/disputeSurface.ts#L25-L55), [backend current queue](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L770), [backend accept recomputation](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/dispute.py#L2107-L2134), [existing source assertion](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/tests/test_live_request_sync_and_dispute_bootstrap.py#L29-L40).

**Required reproduction:** SYSTEM `open`/`juror_review` with no explicit assignment, 0/1 required votes, unrelated account, conflicted reporter/author, and genuinely active unconflicted reviewer. Check that the first three are not advertised as canonically assigned, while legitimate bootstrap review remains possible through fresh authority checks.

### FE-015 — Reports “Open / unresolved” counter disagrees with backend stages
**P2 — confirmed classification mismatch.**

`Disputes.tsx` line 165 derives `openCount` with `items.filter((item) => !String(item?.resolved || '')).length`. The backend `GET /v1/disputes?include_summary=true` uses `_is_active_stage(stage)` to calculate `summary.active` and `summary.resolved` and explicitly returns those counts. It can classify stage `finalized`, `resolved`, `closed`, `dismissed`, or `expired` as inactive without relying on the `resolved` flag. Backend normalization also defaults absent `resolved` fields to false. A terminal-stage record with `resolved: false` can consequently be counted as open by the browser.

**Safer contract:** Consume authoritative summary counts with status/availability checks; distinguish whole-node summary from the bounded 200-item list; if deriving view-specific counts, use the same canonical stages with a clearly labeled subset. Avoid a “0 open” claim on unavailable results.

**Evidence:** [Disputes.tsx lines 110–166](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L110-L166), [backend `_is_active_stage`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L32-L36), [backend summary](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L650-L698).

**Required reproduction:** Feed a `stage: 'finalized', resolved: false` record; compare backend `summary.active` with UI. Test capped pages, filtered views, missing summary and endpoint failure.

### FE-016 — “Assigned to me” matches past/terminal juror statuses
**P2 — confirmed filter/label mismatch.**

`Disputes.tsx` line 147 uses `jurorStatus !== 'unassigned'` for the `assigned` filter, and line 163 applies the same rule to `assignedCount`. `disputeJurorStatus` simply returns the stored juror status; statuses can include `declined`, `withdrawn`, `timed_out`, `completed`, and other terminal states. Those cases can appear as active “Assigned to me” work. The backend `/disputes/current` defines a separate, narrower current-work set.

**Safer contract:** Label history as “Previously involved,” and use a canonical active-assignment predicate for “Needs my action.” Keep public report history readable. Test declined, withdrawn, timed out, accepted, assigned, completed and unavailable.

**Evidence:** [Disputes.tsx lines 139–166](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L139-L166), [disputeSurface.ts lines 58–60](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/disputeSurface.ts#L58-L60), [backend current work filter](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/disputes.py#L740-L774).

## 3. Behaviors verified as guarded in source — do not regress

- **Current account tier:** `GET /v1/accounts/{account}` sets returned `poh_tier` using `effective_poh_tier`; the frontend's consumption of this field is not itself evidence of reading expired legacy status. [Source](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/accounts.py#L399-L426).
- **Same-origin PoH journal:** `normalizePohJournalBase('')` deliberately converts the empty same-origin proxy identifier to `/` before validation. The earlier `invalid_poh_journal_entry` same-origin mismatch appears addressed **in this reviewed source**, not independently verified in a browser. [Source](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/pohSubmissionJournal.ts#L46-L62).
- **PoH case history failures:** `AccountVerificationPage.tsx` retains separate history-read readiness per async/live lane and blocks new signed submissions on uncertain history; not all errors are silently treated as no cases. [Source](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountVerificationPage.tsx#L609-L674).
- **Registration uncertainty:** `AccountRegistrationPage.tsx` tracks transaction IDs and prevents casual re-submission while the original status is unknown; registered account session activation is a separate step. [Source](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L69-L113).
- **Successful transaction apply:** `normalizeTxStatus()` does not mark a transaction confirmed if the backend explicitly reports unsuccessful apply, missing positive apply proof, or `local_state_synced === false`. [Source](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/status.ts#L49-L92).

## 4. Additional watchpoints, not elevated to findings

- `AccountVerificationPage.tsx` substitutes `{registered:false}` if one registered-state read fails while other account reads may succeed. Confirm whether UI actually misstates registration in rendered tests before treating this as a defect; current snapshot calculations may compensate.
- First-run recovery and account registration remain complicated, but the code has meaningful fail-closed checks. A qualitative usability finding requires a browser walkthrough, not simply a file-size judgment.
- The live verification WebRTC room, encrypted evidence viewer and reviewer consent boundaries deserve a separate browser+security review. No source-only assertion of a confirmed leak or connection failure is made here.
- Dev/test bootstrap hooks and current controlled-testnet flags must not be treated as production user entitlements.

## 5. Priority and sequencing

**Tranche F-UX-01 (previous report):** FE-001, FE-002, FE-003 — anonymous public Feed access, group membership guidance, error/empty state truth. No change to consensus or canonical eligibility.

**Tranche F-UX-02 (new):** FE-011 and FE-014 — reviewer queue availability vs empty, provisional vs canonical assignments. Preserve bootstrap review safety and backend-authority boundaries. Add exact-case source and conflict tests.

**Tranche F-UX-03 (new):** FE-012, FE-015, FE-016 — device signing truth, stage-based report counts, active vs past reviewer work.

**Tranche F-UX-04 (new):** FE-013 — account-scoped local tx history with migration of unattributed legacy records. Preserve nonfinal receipt semantics.

**Tranche F-UX-05 (previous):** FE-004 through FE-010 — feed races, bounded discovery, page density, frontend source/UX verification; release controls unchanged.

## 6. Evidence limitations

This work uses GitHub source reads for the verified `main` revision plus the prior uploaded audit ZIP. It does not reproduce browsers, run npm/Playwright, install packages, exercise a live node, inspect confidential PoH material, run an independent security audit, or verify that a nonmain branch's findings have merged. GitHub test *files* are evidence of test intent, not passing exact-head results. Findings are source-backed and require regression and runtime acceptance before final closure.

**Disposition:** Continue audit; do not approve public testnet or publish frontend screenshots from unvalidated user journeys. No direct changes to `main`.

<!-- END UNALTERED SOURCE REPORT -->

---

## Source Report — Phase 3
**Source:** `WeAll_Frontend_Phase3_MAIN_Audit_2026-11-20.zip` / `01_PHASE3_AUDIT_FINDINGS.md`

<!-- BEGIN UNALTERED SOURCE REPORT -->

# WeAll Frontend — Phase 3 Read-Only Audit

**Frozen source:** [`main` at `6d3d69234415d294936d99e819367cff589ced3d`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d); GitHub compare `main` vs this SHA: identical, 0 commits ahead and behind.
**Date:** 2026-11-20  
**Scope:** session lifecycle, account switching, access-node selection, cached chain identity, transaction status provenance, in-flight cleanup.  
**Inputs:** attached Phase 1 and Phase 2 audit packages; live GitHub files fetched explicitly from `main`.  
**Audit method:** static repository/code-path inspection; no checkout, Node/browser server, runtime test, independent observer, or CI executed during this phase.  
**Authority:** source-level findings and candidate test plans only; no code modification or public-testnet release approval.

## Executive summary

Phase 3 adds **7 unique findings (FE-017–FE-023)** to the existing 16-item backlog. Five concern confirmed source-level inconsistencies or inadequate context binding; another is a provenance timing issue; the final item is a concurrency-risk hypothesis requiring actual reproduction. No backend authorization bypass, cross-chain acceptance, or unauthorized key extraction has been demonstrated.

| Finding | Priority | Evidence state | Summary |
|---|---|---|---|
| FE-017 | P1 | Confirmed code-level contract divergence; impact to reproduce | Selected-account identity has two disconnected sources |
| FE-018 | P1 | Confirmed async race structure; visible manifestation untested | In-flight account reads are not guarded against account or node switches |
| FE-019 | P1/P2 | Confirmed source-level stale-target paths; browser outcomes untested | Mounted pages and development Settings can retain old API targets |
| FE-020 | P2 | Confirmed cache/fallback behavior; backend rejection expected | Chain ID cache is global rather than tied to the selected node |
| FE-021 | P2 | Confirmed conditional UI-truth gap; normal fresh-tab safeguard already present | Missing tab-scoped session bearer may be displayed as active |
| FE-022 | P2 | Confirmed provenance ambiguity; effect depends on timing and node sync | Finality monitoring can follow a different node than the submitted action |
| FE-023 | P1 investigation | Source-level race candidate; requires controlled reproduction | Session teardown can clear coordination state while an operation is still pending |

## Findings and corrective scope

### FE-017 — Selected-account identity has two disconnected sources

**Priority:** P1  
**Classification:** Confirmed code-level contract divergence; impact to reproduce  
**Acceptance cases:** R3-01,R3-02,R3-03.

**Evidence:** AccountProvider obtains selected account with getAccount(), which reads weall.account; normal setSession() persists weall_session_v1 but does not update weall.account. The separate key is explicitly set in devBootstrap and fixture code. This can leave shared UI account state missing or attributed to a stale account after ordinary onboarding or switching.

**Remediation boundary:** Derive account context from getSession() (or a single typed session source), not an independent legacy selected-account key. Use a data identity of account + API base + chain identity. Keep signed actions separately gated.

**Exact-main source references:** [`web/src/context/AccountContext.tsx` L2–90](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L2-L90); [`web/src/api/weall.ts` L153–172](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L153-L172); [`web/src/auth/session.ts` L329–363](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L329-L363); [`web/src/lib/devBootstrap.ts` L1–170](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/devBootstrap.ts#L1-L170)

### FE-018 — In-flight account reads are not guarded against account or node switches

**Priority:** P1  
**Classification:** Confirmed async race structure; visible manifestation untested  
**Acceptance cases:** R3-02,R3-03,R3-04,R3-05.

**Evidence:** AccountProvider coalesces every refresh behind one refreshInFlight promise without checking the requested account/base. A later refresh for B waits for A and returns; A may then call setState(A) after the active account changes. Reads after a node switch can likewise land against an obsolete context.

**Remediation boundary:** Assign a monotonically increasing context generation, snapshot account/base/chain before each fetch, and only commit results if the generation and identity still match. On context change invalidate stale results and initiate new fetch. Preserve unavailable as unknown, not an empty verified account.

**Exact-main source references:** [`web/src/context/AccountContext.tsx` L57–132](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L57-L132); [`web/src/lib/revalidation.ts` L20–95](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/revalidation.ts#L20-L95)

### FE-019 — Mounted pages and development Settings can retain old API targets

**Priority:** P1/P2  
**Classification:** Confirmed source-level stale-target paths; browser outcomes untested  
**Acceptance cases:** R3-06,R3-07,R3-08,R3-09.

**Evidence:** Several page components memoize getApiBaseUrl() with an empty dependency array, so their active API calls may remain on node A after switching to B. In the non-public-testnet Settings branch, setApiBaseUrl() is called directly, whereas switchToNode() additionally emits the node-base change event. Existing mounted components are not guaranteed to remount when this happens.

**Remediation boundary:** Centralize selected node as reactive state. Emit a typed change notification for all selection paths, increment a node epoch, invalidate page caches, and use a stable per-operation base for signed transactions. Do not bypass public-testnet compatibility and recognition checks.

**Exact-main source references:** [`web/src/pages/Settings.tsx` L131–177](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Settings.tsx#L131-L177); [`web/src/lib/nodeConnectionManager.ts` L515–532](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/nodeConnectionManager.ts#L515-L532); [`web/src/api/weall.ts` L125–150](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L125-L150); [`web/src/pages/SessionDevicesPage.tsx` L47–86](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L47-L86); [`web/src/pages/Disputes.tsx` L80–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L80-L120)

### FE-020 — Chain ID cache is global rather than tied to the selected node

**Priority:** P2  
**Classification:** Confirmed cache/fallback behavior; backend rejection expected  
**Acceptance cases:** R3-10,R3-11,R3-12.

**Evidence:** getChainId() stores one global value for 60 seconds without a cache key for the selected API base. Normal submitSignedTx()/submitSignedTxInSequence() call resolveChainId(), which falls back to an environment value or literal testnet when the chain-status read fails. In controlled/development switching, an operation sent to B may be signed using a chain ID learned from A. This is not evidence that B would accept a cross-chain transaction. Journal-bound registration/login operations have stricter fresh expectedChainId handling and must remain so.

**Remediation boundary:** Key chain identity by verified node+chain commitments and invalidate on node changes. For new signed mutations, use a verified matching chain identity or fail closed, with explicit retry guidance rather than silent fallback. Keep existing journal-bound exact-ID safety.

**Exact-main source references:** [`web/src/lib/chain.ts` L1–37](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/chain.ts#L1-L37); [`web/src/auth/session.ts` L1080–1130](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1080-L1130); [`web/src/auth/session.ts` L1141–1180](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1141-L1180); [`web/src/lib/browserNodeTransition.ts` L60–117](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeTransition.ts#L60-L117)

### FE-021 — Missing tab-scoped session bearer may be displayed as active

**Priority:** P2  
**Classification:** Confirmed conditional UI-truth gap; normal fresh-tab safeguard already present  
**Acceptance cases:** R3-13,R3-14,R3-15.

**Evidence:** readStoredSessionUnsafe reads persistent account metadata but bearer from tab-scoped sessionStorage. getSessionHealth() checks expiry and local signer, but when bearer is absent may still return active or expiring_soon. App.readyForApp checks that a signer exists and the status is not node_unverified; AppShell only locks writes for degraded SessionHealth. getAuthHeaders() correctly returns no auth headers when bearer is absent. In a controlled state where the tab retains a valid local signer but loses its tab-scoped bearer, the shell may display write-ready even though authenticated headers cannot be supplied. A normal newly opened independent tab usually lacks BOTH signer seed and bearer, so it is already blocked by the missing-local-signer gate. This does not demonstrate a practical authentication bypass.

**Remediation boundary:** Add explicit missing_session_bearer/recovery status; make protected-action readiness require active verified session with bearer and local signer, not just metadata. Keep anonymous public reads available. Keep bearer in sessionStorage (do not move it to localStorage).

**Exact-main source references:** [`web/src/auth/keys.ts` L261–322](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/keys.ts#L261-L322); [`web/src/auth/session.ts` L140–307](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L140-L307); [`web/src/auth/session.ts` L458–471](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L458-L471); [`web/src/App.tsx` L185–205](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L185-L205); [`web/src/components/AppShell.tsx` L85–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L85-L120); [`web/tests/e2e/production_browser_storage_isolation.spec.ts` L1–80](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/production_browser_storage_isolation.spec.ts#L1-L80)

### FE-022 — Finality monitoring can follow a different node than the submitted action

**Priority:** P2  
**Classification:** Confirmed provenance ambiguity; effect depends on timing and node sync  
**Acceptance cases:** R3-16,R3-17,R3-18.

**Evidence:** TxQueueProvider chooses args.finality.base || getApiBaseUrl() when monitoring begins, after the asynchronous task returns. Callers such as Group.tsx provide the original base to submitSignedTx() but do not always pass it into finality. If the active node changes while the action submits, finality may be checked against the newly selected node instead. Same-chain synchronized observers can give valid receipts, but the provenance of this specific operation becomes ambiguous and missing receipts can look like a submission problem.

**Remediation boundary:** Record the submission node, chain commitment, account and tx ID in an immutable action descriptor. Prefer status from the origin, permit separately labeled verified same-chain observer checks, and never treat unavailable as rejected or safe to retry. Preserve read-model reconciliation as nonterminal.

**Exact-main source references:** [`web/src/components/TxQueueProvider.tsx` L305–365](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L305-L365); [`web/src/components/TxQueueProvider.tsx` L445–482](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L445-L482); [`web/src/pages/Group.tsx` L290–342](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L290-L342); [`web/src/lib/status.ts` L49–143](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/status.ts#L49-L143)

### FE-023 — Session teardown can clear coordination state while an operation is still pending

**Priority:** P1 investigation  
**Classification:** Source-level race candidate; requires controlled reproduction  
**Acceptance cases:** R3-19,R3-20,R3-21.

**Evidence:** endSession() directly clears the account nonce reservation, signer lock, signer pending counts, and queued promise map, without awaiting an active runSignerSerialized task. It is called by local-only clear-session and expiry cleanup as well as after logout. Ordinary revoke-on-logout serializes its signed revocation, which mitigates the usual logout route, but direct teardown during another action is not shown to cancel that action. The precise duplicated nonce, late dispatch or user-visible outcome requires a race test; no exploit is claimed.

**Remediation boundary:** Introduce operation-lifecycle ownership and safe cancellation/no-new-work gate on session teardown; do not clear an in-flight lock until its owning task has completed or unequivocally aborted. Reconcile uncertain submissions before nonce reuse. Do not weaken canonical nonce or signer isolation.

**Exact-main source references:** [`web/src/auth/session.ts` L310–395](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L310-L395); [`web/src/auth/session.ts` L475–575](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L475-L575); [`web/src/auth/session.ts` L878–920](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L878-L920); [`web/src/auth/session.ts` L1490–1525](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1490-L1525); [`web/src/pages/SessionDevicesPage.tsx` L208–217](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L208-L217)

## Safeguards that must be preserved

- **Public-node compatibility:** public access-node candidates are checked against pinned chain/genesis/transaction-index/profile identity. Unlisted compatible HTTPS nodes require informed user consent; backend discovery cannot silently elevate an unlisted node to a credential trust root. [Node selection](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeTransition.ts#L1-L119), [public connection](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/connectPublicTestnetBrowser.ts#L1-L54).
- **Remote session recognition:** an active tab bearer must be accepted by the chosen backend before a public-testnet node transition. Failed recognition preserves the previous connection. [browserNodeSession.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeSession.ts#L65-L139).
- **Account custody:** private account signing material and session bearer are not supposed to be automatically inherited by independent browser profiles. Tests already assert that same-profile tabs do not automatically share a sessionStorage bearer. [isolation smoke](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/production_browser_storage_isolation.spec.ts#L1-L80).
- **No optimistic finality:** transaction status normalization requires an explicit successful apply result and locally synchronized state to label confirmed; unknown remains nonterminal. [status.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/status.ts#L49-L140).
- **Existing journal-bound safeguards:** specially tracked login/registration submissions use a freshly read expectedChainId, preserved nonce and durable pre-dispatch intent. Do not regress them when fixing normal transaction chain IDs. [session.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1141-L1229).
- **PoH uncertainty protection:** the async video submission journal already normalizes same-origin proxy base identity, blocks ambiguous duplicate submissions, and preserves uncertainty until canonical reconciliation. [pohSubmissionJournal.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/pohSubmissionJournal.ts#L40-L150).

## Priority development sequence

1. **F-CTX-01 — Canonical selected context:** FE-017/FE-018. Create one typed `(account, api_base, chain_id, context_generation)` binding for account reads and current-session metadata. Write regression tests for delayed responses before changing any presentation.
2. **F-CTX-02 — Honest authenticated-readiness state:** FE-021. Add missing-bearer status and ensure no controls imply authenticated writes on a tab without a bearer. Preserve anonymous public reading and tab-scoped secrets.
3. **F-CTX-03 — Reactive node switching:** FE-019. Make all node change paths publish and consume one event; remount or invalidate stale cached pages with safe handling for active PoH recordings.
4. **F-CTX-04 — Verified chain-bound signing:** FE-020. Use chain identity from the actual intended target instead of a global cache/default fallback for newly signed actions.
5. **F-CTX-05 — Immutable mutation provenance:** FE-022. Track submission origin, account and tx id through the finality monitor.
6. **F-CTX-06 — Teardown race proof:** FE-023. Reproduce with delayed submission and logout/expiry before choosing a minimal cancellation/lock-lifetime repair.

## Nonclaims and release posture

This audit has not run the backend, browsed a deployed development UI, produced new CI evidence, created a pull request, or confirmed a security vulnerability in consensus. The repository readiness statement remains NO-GO for public beta, public multi-validator operation, and mainnet. [Readiness](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md#L1-L35). The priorities here represent frontend source-risk triage, not release-blocker severity adjudication.

<!-- END UNALTERED SOURCE REPORT -->

---

## Source Report — Phase 4
**Source:** `WeAll_Frontend_Phase4_MAIN_Audit_2026-11-20.zip` / `01_PHASE4_FINDINGS.md`

<!-- BEGIN UNALTERED SOURCE REPORT -->

# WeAll — Frontend Phase 4 Audit: Accessibility and Browser Readiness

**Audit date:** 2026-11-20 (America/Los_Angeles)  
**Repository:** https://github.com/errol1swaby2-bit/WeAll-Protocol  
**Branch:** `main`  
**Exact inspected revision:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d)  
**Mode:** Read-only; source inspection plus supplied prior audit packages. **No live frontend, browser-test server, or two-node network was available to execute rendered tests.**  
**Release posture:** public testnet NO-GO, unchanged. No pushes, edits to GitHub, live identity material, or signed transactions.

## 1. Phase 4 verdict

Phase 4 **cannot be marked complete as a rendered acceptance audit**: the source checkout and live frontend/API were not available to the execution environment. An attempt to access the public GitHub repository directly from the sandbox failed DNS resolution; source files were retrieved through the connected GitHub interface instead. The five findings below are supported by exact-commit source inspection. The accompanying Playwright spec is an **unexecuted acceptance asset** and should be run against a trusted test stack after checkout. The three user-supplied prior-phase archives were read directly and reconciled as the baseline.

The strongest new defect is **FE-024**, an accessibility shortcut that modifies the SPA route. Other source issues concern heading semantics, route-change focus, breadcrumbs, and sort-selection semantics. Existing safeguards (drawer keyboard trap, visible focus, reduced-motion CSS, mobile tab minimum targets, protected node switching) remain important and must not be weakened.

## 2. New findings — FE-024 through FE-028

### FE-024 — Skip-to-content anchor changes hash route (P1, confirmed source defect)

- In [`AppShell.tsx` L203](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L203), the skip link has `href="#app-shell-content"`.
- [`router.ts` L916–922](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts#L916) interprets the URL fragment as the client-side path. `#/feed` becomes `#app-shell-content`, which `currentHashPath()` normalizes to `/app-shell-content`.
- The unknown path falls back to `/login` in [`matchRoute()`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/router.ts#L895). The application listens to `hashchange` in [`App.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L206).
- **Impact:** using keyboard skip navigation can navigate away rather than focus the content. This is a source-confirmed route collision, not a completed browser reproduction.
- **Fix boundary:** avoid changing `window.location.hash`. Attach a click handler that calls `preventDefault()`, then focus/scroll the existing `#app-shell-content` node; preserve browser keyboard semantics and skip visibility. Alternatively use a route-safe strategy that does not rewrite the SPA fragment.
- **Acceptance:** R4-01 and R4-02; focus moves to main and `#/feed` / `#/decisions` stays unchanged.

### FE-025 — Duplicate top-level headings (P2, source-confirmed hierarchy inconsistency)

- Shell renders `<h1 className="appShellTitle">` in [`AppShell.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L263).
- Groups renders its own `<h1>` in [`Groups.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Groups.tsx#L112) and Decisions renders another in [`Proposals.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposals.tsx#L237).
- **Impact:** competing page titles and redundant screen-reader heading choices. Multiple H1s do **not automatically prove a WCAG failure**, so classify as design/semantic consistency rather than a formal conformance defect.
- **Fix boundary:** establish one top-level page title per route; keep visible hero titles as properly subordinate H2 or derive the shell title from the page. Preserve visual presentation.
- **Acceptance:** R4-03/R4-04; check exact heading hierarchy in the rendered accessibility tree.

### FE-026 — Route-change focus is not explicitly managed (P2 candidate)

- The shell's main element is focusable (`tabIndex={-1}`) but there is no route-change focus effect in [`AppShell.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L309). Focus movement exists for the context drawer and menu return but not page navigation.
- A navigation control may retain keyboard focus while the route content changes. This may impair assistive-technology orientation, **but requires browser reproduction**; do not mark as WCAG noncompliance yet.
- **Fix boundary:** on a real route transition, focus the newly relevant main heading or main content without stealing focus during a PoH recording or other persistent guided journey. Respect reduced motion and modal state.
- **Acceptance:** R4-05/R4-06, including the guided PoH continuity exception.

### FE-027 — Breadcrumb accessible-label semantics (P3, source confirmed)

- [`AppShell.tsx` L266](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L266) applies `aria-label="Breadcrumbs"` to a plain `div`, not a semantic breadcrumb navigation landmark.
- **Fix boundary:** prefer `<nav aria-label="Breadcrumbs">` with a suitable list/link structure and `aria-current="page"` for the terminal crumb. Preserve route-dependent URLs and role boundaries.
- **Acceptance:** R4-07.

### FE-028 — Feed sort active state only conveyed visually (P2, confirmed source gap)

- [`FeedView.tsx` L585–588](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx#L585) switches `btnPrimary` CSS for Newest, Balanced, and Production sorting, but does not expose `aria-pressed`, a checked radio, or other programmatic state of the currently selected option.
- **Fix boundary:** add a proper single-choice sort control pattern (radio group or pressed toggle semantics), while retaining canonical backend ordering and its existing label distinctions.
- **Acceptance:** R4-08/R4-09, including keyboard-only sort changes and screen-reader state.

## 3. Coverage gap — existing accessibility check is not rendered verification

`web/scripts/test_accessibility_source.mjs` verifies the **presence of tokens** such as `Skip to content`, `id="app-shell-content"`, a reduced-motion media query, and a focus-visible selector. It does not click the skip link, inspect route retention, verify focus behavior, measure overflow, or test screen-reader semantics. `web/scripts/test_focused_shell_source.mjs` likewise uses source-token assertions for much of its coverage.

This explains how FE-024 can remain undetected while a source accessibility check passes. **Do not equate these scripts with a completed WCAG audit.**

## 4. Existing protections to preserve

- The context drawer implements Escape, explicit close control, focus trap, focus restoration and closed-state `inert` handling. See [`AppShell.tsx` L155–199](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L155).
- Reduced-motion and `:focus-visible` styles exist in [`styles.css`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/styles.css).
- Mobile `primaryNavigation` is fixed at narrow widths; the page includes additional bottom padding and minimum tab heights. It **still requires** 320/375/390/768/1024 px rendered overflow, zoom, viewport-keyboard, and safe-area tests. See [`styles.css` L3508](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/styles.css#L3508).
- Public-testnet access-node switching checks compatibility and session recognition before changing the connection. See [`browserNodeTransition.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeTransition.ts). Do not relax pinned identity or bearer limits.
- Identity, custody, transaction-status and earlier FE-001 to FE-023 findings remain open as recorded in user-supplied prior archives; Phase 4 does not reclassify them without new runtime evidence.

## 5. Test coverage and execution ledger

| Category | Prepared | Executed in this audit | Status |
|---|---|---|---|
| Phase 4 accessibility/route Playwright smoke | Yes; attached `.spec.ts` | No | Unexecuted |
| Narrow viewport and keyboard drawer smoke | Yes | No | Unexecuted |
| Two authenticated accounts, isolated browser profiles | Acceptance matrix only | No | Requires actual two-user test stack |
| Two compatible nodes and failover with pending tx | Acceptance matrix only | No | Requires actual controlled two-node environment |
| Camera/evidence privacy, end-to-end PoH | Acceptance matrix only | No | Not exercised |
| Actual frontend showcase screenshots | No | No | Deferred until visual and regression closure |
| Source inspection against exact `main` | Yes | Yes | Completed for named files |

## 6. Ordered development recommendation

1. **P1 keyboard route safety**: FE-024 plus existing FE-001; add rendered route-retention tests.
2. **P1 context consistency**: FE-017/018/019 and FE-023 concurrency investigation before multi-account/multi-node capture.
3. **P2 accessible interaction semantics**: FE-025/026/028, preservation of guided PoH focus, and FE-027 breadcrumb navigation.
4. **P2 interface polish**: FE-007 information hierarchy, Feed/Groups/Decisions responsive layouts, realistic error and empty states.
5. **Rendered acceptance**: run local stack, execute Playwright, inspect screenshots in required viewports, run privacy scrub, and only then capture wiki showcase images.

## 7. Nonclaims

This report does **not** establish a live browser bug reproduction for FE-026, accessibility conformance (or nonconformance) against WCAG as a whole, working camera/mobile devices, cross-node authority bypass, consensus failure, an externally reviewed production release, or a public-testnet launch. Source-confirmed defects and acceptance hypotheses remain labeled separately.

<!-- END UNALTERED SOURCE REPORT -->

---

## Full supporting plans and evidence references

All original acceptance cases remain **planned/unexecuted** as labeled by their source files.

### Phase 1 first remediation work order
**Source:** `Phase 1/02_IMPLEMENTATION_WORK_ORDER.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# WeAll Frontend — F-UX-01 Implementation Work Order

**Target:** `main`, verified as `6d3d69234415d294936d99e819367cff589ced3d` at audit time. Recheck the exact head before implementation; use a branch and pull request, not direct mutation of `main`.

## Goal
Repair three confirmed user-facing inconsistencies in anonymous Feed access, group membership guidance and error/empty states. The purpose is a cohesive, truthful public civic interface before expanded wiki publicity. **Keep this change frontend-only.**

## Scope

1. **FE-001:** In `web/src/components/PrimaryNavigation.tsx`, treat `/feed` as an anonymous-readable destination. Do not unlock posting or reactions. Preserve existing routes and five-destination layout.
2. **FE-002:** In `web/src/pages/Groups.tsx`, distinguish `GROUP_CREATE` eligibility from `GROUP_MEMBERSHIP_REQUEST` eligibility. Verify each required PoH tier against the exact canonical transaction index / runtime action eligibility before changing a gate. Keep the backend and `Group.tsx` as authority on signed requests; fix misleading directory label and readiness status.
3. **FE-003:** For `Groups.tsx`, `Proposals.tsx`, and `FeedView.tsx`, distinguish loading, successful empty collections, unavailable/failed backend data, and populated results. Preserve last-known-good data only if explicitly labeled stale. Ensure failures do not show an authoritative empty directory, empty decision history, or empty feed. Keep precise errors and actionable retry paths.

## Negative constraints

- No new transaction types or changes to canonical eligibility, chain time, constitution, election semantics, BFT, helper execution, crypto, identity policy, signing, nonce, session, API endpoint authority, economics or launch defaults.
- No synthetic user data, fake completed transactions, fake screenshots, or auto-awarded PoH tiers.
- Do not treat a source test or a UI toast as canonical transaction inclusion/finality.
- Do not weaken existing frontend gates for signed actions when permitting public read-only navigation.
- Do not perform production public-testnet release or merge authorization.

## Required regressions

- Anonymous visitor can navigate to Feed from the five-tab primary navigation; the public feed API loads or reports an honest error. Unsigned post/reply/report attempts remain disabled or backend rejected.
- Tier 0, Tier 1, Tier 2, missing/unknown state, expired/revoked standing, lost signer and stale session cases show accurate join eligibility text and must never bypass backend preflight.
- Group creation remains gated at its own canonical tier.
- Feed, group directory and decision hub each separately test loading, empty-success, populated-success, 404/unavailable, timeout and retry. No empty-result claim on failure.
- Viewport review at 390px, 768px, 1440px; keyboard-only traversal and accessibility descriptions for navigation and retry controls.
- Source checks and rendered-browser tests must execute at the same exact PR head. Collect output and do not equate the presence of scripts with a successful run.

## Suggested commands (execute from a clean repository checkout at exact branch head)

```bash
cd web
npm ci
npm run typecheck
npm run build
npm run test:focused-shell-source
npm run test:v16-navigation-source
npm run test:public-social-flow-readiness-source
npm run test:group-flow-readiness-source
npm run test:governance-rendered-journey-source
npm run test:accessibility-source
npm run test:rendered-civic-loop
```

These scripts exist in the current `web/package.json`. Browser tests may require the repository's prescribed test server/fixtures and should not be marked green unless actually run. Also run the repository-level frontend contract and required security checks relevant to changes.

## Acceptance report format

- Exact branch SHA, parent SHA, diff summary.
- List of modified files with rationale.
- Explicit evidence for each above regression, command, exit code and logs.
- Any backend/account/PoH authority mismatch observed during acceptance.
- Manual browser matrix (public / Tier 0 / Tier 1 / Tier 2 / unavailable) with screenshots **for internal QA only**.
- Remaining frontend issues as separate numbered backlog entries.
- Merge verdict independent from broader testnet release verdict. No silent status escalation.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

### Phase 2 complete 20-case matrix
**Source:** `Phase 2/02_PHASE2_ACCEPTANCE_MATRIX.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# WeAll Frontend Phase 2 — Regression and Acceptance Matrix

**Baseline:** `main` = `6d3d69234415d294936d99e819367cff589ced3d` as checked 2026-11-20. Branch new fixes separately and retest their exact new head. **This is a test plan, not a passing results log.**

| Test ID | Area | Stimulus / fixture | Pass criterion | Finding |
|---|---|---|---|---|
| R2-01 | Review queue | Async PoH API times out while live/contents succeed | Async lane says unavailable with retry; other lanes display verified data | FE-011 |
| R2-02 | Review queue | `/disputes/current` returns 403/500 | Current case queue unavailable, not zero assignments; no false all-clear | FE-011 |
| R2-03 | Reviewer status | Account reviewer-status request fails | Review lane standing says unknown/unavailable, not confirmed opt-out | FE-011 |
| R2-04 | Reviewer queue | All six endpoints return success and truly empty arrays | Honest empty state in each lane | FE-011 |
| R2-05 | Device signer | Tier 2, valid account session, missing local signer on public Reports | Public reads work; “Ready to review” remains false | FE-012 |
| R2-06 | Device signer | Tier 2 with expired session/locked device | Signed actions locked; recovery steps remain available | FE-012 |
| R2-07 | Juror fallback | SYSTEM dispute with no assignment; unrelated account | No “canonically assigned” claim; backend rejects unqualified action | FE-014 |
| R2-08 | Juror fallback | SYSTEM dispute; conflicted reporter or target owner | Never represented as confirmed juror or granted reviewer evidence | FE-014 |
| R2-09 | Juror fallback | Legitimate active unconflicted bootstrap reviewer | Can follow deliberate backend-validated accept path without fake preassignment | FE-014 |
| R2-10 | Juror fallback | Canonically assigned account and matching `/disputes/current` | “Assigned to you” appears, with exact source provenance | FE-014 |
| R2-11 | Report summary | Stage finalized, `resolved=false` | Open count follows canonical stage/summary, not `resolved` flag | FE-015 |
| R2-12 | Report summary | More than 200 disputes with backend summary | Network counts explicitly distinguished from returned subset | FE-015 |
| R2-13 | Reports filter | Declined, withdrawn, timed-out or completed reviewer | Not represented as current actionable assignment; history remains readable | FE-016 |
| R2-14 | Reports filter | Assigned, accepted, present or attended reviewer | Active work is visible from authoritative queue/scope | FE-016 |
| R2-15 | Account switch | Account A history; switch to B in same browser | No attribution of A tx to B; legacy unknown records labeled or separated | FE-013 |
| R2-16 | History migration | Existing pending v1/v2/v3 local entries | Preserve tx IDs and unknown status; no silent “confirmed” conversion | FE-013 |
| R2-17 | History proof | Backend `confirmed` but `apply_ok=false` | Mark failed/rejected with explanation | Guardrail |
| R2-18 | History proof | Backend `confirmed` but `local_state_synced=false` | Remain pending/nonfinal | Guardrail |
| R2-19 | PoH journal | Same-origin API base `''` | Journal persists `/`, not an invalid empty address; no duplicate upload retry | Guardrail |
| R2-20 | PoH uncertainty | Case history endpoint fails while a journal exists | Journal remains blocked until exact original case reconciles | Guardrail |

## Recommended automated suite — run from a full-history checkout, at exact new PR head

```bash
cd web
npm ci
npm run typecheck
npm run build
npm run test:accessibility-source
npm run test:focused-shell-source
npm run test:reviewer-critical-source
npm run test:dispute-review-rendered-journey-source
npm run test:tx-apply-receipt-truth
npm run test:tx-reconciliation-truth
npm run test:poh-submission-journal
npm run test:verification-history-panel
npm run test:rendered-civic-loop
```

**Additional targeted evidence:**

- Audit source contract `node scripts/test_dispute_current_queue_source.mjs` if its test harness and fixtures are present at the checked head.
- Add or revise a source+runtime regression specifically for the bootstrap provisional-vs-assigned distinction. The repository's existing `test_live_request_sync_and_dispute_bootstrap.py` **asserts the old fallback exists**; do not delete or bypass it without explicit review of the backend-bootstrap condition and intended acceptance path.
- Add account-switch transaction history tests and reproduce recovery of unattributed old records.
- Run browser viewports (390px, 768px, 1440px) with mouse, keyboard, and screen-reader semantics. Test anonymous, Tier 0/1/2, no key, expired session, service unavailable, and node-switch scenarios.
- Test the real independent-browser 2-node replay/restart flows separately from mocked Playwright/source tests before calling an integrated journey verified.

## Restrictions

No modifications to PoH canonical tiers, signature/nonce logic, consensus, identity evidence privacy, government identity policy, group scope, dispute-juror authority, reputation/sanction law, runtime transaction schemas, economics, node validator settings, or public-beta flags. Failed/unknown status must never be silently upgraded to success. No production authority is inferred from client state.

## Closure record required

For every finding record: exact new commit, diff, relevant tests and exit codes, controlled browser reproduction, accepted negative cases, residual limitations, independent backend-admission behavior, and explicit **frontend-change merge verdict separate from testnet launch verdict**.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

### Phase 3 complete 21-case matrix
**Source:** `Phase 3/02_PHASE3_REGRESSION_MATRIX.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# WeAll Phase 3 — Test Plan (NOT a Passing Results Log)

**Target:** `6d3d69234415d294936d99e819367cff589ced3d`; complete only on a separately reviewed implementation branch.
**Baseline test results in this audit:** none executed.

| ID | Finding | Test stimulus | Acceptance criterion | Evidence needed |
|---|---|---|---|---|
| R3-01 | FE-017 | Normal clean account registration + device session, no dev bootstrap | The selected session account and shared AccountProvider identify exactly the same account; no stale legacy key required | Integration browser; two accounts |
| R3-02 | FE-017/FE-018 | Begin account A read, switch to account B before A resolves | A response never updates B screen or permissions; B read is issued and retained | Delayed HTTP fixture |
| R3-03 | FE-018 | Begin a node A read, switch to B before response | No A data is displayed as B and fresh B state appears | Two verified nodes, delayed A |
| R3-04 | FE-018 | Account A read resolves after local session cleared | Provider state resets to null and cannot repopulate from A | Delayed HTTP + cleanup |
| R3-05 | FE-018 | Two refreshes with distinct identity snapshots while first pending | Refresh coalescing does not discard second identity; unavailable does not imply tier 0 verified | Controlled promise tests |
| R3-06 | FE-019 | Open Feed/Groups, switch to compatible node B without navigating away | Displayed source, list data, and loading state refresh from B; no mixed-source display | Two nodes + browser |
| R3-07 | FE-019 | Change backend via Settings in development mode | A normalized node-changed event and cache invalidation reach all subscribed components | Component harness |
| R3-08 | FE-019 | Switch nodes during PoH evidence recording | Recording safely remains controlled or is explicitly blocked; no silent evidence loss | Browser media stub |
| R3-09 | FE-019 | Public-testnet node mismatch or user declines unlisted HTTPS consent | Selected node unchanged, no bearer leaked, protected writes locked | Existing connection policy + browser |
| R3-10 | FE-020 | Read chain A then change to different development chain B before 60s TTL | New operation uses verified chain B or refuses to sign; never silently signs B action under A | Two dev chains |
| R3-11 | FE-020 | Status endpoint unavailable for a new protected write | Client fails closed with useful retry guidance; no fallback chain string used for new mutation | Fetch failure stub |
| R3-12 | FE-020 | Journal-bound registration while node identity changes | Exact expected chain and pending intent remain intact, no duplicate dispatch | Existing registration end-to-end |
| R3-13 | FE-021 | Open a second tab with shared localStorage session metadata but absent tab bearer | Session health says missing local signer (or a more specific unavailable state), not active; public routes still work | Same-browser-tab test |
| R3-14 | FE-021 | Controlled tab retains a valid signer but loses its tab-scoped bearer | No protected action button claims ready; no session headers sent until tab-scoped bearer is restored | Browser harness |
| R3-15 | FE-021 | Missing/revoked/expired bearer and node-unverified cases | Distinct statuses and recovery steps, never automatic hidden bearer copy to localStorage | Browser + backend simulator |
| R3-16 | FE-022 | Start signed mutation against node A, switch to B before task resolves | Status tracker carries submission node and tx ID; no silent redirection or false finality | Two observers + delay |
| R3-17 | FE-022 | Node A confirms, node B unavailable/stale | Original canonical status can settle; B failure remains diagnostic and cannot falsely reject | Status mock |
| R3-18 | FE-022 | Status unknown on all nodes | Action remains nonfinal with original tx ID and do-not-repeat warning | Transaction mock |
| R3-19 | FE-023 | Call direct local session clear while signer-serialized task holds lock | Lock/nonce ownership cannot be taken by a second submission before first finalizes/aborts; no hidden duplicate | Deterministic deferred promise |
| R3-20 | FE-023 | Session expires mid-nonce-reservation | Original action outcome is tracked; later actions cannot reuse an uncertain nonce | Fake clock + nonce endpoint |
| R3-21 | FE-023 | Normal revoke-on-logout with pending signed action | Pending action resolves or is safely cancelled before teardown; revocation does not falsely report success | Two signed actions under one account |

## Mandatory gating

- Confirm both backend and web compilation/test suites at exact PR head; the existence of a test file is not proof it passed.
- Repeat the browser tests with at least two independent accounts and at least two distinct access-node processes; do not infer cross-machine independence from same-process mocks.
- Never inject production signing keys into screenshots, logs or expected test snapshots. Use dedicated test keys and explicitly labeled fixtures.
- Preserve strict public-only reads, ML-DSA local custody, pinned chain identity, tab-bound bearer storage, no forced duplicate PoH submission, and canonical transaction finality.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

### Phase 3 full source index
**Source:** `Phase 3/03_PHASE3_SOURCE_INDEX.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# Phase 3 Source Index

All links resolve to the frozen `main` commit `6d3d69234415d294936d99e819367cff589ced3d`. The listed line ranges were read via the connected GitHub repository interface.

| Source | Line ranges | Role |
|---|---|---|
| `web/src/App.tsx` | [185–205](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L185-L205) (FE-021) | Read-only source evidence |
| `web/src/api/weall.ts` | [153–172](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L153-L172) (FE-017), [125–150](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/api/weall.ts#L125-L150) (FE-019) | Read-only source evidence |
| `web/src/auth/keys.ts` | [261–322](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/keys.ts#L261-L322) (FE-021) | Tab-scoped private signer seed; public-only local metadata |
| `web/src/auth/session.ts` | [329–363](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L329-L363) (FE-017), [1080–1130](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1080-L1130) (FE-020), [1141–1180](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1141-L1180) (FE-020), [140–307](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L140-L307) (FE-021), [458–471](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L458-L471) (FE-021), [310–395](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L310-L395) (FE-023), [475–575](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L475-L575) (FE-023), [878–920](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L878-L920) (FE-023), [1490–1525](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/auth/session.ts#L1490-L1525) (FE-023) | Read-only source evidence |
| `web/src/components/AppShell.tsx` | [85–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L85-L120) (FE-021) | Read-only source evidence |
| `web/src/components/TxQueueProvider.tsx` | [305–365](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L305-L365) (FE-022), [445–482](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L445-L482) (FE-022) | Read-only source evidence |
| `web/src/context/AccountContext.tsx` | [2–90](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L2-L90) (FE-017), [57–132](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/context/AccountContext.tsx#L57-L132) (FE-018) | Read-only source evidence |
| `web/src/lib/browserNodeTransition.ts` | [60–117](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/browserNodeTransition.ts#L60-L117) (FE-020) | Read-only source evidence |
| `web/src/lib/chain.ts` | [1–37](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/chain.ts#L1-L37) (FE-020) | Read-only source evidence |
| `web/src/lib/devBootstrap.ts` | [1–170](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/devBootstrap.ts#L1-L170) (FE-017) | Read-only source evidence |
| `web/src/lib/nodeConnectionManager.ts` | [515–532](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/nodeConnectionManager.ts#L515-L532) (FE-019) | Read-only source evidence |
| `web/src/lib/revalidation.ts` | [20–95](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/revalidation.ts#L20-L95) (FE-018) | Read-only source evidence |
| `web/src/lib/status.ts` | [49–143](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/status.ts#L49-L143) (FE-022) | Read-only source evidence |
| `web/src/pages/Disputes.tsx` | [80–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Disputes.tsx#L80-L120) (FE-019) | Read-only source evidence |
| `web/src/pages/Group.tsx` | [290–342](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L290-L342) (FE-022) | Read-only source evidence |
| `web/src/pages/SessionDevicesPage.tsx` | [47–86](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L47-L86) (FE-019), [208–217](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/SessionDevicesPage.tsx#L208-L217) (FE-023) | Read-only source evidence |
| `web/src/pages/Settings.tsx` | [131–177](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Settings.tsx#L131-L177) (FE-019) | Read-only source evidence |
| `web/tests/e2e/production_browser_storage_isolation.spec.ts` | [1–80](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/production_browser_storage_isolation.spec.ts#L1-L80) (FE-021) | Read-only source evidence |

## Relevant existing tests (inventory only)

- [web/tests/e2e/production_browser_storage_isolation.spec.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/production_browser_storage_isolation.spec.ts) — asserts tab/profile storage boundaries using fixture-only metadata, not two actual on-chain sessions.
- [web/scripts/test_cloudflare_testnet_behavior.mjs](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/scripts/test_cloudflare_testnet_behavior.mjs) — executable mocked public access-node discovery/session policy, not executed during this audit.
- [web/tests/e2e/account_custody_registration_restore.spec.ts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/tests/e2e/account_custody_registration_restore.spec.ts) — named account registration/restore integration surface; presence is not a passing result.
- [Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md) — release posture NO-GO.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

### Phase 4 complete 20-case matrix
**Source:** `Phase 4/02_PHASE4_ACCEPTANCE_MATRIX.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# WeAll Phase 4 — Browser Acceptance Matrix (NOT EXECUTED)

Main revision: `6d3d69234415d294936d99e819367cff589ced3d`. All cases below are **planned**, not passed. Public testnet remains NO-GO.

| Case | Tracks | Route/setup | Procedure | Pass condition | Evidence state |
|---|---|---|---|---|---|
| R4-01 | FE-024 | Anonymous Feed | Keyboard Tab to Skip to content, press Enter | Hash remains `#/feed`, focus enters content; never fall back to login | Source predicts fail |
| R4-02 | FE-024 | Signed-in Decisions | Keyboard activate skip link | Hash unchanged; `#app-shell-content` focused | Requires signed session |
| R4-03 | FE-025 | Groups | Inspect rendered heading list / accessibility tree | One unambiguous page-level H1, subordinate Groups title | Source predicts duplicate |
| R4-04 | FE-025 | Decisions | Inspect rendered heading list at 100% and 200% zoom | No duplicate top-level page title | Source predicts duplicate |
| R4-05 | FE-026 | Feed → Groups → Decisions | Navigate with keyboard | Main heading or main landmark meaningfully focused/announced | Browser proof required |
| R4-06 | FE-026 | Guided PoH | Change guided stages during recording; Escape modal | No loss of capture controller or evidence; focus returns safely | Real camera and authenticated stack required |
| R4-07 | FE-027 | Groups detail | Inspect accessibility tree breadcrumb landmark | Named navigation landmark with current page semantics | Source predicts missing landmark |
| R4-08 | FE-028 | Feed | Check selected sort active semantics | Exactly one selected sort exposed programmatically | Source predicts fail |
| R4-09 | FE-028 | Feed | Use only keyboard to change sort | Focus and selection state agree with visible sort | Backend test data recommended |
| R4-10 | FE-001 | Anonymous Feed | Open page via public route and main nav | Feed tab is operable without login; post actions still gated | Prior source confirmed |
| R4-11 | FE-017/018 | Two browser profiles | A and B sign in separately; reorder delayed API responses | No cross-account name/tier/nonce/avatar contamination | Two real test accounts required |
| R4-12 | FE-019/020 | Two different dev nodes | Switch A→B→A while mounted | All page reads and signed chain context match selected node | Two controlled compatible nodes required |
| R4-13 | FE-021 | Tab without session bearer | Open fresh independent tab retaining public metadata only | Session shows missing/needs recovery, protected writes disabled | Browser contexts required |
| R4-14 | FE-022 | Pending tx and node change | Submit on A; change to B during finality poll | Display original source node, chain, tx ID; no false completion | Two-node stack required |
| R4-15 | FE-023 | Concurrent signed submission and logout | Pause submission at signer lock; logout/abort; second tab attempts same signer | No nonce or lock corruption; no duplicate submission | Controlled concurrency test required |
| R4-16 | Responsive | 320, 375, 390, 768, 1024 px | Inspect Feed, Groups, Decisions, menus, dialogs | No document-level horizontal scrolling or obscured primary CTA | Visual browser inspection required |
| R4-17 | Accessibility | Zoom 200%; reduced motion; keyboard only | Inspect text clipping, focus visibility, fixed bottom navigation | No lost controls; visible focus; optional animation suppressed | Browser inspection required |
| R4-18 | Review Center | API 503 vs canonical empty result | Simulate failure in one reviewer lane | Unavailable clearly distinct from no assigned cases | Phase 2 regression |
| R4-19 | Verification | Camera denied then retried and route changed | Exercise async PoH journey | No leaked stream, duplicate upload, or claim of unearned tier | Authenticated camera environment required |
| R4-20 | Privacy and publication | Frontend screenshot pass | Inspect rendered populated public Feed/Groups/Decisions | No recovery keys, PoH evidence, bearer, private names, misleading confirmed state | Screenshots deferred |


## Test artifacts to retain after running

- Exact HEAD SHA and clean-tree status; compilation and production-safety checks.
- Browser viewport, zoom, operating-system/device and backend node URLs **without secrets**.
- Playwright traces only in controlled private storage; redact signed payloads, recovery material, session bearers and private PoH evidence before distributing.
- Screenshots of public-safe routes only, labeled as development/testnet where appropriate.
- Pass/fail per case, with original response and canonical receipt evidence for claims of confirmation; no simulated result described as live protocol proof.

## Recommended source-level gate

`npm run typecheck` + `npm run test:accessibility-source` + `npm run test:focused-shell-source` + `npm run production-safety-check` from `web/`, followed by targeted Playwright specs and end-to-end 2-account/2-node rehearsals. These were **not executed** here.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

### Phase 4 execution runbook
**Source:** `Phase 4/04_EXECUTION_RUNBOOK.md`

<!-- BEGIN UNALTERED SUPPORTING DOCUMENT -->

# Phase 4 execution runbook (read-only in audit session)

## Verification basis

Current main was checked against `6d3d69234415d294936d99e819367cff589ced3d` and was identical at the time of audit. Prior Phase 1–3 ZIP contents were opened and compared against the cumulative FE-001–FE-023 ledger. **This package has not been run against a browser frontend.**

The sandbox has Node 22 and TypeScript globally available, but cannot resolve `github.com` from the command-line environment and has no local checkout of the full repository. GitHub source was retrieved through the connected repository interface. A TypeScript transpilation syntax check of the attached spec may be performed locally; that is not a Playwright test execution.

## Run after obtaining the exact main checkout on a trusted machine

1. `git fetch origin main && git checkout main && git rev-parse HEAD` — assert HEAD equals `6d3d69234415d294936d99e819367cff589ced3d` or deliberately refresh the audit against the new HEAD. Do not reset or discard unsaved work.
2. `cd web && npm ci` — use Node >=20.19 and npm >=10; Node 22 is documented in the repository's web toolchain.
3. `npm run typecheck && npm run test:accessibility-source && npm run test:focused-shell-source && npm run production-safety-check`.
4. Place `03_frontend_phase4_acceptance.spec.ts` at `web/tests/e2e/frontend_phase4_acceptance.spec.ts`.
5. Start the supported local frontend and backend according to the root README, preserving the exact node, profile and port configuration. Use a private local development environment and preseeded *test* data only.
6. From `web`, run `PHASE4_BASE_URL=http://127.0.0.1:5173 npx playwright test tests/e2e/frontend_phase4_acceptance.spec.ts` (adjust the URL if the supported local frontend port differs). Some tests intentionally fail on the audited current main and define the acceptance target.
7. Run the existing real-stack suites (`test:account-custody-e2e`, `test:m2-async-independent-browsers`, `test:m2-live-independent-browsers`, `test:m3-civic-governance-real-stack`) using their documented prerequisites; **do not presume** a Playwright mock equals actual protocol evidence.
8. Use matrix R4-11 to R4-20 for controlled authenticated actor and node-switch scenarios. Capture runtime traces and backend receipts privately; redact signing seeds, recovery files, session headers, encrypted private evidence and identities.
9. Only after fixes are merged into `main` and an exact-HEAD fresh clone passes the release acceptance criteria should authentic frontend screenshots be captured for the P2P Wiki.

## Mandatory rollback/safety boundaries

- Do not auto-resubmit a transaction after an unknown result. Reconcile the original signed ID against canonical apply and synchronized state.
- Do not change PoH/reputation/juror authorization policy to fix frontend copy.
- Do not weaken signed registry pins, per-node bearer checks, or reviewer privacy controls.
- If any test requires credentials, generate dedicated local test accounts. Do not load production recovery material.
- Mark every evidence item `source reviewed`, `synthetic fixture`, `browser tested`, or `real-node verified` without conflating them.

<!-- END UNALTERED SUPPORTING DOCUMENT -->

---

## Source data preservation and checks

- The complete package preserves every original extracted member from each source ZIP under `Originals/`, including the Phase 4 Playwright `.spec.ts`.
- Full source-archive and file SHA-256 hashes, finding crosswalk, and acceptance enumeration are in `03_RECONCILIATION_AND_COVERAGE.md`.
- Machine-readable full descriptions and exact source text are in `04_FINDINGS_FULL_DETAIL.json`.
- No new code-level findings were created by the merger.


---

# Phase 5 source extension — FE-029–FE-032

# WeAll Frontend — Phase 5 Read-only Audit: Human-review decisions, bearer handling, and live-room transport

**Audit baseline:** `main` at `6d3d69234415d294936d99e819367cff589ced3d` (verified by exact comparison). **Audit mode:** source inspection only; no repository changes, frontend execution, WebRTC connection, or signed transactions. **Scope:** gaps not covered by FE-001–FE-028 in the previously uploaded complete Phase 1–4 ledger.

**Scope caveat:** An unrelated development branch, `audit/f-ux-01-public-civic-ux-20261120`, was inadvertently created during an earlier response. It is *not part of this audit*, is unmerged, and must not be used as the source baseline. The separate `main` remains at the commit above.

## Summary

| ID | Priority | Evidence | Finding |
|---|---|---|---|
| FE-029 | **P1** | Confirmed source-level unintended action path; no transaction executed | Canceling either PoH reviewer verdict-note prompt still proceeds to a verdict transaction |
| FE-030 | **P2** | Confirmed source-level secret exposure in browser UI; no exfiltration observed | Account Verification prepopulates a plaintext browser prompt with the current session bearer |
| FE-031 | **P1 candidate** | Confirmed event ordering; remote room behavior untested | External live-verification room opens before reviewer acceptance/attendance checks complete |
| FE-032 | **P1 investigation** | Confirmed source policy mismatch; unauthorized media access unproven | WebRTC signaling participant list includes assigned but unaccepted or possibly declined reviewers |

## FE-029 — Cancel on reviewer note prompts does not cancel the verdict

**Priority:** P1. **Status:** Open, source-confirmed defect in intent handling. **Source:** `web/src/pages/JurorDashboard.tsx`, approximately lines 519–566.

The async reviewer function executes `window.prompt("Optional note", "") || ""`, creates the verdict body regardless of whether the prompt returned `null` (Cancel), requests the canonical review transaction skeleton and calls the signed submission helper. The live reviewer verdict function follows the same pattern. In JavaScript, both Cancel (`null`) and accepting an empty note (`""`) become an empty string; this eliminates the user's cancellation signal. The report-content flow in `FeedView.tsx` provides a relevant contrasting precedent: it explicitly returns if the prompt result is `null`.

**Impact:** A reviewer can click Approve/Reject, cancel the apparent dialog, and still initiate the corresponding signed review action. There is no proof a transaction was accepted in production; backend receipt/finality gates still apply. The issue concerns user intent and the irreversibility of a submitted verdict.

**Required behavior:** Distinguish Cancel from an intentionally empty optional note; never construct or sign verdict when canceled. Ideally use a persistent accessible confirmation step that states verdict, case ID, account and any notes before dispatch. Confirm no duplicate submission on repeated input and preserve authoritative backend eligibility checks.

**Source:** `web/src/pages/JurorDashboard.tsx` and `web/src/components/FeedView.tsx`.

## FE-030 — Existing session bearer is displayed in a plaintext native prompt

**Priority:** P2 (raise if demonstrated shoulder-surfing/logging leak in supported environment). **Status:** Open, source-confirmed UI exposure; no exfiltration demonstrated. **Source:** `web/src/pages/AccountVerificationPage.tsx`, approximately lines 806–845 and 1690–1716.

The active Account Verification screen renders a “Save session key” control. Its handler calls `window.prompt("Paste the session key you want linked to this device.", session?.sessionKey || "")`. The second argument *prefills the visible prompt field with the current live bearer* when one is present. The handler subsequently submits a signed `ACCOUNT_SESSION_KEY_ISSUE` action and updates local session state. This contrasts with the browser's otherwise deliberate use of tab-scoped `sessionStorage` for the session bearer.

**Impact:** Exposure to a person looking at the screen or a captured screenshot/recording when this path is used. A native prompt is not a masked secret-entry control. No evidence of transport-level or cross-origin exfiltration was found in this review.

**Required behavior:** Avoid displaying existing bearer values; prefer the existing canonical device-session issuance/recovery pathway. If manual entry is still required, use an explicit masked control with secret reveal/hide, generate rather than accept arbitrary values where supported, and clearly convey authority/revocation consequences. Confirm the optional preserved v1.6 page is not an alternate unjournaled authority path.

**Source:** `web/src/pages/AccountVerificationPage.tsx`, `web/src/auth/session.ts` (tab-scoped bearer design), `web/src/pages/AccountVerificationPageV16Preserved.tsx` (similar preserved code; verify runtime reachability separately).

## FE-031 — External video room is opened before the canonical accept/check-in sequence

**Priority:** P1 candidate; reproduction and deployment-policy review needed. **Status:** Open, event ordering confirmed; media-access impact not established. **Source:** `web/src/pages/LiveVerificationRoom.tsx`, approximately lines 838–887.

`checkIntoRoom()` reads a possible external join URL and invokes `window.open(externalRoomUrl, "_blank", "noopener,noreferrer")` **before** executing the transaction sequence to accept a reviewer assignment, wait for its canonical status, record attendance, and start local media. Thus an external tab may open when the subsequent on-chain eligibility or attendance checks fail. Whether the external provider permits entry or media before chain confirmation depends on the deployed room integration and was not tested.

**Required behavior:** Define when a user may navigate to third-party/self-hosted media transport, ensure that the UI does not imply verified reviewer admission before chain state is current, and test a rejection/unavailable-node sequence without falsely displaying success. Do not conflate opening a page with authorizing a live review or connecting a remote peer.

**Source:** `web/src/pages/LiveVerificationRoom.tsx` and `web/src/pages/JurorDashboard.tsx`.

## FE-032 — Media signaling eligibility is based on case membership, not explicit acceptance

**Priority:** P1 investigation (potential confidentiality boundary; policy decision and controlled two-browser test required). **Status:** Open, source policy discrepancy confirmed; unauthorized live-video access **not** established.

The frontend builds `p2pParticipantAccounts` from the case subject plus *all* jurors in a canonical case. It sets `canJoinReview` for any assigned juror without checking `myJuror.accepted` or whether the juror has declined. A retry button can invoke `startP2PRoom()` when `p2pError` is set, and the helper `ensureP2PRoomStarted()` checks `canJoinReview` rather than acceptance/attendance. The usual guided Join flow does wait for signed acceptance and attendance before initiating media, which is an existing safeguard.

The backend in `Weall-Protocol/src/weall/api/routes_public_parts/poh.py` uses `_require_live_room_participant` (approximately lines 1350–1375) to authorize the case subject or an account in the `jurors` map; it does not test `accepted` in that method. `_live_case_participant_ids` (approximately lines 2475–2486) includes all juror IDs as potential signaling endpoints. The signaling send route calls `_require_live_room_participant` and `_validate_webrtc_target` after authenticating the browser account (approximately lines 2800–2815). Consequently, the visible source does not by itself enforce an `accepted == true` requirement on all WebRTC signaling.

**Uncertainty / constitutional boundary:** The protocol's intended media-visibility policy must be verified. It may intentionally authorize all assigned reviewers to receive live-room transport before formally accepting, or it may intend acceptance/attendance to be a confidentiality gate. This distinction is currently inconsistent with the guided-flow copy. A WebRTC handshake, backend SDP exchange, or actual remote audio/video reception was **not** executed. Case participants must still authenticate; outsiders are denied by backend source checks.

**Required action:** Determine the intended acceptance/decline/recusal transport policy. If only accepted reviewers may receive media, enforce it in the *backend* signal-send, signal-read and target-selection paths—not merely with a disabled frontend button—and in frontend P2P recipient derivation and retry. Exercise accepted, assigned-but-pending, declined, revoked, outsider and applicant scenarios in an isolated two-node/two-browser rehearsal. Do not weaken evidence-encryption restrictions or reclassify transport membership as PoH verdict authority.

**Source:** `web/src/pages/LiveVerificationRoom.tsx`, `Weall-Protocol/src/weall/api/routes_public_parts/poh.py`, `Weall-Protocol/tests/test_restricted_poh_session_and_webrtc_transport.py`.

## Confirmed protective behavior / non-findings

- Canonical `/v1/accounts/{account}` already overrides its public `state.poh_tier` with backend `effective_poh_tier()`. A source-only claim that this endpoint simply exposes the stale legacy tier would be wrong. Legacy client-side reads can remain stale across node/context changes (already FE-017–FE-023), but this is not a separate FE-033 finding.
- The live-room *guided* reviewer join flow waits for canonical review acceptance and attendance before normal media startup. The potential bypass/ambiguity is the broader signaling/participant and retry path, not the guided happy path.
- WebRTC signaling endpoints authenticate session principals and require case participation; this audit does not show that an arbitrary nonparticipant can join.
- The Feed's report prompt preserves Cancel as an abort signal. It is not affected by FE-029.
- Signed verdict acceptance, reviewer assignment, and PoH upgrades remain backend/consensus-authoritative. These frontend findings do not themselves establish a constitutional or cryptographic authorization bypass.

## Evidence / validation limits

This is an **audit of source code from `main`** only. It did not execute Playwright, backend tests, mocked signaling, actual WebRTC transport, a browser media permission request, or a signed PoH reviewer transaction. `P1 investigation` reflects seriousness *if the policy forbids pre-acceptance media access*, not a confirmed exploit. Public-testnet release status remains **NO-GO** per repository reviewer readiness statement.

## Source index (pinned `main`)

- [JurorDashboard.tsx — reviewer verdict prompts](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx)
- [AccountVerificationPage.tsx — manual session prompt](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountVerificationPage.tsx)
- [LiveVerificationRoom.tsx — media join and recipient logic](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/LiveVerificationRoom.tsx)
- [PoH backend route — case participant and signaling guards](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/poh.py)
- [FeedView.tsx — correct report cancellation precedent](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx)
- [Current readiness statement](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md)


# WeAll Phase 5 — Planned regression and acceptance matrix

**Baseline:** `main` / `6d3d692`. **Executed:** none. **Approach:** run only in isolated, disposable test identities and a local two-browser/two-node rehearsal. Do **not** use production PoH evidence or real participants' recordings.

| Case | Finding | Scenario | Required result | Method/status |
|---|---|---|---|---|
| P5-01 | FE-029 | Reviewer selects **Approve**, then Cancel in optional-note prompt | No skeleton request, signing, network submission or state mutation | Browser mock / unrun |
| P5-02 | FE-029 | Reviewer selects **Reject**, then Cancel | Same fail-closed outcome | Browser mock / unrun |
| P5-03 | FE-029 | Live reviewer selects **Pass** or **Fail**, then Cancel | Neither verdict dispatched | Browser mock / unrun |
| P5-04 | FE-029 | Reviewer explicitly confirms decision with empty optional note | Exactly one correct-case verdict, authorized by backend and canonical receipt | Real-stack / unrun |
| P5-05 | FE-029 | Repeated click while verdict pending | No duplicate signed transaction; uncertain receipt not retried as a fresh verdict | Real-stack / unrun |
| P5-06 | FE-030 | Existing session bearer present, open verification setup control | Current bearer is not displayed in plaintext prompt | Browser / unrun |
| P5-07 | FE-030 | User supplies/reissues session key | Authorized, scoped account/device state and secure storage preserved; failure not shown as success | Real-stack / unrun |
| P5-08 | FE-031 | External room configured; case reviewer acceptance rejects | No false 'authorized review' display; inspect whether external tab opens prematurely | Browser mock / unrun |
| P5-09 | FE-031 | External room configured; canonical acceptance and attendance succeed | Transition clearly distinguishes browser tab, media join, chain attendance and verdict | Two-browser / unrun |
| P5-10 | FE-032 | Assigned juror not yet accepted | Check signaling-send/read, local media start and peer offer policy against approved requirement | Backend+browser / unrun |
| P5-11 | FE-032 | Juror explicitly declined / recused | No transport access if policy forbids; verify case map and backend rules | Backend+browser / unrun |
| P5-12 | FE-032 | Fully accepted and attended interacting reviewer | Room and WebRTC media still work; voting remains separately gated | Two-browser / unrun |
| P5-13 | FE-032 | Case outsider with valid separate account session | Session-bound signaling denied (existing security protection) | Backend / unrun |
| P5-14 | FE-032 | Applicant plus accepted reviewer on different nodes | Connection, presence and signaling coherent; no media leak to ineligible juror | Two-node/browser / unrun |
| P5-15 | FE-031/32 | Node mismatch, stale case state, unexpected disconnect | No stale privileged recipient or silent transport success, no constitutional-authority claim | Two-node/browser / unrun |

## Regression preconditions

All new tests must freeze the exact audited commit or a subsequent reviewed implementation head; record changed SHA, node identities, test users, viewport, browser version, permission grants, and source of canonical verdict. Use a *policy decision* to determine whether assignment alone should confer signaling privilege before asserting FE-032 closure. Require canonical transaction receipt, apply evidence, and authoritative state for any action claimed confirmed. No evidence media may appear in public logs or wiki screenshots.

**Test status:** 0/15 executed. These rows are specifications, not test results.


---

# Phase 6 - Cross-domain authority and UI truth (full detail)

# WeAll Frontend Audit — Phase 6: Cross-domain authority, governance and account-state truth

**Mode:** Strictly read-only. **Primary baseline:** `main` commit `6d3d69234415d294936d99e819367cff589ced3d` (GitHub comparison with `main`: identical at inspection). **Secondary test resource:** [draft PR #97](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97), open at inspected head `2ab08aa74b86806e1c4fef1f47b184d4f80c4793`; **not used as evidence of `main` implementation or executed test success**. **Coverage:** FE-033 through FE-039; FE-001–FE-032 are unchanged and preserved in the appended complete master ledger.

## Executive assessment

A well-signed, backend-enforced action can still present a confusing or incorrect *user-facing authority claim*. The Phase 6 findings cluster in three areas: (1) **identity Tier 2 is not the same as membership in a particular electorate**; (2) **ballot privacy removes identity-to-choice state that older frontend controls and reconciliation assume exists**; (3) **account and profile language conflates account existence, social rights and posting eligibility**. A separate backend-source investigation finds that the account API and governance electorate builder consult different PoH interpretations.

| Finding | Priority | Evidence classification | Scope |
|---|---|---|---|
| **FE-033** | **P1** | Source-confirmed frontend readiness misclassification; backend rejection path identified; no vote executed | Group/protocol governance electorate vs page gate |
| **FE-034** | **P2** | Source-confirmed repeated-action affordance under strict ballot privacy; backend duplicate rejection found | Ballot privacy vs vote control |
| **FE-035** | **P2** | Source-confirmed read-model reconciliation incompatibility; canonical receipt path remains authoritative | Private ballot vs transaction reconciliation |
| **FE-036** | **P1/P2** | Source-confirmed invalid multi-option action path; no signed vote executed | Governance choice schema vs lifecycle shortcut |
| **FE-037** | **P2** | Source-confirmed broad account-status mismatch; ordinary action-specific server gates remain effective | Profile status vs social action rights |
| **FE-038** | **P1/P2** | Source-confirmed semantic confusion on basic account status | Registration existence vs posting permission |
| **FE-039** | **P1 investigation** | Source-confirmed mismatch in tier source; electorate/quorum impact conditional and untested | PoH canonical status vs electorate construction |

No finding demonstrates a successful unauthorized transaction, successful duplicate ballot, violation of secret-ballot privacy or consensus failure. All readiness claims remain **NO-GO** pending independent testnet review.

---

## FE-033 — Decision page announces voting readiness without verifying the active electorate

**Classification:** Confirmed misleading frontend readiness logic; backend checks deny ineligible participants. **Priority:** P1 for truthful civic participation. **Area:** `web/src/pages/Proposal.tsx` (lines 378–383, 546–569, 790–800, 870–876, 900–930); `Weall-Protocol/src/weall/runtime/apply/governance.py` (lines 646–687, 759–788, 866–891, 2158–2169).

**Observed code path:** The proposal detail computes `gate = checkGates({loggedIn, canSign, accountState, requireTier:2})` then `canVote = gate.ok && voteWindowOpen && !currentChoice`. It uses this to display **“Vote now”** and enable vote buttons. For group-scoped decisions, the backend computes electorate members using `group_id`, canonical membership and tier constraints, and maintains a voter snapshot for the current round. On submit, `_apply_gov_vote_cast` checks whether the canonical signer belongs to `eligible_voters` and raises `governance_vote_requires_active_round_member` otherwise.

**Reproducible source scenario:** An authenticated, otherwise eligible Tier 2 account views an open group decision where it is *not* in that group's current electorate. The client gate passes and presents `canVote=true`. A forced signed submission should be rejected by backend electorate admission. A group member who lacks the configured group voting minimum can experience the same mismatch. An established electorate snapshot may differ from current membership, so simply querying current membership is not a general replacement.

**User impact:** Misleading voting rights, preventable failed signed actions, bad trust signals in a platform promising one-human-one-vote under explicit group scopes. This is **not** a demonstrated cross-group authorization bypass.

**Remediation boundary:** Never recreate electorate authority with a client-maintained group-membership list. Surface an authoritative, scope-and-round-bound *eligibility decision* (eligible / ineligible / unknown) that does not reveal private ballot choices. When unavailable, describe the requirement and mark it **unverified**, rather than showing unqualified “Vote now.” Preserve public proposal viewing and independently authenticated vote admission.

**Acceptance:** Compare protocol-wide versus group-scoped proposal; group outsider, member, removed member, stale/expired verification, explicitly locked member; current round snapshot versus current group membership; unknown eligibility due to node outage. Confirm frontend does not assert eligibility from Tier 2 alone. Confirm forced backend action remains rejected.

## FE-034 — Redacted ballots cause repeat-voting controls to remain available

**Classification:** Confirmed source-level UI state mismatch. **Priority:** P2, escalate if repeated submission is common. **Area:** `web/src/pages/Proposal.tsx` (lines 525–569, 870–891, 900–930); `Weall-Protocol/src/weall/runtime/apply/governance.py` (lines 2158–2240).

**Observed code path:** Strict ballots omit signer-to-choice maps on purpose. `currentVoteRecord` looks in the public `poll_votes` or `votes` maps, which may be empty even after a valid ballot is cast. `canVote` then tests `!currentChoice`. The resulting “Vote” buttons may remain enabled for a voter who already submitted an immutable ballot. The backend uses a ballot nullifier; a duplicate is rejected with `ballot_already_final` or `poll_ballot_already_recorded`.

**User impact:** The user sees an apparently available action that cannot succeed; repeated attempts can trigger errors and uncertain transaction histories. No extra vote is proven admitted, and privacy controls are not shown bypassed.

**Remediation boundary:** Introduce explicit state for **no known ballot / submitted but unconfirmed / canonically confirmed already voted / unknown / not eligible**, derived from authenticated, privacy-safe admission evidence or original signed transaction receipts. Do not restore public voter-choice maps or infer a private selection from aggregate totals. Keep early poll ballots separate from later final-round ballots.

**Acceptance:** Cast once under strict profile; confirm immutability and repeat controls after refresh and on a separate device; test unconfirmed first attempt, node delay, reorg-like stale reads (if supported), and a new electorate round. Preserve redaction.

## FE-035 — Proposal-vote read-model reconciliation assumes a public signer-to-choice map

**Classification:** Confirmed source-level fallback mismatch. **Priority:** P2. **Area:** `web/src/lib/governance.ts` (lines 310–334); `web/src/pages/Proposal.tsx` (lines 431–468); `web/src/components/TxQueueProvider.tsx` (lines 292–391).

**Observed code path:** `reconcileProposalVote({proposalId, account, choice, base})` reads `/v1/gov/proposals/{id}/votes`, selects `poll_votes` or `votes`, and checks the account's matching choice. Under strict aggregate-only ballots these identity-choice maps are deliberately redacted; this fallback returns `null`, even when the backend admitted the vote. The transaction queue **correctly does not treat a domain read-model observation as finality** and can confirm using `/v1/tx/status` once apply and synchronization evidence is present.

**User impact:** If the canonical transaction-status route is temporarily unavailable, the vote-specific fallback cannot distinguish “admitted but private” from “not yet visible.” The generic recorded/unknown handling is safer than a false confirmation, but unnecessarily weak and may encourage retries. This finding does **not** claim that all valid strict ballots are stuck or that receipt-based finality is broken.

**Remediation boundary:** Keep `/v1/tx/status` canonical for finality. Use authenticated, privacy-preserving, round-bound admission evidence only as *nonfinal* progress; never expose choice. Model states separately from FE-034's action availability. Do not implement public choice-map lookup as the sole proof path.

**Acceptance:** Strict ballot with redacted maps and confirmed receipt; confirmed-but-delayed receipt; unknown tx id; duplicate rejection; mismatched proposal/round and node; ensure no read model alone is treated as final.

## FE-036 — Lifecycle “Vote Yes” shortcut is invalid for a genuine multi-option decision

**Classification:** Confirmed frontend action path mismatch. **Priority:** P1/P2. **Area:** `web/src/pages/Proposal.tsx` (lines 430–460, 900–930, 1008–1018); `Weall-Protocol/src/weall/runtime/apply/governance.py` (lines 2113–2139).

**Observed code path:** The main voting section correctly iterates over proposal-specific option IDs. A second lifecycle panel displays an unconditional “Vote Yes” button whenever `canVote` is true. It calls `castVote("yes")` even if `proposalOptions` is nonempty. `castVote` then emits `{option_id:"yes"}` for a multi-option decision, without mapping to an actual option. Backend `_apply_gov_vote_cast` only accepts an actual option ID or `abstain` when options exist.

**User impact:** A prominent shortcut can initiate a known-invalid transaction for an otherwise valid decision; a rejected transaction is not an unauthorized accepted ballot. Cases where a real option ID happens to be `yes` are not sufficient proof the shortcut is generally correct.

**Remediation boundary:** Display the “Vote Yes” shortcut **only for binary yes/no proposals**. For multi-option proposals, link or focus the canonical option list without choosing an option on the user's behalf. Do not weaken backend option validation.

**Acceptance:** Multi-option IDs `repair`, `replace`, `defer` (no `yes`), multi-option with `yes` as an actual option, binary yes/no, and abstention. Verify no invalid-option submission is initiated by lifecycle navigation.

## FE-037 — Profile says Tier 1 “Interaction Enabled” while ordinary reactions and replies need Tier 2

**Classification:** Confirmed broad capability label mismatch, not a backend authorization bypass. **Priority:** P2. **Area:** `web/src/pages/Account.tsx` (lines 355–365, 1098–1117); `web/src/pages/Thread.tsx` (lines 126–129, 143–208); `web/src/pages/Content.tsx` (lines 192–194); `web/src/lib/userLanguage.ts` (Tier 1 summary); `Weall-Protocol/src/weall/runtime/apply/content.py` (lines 1000–1036).

**Observed code path:** The profile computes `canLikeComment = tier >= 1 && accountExists && !banned && !locked`, and displays **“Interaction: Enabled”**. However the normal thread UI uses `requireTier:2` for reactions and replies, consistent with the backend Tier 2 ordinary-content rule. `CONTENT_REACTION_SET` is Tier 2 in `specs/tx_canon/tx_canon.yaml`. The special `CONTENT_COMMENT_CREATE` Tier 0 floor is explicitly for a constrained **public_lobby** target, while non-lobby comments require Tier 2 in the content applier. Tier 1 reports and group membership requests are separate actions.

**User impact:** A Tier 1 person's account status communicates broad social interaction rights that ordinary post detail screens deny. This can be perceived as arbitrary platform exclusion despite the backend acting consistently.

**Remediation boundary:** Split activity into accurately named, action-scoped capabilities (e.g., browse, report, request group membership, lobby comment if exposed, ordinary reply, react, post). Avoid one “Interaction” boolean that conflates disparate transactions and special contexts. Use backend-provided action-specific authorizations where supported.

**Acceptance:** Tier 0/1/2, group vs protocol posts, ordinary reactions/comments, content flags, lobby special-case, signed session absent, expired PoH. A protected action must not be unlocked just to align a label.

## FE-038 — Profile confuses basic account existence with eligibility for content posting

**Classification:** Confirmed semantic read-model mismatch. **Priority:** P1/P2 (first-run onboarding). **Area:** `web/src/pages/Account.tsx` (lines 207–228, 285–320, 355–365, 507–528, 1070–1090); `web/src/lib/onboarding.ts` (lines 52–107); `Weall-Protocol/src/weall/api/routes_public_parts/accounts.py` (lines 399–454).

**Observed code path:** `Account.tsx` calls `weall.accountRegistered(acct,base)` and defines `registeredState = registered?.registered ?? accountExists`. It labels `registeredState=false` as **“Not registered”** and sets account posture to **“Unregistered”**. But `/v1/accounts/{account}/registered` is a specialized endpoint: its response's `registered` value means the account currently meets **content posting eligibility** (effective Tier 2, not banned). A valid Tier 0 or Tier 1 on-chain account can exist while this endpoint returns `registered:false`. The verification/onboarding UI deliberately distinguishes a basic account from posting eligibility.

**User impact:** Users who have successfully created an on-chain account can be shown as unregistered, directly contradicting the successful account registration and human-verification journey. This can distort the next step and confuse external reviewers.

**Remediation boundary:** Use canonical account existence for **“Basic account registered”** and a separate effective-tier/backend capability for **“Eligible to publish”**. Missing data should be unknown, not false. Do not modify server registration or content authorization for a display fix.

**Acceptance:** Valid Tier 0 with `registered:false`, Tier 1 with `registered:false`, Tier 2 eligible, Tier 2 banned, account missing, and registration endpoint 5xx; confirm consistent labels across Account, onboarding, verification and session pages.

## FE-039 — Account PoH API and governance electorate builder use different tier sources

**Classification:** Confirmed source-level authority-consistency discrepancy; **backend/protocol investigation**, not an established frontend bypass or launch exploit. **Priority:** P1 investigation. **Area:** `Weall-Protocol/src/weall/runtime/poh/state.py` (lines 200–222); `Weall-Protocol/src/weall/api/routes_public_parts/accounts.py` (lines 399–426); `Weall-Protocol/src/weall/runtime/apply/governance.py` (lines 646–687, 716–732, 866–891); frontend `web/src/pages/Proposal.tsx` (lines 378–383, 553–569).

**Observed code path:** `/v1/accounts/{account}` explicitly replaces its public `poh_tier` with `effective_poh_tier(state,account)`. That effective function degrades expired Tier 2 to Tier 1; revoked, suspended, or challenged statuses to Tier 0. But `_active_tier2_human_ids()` and `_active_group_member_ids()` in the governance electorate builder select members using the legacy `record.get("poh_tier")` field and selected flags, not `effective_poh_tier()`. This permits different **inputs** to the displayed account eligibility and the electorate composition. It is source-confirmed that the functions read different fields, not yet demonstrated that a malicious participant can cast an accepted vote.

**Impact and uncertainty:** At an electorate round-opening boundary, a raw legacy Tier 2 account whose effective status is Tier 0 or Tier 1 may still be included in the electorate enumeration. The backend's separate transaction-tier gate and immutable electorate-round semantics may reject its vote, but denominator/quorum and public eligibility representations still require explicit validation. Changes *after* snapshot creation may be intentionally governed by a frozen-round rule and must not be conflated with invalid snapshot construction. A runtime fixture and constitutional/spec review are required.

**Remediation boundary:** Resolve the canonical electorate admission semantics and snapshot timing in backend source before changing client hints. Compare `effective_poh_tier()` and raw tier at electorate construction, then inspect the global tx gate and denominator calculations. Ensure any correction respects deterministic consensus and the constitutionally specified round-freezing rules. The frontend should display *authoritative round-bound electorate eligibility*, never a self-invented approximation.

**Acceptance:** Controlled expired Tier 2, revoked, suspended, challenged and active accounts **at electorate opening**, under protocol-wide and group-scoped decisions; repeated checks after round formation; accepted and rejected submissions; denominator and quorum; two-node deterministic state roots. No substantive remedy should be merged on the basis of source discrepancy alone.

---

## Confirmed safeguards and important non-findings

1. The backend's `GOV_VOTE_CAST` applier checks current round electorate membership and rejects unrecognized option IDs. No source evidence shows that a Tier 2 outsider can force an accepted ballot or submit an arbitrary option.
2. Strict ballots intentionally omit public voter-to-choice maps. The backend uses nullifiers to refuse duplicate strict ballots, and the frontend displays aggregate vote counts without reconstructing private choices.
3. `TxQueueProvider` treats canonical `/v1/tx/status` as the sole transaction finality authority; a domain read model can show progress but cannot independently settle a signed transaction.
4. The account API already exposes *effective* PoH status; the issue at FE-039 lies in governance electorate construction reading legacy fields, not the API failing to compute effective status.
5. Tier 0 public-lobby comments are a narrow, explicitly constrained exception, not general permission to reply to posts. Whether the intended lobby has an accessible complete rendered frontend journey was **not established** in Phase 6.
6. Account/verification onboarding already separates basic account existence from publishing capability in some places. FE-038 concerns inconsistent use elsewhere, not absence of an account model.

## Source provenance and limitations

All source-based conclusions were drawn from the above pinned `main` commit through the connected GitHub source reader. The separately uploaded Phase 1–5 ledger was consulted to avoid duplicate finding IDs. PR #97 was used **only to confirm its open/draft status and availability as an authorized test environment**, and its unmerged contents were not treated as `main`. No PR #97 tests, Playwright tests, live account or vote mutations, GitHub writes, WebRTC connection, two-node rehearsal, or independent external protocol validation were performed. This report is **not an assertion of public-beta or mainnet readiness**.

### Pinned source URLs

- [Proposal detail and voting UI](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposal.tsx)
- [Governance read-model reconciliation](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/governance.ts)
- [Canonical transaction queue](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx)
- [Account profile](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Account.tsx)
- [Thread action gates](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Thread.tsx)
- [Onboarding eligibility](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/onboarding.ts)
- [Account API](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/api/routes_public_parts/accounts.py)
- [Canonical governance applier](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/governance.py)
- [Canonical PoH state model](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/poh/state.py)
- [Canonical content applier](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/content.py)
- [Transaction canon](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/specs/tx_canon/tx_canon.yaml)


---

# Phase 7 appended evidence — FE-040 through FE-046

The entire Phase 1–6 master ledger above is preserved byte-for-byte. The source of truth for the seven new findings is `01_PHASE7_DETAILED_FINDINGS.md` below, replicated here in full for standalone master use.

# WeAll frontend read-only audit — Phase 7 detailed findings

**Date:** 2026-11-20 (Pacific)  
**Repository:** `errol1swaby2-bit/WeAll-Protocol`  
**Authoritative baseline:** `main` at `6d3d69234415d294936d99e819367cff589ced3d`  
**PR #97:** open draft, `audit/public-testnet-remediation`, head `2ab08aa74b86806e1c4fef1f47b184d4f80c4793`; not used as audit baseline.  
**Mode:** Source-inspection documentation only. No browser testing, CI, local node, mutating GitHub operation, or code changes.  
**Existing ledger:** FE-001–FE-039 preserved. This phase appends FE-040–FE-046 only.

## Executive conclusion

Phase 7 targets normal-user workflows rather than widening into backend-only protocol analysis. Seven additional user-facing gaps were identified: incomplete group-election history navigation; premature group-create handoff; premature clearing of post/reply drafts; a mobile layout candidate on the decision stage timeline; missing accessible Feed scope selection; a signed-out My posts scope mismatch; and deterministic group-ID collisions without a recovery path. The existing backend is consulted only where needed to establish the UI contract.

**Source-confirmed does not mean runtime-reproduced.** No public-testnet readiness claim follows from these observations, and nothing has been remediated. Where content intentionally distinguishes submission from finality or already gives bounded-result warnings, those protections are explicitly preserved.

## Findings in full

### FE-040 — Group election index has no UI pagination despite known next offset

- **Priority:** P2
- **Classification:** Confirmed feature gap; runtime impact depends on >100 records
- **Journey:** Group detail → Emissaries → Election history
- **Source evidence:** The frontend requests the canonical election index with `limit: 100, offset: 0` and stores `next_offset`, but the election-history screen renders only the initial `electionRows` and explicitly tells users that the index API supports pagination while the UI does not load additional pages. See [web/src/pages/Group.tsx:93–135](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L93-L135) and [web/src/pages/Group.tsx:810–855](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L810-L855).
- **User impact:** A visitor cannot inspect older/current-state election records beyond the first returned page from within WeAll. An incomplete index can reduce transparency of candidates, outcomes, and term history even though the UI correctly discloses its limitation.
- **Expected frontend behavior:** Provide bounded Load more / next page controls keyed by group and offset, preserve record provenance, signal last page, distinct failure/empty states and no unsupported historical-completeness claims.
- **Safety boundary:** Read-only index only. An election record, candidate listing or voter-snapshot hint must not imply ballot or emissary execution authority.
- **Acceptance cases:** P7-01 through P7-03


### FE-041 — Group creation abandons composer after submission without awaiting canonical inclusion

- **Priority:** P2
- **Classification:** Confirmed source ordering; user-visible failure consequences need browser reproduction
- **Journey:** Groups → Create group → Group detail
- **Source evidence:** `createGroup()` awaits `tx.runTx()` and immediately clears name/description and navigates to `/groups/<id>`. The transaction queue starts canonical finality monitoring asynchronously and returns after dispatch. See [web/src/pages/GroupCreate.tsx:73–130](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/GroupCreate.tsx#L73-L130) and [web/src/components/TxQueueProvider.tsx:430–474](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L430-L474).
- **User impact:** A submitted-but-rejected or unconfirmed group can open a detail route that has no committed object; the user may have lost editable charter text before learning the final outcome. “Submitted” is not “created”.
- **Expected frontend behavior:** Retain a recoverable exact-identity draft and a creation outcome state (preparing/submitted/pending/confirmed/rejected/unknown). Navigate automatically only after canonical visibility, or offer a clearly labeled optional preview while preserving the draft and original tx ID.
- **Safety boundary:** Never blindly resubmit on an unknown receipt, never create a local group as canonical state, and preserve nonce/signature protections.
- **Acceptance cases:** P7-04 through P7-07


### FE-042 — Post and reply drafts are cleared before all canonical transaction outcomes are known

- **Priority:** P2
- **Classification:** Confirmed source-level timing; rejection/timeout scenarios unexecuted
- **Journey:** Feed → Create post; Thread → Reply
- **Source evidence:** The thread clears `reply` immediately after `tx.runTx()` returns. The post composer similarly sets `Submitted`, clears body/tags/file, then awaits `revalidateAfterSubmit()`; that later step can fail. Both share the queue behavior where monitoring is asynchronous. See [web/src/pages/Thread.tsx:179–216](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Thread.tsx#L179-L216), [web/src/pages/CreatePostPage.tsx:675–758](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L675-L758), and [web/src/components/TxQueueProvider.tsx:430–474](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L430-L474).
- **User impact:** Users may lose the original wording, tags or attachment choice during a pending/rejected action. Resubmission after a network ambiguity can become a duplicate-write risk if the UI does not maintain the original transaction identity.
- **Expected frontend behavior:** Keep a recoverable draft until final success, or maintain an explicit Submitted draft snapshot with its tx ID and original media/CID references. Distinguish rejection, pending, unknown, and confirmed; permit safe retry only after checking original identity/finality.
- **Safety boundary:** Do not automatically re-upload media or re-sign an uncertain submission. A visible post or comment is not by itself proof of successful finality.
- **Acceptance cases:** P7-08 through P7-13


### FE-043 — Decision lifecycle forces eight columns, bypassing responsive grid rule

- **Priority:** P2 candidate
- **Classification:** Source-confirmed CSS precedence; exact rendered overflow and accessibility require browser test
- **Journey:** Decisions → Decision detail → Decision path
- **Source evidence:** The lifecycle `.statsGrid` has an inline `gridTemplateColumns: "repeat(8, minmax(0, 1fr))"`; the stylesheet changes `.statsGrid` to one column at ≤860px using a normal class declaration, which loses to the inline style. See [web/src/pages/Proposal.tsx:937–966](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Proposal.tsx#L937-L966) and [web/src/styles.css:747–762](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/styles.css#L747-L762).
- **User impact:** On small screens or high zoom, eight narrow stage cards may be hard to read, create cramped text or cause horizontal overflow. This is a prediction based on the layout rules, not an observed screenshot.
- **Expected frontend behavior:** Allow the lifecycle to wrap, scroll with clear affordance, or use an ordered vertical stepper at narrow widths and 200% zoom; preserve stage and block-height semantics.
- **Safety boundary:** Presentation-only. Do not change governance stage transitions or pretend browser time controls stage eligibility.
- **Acceptance cases:** P7-14 through P7-17


### FE-044 — Feed scope selector does not expose the selected scope programmatically

- **Priority:** P2
- **Classification:** Source-confirmed missing selection semantics; screen-reader impact unexecuted
- **Journey:** Feed → Recent public activity / My posts
- **Source evidence:** `TabButton` sets `.btnPrimary` when active but renders only a plain `<button>` with no `aria-pressed`, `aria-selected`, `aria-current`, or tab-list relationship. The user can select between two feed scopes using it. See [web/src/pages/Feed.tsx:13–28](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Feed.tsx#L13-L28) and [web/src/pages/Feed.tsx:110–117](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Feed.tsx#L110-L117).
- **User impact:** A nonvisual user may not learn which feed scope is selected after switching. This differs from the already recorded FE-028 (sort-mode selection inside FeedView).
- **Expected frontend behavior:** Use a toggle-button group with `aria-pressed`, or a full tabs pattern with selected tab, controlled panel and correct keyboard behavior; announce scope changes without stealing focus.
- **Safety boundary:** Pure navigation semantics; do not alter scope authorization.
- **Acceptance cases:** P7-18 through P7-20


### FE-045 — Signed-out “My posts” selection renders public feed beneath an explanatory notice

- **Priority:** P3
- **Classification:** Confirmed conditional UI mismatch, partially mitigated by notice
- **Journey:** Feed → My posts, while signed out
- **Source evidence:** The Feed page sets scope to `public` and heading to “Latest protocol activity” whenever the `mine` tab lacks an account, but it still leaves the “My posts” button selected. It displays a notice saying sign-in is required. See [web/src/pages/Feed.tsx:72–78](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Feed.tsx#L72-L78) and [web/src/pages/Feed.tsx:113–149](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Feed.tsx#L113-L149).
- **User impact:** A visitor can select “My posts” yet see public posts, with the explanation elsewhere on the page. The notice reduces the severity, but the control/underlying content have contradictory scope semantics.
- **Expected frontend behavior:** Render a distinct sign-in/restore empty state for My posts without substituting public posts, or prevent selection and explain why; return to the intended scope after login.
- **Safety boundary:** Preserve public Feed read access and do not identify anonymous content as belonging to a signed-out viewer.
- **Acceptance cases:** P7-21 through P7-23


### FE-046 — Group ID derives solely from title, with no collision recovery or alternate choice

- **Priority:** P2
- **Classification:** Confirmed product gap against unique backend ID rule
- **Journey:** Groups → Create group
- **Source evidence:** `slugifyGroupId(name)` lowercases/normalizes the title and truncates it to 40 characters; the form offers no independent group ID or availability check. The backend explicitly rejects an already existing ID as `group_exists`. See [web/src/pages/GroupCreate.tsx:23–30](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/GroupCreate.tsx#L23-L30), [web/src/pages/GroupCreate.tsx:73–99](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/GroupCreate.tsx#L73-L99), [web/src/pages/GroupCreate.tsx:280–304](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/GroupCreate.tsx#L280-L304) and [Weall-Protocol/src/weall/runtime/apply/groups.py:524–534](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/groups.py#L524-L534).
- **User impact:** Two distinct group titles normalizing to the same `g:<slug>` cannot both be created through the form. An existing name can block legitimate community creation without a user-facing way to pick an alternate identifier.
- **Expected frontend behavior:** Show derived ID availability as a nonauthoritative preflight, give user an editable unique identifier or deterministic safe suffix strategy, preserve the group title and charter on collision, then recheck at signed submission/chain apply.
- **Safety boundary:** The backend remains authoritative on uniqueness; do not implicitly overwrite existing groups or auto-retry signed transactions without resolving their statuses.
- **Acceptance cases:** P7-24 through P7-27


## Prior findings deliberately not duplicated

| Existing finding | Relationship to Phase 7 |
|---|---|
| FE-001 | Anonymous public Feed disabled in primary navigation; not reopened here. |
| FE-003 | Error-versus-empty-list rendering; distinct from draft-loss timing. |
| FE-005/006 | Bounded directory counts and group discovery; FE-040 is an election-specific UI pagination omission backed by an explicit `next_offset`. |
| FE-007 | General technical-copy density; not counted again without rendered usability testing. |
| FE-013/022 | Transaction history attribution and finality-source provenance; FE-041/042 focus on preservation of **user-authored drafts** across submission uncertainty. |
| FE-024–028 | Page-level keyboard and Feed sort controls; FE-044 concerns the **Feed scope switcher**. |
| FE-033–036 | Decision voting authority/ballot semantics; FE-043 is only responsive presentation. |

## Confirmed existing protections and positive capabilities

- Feed provides public read access via backend and uses a separate `FeedView` for scope-specific activity. The account read-only path and protected writes remain separate.
- Post creation exposes upload, durability, media declaration, and transaction phases; the Phase 7 draft issue does **not** mean the implementation claims immediate canonical finality everywhere.
- Group election UI explicitly labels the first page as bounded when another offset is available and refuses to infer authority from election records. This disclosure should remain when pagination is added.
- Group membership decisions and group-scoped proposals already have dedicated routes and transaction reconciliation helpers; source review is not a claim that every real journey is complete.
- Responsive CSS provides a fixed bottom navigation at <=640px and single-column grid defaults at <=860px. FE-043 concerns a specific inline override, not an allegation that the entire mobile interface is unusable.
- The transaction queue itself distinguishes read-model observations from canonical `/v1/tx/status` finality; a product-safe draft model should retain that separation.

## Acceptance/reproduction status

All 27 Phase 7 acceptance cases are **specified but unexecuted**. Many can be run against a browser and a controlled mocked API; canonical-inclusion, nonce-safety, two-user and cross-node cases require real rehearsal. PR #97 is available for test execution only if it provides a suitable runtime. If used, test artifacts must state PR #97's exact head and must not be misattributed to `main`.

## Recommended frontend-only development order (documentation, not implementation)

1. Draft and outcome safety: FE-041–042; retain exact transaction identity and prior content.
2. Access and navigation: FE-040 and FE-046; ensure group discovery/history works at scale without weakening canonical authorization.
3. Responsive/accessibility acceptance: FE-043–045, combined with already-open FE-024–028.
4. Rendered usability, accessibility-tree, touch-viewport, low-connectivity, and two-account rehearsals before claiming visual readiness.

**Hard stop:** No code is changed by this report. Backend and governance rules are not being redesigned here.


## Phase 7 acceptance matrix — full replica

# Phase 7 — acceptance and regression matrix

**Baseline:** `main` at `6d3d69234415d294936d99e819367cff589ced3d`  
**Execution:** all **UNEXECUTED** as of 2026-11-20. These are required checks, not passed test results.

| Case | Finding | Scenario | Required result | Test context | Status |
|---|---|---|---|---|---|
| P7-01 | FE-040 | Return 101 election index items, page size 100 | Next-page affordance appears and retrieves next offset with exact group provenance | Mock API and browser | Not run |
| P7-02 | FE-040 | Return one page with no next offset | No false missing-record claim or extra-page control | Mock API | Not run |
| P7-03 | FE-040 | Delay page 2, then navigate to a different group | Old page results cannot leak into new group | Browser controlled latency | Not run |
| P7-04 | FE-041 | Submit valid group create, hold receipt pending | User can access original name/charter and tx ID while pending; no finality claim | Mock API/browser | Not run |
| P7-05 | FE-041 | Return canonical group-create rejection after recorded submission | Draft remains recoverable; no final group is claimed | Real-stack preferred | Not run |
| P7-06 | FE-041 | Confirm receipt and group visibility | Safe optional navigation to exact group, no duplicate submission | Real-stack | Not run |
| P7-07 | FE-041 | Return receipt unknown on timeout, then revisit creator | Exact pending action tracked and cannot be blindly re-signed | Mock/API + persistence | Not run |
| P7-08 | FE-042 | Submit a reply then reject transaction | Draft recoverable and no misleading permanent comment label | Mock API/browser | Not run |
| P7-09 | FE-042 | Submit reply with delayed canonical receipt | Submitted copy remains recoverable; original tx tracked | Mock API/browser | Not run |
| P7-10 | FE-042 | Post text and tags; hold finality pending | Preserve submitted text/tags snapshot and tx identifier | Mock API/browser | Not run |
| P7-11 | FE-042 | Media post receives CID but later post transaction rejects | Do not lose content or require duplicate media upload if safe CID is recoverable | Real-stack | Not run |
| P7-12 | FE-042 | Post creation succeeds with all canonical gates | Composer can safely clear after confirmed state while showing exact post link | Real-stack | Not run |
| P7-13 | FE-042 | Reload during uncertain post or reply submission | No automatic duplicate signing; offer resume/inspect path | Browser with persisted mock | Not run |
| P7-14 | FE-043 | Decision path at 320px width, normal zoom | All stages readable; no unintentional horizontal overflow | Playwright browser | Not run |
| P7-15 | FE-043 | Decision path at 390px width and 200% browser zoom | Logical stage order and readable contrast/text maintained | Playwright browser | Not run |
| P7-16 | FE-043 | Decision path at desktop width | No regression in sequence or block-based phase description | Playwright browser | Not run |
| P7-17 | FE-043 | Screen reader/keyboard traverses decision stages | Stages semantically ordered, focus not trapped, no clipping of critical labels | Accessibility-tree check | Not run |
| P7-18 | FE-044 | Keyboard select Feed Recent public activity | Selected state exposed programmatically, only current scope announced | Playwright accessibility tree | Not run |
| P7-19 | FE-044 | Keyboard switch to My posts | Current selection announced without unexpected focus jump | Playwright accessibility tree | Not run |
| P7-20 | FE-044 | Return to public activity with browser back or tab switching | Selected control and displayed scope agree | Browser | Not run |
| P7-21 | FE-045 | Signed-out user selects My posts | No public posts shown under a selected personal-scope control; clear sign-in path | Browser | Not run |
| P7-22 | FE-045 | User signs in after choosing My posts | Intentional personal scope restored without showing another account data | Two-account browser | Not run |
| P7-23 | FE-045 | Signed-out public Feed tab | Public reading remains available without signer or PoH gate | Browser | Not run |
| P7-24 | FE-046 | Try existing group name / same normalized ID | Existing ID signaled without false new-group creation; backend remains final arbiter | Mock API and backend | Not run |
| P7-25 | FE-046 | Two titles differing only by punctuation/case normalize identically | Conflict and alternate ID selection communicated to user | Unit + UI | Not run |
| P7-26 | FE-046 | Long names with same first 40 slug characters | Non-destructive collision recovery, no overwrite | Unit + UI | Not run |
| P7-27 | FE-046 | Group ID appears free, another actor creates first | Apply-time conflict is shown with saved original charter and safe retry instructions | Two-account real-stack | Not run |

## Test integrity and frontend focus

- For browser-only and mocked transport tests, assert the visual state, actual keyboard focus, URL, displayed account ID, source node, and transaction identity, not just component text substrings.
- Any real-stack test should use separately authorized accounts. Do not use private identity evidence, production credentials, or implicit testnet launch authority.
- A pending/unknown signed action must remain pending/unknown until a canonical receipt or explicit fail-closed outcome exists. Do not assert that a read-model change alone proves finality.
- For viewport cases, test 320, 375, 390, 768 and desktop widths, including 200% zoom. `prefers-reduced-motion` and keyboard-only operation also require checks.
- For the PR #97 rehearsal path: record exact PR head, run configuration, account scope, backend revisions, artifacts, and result. A PR-branch test does not automatically validate `main`.
- Do not mark any finding closed based solely on these written criteria.


## Phase 7 feature inventory — full replica

# Phase 7 — user journey and feature-completeness inventory

Source baseline: [6d3d69234415d294936d99e819367cff589ced3d](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d). This is a **source-backed implementation inventory**, not a rendered usability test or proof that services are live.

| Journey | Existing frontend surface | User-facing function in source | Open blockers and gaps | Status |
|---|---|---|---|---|
| Navigation | `AppShell`, `PrimaryNavigation`, `SidebarNav`, router | Dedicated routes and responsive bottom navigation | FE-001, FE-024–027; browser focus acceptance | Implemented; rendered acceptance open |
| Public Feed | `Feed`, `FeedView`, `MediaGallery` | Public ranked/recency reading, authors, media, replies, reports, reactions | FE-004, FE-028, FE-044–045; backend feed launch blocker retained | Implemented with constraints |
| Post creation | `CreatePostPage` | text/tags, group audience, optional single attached media, signed upload/declare/post phases | FE-042; media durability/tx finality test needed | End-to-end proof outstanding |
| Thread discussion | `Thread`, `Content` | reply, edit/delete as permitted, react, flag/report; receipts tracked | FE-042; FE-037 tier-language mismatch | Implemented with UX risks |
| Groups directory | `Groups`, `Group` | read groups, browse charter, member state, request membership, moderation tasks | FE-002/003/005/006, FE-046 | Discovery gap open |
| Group creation | `GroupCreate` | charter + membership mode + signed group creation | FE-041, FE-046 | Premature handoff and collision recovery open |
| Group election history | `Group`, `GroupBallotPlanner` | canonical read-only index, candidates, winners, term-related metadata | FE-040; does not provide voting/execution authority | First-page-only UI |
| Decisions | `Proposals`, `Proposal`, `ProposalCreate`, `ActiveDeliberations` | discover, create, comment, stage, ballot, finality links | FE-033–036; FE-043 responsive stage display | Feature integration and presentation open |
| Onboarding and account custody | `LoginPage`, `AccountRegistrationPage`, `SessionDevicesPage` | account create/restore, signed registration, local-key and session lifecycle | FE-017–023, FE-030; real browser/2-node acceptance | Implemented; state consistency open |
| Human verification | `AccountVerificationPage`, `LiveVerificationRoom` | guided async/live verification and case status | FE-029–032; camera/WebRTC acceptance open | Advanced but not release-accepted |
| Reporting and review | `Disputes`, `DisputeDetail`, `DisputeReview`, `JurorDashboard` | public reports, queues, case review, appeal-related steps | FE-011–016, FE-029, FE-032 | Incomplete runtime acceptance |
| Account/profile | `Account`, profile routes | public profile, reputation summaries, role readiness/status | FE-037–039; authority terminology | Implemented with copy/authority gaps |
| Transaction feedback | `TxQueueProvider`, `TransactionsPage` | submitted/recorded/confirmed tracking; link back to object | FE-013, FE-022, FE-042 | Receipt protections exist; UX gaps open |
| Responsive/accessibility | CSS + dedicated nav/sections | 640px bottom nav, 860px one-column defaults, reduced motion, visible focus | FE-024–028, FE-043–045 | Source support, rendered validation missing |

## Task-based acceptance route map

1. **Anonymous observer:** open Feed/Groups/Decisions, inspect public details, try clearly disabled signed actions, then sign in without losing intent.
2. **Basic account holder:** create local account, confirm registration, view Tier 0 status, understand why some social features are unavailable; keep drafts intact.
3. **Tier 1 participant:** submit allowed content reports or membership requests, observe case status, do not see misleading Tier 2 permissions.
4. **Tier 2 participant:** post, reply, create group, request/obtain membership, initiate a scoped decision, cast an eligible ballot, check receipt history.
5. **Group moderator:** review exact-group pending applications with no leakage across groups, inspect public case history and election records beyond first page.
6. **Juror:** inspect assigned responsibilities, accept case, review permitted evidence, cancel prompts safely, distinguish transport from canonical authority.
7. **Mobile user:** accomplish each applicable task without page-wide horizontal overflow, hidden primary controls, double-scrolling traps, lost focus, or inaccessible selected states.
8. **Interrupted user:** reload or switch accounts/nodes during an in-flight action; restore drafts and transaction provenance without retrying blindly.

## Explicit scope exclusions

Backend reputation mechanics, BFT, constitutional semantics, transaction issuance, PoH evidence cryptography, blockchain governance design, and independent protocol hardening are **not** new audit subjects in Phase 7. They are consulted only to validate frontend behavior and must not be altered to make the UI pass.

## Launch evidence constraint

These pages being present is not evidence that real end-to-end journeys are complete or that public testnet has launched. No new test was run in Phase 7.


---

# Phase 8 — appended findings and evidence (verbatim Phase 8 report)

# WeAll frontend read-only audit — Phase 8: rendered evidence and responsive/accessibility coverage

**Document date:** 2026-11-20 Pacific (report assembled from exact source and CI evidence)  
**Repository:** `errol1swaby2-bit/WeAll-Protocol`  
**Canonical source baseline:** [`main` @ `6d3d69234415d294936d99e819367cff589ced3d`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) — comparison against `main` returned **identical** at audit time.  
**Permitted test context:** [PR #97](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97), open draft `audit/public-testnet-remediation`, head [`2ab08aa74b86806e1c4fef1f47b184d4f80c4793`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/2ab08aa74b86806e1c4fef1f47b184d4f80c4793).  
**Mode:** Read-only inspection of GitHub source, existing GitHub Actions run/job summaries, and local Phase 1–7 master. **No test reruns, browser launches, screenshots, pull-request edits, commits, or backend transactions were made during Phase 8.**

## Executive finding

The existing PR #97 Web CI run is a genuine positive result for the scenarios it actually executed. Its browser evidence is, however, **Desktop Chrome-only**, and no successful run artifact or screenshot from the mobile/accessibility acceptance matrix was available in this audit. Phase 8 therefore documents browser-evidence boundaries instead of claiming to have observed a 390px layout.

Four newly documented frontend gaps/candidates are classified FE-047–FE-050. Existing FE-024–FE-028, FE-043–FE-045, and cross-node/session FE-017–FE-023 remain separate and open. The Phase 8 test program below is a **specification**, not execution evidence.

## Existing CI evidence — exact PR head

- The existing [PR #97 Web CI workflow run #44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) concluded **success** at PR head `2ab08aa74b86806e1c4fef1f47b184d4f80c4793`.
- Four Web CI jobs concluded **success**: *Frontend functional and local deployment rehearsal*, *Governance frontend rendered regression*, *Frontend dependency security*, and the aggregating *web* job.
- Successful listed steps include TypeScript checking, contract checks, production build, Nginx/Chromium deployment smoke, compiled browser custody isolation, compiled theme portability and readable-theme checks, and rendered active deliberation journey.
- The [Playwright configuration](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/2ab08aa74b86806e1c4fef1f47b184d4f80c4793/web/playwright.config.ts) and [production configuration](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/2ab08aa74b86806e1c4fef1f47b184d4f80c4793/web/playwright.production.config.ts) define a single `chromium` project with `devices["Desktop Chrome"]`; no additional mobile/tablet/browser device projects are declared.
- [Active deliberations rendered test](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/2ab08aa74b86806e1c4fef1f47b184d4f80c4793/web/tests/e2e/active_deliberations_rendered.spec.ts) covers decision previews, deliberation history, redacted aggregate views, and source contracts, but does not set 320/390/768/1440px viewports or audit screen-reader output.
- Existing tests include an accessibility-related source checker, but *source token assertions are not a substitute for keyboard/AT acceptance*. This report does **not** claim all tests in `web/package.json` were executed by the PR #97 workflow.
- PR #97 also has **failed** separate gates: Reviewer Readiness, Backend CI, A01–A20 revalidation, and repository-wide change coverage. A passing Web CI does not make the PR, public testnet, or overall release ready.

## Four new findings — full evidence, impact and corrective requirements
### FE-047 — Social images have no author-entered descriptive text; viewer uses file or object labels as alt

- **Priority:** P2
- **Classification:** Source-confirmed authoring and display gap; visual/accessibility impact not browser-tested
- **User journey:** Feed / Create post / thread media
- **Exact-main source evidence:** [web/src/pages/CreatePostPage.tsx:964–1119](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L964-L1119); [web/src/components/MediaGallery.tsx:94–118](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L94-L118); [web/src/components/MediaGallery.tsx:239–254](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L239-L254)
- **User impact and failure mode:** Users relying on nonvisual output may hear a filename, media identifier, CID or generic object label instead of a meaningful description of an image. The problem is particularly visible in image-based posts and group media.
- **Expected frontend behavior / documentation handoff:** Provide optional, safely encoded author-supplied alt descriptions during media composition, preserve through media declaration and public read models only if supported by the canonical schema, and render useful alternatives. If the backend does not support the metadata, mark that contract as an explicit dependency; do not inject uncommitted text as canonical data.
- **Authorization/privacy/safety boundary:** Never infer or publish a description of sensitive PoH evidence without consent. Media URLs must continue to resolve through the same-origin observer proxy and public descriptions must not bypass visibility or privacy constraints.
- **Acceptance scenarios:** P8-01–P8-05 — all **Not run**.

### FE-048 — Uploaded audio/video has no caption, subtitle or transcript workflow in the inspected UI

- **Priority:** P2
- **Classification:** Source-confirmed absence of caption/transcript UI in inspected composer/viewer; scope of canonical support remains to verify
- **User journey:** Create post / MediaGallery
- **Exact-main source evidence:** [web/src/pages/CreatePostPage.tsx:184–199](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L184-L199); [web/src/components/MediaGallery.tsx:247–280](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L247-L280)
- **User impact and failure mode:** People who cannot hear uploaded media or who need a text equivalent are offered native audio/video playback controls without a supported caption or transcript affordance. Depending on the content, this can prevent equal access to discussions.
- **Expected frontend behavior / documentation handoff:** Document and implement accessible caption-track or transcript attachment handling appropriate to the media type, require correct association with the selected media object, and show a clear unavailable state where no alternative exists. For accessibility testing use prerecorded fixture media; do not assume the node already accepts caption metadata.
- **Authorization/privacy/safety boundary:** Do not automatically transcribe private live-verification recordings into public content; restricted evidence handling must respect its authorization, deletion, and disclosure requirements.
- **Acceptance scenarios:** P8-06–P8-10 — all **Not run**.

### FE-049 — Verification/settings section selectors lack explicit controlled-panel relationships

- **Priority:** P3 candidate
- **Classification:** Source-confirmed interaction structure, assistive-technology effect untested
- **User journey:** Verification / Settings section navigation
- **Exact-main source evidence:** [web/src/pages/AccountVerificationPage.tsx:528–538](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountVerificationPage.tsx#L528-L538); [web/src/pages/AccountVerificationPage.tsx:1644–1669](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountVerificationPage.tsx#L1644-L1669); [web/src/pages/Settings.tsx:292–309](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Settings.tsx#L292-L309)
- **User impact and failure mode:** The current section is styled and given aria-current="page" while button activations switch query-driven content. That is meaningful navigational feedback, but there is no programmatic tab-to-panel association or verified focus announcement for the newly shown section. The precise accessibility defect must be reproduced before treating this as a compliance failure.
- **Expected frontend behavior / documentation handoff:** Choose one consistent semantic pattern: route-navigation buttons with explicit active-page/current-section announcements and logical focus movement, or tabs with tablist/tab/tabpanel, aria-selected/controls and keyboard semantics. Preserve browser history and in-flight PoH recording.
- **Authorization/privacy/safety boundary:** Do not remount or discard active recorder/consent state merely to improve tab presentation. Respect flow-specific disabled navigation during recording.
- **Acceptance scenarios:** P8-11–P8-15 — all **Not run**.

### FE-050 — Eight group-profile sections depend on horizontal scrolling without an explicit overflow cue

- **Priority:** P3 candidate
- **Classification:** Source-confirmed overflow strategy; hidden-control discoverability not rendered-tested
- **User journey:** Group detail mobile navigation
- **Exact-main source evidence:** [web/src/lib/groupProfileTabs.ts:1–17](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/groupProfileTabs.ts#L1-L17); [web/src/pages/Group.tsx:490–502](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Group.tsx#L490-L502); [web/src/styles.css:3486–3507](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/styles.css#L3486-L3507)
- **User impact and failure mode:** On narrow displays the row contains eight sections (one conditionally omitted). It uses overflow-x:auto and nowrap tabs, so distant sections can be outside the visible horizontal slice. There is no visible arrow, partial-tab hint, or explicit “more sections” control in the reviewed markup. Keyboard users can still tab through the buttons; actual discoverability and scroll behavior require browser confirmation.
- **Expected frontend behavior / documentation handoff:** Provide an unmistakable accessible way to discover and reach offscreen sections at 320/390px and 200–400% zoom, preserve selection when routed, and avoid screen-level horizontal overflow.
- **Authorization/privacy/safety boundary:** Do not interpret visibility of a tab or user selection as membership or governance authority. The group backend remains authoritative for signed actions.
- **Acceptance scenarios:** P8-16–P8-20 — all **Not run**.

## Existing findings specifically carried forward — no duplicate IDs

| Earlier finding | Phase 8 contribution |
|---|---|
| FE-024 and FE-026–FE-028 | Keyboard skip/focus, breadcrumb and Feed sort semantics need real rendered keyboard/AT tests. Phase 8 does not relabel them. |
| FE-043 | Decision's eight-column inline grid overrides mobile CSS; Phase 8 plans viewport + zoom reproduction, not a duplicate defect. |
| FE-044–FE-045 | Feed scope state and signed-out My posts behavior remain unverified in AT/mobile/browser test. |
| FE-017–FE-023 | Account/node switching and pending-transaction provenance remain high-priority state integrity acceptance work, but Phase 8 does not infer a new exploit. |
| FE-040–FE-042 | Bounded group elections, premature navigation after group creation, and recoverable post/reply drafts must be included in browser test rehearsals. |

## Existing product strengths confirmed

1. Native `video` and `audio` controls exist for playable media, and media proxy paths are preferred over auto-loading arbitrary HTTP gateways. FE-047/048 concern *descriptions and alternatives*, not the total absence of media playback.
2. PR #97 includes real Chromium tests for account custody, production deployment and governance deliberations. These are retained as passed **for that PR head only**.
3. The transaction queue has `aria-live="polite"` in its toast stack and separates canonical receipt finality from read-model observation; Phase 8 does not claim otherwise.
4. The shell already provides a responsive fixed bottom primary navigation at ≤640px, extra content padding, reduced-motion rules and a context drawer that uses `inert`, focus restoration and Escape handling. These are protections to retain during repairs.
5. Group profile sections remain linked to a single canonical group ID; selecting a section does not change backend authority.

## Evidence status, caveats and release boundary

**Source-confirmed:** FE-047/048 authoring/display omissions in the inspected components; FE-049/050 markup and CSS facts.  
**Candidate effects requiring observation:** Assistive-technology experience for FE-049 and scroll-discovery failure for FE-050; mobile overflow previously logged as FE-043.  
**Existing executed tests:** PR #97 Web CI success, scoped to its listed jobs/steps at `{prhead}`.  
**Not executed in this phase:** Any new Playwright run, viewport screenshot, real AT session, low-bandwidth simulation, live multiuser or two-node rehearsal.  
**Release posture:** **NO-GO remains unchanged**. Neither a single passing frontend workflow nor a source-level UX audit establishes public-testnet acceptance.

## Recommended documentation-first next steps

- Capture rendered baseline evidence at 320, 390, 768, 1024 and 1440px with both light and dark themes, and 200%/400% zoom. Capture viewport dimensions, computed overflow, active route, accessibility tree and screenshots.
- Repeat critical journeys with keyboard only and at least one screen reader: nav/skip, Feed, Groups, Decisions, new post, membership, account verification and transaction status.
- Use isolated public/demo fixture media for accessible alternatives; never expose restricted human-verification evidence through captions or screenshots.
- Treat PR #97 as a **permitted test target** only; do not silently merge its branch or attribute its test results to `main`.


---

# Phase 9 — full additional findings and evidence (2026-11-20)

This entire Phase 1–8 master document above is preserved byte-for-byte. The Phase 9 section below extends, and does not replace, any earlier detailed finding.

# WeAll frontend read-only audit — Phase 9: interaction integrity and browser-evidence boundaries

**Document date:** 2026-11-20 (America/Los_Angeles)  
**Repository:** `errol1swaby2-bit/WeAll-Protocol`  
**Audited canonical source:** [`main` @ `6d3d69234415d294936d99e819367cff589ced3d`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) — GitHub exact-commit compare returned **identical** to `main` at verification.  
**Optional permitted test target:** [PR #97](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97) — **open draft**, head `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` at verification.  
**Mode:** read-only source audit and existing CI evidence. **No new full-app browser tests, Playwright jobs, commits, PR updates, merges, backend transactions or deployment changes.**

## Executive conclusions

Phase 9 extends the detailed ledger with **seven frontend findings (FE-051–FE-057)**. Two are explicit source-path trust/UX problems requiring careful runtime reachability tests (unknown tx status and restricted evidence video timer). The other findings cover notification freshness, dialog modality, media failures, nested landmarks and static lifecycle communication.

**The requested full-app rendered acceptance remains blocked in this runtime:** Chromium/Playwright are installed, but PR #97 is not checked out locally; direct `git ls-remote` failed DNS resolution to github.com. The GitHub connector supports read-only file and CI inspection but does not provide a local web application or a playable full source archive. Existing PR #97 Web CI success is useful but is **not** evidence that the new FE-051–FE-057 cases or the complete mobile/screen-reader matrix passed. This report does not use a synthetic DOM fixture as a substitute for the real application.

**Canonical authority rule:** a frontend label, loading spinner, nonce advance, or read-model observation is not a substitute for a confirmed, applied, canonical transaction. Backend authorization and privacy protections remain untouched.

## Detailed findings — source citations, user impacts and acceptance contracts

### FE-051 — Unknown transaction status is treated as sufficient in post/media submission fallback

- **Priority:** P1 candidate
- **Evidence classification:** Source-confirmed unsafe acceptance predicate; production reachability and consequences not reproduced
- **Frontend surface:** Post composer; media declaration; transaction monitoring
- **Exact-main references:** [web/src/pages/CreatePostPage.tsx:36–52](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L36-L52); [web/src/pages/CreatePostPage.tsx:82–87](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L82-L87); [web/src/pages/CreatePostPage.tsx:595–618](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L595-L618); [web/src/pages/CreatePostPage.tsx:644–682](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx#L644-L682); [web/src/components/TxQueueProvider.tsx:315–395](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/TxQueueProvider.tsx#L315-L395)
- **Observed source path / trigger:** When the returned signed envelope does not expose a positive nonce but provides a transaction ID, the composer calls waitForTxConfirmed(). If the tx-status endpoint returns status=unknown, the helper returns immediately and isSubmittedOrConfirmed() returns true. The flow may then proceed to the next step or report the post as submitted. With a positive envelope nonce, the code instead waits for canonical account nonce progress; whether the fallback happens in a real production response is unverified.
- **Potential user impact:** An interrupted or unrecognized transaction might be presented as an adequately submitted media declaration/post, even when the selected node cannot establish inclusion. In the media case, the next post step could reference an unestablished declaration. This is a *risk conditional on fallback reachability*, not proof of a misapplied block or unauthorized issuance.
- **Required behavior / remediation specification:** A status of unknown must remain explicitly unresolved. Never equate it with successful inclusion, application, canonical nonce advancement, or finality. Preserve transaction IDs and submission intent, avoid automatic duplicate sends, and reconcile by the original receipt or canonical state. If sequencing may advance on acceptance alone, document that contract separately from confirmation.
- **Safeguards to preserve:** Retain receipt-first finality in TxQueueProvider and nonce ordering, never retry an uncertain signed transaction automatically, and do not replace backend apply or cryptographic checks with a frontend result.
- **Controlled acceptance method:** Seed signed envelope variants with nonce present/absent, tx status pending/unknown/confirmed/rejected and delayed read models in a disposable PR #97 test network; capture whether any next step is submitted. Do not reuse real participant keys.
- **Planned cases:** P9-01–P9-05 — **Not run**.

### FE-052 — Restricted evidence-video timer resets on replay/resume and does not account for pause

- **Priority:** P2
- **Evidence classification:** Source-confirmed timer wiring; elapsed viewing effect requires controlled browser timing
- **Frontend surface:** Restricted video / reviewer media playback
- **Exact-main references:** [web/src/components/MediaGallery.tsx:177–237](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L177-L237); [web/src/components/MediaGallery.tsx:245–275](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L245-L275)
- **Observed source path / trigger:** The restricted video uses onPlay to clear and restart a timeout; no onPause adjustment is present. A paused video can expire while paused, and a later play event can reset the full window. Rewatch allowance and lock state are component-local.
- **Potential user impact:** The visible promise that restricted evidence locks after a fixed review window is ambiguous or inaccurate under pauses, resumes and repeated starts. Jurors may lose review time while paused or observe longer cumulative playback than the intended cap.
- **Required behavior / remediation specification:** Define the actual policy (wall-clock session, cumulative active playback, per-open window, and permitted replay count), then render consistent remaining time and explicit paused/expired state. Timer correctness must be tested with browser clock controls, reloads and page switches; do not claim a browser timer enforces data confidentiality.
- **Safeguards to preserve:** Keep restricted media behind backend authorization. Do not expose PoH evidence or keys in test recordings, screenshots, traces or artifacts. The browser timer cannot revoke previously delivered media bytes or prevent screen capture.
- **Controlled acceptance method:** Use synthetic local media under a test-only private account, stub time progression and exercise pause/resume, tab backgrounding, end-of-playback, rewatch, reload and rejection.
- **Planned cases:** P9-06–P9-10 — **Not run**.

### FE-053 — Activity count does not refetch new notices while user stays on the same route

- **Priority:** P2
- **Evidence classification:** Source-confirmed refresh-graph gap; user-visible latency not browser reproduced
- **Frontend surface:** Header Activity badge / authenticated notifications
- **Exact-main references:** [web/src/components/ActivityBell.tsx:17–25](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/ActivityBell.tsx#L17-L25); [web/src/components/ActivityBell.tsx:27–50](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/ActivityBell.tsx#L27-L50); [web/src/components/ActivityBell.tsx:52–94](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/ActivityBell.tsx#L52-L94); [web/src/components/AppShell.tsx:90–110](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L90-L110); [web/src/components/AppShell.tsx:243–251](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L243-L251)
- **Observed source path / trigger:** ActivityBell fetches notices in a useEffect dependent on account, API base, and refreshToken. The once-per-minute interval increments clockRevision for local recalculation only; it does not query the server. AppShell passes a token based on current route, so staying on an unchanged route does not trigger notice refresh on a timer.
- **Potential user impact:** A person monitoring a page for incoming activity can retain an outdated activity badge until navigation/remount or another appropriate refresh. This is especially problematic for time-sensitive reviewer or group tasks, though the exact impact depends on whether separate APIs issue proactive notifications.
- **Required behavior / remediation specification:** Define and implement bounded refresh or event-triggered invalidation for authenticated notices, with backoff and visibility/power awareness, explicit freshness/unknown state, and no inference that an unavailable inbox is empty.
- **Safeguards to preserve:** Never persist bearer tokens or query activity under an outdated account/node; retain the existing local quiet-hours, mute, and read-preference semantics.
- **Controlled acceptance method:** With same-route idle browser and mocked authenticated notices, inject a new notice, advance a bounded refresh interval, and check badge/AT label update without navigation. Also test offline and account switch.
- **Planned cases:** P9-11–P9-15 — **Not run**.

### FE-054 — Context drawer marks itself modal but does not make the application background inert

- **Priority:** P2 candidate
- **Evidence classification:** Source-confirmed modal structure; screen-reader/virtual-cursor leakage remains unverified
- **Frontend surface:** Application shell context and status dialog
- **Exact-main references:** [web/src/components/AppShell.tsx:155–198](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L155-L198); [web/src/components/AppShell.tsx:201–212](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L201-L212); [web/src/components/AppShell.tsx:309–343](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L309-L343); [web/src/styles.css:3310–3354](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/styles.css#L3310-L3354)
- **Observed source path / trigger:** AppShell adds inert to the *closed drawer* and removes it when open, traps keyboard Tab inside the drawer and sets aria-modal={infoOpen}. No corresponding inert or aria-hidden is applied to the background app content while the drawer is open.
- **Potential user impact:** Ordinary Tab navigation receives focus trapping, but some screen-reader browse/virtual-cursor navigation may still encounter underlying page content. Whether a particular browser hides that content under aria-modal must be measured, not assumed.
- **Required behavior / remediation specification:** Choose a standards-consistent modal isolation strategy that makes background content noninteractive and absent from modal browse navigation, preserves focus restoration and Escape, and avoids disabling the dialog itself.
- **Safeguards to preserve:** Do not add blanket inert to the common ancestor containing the dialog. Preserve recording state and route transition behavior; do not replace backend gating with modal gating.
- **Controlled acceptance method:** Use Chrome, Firefox, and at least one real screen reader to check landmark navigation, virtual cursor isolation, focus restoration after Escape/backdrop, and app background pointer interactions at multiple sizes.
- **Planned cases:** P9-16–P9-20 — **Not run**.

### FE-055 — Media loading failures have no explicit error, retry, or degraded-content affordance

- **Priority:** P2
- **Evidence classification:** Source-confirmed absence of media element load-error handling; actual browser failure appearance untested
- **Frontend surface:** Feed, thread, and group shared media viewer
- **Exact-main references:** [web/src/components/MediaGallery.tsx:111–145](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L111-L145); [web/src/components/MediaGallery.tsx:240–292](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L240-L292); [web/src/components/MediaGallery.tsx:75–95](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/MediaGallery.tsx#L75-L95)
- **Observed source path / trigger:** Image, video, and audio elements are rendered with the selected proxy URL but without onError or failed-load state. The card still shows its media label and “viewport loaded” metadata when the viewport is reached, even if the resource cannot be fetched.
- **Potential user impact:** A temporarily unavailable observer/IPFS proxy may show a broken image or non-working player with no clear explanation or retry; “viewport loaded” can be mistaken for successful media retrieval.
- **Required behavior / remediation specification:** Distinguish not-yet-requested, loading, loaded, failed and inaccessible states, expose a retry action, retain CID and source provenance, and announce failures without flooding the accessibility live region.
- **Safeguards to preserve:** Keep media fetched through the node observer proxy. Do not auto-load arbitrary third-party gateways or leak authorization headers to external URLs. Distinguish a 403 restricted asset from temporary outage.
- **Controlled acceptance method:** Mock image/video/audio proxy 404, 403, 503, timeout and recovery on PR #97; verify no blank/broken outcome is mislabeled loaded and retry does not initiate unauthorized fetch.
- **Planned cases:** P9-21–P9-25 — **Not run**.

### FE-056 — Account registration renders a main landmark nested inside the shell main landmark

- **Priority:** P2
- **Evidence classification:** Source-confirmed nested JSX markup; exact accessibility-tree representation not run
- **Frontend surface:** Registration / onboarding route and shell landmarks
- **Exact-main references:** [web/src/pages/AccountRegistrationPage.tsx:245–281](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L245-L281); [web/src/App.tsx:44–51](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L44-L51); [web/src/App.tsx:397–402](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L397-L402); [web/src/components/AppShell.tsx:303–312](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx#L303-L312)
- **Observed source path / trigger:** The registered-account route is rendered as a child of AppShell, which already provides <main id="app-shell-content">. AccountRegistrationPage returns its own <main> in both its recovery-needed and guided-registration branches.
- **Potential user impact:** Nested main landmarks are nonconforming and may produce duplicate/ambiguous main navigation for assistive-technology users. This is distinct from the duplicate top-level heading issue FE-025.
- **Required behavior / remediation specification:** Use a non-landmark container inside the existing shell main and keep a single main landmark per document. Confirm that the login page that bypasses the shell still has correct semantics.
- **Safeguards to preserve:** Do not disrupt registration nonce, transaction-deduplication journal, signer retention or page mounting to fix semantic markup.
- **Controlled acceptance method:** Inspect landmark roles on account-registered and recovery-needed registration branches, then compare anonymous login and authenticated settings pages.
- **Planned cases:** P9-26–P9-30 — **Not run**.

### FE-057 — Illustrative action lifecycle card does not reflect actual transaction progress

- **Priority:** P3
- **Evidence classification:** Source-confirmed static component; user interpretation requires usability testing
- **Frontend surface:** Create group / create decision / dispute review action surfaces
- **Exact-main references:** [web/src/components/ActionLifecycleCard.tsx:1–43](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/ActionLifecycleCard.tsx#L1-L43); [web/src/pages/GroupCreate.tsx:226–240](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/GroupCreate.tsx#L226-L240); [web/src/pages/ProposalCreate.tsx:292–320](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/ProposalCreate.tsx#L292-L320); [web/src/pages/DisputeReview.tsx:190–240](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/DisputeReview.tsx#L190-L240)
- **Observed source path / trigger:** ActionLifecycleCard accepts only title and intro, and renders every lifecycle stage as a static tag. It does not receive the actual pending/recorded/confirmed/error state or highlight a current step.
- **Potential user impact:** The presentation can be interpreted as a live tracker despite being explanatory documentation. It competes visually with real transaction feedback and cannot tell the user which stage is currently active.
- **Required behavior / remediation specification:** Clearly label it as an illustrative process guide or connect it to the canonical transaction queue lifecycle with accurate current-state announcements, persistent tx identifier and an unambiguous distinction between submitted and finalized.
- **Safeguards to preserve:** Never infer finality from local step progression; use only canonical receipt/observer evidence for confirmation, and preserve the existing TxStatusToast aria-live notification path.
- **Controlled acceptance method:** Compare the static lifecycle card and actual transaction toast at validating/recorded/unknown/confirmed/failed on three action pages; keyboard and screen-reader users should be able to distinguish the instructional text from live status.
- **Planned cases:** P9-31–P9-35 — **Not run**.

## Relationship to previous phases — no duplicate findings

| Earlier finding | Distinction from Phase 9 |
|---|---|
| FE-042 | FE-042 addresses clearing post/reply drafts before confirmed finality. FE-051 identifies the specific `unknown` fallback acceptance predicate and its sequencing consequences; both remain open. |
| FE-048 | FE-048 addresses absent caption/transcript alternatives. FE-055 addresses missing media *load error* and retry UX, not missing captions. |
| FE-024, FE-026, FE-049 | FE-054 addresses background isolation of a purported modal; FE-056 concerns nested main landmarks. Neither is a duplicate of skip-navigation or section-tab semantics. |
| FE-017–FE-023 | FE-053 must not be fixed by bypassing account/node/session provenance or by using local read state as authoritative remote notices. |
| FE-050 | FE-050 remains a mobile group-tab discoverability candidate; Phase 9 does not restate it with a new ID. |
| FE-043 | The eight-column Decision lifecycle is still awaiting a rendered narrow-viewport test. This phase does not claim it passed. |

## Existing safeguards independently observed in the source

- `TxQueueProvider` differentiates canonical `/v1/tx/status` confirmation from read-model observations; FE-051 is **not** an allegation that the entire transaction queue confirms unknown results.
- `AccountRegistrationPage` preserves submission intent and a predicted transaction ID before dispatch to prevent careless duplicate registration.
- `ActivityBell` refuses to present a failed authenticated notice fetch as a zero-count inbox, and it does not persist session headers.
- `AppShell` already traps Tab within the context drawer, restores focus and closes on Escape. FE-054 asks for virtual-cursor/background isolation verification *in addition* to existing keyboard controls.
- `MediaGallery` prefers same-origin observer proxy URLs for CID-backed resources and does not auto-load third-party gateways.
- `GroupBallotPlanner` is explicitly practice-only; no election authority is implied.

## Evidence classification and release posture

- **Source-verified, potentially misrepresentative states:** FE-051, FE-052, FE-053, FE-055, FE-056, FE-057; FE-051 exact operational reachability and FE-052 elapsed-time effects need runtime reproduction.
- **Source-verified structure, accessibility effect pending:** FE-054, FE-056.
- **Actually executed in Phase 9:** Source reads, GitHub exact-baseline comparison, PR status and prior archive file inspection; no new browser/acceptance executions.
- **Existing PR #97 CI:** [Web CI run #44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) previously passed for its own head; broader gates have failures. This does not close any new finding.
- **Public-testnet release decision:** **NO-GO unchanged**. This is a frontend documentation artifact and does not assess backend consensus readiness.


---

# Phase 9 acceptance matrix — all 35 cases NOT RUN

# Phase 9 — 35-case frontend regression and acceptance matrix

**Canonical review source:** `6d3d69234415d294936d99e819367cff589ced3d` (`main`); **permitted runtime target:** PR #97 at `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` if checkout becomes available.

**Execution status for all cases:** NOT RUN in Phase 9. Existing successful PR #97 Web CI does not count as these tests.

| Case | Finding | Focus | Fixture / setup | Expected observable result | Status |
|---|---|---|---|---|---|
| P9-01 | FE-051 | positive nonce + pending receipt | Signed envelope contains nonce; nonce read model lags | Prevent finality claim; keep safe pending status and no duplicate dispatch | **NOT RUN** |
| P9-02 | FE-051 | no nonce + tx unknown | Signed envelope omits nonce but returns tx_id; /tx/status returns unknown | Do not classify as confirmed or sequence dependent actions based on the unknown alone | **NOT RUN** |
| P9-03 | FE-051 | no nonce + tx rejected | Same as prior but final receipt fails apply | Show rejected with tx id; never clear recovery evidence or submit next step | **NOT RUN** |
| P9-04 | FE-051 | no nonce + tx confirmed | Exact tx receipt confirmed, applied and synced | Advance only along explicitly supported canonical/receipt conditions | **NOT RUN** |
| P9-05 | FE-051 | network outage while declaring media | Media declaration pending; connectivity drops | Retain CID, envelope, tx id and prepared post; no blind retries | **NOT RUN** |
| P9-06 | FE-052 | pause longer than window | Restricted synthetic video; pause and advance clock | Policy-defined deadline and pause behavior reflected faithfully | **NOT RUN** |
| P9-07 | FE-052 | resume multiple times | Start/pause/restart repeatedly with controlled clock | No accidental window reset bypass or inconsistent remaining time | **NOT RUN** |
| P9-08 | FE-052 | end playback | Video ends before deadline | Lock or offer the authorized bounded rewatch exactly as specified | **NOT RUN** |
| P9-09 | FE-052 | one rewatch used | Evidence is opened and rewatched once | No second rewatch; status clear and keyboard accessible | **NOT RUN** |
| P9-10 | FE-052 | navigation, reload, background tab | Open review, switch away, return and reload | Apply explicit persistence/backend policy; never claim client timer protects bytes | **NOT RUN** |
| P9-11 | FE-053 | new notice same route | Authenticated user remains on /feed; new notice arrives | Badge refreshes within documented freshness SLA without route change | **NOT RUN** |
| P9-12 | FE-053 | authenticated notice outage | Notice API returns 503 on refresh | Display unavailable/stale, never silently zero | **NOT RUN** |
| P9-13 | FE-053 | account switch | Switch from @alice to @bob while old read is in flight | No Alice identifiers/counts appear on Bob session | **NOT RUN** |
| P9-14 | FE-053 | node switch | Switch target to compatible node with different notice set | No stale badge imported across node provenance | **NOT RUN** |
| P9-15 | FE-053 | read/mute/quiet-hours | Update local preferences while remote set stable | Count and accessible label reflect local preference without new false remote state | **NOT RUN** |
| P9-16 | FE-054 | keyboard focus trap | Open Context & status; Tab and Shift+Tab | Focus stays in dialog; Escape returns to opener | **NOT RUN** |
| P9-17 | FE-054 | screen-reader browse isolation | Open dialog with background headings/links | Virtual cursor and landmarks exclude inert background while modal open | **NOT RUN** |
| P9-18 | FE-054 | pointer/backdrop behavior | Open drawer and click outside | Close without triggering app actions underneath | **NOT RUN** |
| P9-19 | FE-054 | route transition | Open drawer and navigate | Background restored, focus placed predictably and drawer closed | **NOT RUN** |
| P9-20 | FE-054 | mobile 320/390 and 400% zoom | Open drawer on narrow viewport/zoom | Dialog fits and all controls are accessible without unintended overflow | **NOT RUN** |
| P9-21 | FE-055 | image proxy 503 | Image CID proxy fails once, then recovers | Visible load error and explicit retry; no false loaded label | **NOT RUN** |
| P9-22 | FE-055 | video unauthorized | Restricted asset returns HTTP 403 | No external fallback or exposure; precise unavailable wording | **NOT RUN** |
| P9-23 | FE-055 | audio 404 | Audio URL points to missing content | Textual error and accessible alternative/retry where safe | **NOT RUN** |
| P9-24 | FE-055 | offline/slow network | Media request times out then connection returns | Bounded retry/cancel, distinct pending versus failed states | **NOT RUN** |
| P9-25 | FE-055 | valid media | Proxy serves image/video/audio successfully | Rendered media, correct alt/status, no gratuitous error warning | **NOT RUN** |
| P9-26 | FE-056 | registered onboarding route | Open /onboarding/register with signing key | Exactly one main landmark in accessibility tree | **NOT RUN** |
| P9-27 | FE-056 | recovery-needed route | Visit registration without key | Single main landmark with accurate recovery heading | **NOT RUN** |
| P9-28 | FE-056 | anonymous login | Navigate /login outside AppShell | Single understandable main content and no missing landmarks | **NOT RUN** |
| P9-29 | FE-056 | authenticated settings | Navigate protected /settings | Shell main remains present and is focusable | **NOT RUN** |
| P9-30 | FE-056 | keyboard heading/landmark traversal | Use landmarks and headings navigation on registration | No ambiguous nested main or duplicated target | **NOT RUN** |
| P9-31 | FE-057 | group create pending | Submit group creation, receipt still pending | Process guide not mistaken for live confirmation | **NOT RUN** |
| P9-32 | FE-057 | decision create rejected | Submit invalid decision in controlled fixture | Actual failure clearly marked separately from static guide | **NOT RUN** |
| P9-33 | FE-057 | dispute review confirmed | Submit authorized synthetic review fixture | Real receipt state not inferred from illustrated stages | **NOT RUN** |
| P9-34 | FE-057 | missing receipt | Simulate submit acknowledgment without receipt | Explicit unknown, original tx id preserved, no static Done claim | **NOT RUN** |
| P9-35 | FE-057 | screen-reader status | Navigate guide and toast live region | Instructional and actual status described distinctly | **NOT RUN** |

## Required coverage and evidence rules

1. Run only on an isolated read-only or disposable browser and controlled PR #97 test network. The act of submitting a transaction must be limited to synthetic fixture accounts, never real users.
2. Capture baseline SHA, PR SHA, page route, viewer account category (not bearer or private key), API target identity, viewport, browser version, and exact action outcome.
3. Include native screen-reader observations for modal and landmark cases; programmatic Playwright accessibility assertions alone are insufficient.
4. Test narrow viewports 320, 390, 768, 1024 and 1440 CSS px, plus 200% and 400% zoom where meaningful; do not silently replace real evidence with a simulated static fixture.
5. Confirm a valid original signed transaction before every retry, never infer successful application from unknown/pending, and check complete receipt before marking a case PASS.
6. Screenshots and traces must not contain PoH evidence, bearer tokens, recovery seeds, private media, or other user secrets.
7. Classify test result as PASS/FAIL/BLOCKED and link exact executable job/artifact. CI does not automatically close a finding; provide exact reproduction and remediation review.

## Test harness availability

The container has Node, Playwright and Chromium, but the exact PR #97 working tree is absent and direct git clone cannot resolve github.com. No full-app browser tests were run. GitHub source and CI information were inspected through the connected repository only.


---

# Phase 9 existing CI evidence boundaries

# PR #97 — Phase 9 browser evidence boundary

**Canonical baseline:** `6d3d69234415d294936d99e819367cff589ced3d` (`main`) — exact commit comparison identical.  
**PR #97:** [open draft](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97) `audit/public-testnet-remediation` @ `2ab08aa74b86806e1c4fef1f47b184d4f80c4793`.  
**Previously completed Web CI:** [run #44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842), conclusion **success**, checked using GitHub connector in prior phase.  
**This phase:** **No new workflow dispatch, rerun, browser launch or screenshot**.

## What the existing run actually supports

The previously completed Web CI reports successful jobs for frontend functional/deployment rehearsal, rendered governance deliberation, frontend dependency security and aggregator. Job steps include TypeScript check, built web app, Nginx production smoke, Chromium account isolation, theme transfer, rendered active deliberations. These are positive evidence **for those scenarios and PR head only**.

## What that run does not establish

- The Playwright configuration contains a `chromium` project using `devices["Desktop Chrome"]`. It does not set mobile/tablet projects with touch/input emulation or explicit 320–390px acceptance for all routes.
- No new FE-051–FE-057 test cases have been executed or linked to a recorded run.
- The past run does not demonstrate a screen-reader-specific browse-mode dialog isolation test, end-user restricted video timing policy, idle-notification refresh behavior, media error/retry behavior, or nested-landmark checks.
- Source contract check scripts and mock HTTP responses do not substitute for authenticated two-account/two-node real-browser acceptance.
- PR #97 still has separate failed checks in its observed run batch: Backend CI, Reviewer Readiness, A01–A20 revalidation and repository-wide change coverage. Web CI success does not authorize merge or public testnet.

## Local runtime constraints verified

- Installed: Node.js, Chromium, Playwright.
- Missing: local checked-out PR #97 frontend and supporting node setup.
- `git ls-remote https://github.com/errol1swaby2-bit/WeAll-Protocol.git HEAD` failed here because `github.com` could not be resolved.
- GitHub connector can read exact source files and existing CI but does not hand off a complete runnable frontend checkout. No substitute mock UI was presented as genuine rendered acceptance.

## Evidence grading

**E0 — code inspection:** all FE-051–FE-057 source paths.  
**E1 — existing CI:** prior PR #97 job completions, limited to jobs and commits recorded above.  
**E2 — new full-app automated acceptance:** not available in this phase.  
**E3 — manual mobile + screen-reader acceptance:** not available in this phase.

Passing a source-level contract does not elevate E0 to E2. If a local checkout becomes available, use `02_PHASE9_ACCEPTANCE_MATRIX.md` as the executable test contract and preserve the exact hashes and recordings.


---

# PHASE 10 — FULL DETAILED FRONTEND ADDENDUM (FE-058–FE-064)

# WeAll Frontend — Phase 10 detailed read-only audit

**Date:** 2026-11-20 (America/Los_Angeles)  
**Canonical `main` snapshot:** [`6d3d69234415d294936d99e819367cff589ced3d`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) (compared with live `main` and identical during this phase)  
**Permitted optional CI/test target:** [PR #97](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97) — open draft at `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` at verification.  
**Scope:** frontend behavior, account registration UI, notification presentation, decision creation, local transaction history. Backend source inspected only for canonical contract checking.  
**Mode:** strictly read-only; no repository edits, PR writes, new CI requests, node transactions, rendered tests, or screenshots.

## Executive summary

Phase 10 records **seven new documented frontend defects or candidate risks (FE-058–FE-064)**. These extend the prior 57-item ledger, now reaching **64 cumulative findings**. Main concerns are (a) provenance of pending account registration across account/node transitions, (b) preserving read-only Activity data through failure and user preferences, (c) session renewal vs frozen protected request headers, (d) second-precision proposal ID collisions, and (e) protecting locally useful transaction evidence from accidental deletion.

**Confidence labels matter.** A *source-confirmed* state or UI defect means the code path can be established directly. Where a user would have to switch accounts, recover a session without remount, or submit two decisions within the same UTC second, production reachability and end-user impact still require the listed controlled-browser tests. Nothing here claims a backend authorization bypass. 

**What is not new:** FE-013 already covers account-unscoped local tx histories; FE-017/018 cover broader account-context identity and in-flight reads; FE-019 covers frozen node base URLs; FE-053 covers the notification bell not polling new notices. Phase 10 examines separate concrete frontend paths and cross-references these earlier issues rather than duplicating them.

## Findings and detailed development handoff
## FE-058 — Pending registration journal omits node and chain provenance

**Priority:** P1/P2  
**Evidence classification:** Source-confirmed state-key defect; cross-node reproduction unexecuted  
**Frontend domain:** Onboarding / cross-node registration

### Source-confirmed mechanism
AccountRegistrationPage.pendingRegistrationKey(account) returns only `weall.account_registration_pending::<account>`; the predicted transaction ID is durably written to that account-only key. AccountRegistrationPage reuses the same ID and queries receipt status against a separate `base` selected at mount. Chain/genesis/node identity are not part of the journal namespace.

### User-visible effect and evidence boundary
A registration started on node A can be rediscovered on node B for the same account and be interpreted using node B transaction/status results. This can leave the account blocked as “pending” on B or associate a successful chain-specific record with the wrong pending intent. The source does NOT show that this permits duplicate transactions or forged receipts.

### Reproduction conditions
Same browser origin/profile, same account handle, change of selected node or chain after a pending registration. A same-chain observer transition may be legitimate only after verifying exact chain/genesis semantics.

### Frontend acceptance requirement / recommended corrective boundary
Scope the persistent intent to account + verified chain/genesis + originating submission node or durable network provenance. On transition, retain the old intent but show explicit originating-node recovery; only reconcile using provably equivalent chain identity and exact transaction ID. Preserve the before-dispatch durable-journal guard.

### Existing safeguards that must remain intact
Do not clear or silently re-sign a pending registration merely because a new node lacks the record; account registration remains fail-closed. Preserve canonical signer/public-key comparison and tx receipt verification.

### Exact source references
- [`web/src/pages/AccountRegistrationPage.tsx` lines 13–47](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L13-L47)
- [`web/src/pages/AccountRegistrationPage.tsx` lines 52–114](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L52-L114)
- [`web/src/lib/accountSetupRegistration.ts` lines 60–83](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/accountSetupRegistration.ts#L60-L83)

### Planned tests — NOT RUN
- **P10-01:** Initiate registration on node A, retain unresolved exact tx ID, switch to unrelated chain B: B must not claim A’s pending ID as its own.
- **P10-02:** Switch between two authenticated observers of same chain/genesis: permitted reconciliation must explicitly establish equivalence before reusing intent.
- **P10-03:** Return to A after interruption: exact durable ID is recovered and cannot be silently resubmitted.
- **P10-04:** Simulate unavailable transaction status on A/B: both stay unknown, preserving origin and no duplicate submission.

## FE-059 — Registration pending ID can remain associated with a prior selected account

**Priority:** P2 candidate  
**Evidence classification:** Source-confirmed initial-only state; account-switch reachability requires browser test  
**Frontend domain:** Onboarding / account switching

### Source-confirmed mechanism
`const [transactionId, setTransactionId] = useState(() => readPendingTransaction(account))` runs at component initialization. No account-change effect reloads the ID and resets `synced`, `rejected`, message, and other account-specific state. React remounting on navigation can mitigate the issue, but the component is not keyed by account in the inspected render path.

### User-visible effect and evidence boundary
When an account changes without unmounting the registration component, the new account’s UI may display the previous account’s transaction ID and pending/rejected state; the new account may be prevented from starting its own correct registration. There is no demonstrated cross-account signature or registration acceptance.

### Reproduction conditions
Same route/component instance, account A to account B via a session update, browser storage event or context change. Requires a controlled real-browser transition because normal navigation might remount the page.

### Frontend acceptance requirement / recommended corrective boundary
Bind registration view state to account and verified node identity. On identity change, cancel old reads/timers, discard prior presentation state, then load and verify only the destination identity’s durable intent. Make the state snapshot explicit.

### Existing safeguards that must remain intact
Do not delete account A’s durable pending intent during a switch; account B must not get a false green “registered” badge.

### Exact source references
- [`web/src/pages/AccountRegistrationPage.tsx` lines 52–66](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L52-L66)
- [`web/src/pages/AccountRegistrationPage.tsx` lines 69–120](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/AccountRegistrationPage.tsx#L69-L120)
- [`web/src/App.tsx` lines 44–50](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx#L44-L50)

### Planned tests — NOT RUN
- **P10-05:** Switch account A→B without route unmount while A has pending registration: B must not display A’s ID or status.
- **P10-06:** After switching A→B→A, each account resumes its own exact durable intent; never clear the other account’s record.
- **P10-07:** Delay A’s registration status fetch until B is selected: late A response must not mutate B’s display.
- **P10-08:** Verify whether normal session flows actually keep registration component mounted before confirming production reachability.

## FE-060 — Activity refresh clears last-known notices and read-state presentation before success

**Priority:** P2  
**Evidence classification:** Source-confirmed last-successful-snapshot loss on request failure  
**Frontend domain:** Activity / offline and transient failure

### Source-confirmed mechanism
`Activity.load()` clears `items`, `cursor`, `readIds`, `preferences` and `storageKey` on every first-page refresh **before** awaiting `weall.activityNotices()`. A failed call sets an error but cannot restore previously loaded notices. Stored read choices survive in localStorage; the page just drops their current presentation until a successful reload.

### User-visible effect and evidence boundary
An authenticated user can lose the previously readable notification list and preference controls following a short outage. The error banner correctly prevents an explicit “no events exist” conclusion, so this is not FE-003’s false-empty claim; the gap is last-good-data continuity.

### Reproduction conditions
Activity first-page refresh, session lapse, temporary node outage, CORS/retry interruption, or malformed response.

### Frontend acceptance requirement / recommended corrective boundary
Keep the previous successful list with a visible stale badge while refreshing. Commit replacement data atomically on verified success; preserve current read state and preferences on failure. On account/chain changes intentionally isolate the previous snapshot rather than display it under the new identity.

### Existing safeguards that must remain intact
Do not fabricate updated notices or imply stale data are current. Keep personal notices scoped to authenticated user and chain/genesis.

### Exact source references
- [`web/src/pages/Activity.tsx` lines 67–115](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L67-L115)
- [`web/src/pages/Activity.tsx` lines 178–195](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L178-L195)

### Planned tests — NOT RUN
- **P10-09:** Load real notices, force next first-page request to fail: prior cards remain visible with “last loaded” labeling and retry.
- **P10-10:** On failed refresh, previously set quiet-hour and mute controls remain displayed without reinitializing to defaults.
- **P10-11:** After a successful refresh, replace outdated list and reconcile read IDs using the same verified key.
- **P10-12:** Account change must never carry prior private personalized notices into destination account’s view.

## FE-061 — Previously muted Activity category may have no visible unmute control

**Priority:** P3  
**Evidence classification:** Source-confirmed reversibility gap, with presence-dependent UI  
**Frontend domain:** Activity / preferences

### Source-confirmed mechanism
`noticeCategories` is computed solely from `items.map(item => item.type)`, while saved muted types are read from a separate persistent preference key. The UI renders Mute/Unmute buttons only for categories in the current loaded results.

### User-visible effect and evidence boundary
A category can remain muted but disappear from the current 50-notice page. Its saved mute setting persists, while the user sees no control to unmute it until an example of that category appears on a loaded page.

### Reproduction conditions
Previously muted category absent from current first-page results; pagination, archival turnover or a node with different event categories.

### Frontend acceptance requirement / recommended corrective boundary
Always list the union of known supported categories and saved mutedTypes, separating “currently observed in recent notices” from “saved preferences”. Allow unmute without requiring a new event.

### Existing safeguards that must remain intact
Preserve the explicit guarantee that high-priority safety and review-duty notices cannot be suppressed by client mutes or quiet hours.

### Exact source references
- [`web/src/pages/Activity.tsx` lines 132–149](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L132-L149)
- [`web/src/pages/Activity.tsx` lines 258–283](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L258-L283)
- [`web/src/lib/activityReadState.ts` lines 76–112](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/lib/activityReadState.ts#L76-L112)

### Planned tests — NOT RUN
- **P10-13:** Mute a category, then refresh with only other categories: its Unmute control remains available.
- **P10-14:** Unmute a saved category with no visible notice of that type; preference is updated and remains unmuted after reload.
- **P10-15:** High-priority notice still counts for attention despite the category being muted.
- **P10-16:** Unknown formerly saved categories are rendered safely without claiming they are active event types.

## FE-062 — Activity authorization headers are memoized only by account, not live session state

**Priority:** P2 candidate  
**Evidence classification:** Source-confirmed stale capture; impact depends on in-place session renewal path  
**Frontend domain:** Activity / session recovery

### Source-confirmed mechanism
`const headers = useMemo(() => (account ? getAuthHeaders(account) : undefined), [account]);` freezes the headers during same-account bearer renewal. `load()` reuses the captured headers even when login/session repair updates the bearer. `base` is also mount-time memoized, already tracked separately as FE-019.

### User-visible effect and evidence boundary
If account remains identical while the browser acquires or renews an authenticated session, Activity refresh can keep using stale or missing headers until the component remounts. This is an availability/UX flaw, not evidence of backend authentication bypass.

### Reproduction conditions
Open Activity during expired/missing session, repair same-account session without unmount, then refresh notices; tab-local bearer can change independently of account string.

### Frontend acceptance requirement / recommended corrective boundary
Acquire headers from the canonical live session at each protected request, optionally with a reactive session revision; verify account and destination node on response. In-flight requests should have version/cancellation protection (already present) and never use a foreign node’s token.

### Existing safeguards that must remain intact
Do not persist bearer in localStorage and do not treat a signer alone as an authenticated session.

### Exact source references
- [`web/src/pages/Activity.tsx` lines 52–88](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L52-L88)
- [`web/src/pages/Activity.tsx` lines 116–124](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/Activity.tsx#L116-L124)

### Planned tests — NOT RUN
- **P10-17:** Mount Activity with no valid bearer, renew same account on same mounted route, then refresh; request must use newly authorized headers.
- **P10-18:** Revoke or rotate an old session token; no retries may reuse the revoked bearer after renewal.
- **P10-19:** Change account while an old request is unresolved: stale response must not populate new account’s notices.
- **P10-20:** Confirm absence of bearer storage in localStorage and preserved backend /session/me authorization.

## FE-063 — Normal decision auto-generated IDs use only account, title slug and current second

**Priority:** P2  
**Evidence classification:** Source-confirmed potential ID collision; backend rejection independently verified  
**Frontend domain:** Decisions / creation reliability

### Source-confirmed mechanism
`buildGeneratedProposalId()` combines normalized account, first 48 slug characters and a UTC timestamp truncated to 14 digits (second precision). Normal-mode creation calls it at submission and exposes no custom ID or preflight uniqueness check. The backend `GOV_PROPOSAL_CREATE` handler rejects duplicate proposal IDs with `proposal_already_exists`.

### User-visible effect and evidence boundary
Two submissions from the same account with the same or slug-equivalent title within one second generate the same ID. The second is rejected; rapid sequential submissions may normally be limited by the signer lane, so actual concurrent reachability needs a controlled test. This does not allow overwriting an existing decision.

### Reproduction conditions
Same account, same UTC second and equal title slugs (including first 48 characters); different body may not disambiguate if title present.

### Frontend acceptance requirement / recommended corrective boundary
Generate an unpredictable unique proposal ID once per composition attempt, retain it throughout submission/retry journaling, and associate all status checks with that exact ID. On explicit collision, offer safe recovery without automatically resubmitting unknown transactions.

### Existing safeguards that must remain intact
Retain backend duplicate-ID rejection. Do not use client clock as the sole source of transaction uniqueness or invent an already-finalized decision.

### Exact source references
- [`web/src/pages/ProposalCreate.tsx` lines 23–36](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/ProposalCreate.tsx#L23-L36)
- [`web/src/pages/ProposalCreate.tsx` lines 203–226](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/ProposalCreate.tsx#L203-L226)
- [`Weall-Protocol/src/weall/runtime/apply/governance.py` lines 1683–1691](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/Weall-Protocol/src/weall/runtime/apply/governance.py#L1683-L1691)

### Planned tests — NOT RUN
- **P10-21:** Freeze browser clock to one UTC second and generate two same-account/same-title decisions: IDs must differ.
- **P10-22:** Different bodies under same title in same second must not unexpectedly collide.
- **P10-23:** Simulated duplicate-id backend rejection leaves draft intact and gives clear non-duplicating recovery guidance.
- **P10-24:** A lost acknowledgement retry must reconcile the first exact transaction/proposal ID rather than silently mint another.

## FE-064 — Transaction history can be cleared without confirmation or recovery, across all local accounts

**Priority:** P2/P3  
**Evidence classification:** Source-confirmed one-click destructive client-only action  
**Frontend domain:** Transactions / local evidence continuity

### Source-confirmed mechanism
TransactionsPage `clearHistory()` immediately removes all three local-storage history keys (`weall_tx_activity_v3/v2/v1`) and resets the displayed list. The button’s onClick calls it directly with no confirmation/undo. FE-013 previously documented that the underlying history is not account scoped; this new finding is the UI destruction and recovery safeguard, not a duplicate account-scoping defect.

### User-visible effect and evidence boundary
An accidental click irreversibly removes browser-stored submission evidence for multiple accounts at once, including potentially useful pending/unknown transaction identifiers not yet copied elsewhere. Canonical chain records are not deleted.

### Reproduction conditions
Any browser profile with locally tracked transactions; particularly sensitive when a user is still reconciling uncertain actions.

### Frontend acceptance requirement / recommended corrective boundary
Use an explicit, accessible confirmation showing scope (“all local accounts in this browser”), pending/unknown count, and irreversible local effect; default to preserving unresolved tx IDs and offer export/backup before deletion. Implement a recoverable local history archive if feasible.

### Existing safeguards that must remain intact
The purge is local only. Never imply that removing local history cancels or reverses a protocol transaction; do not mutate chain state.

### Exact source references
- [`web/src/pages/TransactionsPage.tsx` lines 49–63](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L49-L63)
- [`web/src/pages/TransactionsPage.tsx` lines 208–220](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L208-L220)
- [`web/src/pages/TransactionsPage.tsx` lines 315–333](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/TransactionsPage.tsx#L315-L333)

### Planned tests — NOT RUN
- **P10-25:** With history from accounts A and B, select clear: show explicit all-account scope and require a separate affirmative confirmation.
- **P10-26:** Cancel: storage keys and displayed rows remain byte-for-byte unchanged.
- **P10-27:** With unresolved tx IDs, clearing warns and preserves a recovery path before any deletion.
- **P10-28:** After confirmed deletion, canonical transaction status remains retrievable independently from chain; no cancellation is claimed.

## Confirmed safeguards and non-findings

- `readAccountRegistrationStatus()` checks the local signer against canonical account public key, and returns unavailable on read failure. The registration Submit button is disabled for status other than `not_registered`, including `key_mismatch` and `unavailable`. Do **not** misreport FE-058/059 as permission for a second registration.
- Before registration dispatch the exact predicted transaction ID is written durably and verified with a readback. Any repair must preserve this no-duplicate safety barrier.
- Activity’s `requestVersion` prevents stale overlapping HTTP responses from replacing the latest request, and errors produce a visible banner. FE-060 concerns loss of the last successful snapshot, not a hidden failure or false success.
- Activity’s `activityReadKey` already binds stored notification preferences to base, chain ID, genesis ID and account. FE-061 concerns the visible **category-selection** controls, not the storage namespace.
- `countRecentAttention` always includes high-priority notices regardless of quiet-hours and muted types. Preserve this.
- Governance duplicate-ID enforcement is canonical. FE-063 concerns avoiding unnecessary UX rejection, not accepting duplicate decisions.
- Clearing browser history does not modify blockchain data. The original on-screen label accurately states that it only clears browser history.

## Evidence limits

This phase inspected exact `main` source via the connected GitHub repository, independently verified the backend duplicate-proposal rejection, and inspected uploaded Phase 1–9 documentation. No new end-to-end browser or real node acceptance cases were executed; **all P10 tests are NOT RUN**. Existing PR #97 Web CI from previous phases is historical evidence for its tested head only, not proof of Phase 10 regressions. No patch, branch, PR update, workflow re-run, GitHub mutation, or transaction submission occurred.


---

# APPENDED PHASE 11 HANDOFF — original previous ledger above preserved byte-for-byte

# WeAll frontend — Phase 11 audit completeness assessment

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

## Executive decision

**Source-documentation reconciliation: complete for the 64-item historical ledger.** Every FE-001–FE-064 has a source report, priority/classification in the original records, and a stable handoff reference. No Phase 11 findings have been added, renumbered, discarded, merged into an undocumented issue, or reported closed.

**Rendered end-to-end frontend acceptance: not complete.** The historical documentation specifies **224 numbered scenarios** across Phases 2–10. Phase 11 supplements these with **9 new, unexecuted case specifications** for FE-002–FE-010, producing **233** documented numbered cases in total. Phase 11 has not executed any of them. The Phase 1 work order is preserved and is not deceptively counted as a numbered matrix. The existing PR #97 Web CI is positive for the exact scenarios in its jobs, not blanket evidence for 224 test cases.

**Release readiness: NO-GO / no approval is implied.** A completed source-documentation review does not close findings, establish human accessibility, or authorize public-testnet launch.

## Evidence inventory

| Evidence / artifact | Observed state | Interpretation |
|---|---|---|
| Historical files retained | **61** files with identical ZIP member names/bytes | Phase 1–10 source reports, matrices, preserved code/test files and ledgers remain auditable |
| Unique findings | **64** (FE-001–FE-064) | Tracked items include confirmed source defects, candidates, investigations and program gaps; not 64 proven vulnerabilities |
| Numbered acceptance cases | **224 historical + 9 Phase 11 proposed = 233** | All specified; **none executed in Phase 11** |
| Current `main` | `6d3d69234415d294936d99e819367cff589ced3d` | Exact comparison to live `main` returned **identical** in Phase 11 |
| PR #97 | draft/open @ `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` | Ahead four commits, with eight changes limited to `.github/workflows/` and `audit/`; **no `web/` changes** vs canonical `main` |
| Existing PR #97 Web CI | [run 44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842): success | Tested web source matches `main`'s web tree; only scenarios actually run get historical E1 evidence |
| Other PR #97 run checks | Backend CI, reviewer readiness and change coverage failed on observed batch | No overall readiness or merge claim |
| New browser, mobile, or assistive tests | **0** | The environment lacks a runnable PR frontend checkout; do not confuse source inspection with execution |

### Detailed numbered-case inventory

| Phase | Cases | Original matrix | Status |
|---|---:|---|---|
| 2 | 20 | `Originals_Phases1-6/WeAll_Frontend_Phase6_MAIN_ReadOnly_2026-11-20/Originals_Phases1-5/Originals_Phases1-4/Phase2/02_PHASE2_ACCEPTANCE_MATRIX.md` | Not rerun |
| 3 | 21 | `Originals_Phases1-6/WeAll_Frontend_Phase6_MAIN_ReadOnly_2026-11-20/Originals_Phases1-5/Originals_Phases1-4/Phase3/02_PHASE3_REGRESSION_MATRIX.md` | Not rerun |
| 4 | 20 | `Originals_Phases1-6/WeAll_Frontend_Phase6_MAIN_ReadOnly_2026-11-20/Originals_Phases1-5/Originals_Phases1-4/Phase4/02_PHASE4_ACCEPTANCE_MATRIX.md` | Not rerun |
| 5 | 15 | `Originals_Phases1-6/WeAll_Frontend_Phase6_MAIN_ReadOnly_2026-11-20/Originals_Phases1-5/02_PHASE5_ACCEPTANCE_MATRIX.md` | Not rerun |
| 6 | 28 | `Originals_Phases1-6/WeAll_Frontend_Phase6_MAIN_ReadOnly_2026-11-20/02_PHASE6_ACCEPTANCE_MATRIX.md` | Not rerun |
| 7 | 27 | `WeAll_Frontend_Phase7_MAIN_ReadOnly_2026-11-20/02_PHASE7_ACCEPTANCE_MATRIX.md` | Not rerun |
| 8 | 30 | `WeAll_Frontend_Phase8_MAIN_ReadOnly_2026-11-20/02_PHASE8_ACCEPTANCE_MATRIX.md` | Not rerun |
| 9 | 35 | `WeAll_Frontend_Phase9_MAIN_ReadOnly_2026-11-20/02_PHASE9_ACCEPTANCE_MATRIX.md` | Not rerun |
| 10 | 28 | `WeAll_Frontend_Phase10_MAIN_ReadOnly_2026-11-20/02_PHASE10_ACCEPTANCE_MATRIX.md` | Not rerun |
| 11 | 9 | `10_PHASE11_ACCEPTANCE_SUPPLEMENT.md` (new, not historical) | Proposed only |
| **TOTAL** | **233** | **224 historical preserved + 9 new proposals** | **Unexecuted in Phase 11** |

## Scope and what “complete” means

1. **Document reconciliation complete** when every historical source report, acceptance case, FE ID, priority and confidence distinction is preserved and retrievable, with no accidental claim of runtime proof. **Achieved for current historical archive.**
2. **Source-audit content complete** when major frontend user journeys have a defined route/component inventory, risk/trust-boundary map, and development acceptance contract. **Substantially covered; targeted checks remain after runtime observations.**
3. **Rendered frontend audit complete** when the prioritized tests are executed in an isolated environment at exact revisions and each case records result/evidence. **Not achieved.**
4. **Accessibility acceptance complete** when actual rendered mobile/zoom/keyboard/screen-reader observations are recorded across the published primary journeys, with fixes independently rechecked. **Not achieved.**
5. **Release authorization** remains a separate, stricter protocol and operational decision. **Not requested or given.**

## Recommended next audit action

**Stop inventing new FE numbers for now.** Stage read-only test evidence against PR #97 or a clean test branch that preserves the audited frontend tree, starting with batches B01–B06 in the acceptance handoff. If a current source delta appears, record the new SHA and re-evaluate affected findings before execution. For every case: capture expected/observed result, browser/viewport, account/node fixtures, precise API fixture, console errors, screenshots where safe, and exact source commit. Preserve safeguards: signed-state authority, fail-closed sessions/PoH, vote privacy, evidence access limits, no duplicated dispatch.

## Audit-grade legend

- **E0** — inspected exact source and prior audit document (available).
- **E1** — historical, exact-commit CI result on a particular scenario; current 97 Web CI is useful but not exhaustive.
- **E2** — fresh controlled browser/end-to-end reproduction of a documented case (not run here).
- **E3** — hands-on assistive-technology/mobile and realistic user-journey acceptance (not run here).

### Traceability gap resolved in this documentation phase

The nine early FE-002–FE-010 items previously had no directly linked numbered case, even though their narratives and the Phase 1 work order existed. The new P11-01–P11-09 proposals provide an explicit validation contract without asserting execution. Ten existing historical cases (`R2-17, R2-18, R2-19, R2-20, R4-16, R4-17, R4-18, R4-19, R4-20, P8-30`) are broad cross-cutting tests with no specific FE assignment in their original rows; their lack of a direct FE link is **retained and documented**, not silently invented.

**Important:** The audit already distinguishes source-confirmed defects from conditional risks and investigations. Existing classifications remain authoritative in their original individual finding reports. “Overlapping workstream” is not “duplicate finding” and is not a closure signal.


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


# Phase 11 — overlap, dependencies and non-duplicate map

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

**Review result:** No FE ID has been deleted or closed. These are development *bundling suggestions*, not assertions of identical causes. A single fix may address several user symptoms, but each original case still requires explicit validation.

### D01 — Public Feed anonymous vs personal Feed state

**Related:** FE-001, FE-045.  
**Boundary:** Same public/private navigation boundary; different disabled control vs wrong-tab content.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D02 — Backend read failures and stale read-model UI

**Related:** FE-003, FE-011, FE-060, FE-055.  
**Boundary:** Common last-known vs error truth; different Feed, review queue, Activity and media data sources.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D03 — Selected account / node / session provenance

**Related:** FE-008, FE-017, FE-018, FE-019, FE-020, FE-021, FE-022, FE-023, FE-058, FE-059, FE-062.  
**Boundary:** Shared identity and asynchronous binding principle; each has different receipt, bearer, journal or cache contracts.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D04 — General eligibility copy vs canonical per-action authority

**Related:** FE-002, FE-012, FE-014, FE-033, FE-037, FE-038, FE-039.  
**Boundary:** Similar language/authority drift; distinct member, signer, reviewer and electorate gates.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D05 — Ballot visibility, choice and receipt state

**Related:** FE-033, FE-034, FE-035, FE-036.  
**Boundary:** One governance journey, four independent failure surfaces.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D06 — Accessibility, focus and landmarks

**Related:** FE-024, FE-025, FE-026, FE-027, FE-028, FE-044, FE-049, FE-054, FE-056.  
**Boundary:** Related accessibility user journeys; distinct semantics and concrete UI components.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D07 — Responsive density and scroll reachability

**Related:** FE-007, FE-009, FE-043, FE-050.  
**Boundary:** Visual overload and responsive acceptance; not interchangeable.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D08 — Group discovery vs election index pagination

**Related:** FE-005, FE-006, FE-040.  
**Boundary:** Bounded list disclosure and pagination, but different endpoint contracts.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D09 — Signed action status vs draft continuity

**Related:** FE-041, FE-042, FE-051, FE-057.  
**Boundary:** Submission/confirmation truth and user retention; distinct group, post, reply and lifecycle-card implementations.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D10 — Generated entity IDs and collision recovery

**Related:** FE-046, FE-063.  
**Boundary:** Group name-derived slug versus decision time-derived ID; different rules and remedies.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D11 — Media authoring, access and playback

**Related:** FE-047, FE-048, FE-052, FE-055.  
**Boundary:** Images/audio/video semantics, transport and evidence playback are separate areas.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D12 — Activity notifications and preferences

**Related:** FE-053, FE-060, FE-061, FE-062.  
**Boundary:** Bell freshness vs page availability vs muted categories vs bearer freshness.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D13 — Global local transaction history and destructive action

**Related:** FE-013, FE-064.  
**Boundary:** One storage design; separate cross-account segregation vs deletion safeguards.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

### D14 — Reviewer verdict intent and live transport

**Related:** FE-029, FE-031, FE-032.  
**Boundary:** Reviewer decision cancellation vs early external-room tab vs policy on signaling.  
**Closure rule:** Confirm each member of the group with its own original acceptance cases and evidence before marking that FE item resolved.

## Workstream partition (all FE items accounted exactly once)

| Workstream | Count | Finding IDs |
|---|---:|---|
| W1 Navigation, accessibility and responsive UX | 11 | FE-001, FE-024, FE-025, FE-026, FE-027, FE-028, FE-044, FE-045, FE-049, FE-054, FE-056 |
| W2 Public discovery, directories and page complexity | 11 | FE-003, FE-004, FE-005, FE-006, FE-007, FE-008, FE-009, FE-010, FE-040, FE-043, FE-050 |
| W3 Account, node, session and identity continuity | 10 | FE-017, FE-018, FE-019, FE-020, FE-021, FE-022, FE-023, FE-058, FE-059, FE-062 |
| W4 PoH reviewer verdict and live-room experience | 4 | FE-029, FE-030, FE-031, FE-032 |
| W5 Civic participation and decision rights | 10 | FE-002, FE-012, FE-014, FE-033, FE-034, FE-035, FE-036, FE-037, FE-038, FE-039 |
| W6 Reviewer/report queues and evidence viewing | 4 | FE-011, FE-015, FE-016, FE-052 |
| W7 Composers, signed actions and local history | 8 | FE-013, FE-041, FE-042, FE-046, FE-051, FE-057, FE-063, FE-064 |
| W8 Social media accessibility and delivery | 3 | FE-047, FE-048, FE-055 |
| W9 Activity and notification freshness | 3 | FE-053, FE-060, FE-061 |

**Important exceptions:** FE-010 is explicitly a program-level dependency rather than a new code defect; FE-023, FE-032, FE-039 and other “candidate/investigation” items must not be re-labeled as proven exploits based solely on location in an epic. FE-054 requires assistive-technology reproduction despite existing keyboard focus-trap protections.


# Phase 11 — frontend journey coverage and evidence gap matrix

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

Route coverage is sourced from the Phase 7 journey inventory and the intervening Phase 8–10 findings. “E0 reviewed” means source support, not successful navigation in a production browser.

| Journey | Surfaces | Related FE examples | Established evidence | Missing acceptance |
|---|---|---|---|---|
| **J01: Anonymous observer** | Feed, Groups, Decisions, thread, read-only navigation | FE-001, FE-003, FE-024, FE-045 | E0 source reviewed; E1 selected PR Web CI | E2 public-tab, deep-link, empty/error, E3 keyboard+mobile |
| **J02: Basic account creation and restoration** | LoginPage, AccountRegistrationPage, SessionDevicesPage | FE-017, FE-021, FE-030, FE-056, FE-058, FE-059 | E0 source reviewed; E1 PR browser custody subset | E2 registration journal/node switch; E3 accessible recovery |
| **J03: PoH guided asynchronous** | AccountVerificationPage, evidence upload, reviewer dashboard | FE-011, FE-017, FE-029, FE-030 | E0; E1 source/production smoke only | E2 all stages+interrupted journaling; E3 consent/assistive access |
| **J04: PoH live meeting** | LiveVerificationRoom, JurorDashboard, restricted evidence | FE-031, FE-032, FE-052 | E0; no media-access replay | E2 accepted/unaccepted/rejected + multi-browser media |
| **J05: Public Feed and search** | Feed, FeedView, group discovery | FE-001, FE-004, FE-005, FE-006, FE-028, FE-044, FE-045 | E0; some E1 smoke | E2 ranking race/search/pagination; E3 screen-reader sort |
| **J06: Post, reply and media publishing** | CreatePostPage, Thread, MediaGallery | FE-042, FE-047, FE-048, FE-051, FE-055 | E0; limited E1 static contract | E2 receipt unknown/failed/retry; E3 alt/caption/touch |
| **J07: Group creation and membership** | Groups, Group, GroupCreate | FE-002, FE-003, FE-040, FE-041, FE-046 | E0 | E2 Tier1/Tier2, collision, approval, pagination |
| **J08: Decisions and ballots** | Proposals, Proposal, ProposalCreate | FE-033, FE-034, FE-035, FE-036, FE-039, FE-043, FE-063 | E0; E1 limited rendered deliberation | E2 electorate/nullifier/ID; E3 timeline layout |
| **J09: Group elections/emissaries** | Group elections, GroupBallotPlanner | FE-040 | E0; E1 source checks in selected routes | E2 >100 election history and round-bound eligibility |
| **J10: Reports and juror work** | Disputes, DisputeReview, DisputeDetail, JurorDashboard | FE-011, FE-012, FE-014, FE-015, FE-016, FE-029 | E0 | E2 partial failures, cancellation, post-review states |
| **J11: Account profile and reputation presentation** | Account, public profile, roles | FE-037, FE-038, FE-039 | E0 | E2 Tier0-3, expired, suspended, changed role |
| **J12: Transaction history and recovery** | TxQueueProvider, TransactionsPage | FE-013, FE-022, FE-051, FE-057, FE-064 | E0; E1 receipt source checks | E2 two-node pending/rejected/unknown; E3 live announcements |
| **J13: Activity and preferences** | ActivityBell, Activity, activityReadState | FE-053, FE-060, FE-061, FE-062 | E0 | E2 notice freshness/read-state/offline/token renewal |
| **J14: Responsive & assistive navigation** | AppShell, mobile primary, dialogs, tabs | FE-024, FE-025, FE-026, FE-027, FE-028, FE-043, FE-049, FE-050, FE-054, FE-056 | E0; E1 theme contrast subset | E2 320/390/768/1440, 200/400% zoom; E3 screen reader |

## Cross-cutting personas and constraints

- **Anonymous / Tier0 / Tier1 / Tier2 / Tier3**: validate visually presented rights independently of signer/PoH backend protections. No real-person footage, identity secrets or governance actions on live community accounts.
- **Same account across two nodes, and two accounts on one browser**: verify chain identity, receipt provenance, sticky drafts, stale responses and disabled actions; do not loosen canonical source of truth.
- **320/390/768/1440px, 200% and 400% zoom, touch, keyboard and screen reader**: these are planned acceptance conditions, not claims of existing coverage.
- **Offline, delayed, failed, unknown and confirmed**: no false-empty, false-finality or premature draft loss.


# Phase 11 — prioritized read-only browser acceptance handoff

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

**This is a test plan, not a passed test report.** Run on isolated dummy accounts/test nodes. Keep PR #97 unmodified; if test execution requires separate fixtures, record fixture commit and never claim the PR’s UI changed. Every cited original case remains available in the ZIP.

| Batch | Priority | Frontend journey | Required role and context | Device/runtime | Related IDs | Existing test IDs to execute | Minimum acceptance outcome |
|---|---|---|---|---|---|---|---|
| **B01** | P1 | Anonymous/public navigation and skip link | Anonymous observer | 320px, 390px, 1440px + keyboard | FE-001, FE-024, FE-026, FE-045 | R4-01, R4-02, P8-23, P8-28, P7-21 | Keyboard skip must preserve route, Feed remains publicly reachable, no signing unlocked |
| **B02** | P1 | Account/node race and provenance | Account A/B, Node A/B, same/different chain | Two-browser two-node simulated delays | FE-017, FE-018, FE-019, FE-022, FE-023, FE-058, FE-059, FE-062 | R3-01, R3-02, P10-01, P10-05, P10-07, P10-17 | Only selected identity/network can update UI; receipts stay anchored; no duplicated sign |
| **B03** | P1 | Reviewer verdict cancellation | Tier3 juror, review fixture | Keyboard & browser prompt | FE-029 | P5-01, P5-02, P5-03, P5-05 | Cancel must cause zero signed verdict transactions; confirmed choice still obeys backend |
| **B04** | P1 investigation | Live room authority and confidential media | Applicant, accepted/unaccepted/declined jurors, outsider | Two-browser isolated WebRTC; backend signaling mocks | FE-031, FE-032, FE-052 | P5-08, P5-10, P5-11, P5-12, P5-13, P9-06 | Verify intended policy before pass/fail; no unauthorized media or false admission |
| **B05** | P1/P2 | Governance electorate and strict ballots | Tier2 member/outsider; closed/frozen election snapshot | Browser + canonical backend test fixtures | FE-033, FE-034, FE-035, FE-036, FE-039 | P6-02, P6-04, P6-08, P6-11, P6-13, P6-24, P6-28 | Unknown eligibility never shown as yes; redaction and nullifier remain protected |
| **B06** | P1 candidate | Media/post transaction unknown-state branch | Signed dummy account, media declaration | Backend tx-status returns pending/unknown/confirmed/rejected | FE-042, FE-051 | P9-01, P9-02, P9-03, P9-04, P7-10, P7-13 | Unknown is non-final and cannot authorize dependent continuation; drafts recoverable |
| **B07** | P2 | Civic directories and group actions | Tier0/1/2; group moderator | Error injection, >100 index rows | FE-002, FE-003, FE-005, FE-006, FE-040, FE-041, FE-046 | P7-01, P7-03, P7-04, P7-05, P7-24, P7-27 | Correct join tier, true empty/error, complete paged results, preserve creation intent |
| **B08** | P2 | Activity, notices, and account recovery | Authenticated dummy accounts with safe notice fixtures | Fast refresh, quiet hours, bearer renewal, node switches | FE-053, FE-060, FE-061, FE-062 | P9-11, P9-12, P9-13, P10-09, P10-13, P10-17 | Retain last-good authorized notices, fresh headers, auditable attention states |
| **B09** | P2 | Mobile/a11y visual acceptance | Anonymous + signed roles | 320/390/768/1440px; zoom 200/400%; screen reader | FE-025, FE-027, FE-028, FE-043, FE-044, FE-049, FE-050, FE-054, FE-056 | P7-14, P7-15, P8-11, P8-16, P8-21, P8-25, P9-17, P9-26, P9-30 | No unreadable overflow; landmarks, focus, choice and dialog isolation verified |
| **B10** | P2 | Social media accessibility and failed delivery | Media post with image/audio/video, restricted evidence | Screen reader and network 403/404/503 | FE-047, FE-048, FE-055 | P8-01, P8-06, P8-08, P9-21, P9-22, P9-23 | Meaningful alt/caption/transcript policy; media retry; no privacy leaks |
| **B11** | P2 | Composers, transaction activity, local history | Two dummy accounts, two signed actions | Delayed receipts, cross-account refresh, destructive action | FE-013, FE-041, FE-042, FE-057, FE-063, FE-064 | P7-08, P7-09, P7-12, P9-31, P10-21, P10-25, P10-26, P10-27 | Save draft and identity context; prevent ID collisions; no unconfirmed success |
| **B12** | P2 | Reports, roles and permissions | Reporter, reviewer, group moderator, juror | Partial endpoint failure and role transition | FE-011, FE-012, FE-014, FE-015, FE-016 | R2-01, R2-02, R2-03, R2-07, R2-17 | No false empty/assigned rights; distinguish provisional from canonical status |

## Evidence capture contract

For **each individual original case**: (1) exact commit and diff vs audited `main`; (2) environment (hosted/local, dummy accounts, node/chain IDs); (3) fixture and resulting request/response **without secrets**; (4) viewport, zoom and assistive technology, if relevant; (5) screen/console/trace capture with privacy review; (6) observed result and whether reproduced; (7) proposed fix or justified exception; (8) repeat after fixes with independent evidence. Record PASS, FAIL, BLOCKED or NOT RUN with precise rationale, not inference from unrelated CI.

## Safe execution boundary

- Read-only *audit* does not require a new PR or change to canonical `main`; use existing PR #97 only for tests if a runnable environment is available.
- Mocked **test fixtures** can simulate faults; do not send signed PoH, juror, financial or governance transactions to real accounts.
- Preserve canonical ballot privacy, PoH validity, media confidentiality, deterministic transaction ordering, and local observer receipt checks.
- Stop at the first potential unintended real-world authorization or credential exposure.
- Existing PR Web CI passed selected browser tests; it cannot be used to backfill PASS to any unexecuted FE acceptance case.


# Phase 11 — exact-commit CI provenance and audit closure policy

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

## Source delta verification

Connector comparison: `main` at `6d3d69234415d294936d99e819367cff589ced3d` versus PR #97 head `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` → PR ahead **4 commits**, behind **0**, **8 changed files**. Changed paths (each non-frontend):

- `.github/workflows/public-testnet-audit-diagnostic.yml`
- `audit/public-testnet/FULL_REPORT.md`
- `audit/public-testnet/README.md`
- `audit/public-testnet/diagnostics/test_r1b_helper_hierarchy.py`
- `audit/public-testnet/diagnostics/test_r1c_helper_authority.py`
- `audit/public-testnet/evidence/WeAll_Master_Audit_Reaudit_Through_R1A.zip`
- `audit/public-testnet/results/R1B-9d547a6-diagnostic.log`
- `audit/public-testnet/results/R1C-6485276-diagnostic.log`

**Result:** there are no `web/` changes in that comparison. The Web CI run on PR #97 therefore checked web source identical to the `main` web tree at this snapshot, subject to the exact workflow and environment used. The workflow suite's test selection—not source identity—determines the scope of passing evidence.

## Historical PR #97 workflow results, retrieved read-only in Phase 11

| Workflow | Run | Observed result | Evidence implication |
|---|---:|---|---|
| Web CI | [44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) | **success** | Selected TypeScript, build, production Chromium, custody, theme, deliberation and dependency steps reported pass |
| Backend CI | [44799230934](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230934) | failure | Cannot declare overall PR/release ready |
| Reviewer Readiness Gate | [44799230972](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230972) | failure | Cannot declare reviewer readiness closed |
| Repository-wide change coverage | [44799230878](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230878) | failure | Unresolved coverage/approval evidence |

## Closure rules for the 64 FE findings

1. A source-confirmed issue remains **open** until a change and scenario-specific validation show that its effect is gone. Passing an unrelated CI job never closes it.
2. A *candidate* is resolved only by an actual reproduction, stronger proof of nonreachability, or a documented policy/product decision backed by controlled tests. Do not silently downgrade.
3. A frontend display/right/eligibility mismatch must be corrected without weakening backend eligibility, signing, finality, appeal or evidence access rules.
4. Browser acceptance must include error states and representative user roles, not only happy-path screens; mobile/a11y require rendered/assistive evidence.
5. Document-only Phase 11 adds **zero** findings, **zero** closures, **zero** new CI or browser executions, and **zero** repository writes.

## Next-step gating table

| Level | Current posture | What changes it |
|---|---|---|
| Source/document traceability | Reconciled for 64 items | Reopen exact source as code evolves; keep full docs |
| Individual FE validation | Predominantly E0, selected historical E1 | Execute explicit case IDs and record results at exact head |
| End-to-end user journeys | Not independently accepted | Isolated 2-account/2-node, recovery and signed-receipt rehearsals |
| Mobile and screen-reader acceptance | Not established by Desktop Chrome CI | Run mobile/zoom/keyboard/assistive matrix |
| Public testnet | **NO-GO; no approval issued** | Separate technical, security and operational gates; not resolved by this documentation |


---

# Phase 12 — read-only targeted acceptance evidence (append-only)



## Appended source: `01_PHASE12_OUTCOME_AND_BOUNDARIES.md`

# Phase 12 — targeted frontend acceptance evidence and execution disposition

**Date:** 2026-11-20  · **Audit mode:** strictly read-only / documentation-only  · **Canonical `main`:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d)  · **PR #97:** [open draft](https://github.com/errol1swaby2-bit/WeAll-Protocol/pull/97) at `2ab08aa74b86806e1c4fef1f47b184d4f80c4793`.

## Result

- **Three top-priority acceptance batches analyzed:** B01 (public navigation), B03 (juror decision cancellation), B06 (publishing finality), as prioritized in the preserved Phase 11 test handoff.
- **Source evidence reverified (E0):** FE-001, FE-024, FE-029 and FE-051, with exact repository file paths and observations in document `02_TARGETED_SOURCE_EVIDENCE.md`.
- **New browser or full-application tests executed: 0.** PR #97's checkout could not be obtained in the available container: direct GitHub `git ls-remote` returned `Could not resolve host: github.com`. The connected GitHub repository source-reading capability worked; it is not a runnable browser checkout.
- **Previously completed Web CI:** [run 44799230842](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/44799230842) reported success for four Web CI jobs on PR #97. It is **historical E1 evidence for those selected tests**, not a PASS for any of the 233 audit acceptance cases without an exact mapping and assertion review.
- **Repository integrity:** live GitHub comparison returned `main` identical to `6d3d69234415d294936d99e819367cff589ced3d`. PR #97 remains open/draft. No repository file, workflow, PR, branch, or release was modified.
- **Open tracked findings:** FE-001 through FE-064; zero are closed by Phase 12. **Numbered acceptance cases:** 233 (224 original Phase 2–10 plus 9 Phase 11 supplements). All are `NOT_RUN` for this Phase 12; E0 source reads are recorded separately from test status.

## Phase 12 status table

| Batch | Source evidence outcome | Runtime result | Release disposition |
|---|---|---|---|
| B01 — FE-001, FE-024, FE-026, FE-045 | Disabled anonymous Feed primary tab and raw skip-link fragment reverified; render focus/route not reproduced | NOT RUN | OPEN |
| B03 — FE-029 | `window.prompt(...) || ""` loses Cancel distinction; verdict skeleton call follows | NOT RUN | OPEN |
| B06 — FE-042, FE-051 | Fallback predicate treats `unknown` as acceptable; reachability and downstream outcome not proven | NOT RUN | OPEN |
| Other batches B02, B04, B05, B07–B12 | Prior E0 and any specifically matched E1 evidence retained in source reports | NOT RUN this phase | OPEN / unverified |

### What we can and cannot conclude

The re-reviewed source **demonstrates the conditions and guards described**. It does **not** show a user-visible failure occurring on a running deployment, unauthorized signing, failed backend invariants, a media leak, or a violated consensus rule. Existing CI success cannot prove the unexecuted keyboard, live juror, or unknown-status acceptance cases.

### High-priority next test environment requirement

Use an isolated PR #97 checkout or deployed preview with an exact SHA, controlled dummy identities, safe mocked node responses, and no real signed governance/verification events. Capture **browser console, URL/focus before-after, sanitized network calls, viewport, and assertions**. Keep branch and tests unmodified; additional runtime probes should be external/test-only and not mutate the code under audit. When results are available, update each `case_id` row with PASS/FAIL/BLOCKED and its evidence URI; do not retroactively mark tests passed based on source reads.

**Overall:** source-documentation continuity PASS; targeted browser acceptance NOT RUN; public-testnet release authorization **NO-GO**.


## Appended source: `02_TARGETED_SOURCE_EVIDENCE.md`

# Phase 12 — three targeted batches: exact-head source evidence

**Reference:** [`main` at `6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d); PR #97 `web/` subtree unchanged relative to this base (Phase 11 comparison of the PR). All links below point to exact audited-source paths, not to a development or remediation branch.

## B01: Anonymous Feed primary navigation and keyboard skip link

### FE-001 — source-confirmed primary-navigation inconsistency

- `web/src/components/PrimaryNavigation.tsx` lines 6–11 declare `{ label: "Feed", href: "/feed", sessionOnly: true }`. Lines 20–31 calculate `unavailable = item.sessionOnly && !ready` and set `disabled={unavailable}`.
- `web/src/App.tsx` lines 51–55 deliberately render `<Feed />` on `/feed` without requiring a session.
- **Narrow finding:** the **primary** public Feed tab is disabled for an anonymous observer, despite the public route. The page remains potentially accessible through a direct route; do not claim full feed lockout.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx); [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx).

### FE-024 — skip-link route-collision mechanism, not rendered yet

- `web/src/components/AppShell.tsx` lines 202–206: `<a className="appShellSkipLink" href="#app-shell-content">` without an activation handler.
- Lines 308–311: `<main id="app-shell-content" ... tabIndex={-1}>`. A DOM anchor target exists but the application uses a hash router (`/#/feed`). Following a raw fragment can replace that route segment. The actual navigation/focus response still requires browser observation.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx).

**Existing-test gap:** `web/scripts/test_accessibility_source.mjs` verifies that the text `Skip to content` and the target `id="app-shell-content"` exist. It does not activate the link or assert the hash route/focus. `web/scripts/test_focused_shell_source.mjs` similarly asserts source tokens, not keyboard behavior.

**Required runtime assertions:** anonymous `/#/feed` loads; primary Feed control remains available; Tab→Skip→Enter leaves the route `/#/feed`; focus lands on main; signed actions remain backend-gated; keyboard order and 320/390/1440px variations captured. **Status: NOT RUN.**

## B03: FE-029 juror decision cancellation

- `web/src/pages/JurorDashboard.tsx` lines 518–529: `const note = window.prompt("Optional note", "") || "";`, followed by `weall.pohAsyncTxReview(body, apiBase, headers)` and `submitSkeletonTx(...)`. Browser `prompt()` returns `null` on Cancel; the fallback converts it to `""` and no early return is visible in that function.
- Contrasting safeguard: `web/src/components/FeedView.tsx` explicitly checks `if (reasonRaw === null) return;` after its report prompt. This is **behavioral consistency evidence**, not a substitute reviewer authorization check.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx), [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx).

**Required runtime assertions:** with fake authenticated Tier3 reviewer and fully mocked endpoints, choose Approve/Reject→Cancel optional-note prompt; request counter for juror-review skeleton and signed submission remains **zero**. Deliberate confirmation should proceed through canonical gates. No real case or identity involved. **Status: NOT RUN.**

## B06: FE-051 unknown transaction state in post publishing

- `web/src/pages/CreatePostPage.tsx` lines 82–85: `isSubmittedOrConfirmed()` returns true for `confirmed`, `pending`, **and `unknown`**.
- Lines 643–664: when no nonzero submission nonce is returned but a transaction ID exists, the function checks `waitForTxConfirmed()` and then accepts any status recognized by that predicate before proceeding to retain `finalPostId` / return the submission object.
- **Boundary:** This is a conditional fallback; the ordinary nonzero-nonce path instead waits for account nonce advancement. No fresh test has shown which API branch is reached in production, whether backend inclusion fails, or what finality UI states result. The frontend distinguishes local transaction receipt in other components.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx).

**Required runtime assertions:** dummy node reply with tx ID and missing/zero nonce; return `unknown` vs `pending` vs valid successful receipt vs rejected; verify no optimistic **confirmed** outcome, no premature dependent stage/irreversible draft loss, no duplicate dispatch on retry, and honest path to Transactions. **Status: NOT RUN.**

## Evidence grading

- **E0 reverified:** exact source snippets above were fetched at the canonical SHA with the connected GitHub reader.
- **E1 historical:** existing PR #97 CI applies to the same `web/` tree but its successful tests are narrower than these cases.
- **E2 / E3:** no Phase 12 application browser or assistive-technology evidence. **No finding closed.**


## Appended source: `03_PR97_TEST_SCOPE_AND_STATUS.md`

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


## Appended source: `04_THREE_BATCH_READ_ONLY_REPLAY_RUNBOOK.md`

# Phase 12 — bounded read-only runtime acceptance runbook

**This is an executable test plan, not an executed test report.** It does not modify source, CI, PR #97, or any canonical chain state. Use an isolated instance of the exact PR #97 frontend with test-only mocked APIs or dedicated disposable nodes; do not transmit real signed PoH, governance, economic or reviewer transactions.

## Common evidence manifest

Record: test-case ID and batch; repository and exact SHA; browser build/version; fixture identity (dummy, redacted); node/chain/genesis identity; request/response and clock (sanitized); viewport and zoom; initial/final URL and focused element; screenshot/video/trace when safe; intercepted submission count; expected/observed; result PASS/FAIL/BLOCKED; reason; evidence artifact SHA256. Never record bearers, private keys, recovery files or real evidence media.

## B01 — public route and keyboard skip

1. On an isolated browser profile with no local account, start at `/#/feed` with a public fixture endpoint and zero bearer.
2. Assert public Feed can be opened from primary navigation; no hidden authentication requirement to read.
3. Focus the first `Skip to content` link, activate by keyboard; record `location.hash`, `document.activeElement`, main content visibility, and console exceptions.
4. Repeat at 320px, 390px, and 1440px and with a direct deep link. Verify writes remain disabled for anonymous actor.
5. Tie observations to FE-001 / FE-024, R4-01/R4-02, and P8-23/P8-28. No code fix or failed-test retry should be automatically invoked.

## B03 — canceled juror note

1. Use a disposable, non-live Tier3 reviewer identity and mocked async review case. Block all outbound nonlocal requests.
2. Instrument mocks for the juror skeleton endpoint and any eventual signed transaction submission, initially zero.
3. Trigger approve and reject separately; dismiss the optional-note prompt with **Cancel**.
4. Assert zero request/signed-submission calls. If calls occur, record the exact intercepted payload and abort any actual signature or broadcast.
5. Compare against the deliberate-confirmation scenario in the same fixture. Tie to FE-029 and P5-01/P5-02/P5-03/P5-05.

## B06 — post creation unknown status

1. Use a dummy account with mocked signer and a deterministic media/post submission response.
2. Arrange a response with tx ID and **missing or zero** nonce (the conditional fallback) and inject `unknown` from the status endpoint; record all later stage requests.
3. Repeat with `pending`, `confirmed`, `rejected`, and an empty transaction ID, plus a separate nonzero nonce scenario.
4. Record whether drafts persist, whether any dependent step/confirmed UI advances prematurely, and whether repeat submission is prevented while outcome is unknown.
5. Tie to FE-042/FE-051, P9-01–P9-04 and P7-10/P7-13. Do not regard a submitted transaction as confirmed.

## Stop and release condition

Abort test execution on unexpected real credentials, personal media, nonmock authorization, uncontrolled signing, or nonlocal node writes. Each case must receive independently recorded PASS/FAIL/BLOCKED with evidence. Source assertion success, existing CI pass, or a nonfunctional route preview cannot close cases. All three batches remain **NOT RUN** in this Phase 12 handoff.


## Appended source: `05_REGISTER_README.md`

# Phase 12 — all 233 numbered acceptance cases

`05_ALL_233_CASES_EXECUTION_REGISTER.csv` and `06_ALL_233_CASES_EXECUTION_REGISTER.json` enumerate the original case IDs exactly once, with the **complete, original source matrix row** and its archive path/line number.

- 224 Phase 2–10 historical cases + nine Phase 11 proposed cases.
- Status for **every case: NOT_RUN in Phase 12**. Never interpret source evidence or CI test names as a case-specific PASS without independent reproduction.
- `E0_SOURCE_REVERIFIED` is attached to the 15 cases selected across B01/B03/B06 *only as source review bookkeeping*; it is **not a claim that their browser assertions were executed**.
- Original source matrices and complete historic master remain unmodified in the cumulative ZIP.
- Cases are stable identifiers; documents preserve original classification and authorization constraints. No changes to finding numbers FE-001–FE-064.
